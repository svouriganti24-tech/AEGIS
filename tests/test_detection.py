"""Tests for the rules engine, threat detector and alert manager."""

from __future__ import annotations

import time
import unittest

from core.constants import AlertStatus, Severity
from data.models import SecurityEvent
from security.alerts.alert_manager import AlertManager
from security.detection.rules_engine import (
    BruteForceRule,
    EventRateRule,
    EvaluationContext,
    OpenPortExposureRule,
    OffHoursRule,
    PortSweepRule,
    RulesEngine,
    SuspiciousKeywordRule,
)
from security.detection.threat_detector import EventBuffer, ThreatDetector
from tests.helpers import PROJECT_ROOT  # noqa: F401  (path setup)


def make_event(event_type="AUTH_LOGIN_FAILURE", source="10.0.0.9", description="Failed login",
               severity=Severity.LOW, timestamp=None, **kwargs):
    return SecurityEvent(event_type=event_type, source=source, description=description,
                         severity=severity,
                         timestamp=timestamp or time.strftime("%Y-%m-%dT%H:%M:%S"), **kwargs)


class RuleTests(unittest.TestCase):
    def test_brute_force_below_threshold_no_match(self):
        rule = BruteForceRule()
        ctx = EvaluationContext(brute_force_threshold=5)
        result = rule.evaluate(make_event(), ctx)
        self.assertFalse(result.matched)

    def test_brute_force_matches_at_threshold(self):
        rule = BruteForceRule()
        ctx = EvaluationContext(brute_force_threshold=5,
                                recent_events=[make_event() for _ in range(4)])
        result = rule.evaluate(make_event(), ctx)
        self.assertTrue(result.matched)
        self.assertEqual(result.severity, Severity.HIGH)

    def test_brute_force_escalates_to_critical(self):
        rule = BruteForceRule()
        ctx = EvaluationContext(brute_force_threshold=5,
                                recent_events=[make_event() for _ in range(11)])
        result = rule.evaluate(make_event(), ctx)
        self.assertEqual(result.severity, Severity.CRITICAL)

    def test_brute_force_ignores_other_events(self):
        rule = BruteForceRule()
        result = rule.evaluate(make_event(event_type="PORT_SCAN"), EvaluationContext())
        self.assertFalse(result.matched)

    def test_port_sweep_rule(self):
        rule = PortSweepRule()
        ctx = EvaluationContext(repeated_scan_threshold=3,
                                recent_events=[make_event(event_type="PORT_SCAN") for _ in range(2)])
        result = rule.evaluate(make_event(event_type="PORT_SCAN"), ctx)
        self.assertTrue(result.matched)
        self.assertEqual(result.severity, Severity.MEDIUM)

    def test_event_rate_rule(self):
        rule = EventRateRule()
        ctx = EvaluationContext(event_rate_threshold=40,
                                recent_events=[make_event(event_type="NOISE") for _ in range(40)])
        result = rule.evaluate(make_event(), ctx)
        self.assertTrue(result.matched)

    def test_suspicious_keyword_rule(self):
        rule = SuspiciousKeywordRule()
        result = rule.evaluate(make_event(description="Possible SQL injection attempt"),
                               EvaluationContext())
        self.assertTrue(result.matched)
        self.assertEqual(result.severity, Severity.HIGH)

    def test_open_port_exposure_rule(self):
        rule = OpenPortExposureRule()
        ctx = EvaluationContext()
        quiet = rule.evaluate(make_event(event_type="PORT_SCAN",
                                         details={"open_count": 3}), ctx)
        self.assertFalse(quiet.matched)
        loud = rule.evaluate(make_event(event_type="PORT_SCAN",
                                        details={"open_count": 40}), ctx)
        self.assertTrue(loud.matched)
        self.assertEqual(loud.severity, Severity.LOW)

    def test_off_hours_rule_daytime_no_match(self):
        rule = OffHoursRule()
        # Build a timestamp at local noon regardless of the test machine's TZ.
        import datetime
        noon = datetime.datetime.now().astimezone().replace(hour=12, minute=0)
        event = make_event(event_type="AUTH_LOGIN_SUCCESS",
                           timestamp=noon.isoformat(timespec="seconds"))
        self.assertFalse(rule.evaluate(event, EvaluationContext()).matched)


class EngineAndDetectorTests(unittest.TestCase):
    def test_engine_runs_all_rules_and_sorts(self):
        engine = RulesEngine()
        ctx = EvaluationContext(brute_force_threshold=5,
                                recent_events=[make_event() for _ in range(6)])
        matches = engine.evaluate(make_event(), ctx)
        self.assertTrue(matches)
        weights = [m.severity.weight for m in matches]
        self.assertEqual(weights, sorted(weights, reverse=True))

    def test_detector_emits_detection_once_then_cooldowns(self):
        detector = ThreatDetector(cooldown_seconds=60)
        first = detector.process(make_event())  # 1st failure
        self.assertEqual(first, [])
        for _ in range(4):                      # failures 2..5
            detections = detector.process(make_event())
        self.assertEqual(len(detections), 1)    # exactly one new detection (5th)
        again = detector.process(make_event())  # within cooldown
        self.assertEqual(again, [])

    def test_internal_events_are_ignored(self):
        detector = ThreatDetector(cooldown_seconds=0)
        self.assertEqual(detector.process(make_event(internal=True)), [])

    def test_event_buffer_window(self):
        buffer = EventBuffer(window_seconds=1)
        buffer.add(make_event())
        self.assertEqual(len(buffer.events_for("10.0.0.9")), 1)
        time.sleep(1.1)
        self.assertEqual(len(buffer.events_for("10.0.0.9")), 0)


class AlertManagerTests(unittest.TestCase):
    def setUp(self):
        from tests.helpers import make_runtime
        self.registry, self.tmp = make_runtime()
        self.manager = self.registry.alert_manager
        self._tmp = self.tmp

    def tearDown(self):
        self.registry.shutdown()

    def _detection(self, title="Test alert", source="src"):
        from security.detection.threat_detector import Detection
        return Detection(rule_id="test", rule_name="Test", title=title,
                         description="desc", severity=Severity.MEDIUM, source=source)

    def test_dedupes_into_occurrences(self):
        first = self.manager.raise_from_detection(self._detection())
        second = self.manager.raise_from_detection(self._detection())
        self.assertEqual(first.id, second.id)
        self.assertEqual(second.occurrences, 2)
        self.assertEqual(self.manager.open_count(), 1)

    def test_escalation_on_threshold(self):
        self.manager.escalation_threshold = 2
        alert = self.manager.raise_from_detection(self._detection())
        self.assertEqual(alert.severity, Severity.MEDIUM)
        alert = self.manager.raise_from_detection(self._detection())
        self.assertEqual(alert.severity, Severity.HIGH)

    def test_ack_and_resolve_lifecycle(self):
        alert = self.manager.raise_from_detection(self._detection())
        acked = self.manager.acknowledge(alert.id, "admin")
        self.assertEqual(acked.status, AlertStatus.ACKNOWLEDGED.value)
        self.assertEqual(acked.acknowledged_by, "admin")
        resolved = self.manager.resolve(alert.id, "admin")
        self.assertEqual(resolved.status, AlertStatus.RESOLVED.value)

    def test_subscriber_notified(self):
        seen = []
        self.manager.subscribe(seen.append)
        self.manager.raise_from_detection(self._detection())
        self.assertEqual(len(seen), 1)
        self.manager.unsubscribe(seen.append)


if __name__ == "__main__":
    unittest.main()
