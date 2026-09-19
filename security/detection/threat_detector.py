"""Threat detector: buffers recent events, applies rules, emits detections.

The detector keeps a per-source sliding window of recent events so rules can
reason about *history* (how many failures happened in the last N seconds?).
It collapses duplicate detections with a per-(rule, source) cooldown so a
brute-force burst produces one alert, not one alert per attempt.
"""

from __future__ import annotations

import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import timedelta

from core.constants import Severity
from core.logger import get_logger
from core.utils import parse_iso, utc_now
from data.models import SecurityEvent
from security.detection.rules_engine import EvaluationContext, RuleResult, RulesEngine

log = get_logger("security.detection")


@dataclass
class Detection:
    """An engine-level threat finding, pre-alert."""

    rule_id: str
    rule_name: str
    title: str
    description: str
    severity: Severity
    source: str
    evidence_event_id: int | None = None
    details: dict = field(default_factory=dict)
    detected_at: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "source": self.source,
            "evidence_event_id": self.evidence_event_id,
            "details": self.details,
            "detected_at": self.detected_at,
        }


class EventBuffer:
    """Thread-safe per-source ring buffer of recent events."""

    def __init__(self, window_seconds: int = 900, max_per_source: int = 500):
        self.window_seconds = window_seconds
        self.max_per_source = max_per_source
        self._buffers: dict[str, deque] = defaultdict(lambda: deque(maxlen=max_per_source))
        self._lock = threading.RLock()

    def add(self, event: SecurityEvent) -> None:
        with self._lock:
            self._buffers[event.source].append(event)

    def events_for(self, source: str, *, window_seconds: int | None = None) -> list[SecurityEvent]:
        window = window_seconds or self.window_seconds
        cutoff = utc_now() - timedelta(seconds=window)
        with self._lock:
            return [
                e for e in self._buffers.get(source, ())
                if (parse_iso(e.timestamp) or utc_now()) >= cutoff
            ]

    def prune(self) -> int:
        cutoff = utc_now() - timedelta(seconds=self.window_seconds)
        removed = 0
        with self._lock:
            for source in list(self._buffers):
                buf = self._buffers[source]
                keep = deque(
                    (e for e in buf if (parse_iso(e.timestamp) or utc_now()) >= cutoff),
                    maxlen=buf.maxlen,
                )
                removed += len(buf) - len(keep)
                if keep:
                    self._buffers[source] = keep
                else:
                    self._buffers.pop(source, None)
        return removed

    def tracked_sources(self) -> int:
        with self._lock:
            return len(self._buffers)


class ThreatDetector:
    """Turns the event stream into :class:`Detection` objects via the rules engine."""

    def __init__(
        self,
        rules_engine: RulesEngine | None = None,
        *,
        buffer_window_seconds: int = 900,
        cooldown_seconds: int = 20,
        detection_callback=None,
    ):
        self.engine = rules_engine or RulesEngine()
        self.buffer = EventBuffer(window_seconds=buffer_window_seconds)
        self.cooldown_seconds = cooldown_seconds
        self._cooldowns: dict[tuple[str, str], datetime] = {}
        self._lock = threading.RLock()
        self._detection_callback = detection_callback
        self.stats = {"events_seen": 0, "detections": 0, "suppressed": 0}

    # ------------------------------------------------------------------ API

    def process(self, event: SecurityEvent) -> list[Detection]:
        """Feed one event through the pipeline; returns new detections."""
        if event.internal:
            return []
        self.stats["events_seen"] += 1
        self.buffer.add(event)

        ctx = self._build_context(event)
        try:
            results = self.engine.evaluate(event, ctx)
        except Exception:  # noqa: BLE001
            log.exception("Rules engine evaluation failed")
            return []

        detections = []
        for result in results:
            detection = self._to_detection(event, result)
            if self._in_cooldown(detection.rule_id, detection.source):
                self.stats["suppressed"] += 1
                continue
            self._mark_cooldown(detection.rule_id, detection.source)
            detections.append(detection)
            self.stats["detections"] += 1
            log.info("Detection: %s (%s) severity=%s source=%s",
                     detection.title, detection.rule_id, detection.severity.value, detection.source)

        if detections and self._detection_callback:
            try:
                self._detection_callback(detections)
            except Exception:  # noqa: BLE001
                log.exception("Detection callback failed")
        return detections

    # ------------------------------------------------------------- internals

    def _build_context(self, event: SecurityEvent) -> EvaluationContext:
        from core import constants as C
        recent = self.buffer.events_for(event.source, window_seconds=max(
            C.BRUTE_FORCE_WINDOW_SECONDS, C.REPEATED_SCAN_WINDOW_SECONDS, C.EVENT_RATE_WINDOW_SECONDS))
        # Exclude the event currently being processed from "history" counts.
        recent = [e for e in recent if e is not event]
        return EvaluationContext(
            recent_events=recent,
            brute_force_threshold=C.BRUTE_FORCE_THRESHOLD,
            brute_force_window_seconds=C.BRUTE_FORCE_WINDOW_SECONDS,
            repeated_scan_threshold=C.REPEATED_SCAN_THRESHOLD,
            repeated_scan_window_seconds=C.REPEATED_SCAN_WINDOW_SECONDS,
            event_rate_threshold=C.EVENT_RATE_THRESHOLD,
            event_rate_window_seconds=C.EVENT_RATE_WINDOW_SECONDS,
        )

    def _to_detection(self, event: SecurityEvent, result: RuleResult) -> Detection:
        severity = Severity(result.severity)
        if event.severity.weight > severity.weight:
            severity = event.severity  # never downgrade below the event's own severity
        return Detection(
            rule_id=result.rule_id,
            rule_name=result.rule_name,
            title=result.title,
            description=result.description,
            severity=severity,
            source=event.source or "unknown",
            evidence_event_id=event.id,
            details=dict(result.details),
            detected_at=utc_now().isoformat(timespec="seconds"),
        )

    def _in_cooldown(self, rule_id: str, source: str) -> bool:
        with self._lock:
            last = self._cooldowns.get((rule_id, source))
            if last is None:
                return False
            elapsed = (utc_now() - last).total_seconds()
            if elapsed >= self.cooldown_seconds:
                self._cooldowns.pop((rule_id, source), None)
                return False
            return True

    def _mark_cooldown(self, rule_id: str, source: str) -> None:
        with self._lock:
            self._cooldowns[(rule_id, source)] = utc_now()
