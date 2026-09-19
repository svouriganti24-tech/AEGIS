"""Extensible security rules engine.

A *rule* receives one :class:`SecurityEvent` plus an :class:`EvaluationContext`
(recent history + thresholds) and returns a :class:`RuleResult`. The engine
runs every registered rule; anything that matches is passed upward by the
threat detector.

Adding a new rule = subclass :class:`SecurityRule`, implement ``evaluate``,
and ``engine.register(MyRule())`` — no other code changes required.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from core.constants import Severity, SUSPICIOUS_KEYWORDS
from data.models import SecurityEvent


@dataclass
class RuleResult:
    rule_id: str
    rule_name: str
    matched: bool
    severity: Severity = Severity.INFO
    title: str = ""
    description: str = ""
    details: dict = field(default_factory=dict)

    @classmethod
    def no_match(cls, rule: "SecurityRule") -> "RuleResult":
        return cls(rule_id=rule.id, rule_name=rule.name, matched=False)


@dataclass
class EvaluationContext:
    """Everything a rule may need beyond the event itself."""

    recent_events: list[SecurityEvent] = field(default_factory=list)  # trailing window, same source
    brute_force_threshold: int = 5
    brute_force_window_seconds: int = 300
    repeated_scan_threshold: int = 3
    repeated_scan_window_seconds: int = 600
    event_rate_threshold: int = 40
    event_rate_window_seconds: int = 60

    def count(self, *, event_type: str | None = None) -> int:
        if event_type is None:
            return len(self.recent_events)
        return sum(1 for e in self.recent_events if e.event_type == event_type)


class SecurityRule(ABC):
    """Base class for all detection rules."""

    id: str = "base-rule"
    name: str = "Base rule"
    description: str = ""

    @abstractmethod
    def evaluate(self, event: SecurityEvent, ctx: EvaluationContext) -> RuleResult:
        """Return a RuleResult; ``matched=True`` triggers alert handling."""

    def __repr__(self) -> str:  # pragma: no cover
        return f"<{type(self).__name__} id={self.id!r}>"


# ---------------------------------------------------------------------------
# Built-in rules
# ---------------------------------------------------------------------------


class BruteForceRule(SecurityRule):
    """Repeated failed logins from the same source."""

    id = "brute-force"
    name = "Brute-force authentication"
    description = "Detects repeated failed logins from one source within a short window."

    def evaluate(self, event: SecurityEvent, ctx: EvaluationContext) -> RuleResult:
        if event.event_type != "AUTH_LOGIN_FAILURE":
            return RuleResult.no_match(self)
        failures = 1 + ctx.count(event_type="AUTH_LOGIN_FAILURE")
        if failures < ctx.brute_force_threshold:
            return RuleResult.no_match(self)
        severity = Severity.HIGH
        if failures >= ctx.brute_force_threshold * 2:
            severity = Severity.CRITICAL
        return RuleResult(
            rule_id=self.id,
            rule_name=self.name,
            matched=True,
            severity=severity,
            title="Brute-force authentication attempts",
            description=(
                f"{failures} failed login attempts from '{event.source}' within "
                f"{ctx.brute_force_window_seconds} seconds."
            ),
            details={"failures": failures, "window_seconds": ctx.brute_force_window_seconds},
        )


class PortSweepRule(SecurityRule):
    """Repeated scans against the same target — possible reconnaissance."""

    id = "port-sweep"
    name = "Repeated port scanning"
    description = "Detects multiple scan jobs aimed at one target in a short window."

    def evaluate(self, event: SecurityEvent, ctx: EvaluationContext) -> RuleResult:
        if event.event_type != "PORT_SCAN":
            return RuleResult.no_match(self)
        scans = 1 + ctx.count(event_type="PORT_SCAN")
        if scans < ctx.repeated_scan_threshold:
            return RuleResult.no_match(self)
        severity = Severity.MEDIUM
        if scans >= ctx.repeated_scan_threshold * 2:
            severity = Severity.HIGH
        return RuleResult(
            rule_id=self.id,
            rule_name=self.name,
            matched=True,
            severity=severity,
            title="Repeated port scanning activity",
            description=(
                f"{scans} scans against '{event.source}' within "
                f"{ctx.repeated_scan_window_seconds} seconds — possible reconnaissance sweep."
            ),
            details={"scans": scans, "window_seconds": ctx.repeated_scan_window_seconds},
        )


class EventRateRule(SecurityRule):
    """Abnormal event volume from a single source."""

    id = "event-rate"
    name = "Abnormal event frequency"
    description = "Flags sources producing an unusual number of events in one minute."

    def evaluate(self, event: SecurityEvent, ctx: EvaluationContext) -> RuleResult:
        if event.internal:
            return RuleResult.no_match(self)
        volume = 1 + ctx.count()
        if volume < ctx.event_rate_threshold:
            return RuleResult.no_match(self)
        return RuleResult(
            rule_id=self.id,
            rule_name=self.name,
            matched=True,
            severity=Severity.MEDIUM,
            title="Abnormal event frequency",
            description=(
                f"Source '{event.source}' generated {volume} events in "
                f"{ctx.event_rate_window_seconds} seconds."
            ),
            details={"volume": volume, "window_seconds": ctx.event_rate_window_seconds},
        )


class SuspiciousKeywordRule(SecurityRule):
    """Descriptions containing high-risk security keywords."""

    id = "suspicious-keyword"
    name = "Suspicious keyword"
    description = "Raises severity when event text mentions exploitation activity."

    _CACHE: dict[str, tuple[Severity, str]] = {}

    def evaluate(self, event: SecurityEvent, ctx: EvaluationContext) -> RuleResult:
        text = f"{event.description} {event.event_type}".lower()
        hit = None
        for keyword, severity in SUSPICIOUS_KEYWORDS.items():
            if keyword in text:
                if hit is None or severity.weight > hit[0].weight:
                    hit = (severity, keyword)
        if hit is None:
            return RuleResult.no_match(self)
        severity, keyword = hit
        return RuleResult(
            rule_id=self.id,
            rule_name=self.name,
            matched=True,
            severity=severity,
            title=f"Suspicious activity detected ('{keyword}')",
            description=f"Event from '{event.source}' mentions '{keyword}': {event.description[:200]}",
            details={"keyword": keyword, "event_id": event.id},
        )


class OffHoursRule(SecurityRule):
    """Authentication or scanning activity between 00:00 and 05:00 local."""

    id = "off-hours"
    name = "Unusual-hour activity"
    description = "Flags sensitive activity in the 00:00-05:00 window."

    def evaluate(self, event: SecurityEvent, ctx: EvaluationContext) -> RuleResult:
        sensitive = {"AUTH_LOGIN_SUCCESS", "AUTH_LOGIN_FAILURE", "PORT_SCAN", "USER_MANAGEMENT"}
        if event.event_type not in sensitive:
            return RuleResult.no_match(self)
        from core.utils import parse_iso
        ts = parse_iso(event.timestamp)
        if ts is None:
            return RuleResult.no_match(self)
        local_hour = ts.astimezone().hour
        if not (0 <= local_hour < 5):
            return RuleResult.no_match(self)
        return RuleResult(
            rule_id=self.id,
            rule_name=self.name,
            matched=True,
            severity=Severity.LOW,
            title="Unusual-hour account activity",
            description=(
                f"'{event.event_type}' involving '{event.source}' occurred at "
                f"{local_hour:02d}:00 local time, outside the normal activity window."
            ),
            details={"local_hour": local_hour, "event_id": event.id},
        )


class OpenPortExposureRule(SecurityRule):
    """A scan that exposed an unusually large number of open ports."""

    id = "open-port-exposure"
    name = "Large attack surface"
    description = "Advisory raised when a scan reports many open ports."

    def evaluate(self, event: SecurityEvent, ctx: EvaluationContext) -> RuleResult:
        if event.event_type != "PORT_SCAN":
            return RuleResult.no_match(self)
        open_count = int(event.details.get("open_count", 0) or 0)
        threshold = getattr(ctx, "open_port_advisory_threshold", 20)
        if open_count < threshold:
            return RuleResult.no_match(self)
        return RuleResult(
            rule_id=self.id,
            rule_name=self.name,
            matched=True,
            severity=Severity.LOW,
            title="Large attack surface observed",
            description=(
                f"Scan of '{event.source}' found {open_count} open ports; review firewall policy."
            ),
            details={"open_count": open_count, "threshold": threshold, "event_id": event.id},
        )


DEFAULT_RULES: tuple[SecurityRule, ...] = (
    BruteForceRule(),
    PortSweepRule(),
    EventRateRule(),
    SuspiciousKeywordRule(),
    OffHoursRule(),
    OpenPortExposureRule(),
)


class RulesEngine:
    """Registry + dispatcher. Thread-safe by construction (rules are stateless)."""

    def __init__(self, rules: list[SecurityRule] | None = None):
        self._rules: dict[str, SecurityRule] = {}
        for rule in (rules if rules is not None else DEFAULT_RULES):
            self.register(rule)

    def register(self, rule: SecurityRule) -> None:
        if rule.id in self._rules:
            from core.logger import get_logger
            get_logger("security.rules").debug("Replacing existing rule '%s'", rule.id)
        self._rules[rule.id] = rule

    def unregister(self, rule_id: str) -> bool:
        return self._rules.pop(rule_id, None) is not None

    def rules(self) -> list[SecurityRule]:
        return list(self._rules.values())

    def describe(self) -> list[dict]:
        return [
            {"id": r.id, "name": r.name, "description": r.description}
            for r in self._rules.values()
        ]

    def evaluate(self, event: SecurityEvent, ctx: EvaluationContext) -> list[RuleResult]:
        matched = []
        for rule in self._rules.values():
            try:
                result = rule.evaluate(event, ctx)
            except Exception:  # noqa: BLE001 - one bad rule must not break the pipeline
                from core.logger import get_logger
                get_logger("security.rules").exception("Rule '%s' crashed", rule.id)
                continue
            if result.matched:
                matched.append(result)
        matched.sort(key=lambda r: r.severity.weight, reverse=True)
        return matched
