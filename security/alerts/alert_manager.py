"""Alert manager: persistence, de-duplication, escalation, observers."""

from __future__ import annotations

import threading
from typing import Callable

from core.constants import AlertStatus, EventType, Severity
from core.exceptions import RecordNotFoundError, ValidationError
from core.logger import get_logger
from core.validators import sanitize_text
from data.models import Alert
from data.repositories import AlertRepository
from security.detection.threat_detector import Detection

log = get_logger("security.alerts")

Subscriber = Callable[[Alert], None]


class AlertManager:
    """Converts detections into durable alerts and notifies subscribers.

    Behaviour
    ---------
    * **De-duplication** — an OPEN alert with the same title+source inside the
      dedupe window absorbs new occurrences (count + last_seen) instead of
      spamming duplicate rows.
    * **Escalation** — every N occurrences of the same open alert bump its
      severity one level (capped at CRITICAL).
    * **Observer pattern** — GUI/toast layers subscribe to ``subscribe()``.
    """

    def __init__(self, alerts: AlertRepository, *, dedupe_window_seconds: int = 600,
                 escalation_threshold: int = 3):
        self.repo = alerts
        self.dedupe_window_seconds = dedupe_window_seconds
        self.escalation_threshold = max(1, escalation_threshold)
        self._subscribers: list[Subscriber] = []
        self._lock = threading.RLock()

    # ------------------------------------------------------------- observers

    def subscribe(self, callback: Subscriber) -> None:
        with self._lock:
            self._subscribers.append(callback)

    def unsubscribe(self, callback: Subscriber) -> None:
        with self._lock:
            if callback in self._subscribers:
                self._subscribers.remove(callback)

    def _notify(self, alert: Alert) -> None:
        with self._lock:
            subscribers = list(self._subscribers)
        for callback in subscribers:
            try:
                callback(alert)
            except Exception:  # noqa: BLE001
                log.exception("Alert subscriber failed")

    # --------------------------------------------------------------- raising

    def raise_from_detection(self, detection: Detection) -> Alert:
        alert = Alert(
            title=sanitize_text(detection.title, 120),
            severity=detection.severity,
            source=sanitize_text(detection.source, 120),
            description=sanitize_text(detection.description, 800),
            details=dict(detection.details),
        )
        return self.raise_alert(alert)

    def raise_alert(self, alert: Alert) -> Alert:
        with self._lock:
            existing = self.repo.find_similar_open_alert(
                alert.title, alert.source, dedupe_window_seconds=self.dedupe_window_seconds
            )
            if existing is not None:
                escalate_to = None
                new_count = existing.occurrences + 1
                if new_count % self.escalation_threshold == 0:
                    escalate_to = existing.severity.escalated(1).value
                self.repo.record_occurrence(existing.id, escalate_to=escalate_to)
                updated = self.repo.get_alert(existing.id)
                assert updated is not None
                if escalate_to:
                    log.info("Alert #%s escalated to %s after %d occurrences",
                             existing.id, escalate_to, new_count)
                self._notify(updated)
                return updated
            created = self.repo.create_alert(alert)
            log.info("Alert #%s raised: %s (%s) source=%s",
                     created.id, created.title, created.severity.value, created.source)
        self._notify(created)
        return created

    # ------------------------------------------------------------- lifecycle

    def acknowledge(self, alert_id: int, actor_username: str | None) -> Alert:
        alert = self.repo.get_alert(alert_id)
        if alert is None:
            raise RecordNotFoundError(f"Alert #{alert_id} not found.")
        if alert.status == AlertStatus.RESOLVED.value:
            raise ValidationError("Resolved alerts cannot be acknowledged.")
        self.repo.set_status(alert_id, AlertStatus.ACKNOWLEDGED.value, actor=actor_username)
        updated = self.repo.get_alert(alert_id)
        assert updated is not None
        return updated

    def resolve(self, alert_id: int, actor_username: str | None) -> Alert:
        alert = self.repo.get_alert(alert_id)
        if alert is None:
            raise RecordNotFoundError(f"Alert #{alert_id} not found.")
        self.repo.set_status(alert_id, AlertStatus.RESOLVED.value, actor=actor_username)
        updated = self.repo.get_alert(alert_id)
        assert updated is not None
        return updated

    # ----------------------------------------------------------------- read

    def open_alerts(self, limit: int = 50) -> list[Alert]:
        return self.repo.list_alerts(status=AlertStatus.OPEN.value, limit=limit)

    def open_count(self) -> int:
        return self.repo.count_alerts(status=AlertStatus.OPEN.value)

    def open_count_by_severity(self) -> dict[str, int]:
        return self.repo.count_open_by_severity()

    def status_counts(self) -> dict[str, int]:
        return self.repo.count_by_status()
