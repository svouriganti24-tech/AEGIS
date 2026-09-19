"""Event processor: the asynchronous heart of the security pipeline.

Flow::

    submit() ──► queue ──► worker thread ──► persist (EventRepository)
                                        └─► ThreatDetector ─► AlertManager
                                        └─► UI subscribers (live feed)

Guarantees
----------
* ``submit()`` never blocks the caller (drops + logs when the queue is full).
* One failure during processing never kills the worker thread.
* ``process_sync()`` runs the identical pipeline inline for tests.
"""

from __future__ import annotations

import queue
import threading
from typing import Callable

from core.constants import (
    EVENT_QUEUE_MAXSIZE,
    EVENT_WORKER_POLL_INTERVAL,
    EventType,
    INTERNAL_EVENT_TYPES,
    Severity,
)
from core.exceptions import ValidationError
from core.logger import get_logger
from core.utils import utc_now_iso
from core.validators import sanitize_text
from data.models import SecurityEvent
from data.repositories import EventRepository
from security.alerts.alert_manager import AlertManager
from security.detection.threat_detector import ThreatDetector

log = get_logger("security.monitoring")

UiEventCallback = Callable[[SecurityEvent], None]


class EventProcessor:
    def __init__(
        self,
        events: EventRepository,
        detector: ThreatDetector,
        alert_manager: AlertManager,
        *,
        queue_size: int = EVENT_QUEUE_MAXSIZE,
    ):
        self.repo = events
        self.detector = detector
        self.alerts = alert_manager
        self._queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self._worker: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._ui_subscribers: list[UiEventCallback] = []
        self._sub_lock = threading.RLock()
        self.processed_count = 0
        self.dropped_count = 0

    # ------------------------------------------------------------- lifecycle

    def start(self) -> None:
        if self._worker and self._worker.is_alive():
            return
        self._stop_event.clear()
        self._worker = threading.Thread(
            target=self._worker_loop, name="event-processor", daemon=True
        )
        self._worker.start()
        log.info("Event processor started")

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        if self._worker and self._worker.is_alive():
            self._worker.join(timeout=timeout)
        self._worker = None
        log.info("Event processor stopped (processed=%d dropped=%d)",
                 self.processed_count, self.dropped_count)

    @property
    def is_running(self) -> bool:
        return bool(self._worker and self._worker.is_alive())

    @property
    def queue_depth(self) -> int:
        return self._queue.qsize()

    # ------------------------------------------------------------- ingestion

    def submit(
        self,
        event_type: str,
        source: str,
        description: str,
        severity: Severity = Severity.INFO,
        *,
        username: str | None = None,
        details: dict | None = None,
        internal: bool = False,
    ) -> bool:
        """Enqueue an event; returns False if the queue rejected it."""
        event = self._build_event(event_type, source, description, severity,
                                  username, details, internal)
        try:
            self._queue.put_nowait(event)
            return True
        except queue.Full:
            self.dropped_count += 1
            log.error("Event queue full; dropped event %s from '%s'", event_type, source)
            return False

    def process_sync(
        self,
        event_type: str,
        source: str,
        description: str,
        severity: Severity = Severity.INFO,
        *,
        username: str | None = None,
        details: dict | None = None,
        internal: bool = False,
    ) -> SecurityEvent:
        """Build + run the full pipeline inline (tests, seeding, CLI)."""
        event = self._build_event(event_type, source, description, severity,
                                  username, details, internal)
        self._handle_event(event)
        return event

    # ------------------------------------------------------------ observers

    def subscribe(self, callback: UiEventCallback) -> None:
        with self._sub_lock:
            self._ui_subscribers.append(callback)

    def unsubscribe(self, callback: UiEventCallback) -> None:
        with self._sub_lock:
            if callback in self._ui_subscribers:
                self._ui_subscribers.remove(callback)

    def _notify_subscribers(self, event: SecurityEvent) -> None:
        with self._sub_lock:
            subscribers = list(self._ui_subscribers)
        for callback in subscribers:
            try:
                callback(event)
            except Exception:  # noqa: BLE001
                log.exception("UI event subscriber failed")

    # ------------------------------------------------------------- internals

    @staticmethod
    def _build_event(event_type, source, description, severity, username, details, internal) -> SecurityEvent:
        event_type = sanitize_text(str(event_type), 60)
        if not event_type:
            raise ValidationError("Event type is required.")
        return SecurityEvent(
            timestamp=utc_now_iso(),
            event_type=event_type,
            source=sanitize_text(str(source), 160),
            description=sanitize_text(str(description), 1000),
            severity=severity if isinstance(severity, Severity) else Severity(str(severity)),
            username=sanitize_text(username, 64) if username else None,
            details=details or {},
            internal=internal or event_type in INTERNAL_EVENT_TYPES,
        )

    def _worker_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                event = self._queue.get(timeout=EVENT_WORKER_POLL_INTERVAL)
            except queue.Empty:
                continue
            try:
                self._handle_event(event)
            except Exception:  # noqa: BLE001 - worker must survive anything
                log.exception("Event processing crashed for type=%s", event.event_type)
            finally:
                try:
                    self._queue.task_done()
                except ValueError:
                    pass

    def _handle_event(self, event: SecurityEvent) -> None:
        event = self.repo.add_event(event)          # persist → assigns id
        self.processed_count += 1

        detections = self.detector.process(event)   # rules + history analysis
        for detection in detections:
            alert = self.alerts.raise_from_detection(detection)
            self.repo.add_event(SecurityEvent(
                timestamp=utc_now_iso(),
                event_type=EventType.ALERT_RAISED,
                source=detection.source,
                description=f"Alert #{alert.id}: {alert.title} ({alert.severity.value})",
                severity=alert.severity,
                details={"alert_id": alert.id, "rule": detection.rule_id,
                         "occurrences": alert.occurrences},
                internal=True,
            ))
        self._notify_subscribers(event)
