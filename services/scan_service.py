"""Scan orchestration: background threads, progress, persistence, events."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Callable

from core import constants as C
from core.config import AppConfig
from core.constants import EventType, PortState, ScanStatus, Severity
from core.exceptions import ScanError, ScanLimitReachedError, ValidationError
from core.logger import get_logger
from core.utils import humanize_duration
from core.validators import parse_port_spec, validate_target
from data.models import ScanRecord
from data.repositories import ScanRepository
from auth.authorization import Permissions, require_permission
from security.monitoring.event_processor import EventProcessor
from security.scanner.models import ScanTarget
from security.scanner.port_scanner import PortScanner

log = get_logger("services.scan")

#: Progress callback receives (scan_id, completed, total, status_string).
ScanUpdateCallback = Callable[[int, int, int, str], None]


@dataclass
class ActiveScan:
    scan_id: int
    target: str
    thread: threading.Thread
    cancel_event: threading.Event
    progress: tuple[int, int] = (0, 0)


class ScanService:
    """Runs scans on worker threads; the GUI only ever sees updates via callbacks."""

    def __init__(self, scans: ScanRepository, config: AppConfig, events: EventProcessor):
        self.repo = scans
        self.config = config
        self.events = events
        self._active: dict[int, ActiveScan] = {}
        self._lock = threading.RLock()
        self._update_subscribers: list[ScanUpdateCallback] = []

    # ------------------------------------------------------------ observers

    def subscribe_updates(self, callback: ScanUpdateCallback) -> None:
        self._update_subscribers.append(callback)

    def _notify_update(self, scan_id: int, completed: int, total: int, status: str) -> None:
        for callback in list(self._update_subscribers):
            try:
                callback(scan_id, completed, total, status)
            except Exception:  # noqa: BLE001
                log.exception("Scan update subscriber failed")

    # ------------------------------------------------------------------ API

    @staticmethod
    def port_presets() -> list[str]:
        """Labels offered by the GUI; also accepted by ``resolve_preset``."""
        return list(_PRESET_LABELS())

    def resolve_preset(self, label: str) -> list[int]:
        """Turn a preset label or raw spec into an explicit port list."""
        from core.validators import PORT_PRESETS
        if label in PORT_PRESETS:
            ports = PORT_PRESETS[label]
            if ports is None:
                raise ValidationError(
                    "Scanning all 65535 ports exceeds the configured limit; "
                    "specify a narrower range."
                )
            return list(ports)
        return parse_port_spec(label, max_ports=self.config.max_ports_per_scan)

    @require_permission(Permissions.RUN_SCAN)
    def start_scan(
        self,
        actor,
        target: str,
        port_spec: str,
        *,
        timeout: float | None = None,
        max_threads: int | None = None,
    ) -> int:
        target = validate_target(target)
        ports = self.resolve_preset(port_spec)
        if not ports:
            raise ValidationError("No ports selected for the scan.")
        if len(ports) > self.config.max_ports_per_scan:
            raise ValidationError(
                f"{len(ports)} ports exceeds the configured limit of "
                f"{self.config.max_ports_per_scan}; choose a narrower range."
            )

        with self._lock:
            if len(self._active) >= self.config.max_concurrent_scans:
                raise ScanLimitReachedError(
                    f"At most {self.config.max_concurrent_scans} scans may run at once."
                )

        scan_id = self.repo.create_scan(
            user_id=actor.id,
            username=actor.username,
            target=target,
            resolved_ip=target,
            scan_type="TCP_CONNECT",
            port_spec=_describe_spec(port_spec, ports),
            total_ports=len(ports),
        )

        active = ActiveScan(
            scan_id=scan_id,
            target=target,
            thread=None,  # type: ignore[arg-type]
            cancel_event=threading.Event(),
        )
        thread = threading.Thread(
            target=self._run_scan,
            args=(actor, scan_id, target, ports,
                  timeout if timeout is not None else self.config.default_scan_timeout,
                  max_threads or self.config.max_scan_threads,
                  active.cancel_event),
            name=f"scan-{scan_id}",
            daemon=True,
        )
        active.thread = thread
        with self._lock:
            self._active[scan_id] = active
        thread.start()

        self.events.submit(
            EventType.PORT_SCAN, target,
            f"Scan started by {actor.username}: {len(ports)} ports on {target}",
            Severity.INFO, username=actor.username, details={"scan_id": scan_id},
        )
        log.info("Scan #%d launched by '%s' against %s (%d ports)",
                 scan_id, actor.username, target, len(ports))
        return scan_id

    @require_permission(Permissions.CANCEL_SCAN)
    def cancel_scan(self, actor, scan_id: int) -> bool:
        with self._lock:
            active = self._active.get(scan_id)
            if active is None:
                return False
            active.cancel_event.set()
        log.info("Scan #%d cancellation requested by '%s'", scan_id, actor.username)
        return True

    def is_running(self, scan_id: int) -> bool:
        with self._lock:
            return scan_id in self._active

    def running_scan_ids(self) -> list[int]:
        with self._lock:
            return list(self._active.keys())

    def get_scan(self, scan_id: int, *, with_ports: bool = True) -> ScanRecord:
        record = self.repo.get_scan(scan_id)
        if record is None:
            from core.exceptions import RecordNotFoundError
            raise RecordNotFoundError(f"Scan #{scan_id} not found.")
        if with_ports:
            record.ports = self.repo.get_ports(scan_id)
        return record

    def list_scans(self, *, limit: int = 50, offset: int = 0, status: str | None = None,
                   search: str | None = None) -> list[ScanRecord]:
        return self.repo.list_scans(limit=limit, offset=offset, status=status, search=search)

    def history_with_open_ports(self, limit: int = 25) -> list[ScanRecord]:
        records = self.repo.list_scans(limit=limit)
        for record in records:
            record.ports = self.repo.get_ports(record.id or 0, only_open=True)
        return records

    # ------------------------------------------------------------- dashboards

    def stats(self) -> dict:
        from core.utils import iso_in_past
        return {
            "total": self.repo.count_scans(),
            "today": self.repo.count_scans(since=iso_in_past(days=1)),
            "running": len(self.running_scan_ids()),
            "failed": self.repo.count_scans(status=ScanStatus.FAILED.value),
            "completed": self.repo.count_scans(status=ScanStatus.COMPLETED.value),
            "recent": [s.to_dict() for s in self.repo.list_scans(limit=5)],
        }

    def shutdown(self) -> None:
        """Signal every active scan to cancel (called at app exit)."""
        with self._lock:
            for active in self._active.values():
                active.cancel_event.set()

    # ------------------------------------------------------------- internals

    def _run_scan(self, actor, scan_id: int, target: str, ports: list[int],
                  timeout: float, max_threads: int, cancel_event: threading.Event) -> None:
        scanner = PortScanner(timeout=timeout, max_threads=max_threads)
        total = len(ports)

        def progress(completed: int, _total: int) -> None:
            with self._lock:
                active = self._active.get(scan_id)
                if active:
                    active.progress = (completed, _total)
            self._notify_update(scan_id, completed, _total, ScanStatus.RUNNING.value)

        try:
            result = scanner.scan(
                ScanTarget(host=target, ports=ports, timeout=timeout),
                progress_callback=progress,
                cancel_event=cancel_event,
            )
            open_results = result.open_ports
            self.repo.add_port_results(scan_id, list(_to_port_rows(result.results)))

            status = ScanStatus(result.status.value)
            self.repo.finish_scan(
                scan_id, status=status, open_ports=len(open_results), error=result.error
            )
            if status == ScanStatus.COMPLETED:
                severity = (Severity.LOW
                            if len(open_results) >= self.config.detection.open_port_advisory_threshold
                            else Severity.INFO)
                self.events.submit(
                    EventType.PORT_SCAN, target,
                    f"Scan completed: {len(open_results)}/{total} ports open on {target} "
                    f"in {humanize_duration(result.duration_seconds)}",
                    severity, username=actor.username,
                    details={"scan_id": scan_id, "open_count": len(open_results), "total": total},
                )
            elif status == ScanStatus.CANCELLED:
                self.events.submit(
                    EventType.PORT_SCAN, target,
                    f"Scan cancelled after {len(result.results)}/{total} ports",
                    Severity.INFO, username=actor.username, details={"scan_id": scan_id},
                )
            self._notify_update(scan_id, total, total, status.value)
        except ScanError as exc:
            self.repo.finish_scan(scan_id, status=ScanStatus.FAILED, error=str(exc))
            self.events.submit(
                EventType.PORT_SCAN, target, f"Scan failed: {exc}", Severity.LOW,
                username=actor.username, details={"scan_id": scan_id},
            )
            self._notify_update(scan_id, 0, total, ScanStatus.FAILED.value)
        except Exception as exc:  # noqa: BLE001 - worker thread must never die silently
            log.exception("Scan #%d crashed", scan_id)
            self.repo.finish_scan(scan_id, status=ScanStatus.FAILED,
                                  error=f"Unexpected error: {exc}")
            self._notify_update(scan_id, 0, total, ScanStatus.FAILED.value)
        finally:
            with self._lock:
                self._active.pop(scan_id, None)


def _to_port_rows(results):
    """Adapt engine PortProbeResult objects into repository PortRecord rows."""
    from data.models import PortRecord
    for r in results:
        yield PortRecord(port=r.port, state=r.state.value, service=r.service,
                         banner=r.banner, latency_ms=r.latency_ms)


def _describe_spec(spec: str, ports: list[int]) -> str:
    if len(ports) <= 12:
        return ",".join(map(str, ports))
    return f"{spec} ({len(ports)} ports)"


def _PRESET_LABELS():
    from core.validators import PORT_PRESETS
    return PORT_PRESETS.keys()
