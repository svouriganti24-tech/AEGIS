"""Concurrent TCP connect scanner (pure standard library).

Design
------
* A :class:`ThreadPoolExecutor` fans out connect attempts; the pool size and
  per-socket timeout are configurable.
* Cancellation is cooperative: a :class:`threading.Event` is checked between
  submissions and inside the progress loop, so cancelling a large sweep is
  responsive without killing threads abruptly.
* Open ports get a best-effort banner grab: passive ``recv`` first, and an
  HTTP ``HEAD`` probe for known plaintext-HTTP ports.
* All failures are converted into typed results (CLOSED / FILTERED) or a
  :class:`ScanError` for target-level problems — the engine never leaks raw
  socket exceptions to the caller.
"""

from __future__ import annotations

import socket
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Callable, Iterable

from core.constants import PortState, ScanStatus
from core.logger import get_logger
from core.validators import resolve_host_label
from security.scanner.models import (
    HTTP_PROBE_PORTS,
    WELL_KNOWN_PORTS,
    PortProbeResult,
    ScanResult,
    ScanTarget,
)

log = get_logger("security.scanner")

ProgressCallback = Callable[[int, int], None]   # (completed, total)


class PortScanner:
    """A friendly, well-behaved TCP connect scanner for authorised targets."""

    def __init__(
        self,
        *,
        timeout: float = 1.0,
        max_threads: int = 32,
        scan_id: str | None = None,
    ):
        self.timeout = max(0.05, float(timeout))
        self.max_threads = max(1, min(128, int(max_threads)))
        self.scan_id = scan_id or uuid.uuid4().hex[:12]

    # ------------------------------------------------------------------ API

    def scan(
        self,
        target: ScanTarget,
        *,
        progress_callback: ProgressCallback | None = None,
        cancel_event=None,
    ) -> ScanResult:
        """Scan ``target`` and return a fully populated :class:`ScanResult`."""
        result = ScanResult(target=target.host)
        resolved = self._resolve(target.host)
        result.resolved_ip = resolved

        total = len(target.ports)
        result.ports_scanned = total
        log.info("Scan %s: probing %d port(s) on %s (%s)", self.scan_id, total, target.host, resolved)

        completed = 0
        stop_requested = False

        def worker(port: int) -> PortProbeResult:
            return self._probe_port(resolved, port, target.timeout)

        max_workers = max(1, min(self.max_threads, total or 1))
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix=f"scan-{self.scan_id}") as pool:
            futures = []
            for port in target.ports:
                if cancel_event is not None and cancel_event.is_set():
                    stop_requested = True
                    break
                futures.append(pool.submit(worker, port))

            for future in futures:
                if cancel_event is not None and cancel_event.is_set():
                    stop_requested = True
                    break
                try:
                    probe = future.result(timeout=self.timeout + 5)
                except Exception as exc:  # noqa: BLE001 - single-port failure must not abort scan
                    log.debug("Probe failure: %s", exc)
                    probe = PortProbeResult(port=0, state=PortState.FILTERED)
                result.results.append(probe)
                completed += 1
                if progress_callback and (completed % 5 == 0 or completed == total):
                    try:
                        progress_callback(completed, total)
                    except Exception:  # noqa: BLE001
                        log.exception("Progress callback failed")

        if stop_requested:
            result.status = ScanStatus.CANCELLED
        else:
            result.status = ScanStatus.COMPLETED
        result.finished_at = datetime.now(timezone.utc)
        result.results.sort(key=lambda r: r.port)
        log.info("Scan %s finished: %s", self.scan_id, result.statistics())
        return result

    def scan_single_port(self, host: str, port: int, timeout: float | None = None) -> PortProbeResult:
        resolved = self._resolve(host)
        return self._probe_port(resolved, port, timeout or self.timeout)

    # ------------------------------------------------------------- internals

    def _resolve(self, host: str) -> str:
        label = resolve_host_label(host)
        try:
            socket.inet_pton(socket.AF_INET, label)
            return label
        except OSError:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, label)
            return label
        except OSError:
            pass
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
            return infos[0][4][0]
        except socket.gaierror as exc:
            from core.exceptions import ScanTargetUnresolvableError
            raise ScanTargetUnresolvableError(
                f"Could not resolve host '{host}': {exc}"
            ) from exc

    def _probe_port(self, ip: str, port: int, timeout: float) -> PortProbeResult:
        probe = PortProbeResult(port=port, service=WELL_KNOWN_PORTS.get(port, ""))
        start = time.perf_counter()
        sock = None
        try:
            sock = socket.create_connection((ip, port), timeout=timeout)
            probe.latency_ms = round((time.perf_counter() - start) * 1000, 2)
            probe.state = PortState.OPEN
            probe.banner = self._grab_banner(sock, port)
        except ConnectionRefusedError:
            probe.state = PortState.CLOSED
        except (socket.timeout, TimeoutError):
            probe.state = PortState.FILTERED
        except OSError:
            # ENETUNREACH / EHOSTUNREACH / EACCES etc. → indeterminate
            probe.state = PortState.FILTERED
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        return probe

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """Best-effort service banner (passive recv, HTTP HEAD when useful)."""
        banner = ""
        try:
            if port in HTTP_PROBE_PORTS:
                sock.settimeout(0.6)
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\nUser-Agent: AegisScan/1.0\r\n\r\n")
                banner = sock.recv(512).decode("utf-8", "replace")
            else:
                sock.settimeout(0.35)
                banner = sock.recv(256).decode("utf-8", "replace")
        except (OSError, socket.timeout):
            return ""
        return _clean_banner(banner)


def _clean_banner(raw: str) -> str:
    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    if not lines:
        return ""
    keep = lines[0]
    for line in lines[1:]:
        lowered = line.lower()
        if lowered.startswith(("server:", "x-powered-by:", "content-type:", "ssh-")):
            keep += f" | {line}"
            if len(keep) > 160:
                break
    return keep[:200]


def scan_ports_sync(
    host: str, ports: Iterable[int], *, timeout: float = 1.0, max_threads: int = 32,
    progress_callback: ProgressCallback | None = None, cancel_event=None,
) -> ScanResult:
    """Convenience one-shot wrapper around :class:`PortScanner`."""
    scanner = PortScanner(timeout=timeout, max_threads=max_threads)
    return scanner.scan(
        ScanTarget(host=host, ports=list(ports), timeout=timeout),
        progress_callback=progress_callback,
        cancel_event=cancel_event,
    )
