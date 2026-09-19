from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PortRecord:
    """Outcome of probing a single TCP port."""

    port: int
    state: str = "CLOSED"          # OPEN / CLOSED / FILTERED
    service: str = ""
    banner: str = ""
    latency_ms: float | None = None

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "state": self.state,
            "service": self.service,
            "banner": self.banner,
            "latency_ms": self.latency_ms,
        }


@dataclass
class ScanRecord:
    """A single scan job with its aggregate outcome."""

    id: int | None = None
    user_id: int | None = None
    username: str = ""
    target: str = ""
    resolved_ip: str = ""
    scan_type: str = "TCP_CONNECT"
    port_spec: str = ""
    status: str = "PENDING"        # ScanStatus value
    started_at: str = ""
    finished_at: str | None = None
    total_ports: int = 0
    open_ports: int = 0
    error: str | None = None
    ports: list[PortRecord] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float | None:
        from core.utils import parse_iso
        start = parse_iso(self.started_at)
        end = parse_iso(self.finished_at)
        if start and end:
            return (end - start).total_seconds()
        return None

    def to_dict(self, include_ports: bool = False) -> dict:
        data = {
            "id": self.id,
            "user_id": self.user_id,
            "username": self.username,
            "target": self.target,
            "resolved_ip": self.resolved_ip,
            "scan_type": self.scan_type,
            "port_spec": self.port_spec,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "total_ports": self.total_ports,
            "open_ports": self.open_ports,
            "error": self.error,
            "duration_seconds": self.duration_seconds,
        }
        if include_ports:
            data["ports"] = [p.to_dict() for p in self.ports]
        return data
