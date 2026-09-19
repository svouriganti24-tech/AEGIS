from __future__ import annotations

from dataclasses import dataclass, field

from core.constants import Severity


@dataclass
class SecurityEvent:
    """A security-relevant occurrence recorded by any module."""

    id: int | None = None
    timestamp: str = ""
    event_type: str = ""
    source: str = ""               # who/what generated it: username, host, subsystem
    description: str = ""
    severity: Severity = Severity.INFO
    username: str | None = None    # acting account (if any)
    status: str = "NEW"            # NEW / REVIEWED
    details: dict = field(default_factory=dict)
    internal: bool = False         # pipeline-internal, excluded from detection

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "source": self.source,
            "description": self.description,
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "username": self.username,
            "status": self.status,
            "details": self.details,
        }
