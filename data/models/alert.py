from __future__ import annotations

from dataclasses import dataclass, field

from core.constants import AlertStatus, Severity


@dataclass
class Alert:
    """A raised security alert — persisted, acknowledged, resolved."""

    id: int | None = None
    created_at: str = ""
    title: str = ""
    severity: Severity = Severity.MEDIUM
    source: str = ""
    description: str = ""
    status: str = AlertStatus.OPEN.value
    occurrences: int = 1
    last_seen_at: str = ""
    acknowledged_by: str | None = None
    acknowledged_at: str | None = None
    resolved_at: str | None = None
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "title": self.title,
            "severity": self.severity.value if isinstance(self.severity, Severity) else str(self.severity),
            "source": self.source,
            "description": self.description,
            "status": self.status,
            "occurrences": self.occurrences,
            "last_seen_at": self.last_seen_at,
            "acknowledged_by": self.acknowledged_by,
            "acknowledged_at": self.acknowledged_at,
            "resolved_at": self.resolved_at,
            "details": self.details,
        }
