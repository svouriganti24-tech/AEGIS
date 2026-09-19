"""Threat & alert service: read models + alert lifecycle for the GUI."""

from __future__ import annotations

from dataclasses import dataclass

from auth.authorization import Permissions, require_permission
from core.constants import AlertStatus, EventType, Severity
from core.exceptions import RecordNotFoundError
from core.utils import iso_in_past
from data.models import Alert, SecurityEvent, User
from data.repositories import EventRepository
from security.alerts.alert_manager import AlertManager
from security.monitoring.event_processor import EventProcessor


@dataclass
class Page:
    items: list
    total: int
    offset: int
    limit: int

    @property
    def has_next(self) -> bool:
        return self.offset + self.limit < self.total


class ThreatService:
    def __init__(self, events_repo: EventRepository, alert_manager: AlertManager,
                 event_processor: EventProcessor):
        self.events_repo = events_repo
        self.alert_manager = alert_manager
        self.processor = event_processor

    # ---------------------------------------------------------------- events

    @require_permission(Permissions.VIEW_LOGS)
    def events_page(self, actor: User, *, limit: int = 50, offset: int = 0,
                    severity: str | None = None, event_type: str | None = None,
                    source: str | None = None, search: str | None = None) -> Page:
        items = self.events_repo.list_events(
            limit=limit, offset=offset, severity=severity, event_type=event_type,
            source=source, search=search,
        )
        total = self.events_repo.count_events(
            severity=severity, event_type=event_type, source=source, search=search,
        )
        return Page(items=items, total=total, offset=offset, limit=limit)

    @require_permission(Permissions.VIEW_LOGS)
    def recent_events(self, actor: User, limit: int = 10) -> list[SecurityEvent]:
        return self.events_repo.recent(limit)

    def event_types(self) -> list[str]:
        return self.events_repo.distinct_event_types()

    def event_stats(self, *, days: int = 7) -> dict:
        since = iso_in_past(days=days)
        by_severity = self.events_repo.count_by_severity(since=since)
        return {
            "by_severity": by_severity,
            "by_type": self.events_repo.count_by_type(since=since, limit=8),
            "top_sources": self.events_repo.top_sources(since=since, limit=5),
            "last_24h": self.events_repo.count_events(since=iso_in_past(days=1)),
            "total": sum(by_severity.values()),
        }

    # ---------------------------------------------------------------- alerts

    @require_permission(Permissions.VIEW_ALERTS)
    def alerts_page(self, actor: User, *, limit: int = 100, offset: int = 0,
                    status: str | None = None, severity: str | None = None,
                    search: str | None = None) -> Page:
        items = self.alert_manager.repo.list_alerts(
            limit=limit, offset=offset, status=status, severity=severity, search=search,
        )
        total = self.alert_manager.repo.count_alerts(status=status, severity=severity)
        return Page(items=items, total=total, offset=offset, limit=limit)

    @require_permission(Permissions.VIEW_ALERTS)
    def recent_alerts(self, actor: User, limit: int = 5) -> list[Alert]:
        return self.alert_manager.repo.recent(limit)

    @require_permission(Permissions.MANAGE_ALERTS)
    def acknowledge_alert(self, actor: User, alert_id: int) -> Alert:
        alert = self.alert_manager.acknowledge(alert_id, actor.username)
        self.processor.submit(
            EventType.ALERT_ACKNOWLEDGED, alert.source,
            f"Alert #{alert_id} '{alert.title}' acknowledged by {actor.username}",
            Severity.INFO, username=actor.username, internal=True,
        )
        return alert

    @require_permission(Permissions.MANAGE_ALERTS)
    def resolve_alert(self, actor: User, alert_id: int) -> Alert:
        alert = self.alert_manager.resolve(alert_id, actor.username)
        self.processor.submit(
            EventType.ALERT_RESOLVED, alert.source,
            f"Alert #{alert_id} '{alert.title}' resolved by {actor.username}",
            Severity.INFO, username=actor.username, internal=True,
        )
        return alert

    def get_alert(self, alert_id: int) -> Alert:
        alert = self.alert_manager.repo.get_alert(alert_id)
        if alert is None:
            raise RecordNotFoundError(f"Alert #{alert_id} not found.")
        return alert

    def alert_stats(self) -> dict:
        return {
            "by_status": self.alert_manager.status_counts(),
            "open_by_severity": self.alert_manager.open_count_by_severity(),
            "open_total": self.alert_manager.open_count(),
        }

    # ------------------------------------------------------------ dashboards

    def dashboard_stats(self) -> dict:
        stats = self.event_stats(days=7)
        severity = {s.value: int(stats["by_severity"].get(s.value, 0)) for s in Severity}
        return {
            "open_alerts": self.alert_manager.open_count(),
            "open_by_severity": self.alert_manager.open_count_by_severity(),
            "events_24h": stats["last_24h"],
            "events_7d": stats["total"],
            "severity_7d": severity,
            "top_sources": stats["top_sources"],
            "by_type": stats["by_type"],
        }
