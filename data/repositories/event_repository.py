from __future__ import annotations

from core.constants import Severity
from core.utils import json_dumps, json_loads, utc_now_iso
from data.database import DatabaseManager
from data.models import SecurityEvent


class EventRepository:
    def __init__(self, db: DatabaseManager):
        self.db = db

    # ------------------------------------------------------------- mapping

    @staticmethod
    def _to_event(row: dict) -> SecurityEvent:
        return SecurityEvent(
            id=row["id"],
            timestamp=row["timestamp"],
            event_type=row["event_type"],
            source=row["source"] or "",
            description=row["description"] or "",
            severity=Severity(row["severity"]),
            username=row["username"],
            status=row["status"],
            details=json_loads(row["details"]),
            internal=bool(row["internal"]),
        )

    # ------------------------------------------------------------- queries

    def get_event(self, event_id: int) -> SecurityEvent | None:
        row = self.db.query_one("SELECT * FROM security_events WHERE id = ?", (event_id,))
        return self._to_event(row) if row else None

    def list_events(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        severity: str | None = None,
        event_type: str | None = None,
        source: str | None = None,
        search: str | None = None,
        since: str | None = None,
    ) -> list[SecurityEvent]:
        sql = "SELECT * FROM security_events"
        clauses, params = [], []
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if source:
            clauses.append("source LIKE ?")
            params.append(f"%{source}%")
        if search:
            clauses.append("(description LIKE ? OR source LIKE ? OR username LIKE ?)")
            like = f"%{search}%"
            params.extend([like, like, like])
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        return [self._to_event(r) for r in self.db.query(sql, params)]

    def count_events(
        self,
        *,
        severity: str | None = None,
        event_type: str | None = None,
        source: str | None = None,
        search: str | None = None,
        since: str | None = None,
    ) -> int:
        sql = "SELECT COUNT(*) FROM security_events"
        clauses, params = [], []
        if severity:
            clauses.append("severity = ?"); params.append(severity)
        if event_type:
            clauses.append("event_type = ?"); params.append(event_type)
        if source:
            clauses.append("source LIKE ?"); params.append(f"%{source}%")
        if search:
            clauses.append("(description LIKE ? OR source LIKE ? OR username LIKE ?)")
            like = f"%{search}%"
            params.extend([like, like, like])
        if since:
            clauses.append("timestamp >= ?"); params.append(since)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        return int(self.db.scalar(sql, params) or 0)

    def count_by_severity(self, *, since: str | None = None, internal: bool = False) -> dict[str, int]:
        sql = "SELECT severity, COUNT(*) AS n FROM security_events"
        clauses, params = [], []
        if since:
            clauses.append("timestamp >= ?"); params.append(since)
        if internal:
            clauses.append("internal = 1")
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " GROUP BY severity"
        return {r["severity"]: r["n"] for r in self.db.query(sql, params)}

    def count_by_type(self, *, since: str | None = None, limit: int = 10) -> list[dict]:
        sql = "SELECT event_type, COUNT(*) AS n FROM security_events"
        params: list = []
        if since:
            sql += " WHERE timestamp >= ?"
            params.append(since)
        sql += " GROUP BY event_type ORDER BY n DESC LIMIT ?"
        params.append(limit)
        return self.db.query(sql, params)

    def top_sources(self, *, since: str | None = None, limit: int = 5) -> list[dict]:
        sql = "SELECT source, COUNT(*) AS n FROM security_events"
        params: list = []
        if since:
            sql += " WHERE timestamp >= ?"
            params.append(since)
        sql += " AND source != '' GROUP BY source ORDER BY n DESC LIMIT ?" if since else \
               " WHERE source != '' GROUP BY source ORDER BY n DESC LIMIT ?"
        params.append(limit)
        return self.db.query(sql, params)

    def recent(self, limit: int = 10) -> list[SecurityEvent]:
        return self.list_events(limit=limit)

    def distinct_event_types(self) -> list[str]:
        rows = self.db.query("SELECT DISTINCT event_type FROM security_events ORDER BY event_type")
        return [r["event_type"] for r in rows]

    def count_events_for_source(
        self, source: str, *, window_seconds: int, event_type: str | None = None
    ) -> int:
        """Count events for a source inside a trailing time window."""
        from core.utils import iso_in_past
        since = iso_in_past(seconds=window_seconds)
        sql = "SELECT COUNT(*) FROM security_events WHERE source = ? AND timestamp >= ?"
        params: list = [source, since]
        if event_type:
            sql += " AND event_type = ?"
            params.append(event_type)
        return int(self.db.scalar(sql, params) or 0)

    # -------------------------------------------------------------- writes

    def add_event(self, event: SecurityEvent) -> SecurityEvent:
        from core.utils import utc_now_iso
        new_id = self.db.execute(
            "INSERT INTO security_events(timestamp, event_type, source, description, severity, "
            "username, status, details, internal) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event.timestamp or utc_now_iso(),
                event.event_type,
                event.source,
                event.description,
                event.severity.value if isinstance(event.severity, Severity) else str(event.severity),
                event.username,
                event.status,
                json_dumps(event.details),
                1 if event.internal else 0,
            ),
        )
        event.id = new_id
        return event

    def set_status(self, event_id: int, status: str) -> None:
        self.db.execute("UPDATE security_events SET status = ? WHERE id = ?", (status, event_id))

    def purge_older_than(self, iso_timestamp: str) -> int:
        n = int(self.db.scalar("SELECT COUNT(*) FROM security_events WHERE timestamp < ?", (iso_timestamp,)) or 0)
        if n:
            self.db.execute("DELETE FROM security_events WHERE timestamp < ?", (iso_timestamp,))
        return n
