from __future__ import annotations

from core.constants import AlertStatus, Severity
from core.utils import json_dumps, json_loads, utc_now_iso
from data.database import DatabaseManager
from data.models import Alert


class AlertRepository:
    def __init__(self, db: DatabaseManager):
        self.db = db

    # ------------------------------------------------------------- mapping

    @staticmethod
    def _to_alert(row: dict) -> Alert:
        return Alert(
            id=row["id"],
            created_at=row["created_at"],
            title=row["title"],
            severity=Severity(row["severity"]),
            source=row["source"] or "",
            description=row["description"] or "",
            status=row["status"],
            occurrences=row["occurrences"],
            last_seen_at=row["last_seen_at"],
            acknowledged_by=row["acknowledged_by"],
            acknowledged_at=row["acknowledged_at"],
            resolved_at=row["resolved_at"],
            details=json_loads(row["details"]),
        )

    # ------------------------------------------------------------- queries

    def get_alert(self, alert_id: int) -> Alert | None:
        row = self.db.query_one("SELECT * FROM alerts WHERE id = ?", (alert_id,))
        return self._to_alert(row) if row else None

    def list_alerts(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        status: str | None = None,
        severity: str | None = None,
        search: str | None = None,
    ) -> list[Alert]:
        sql = "SELECT * FROM alerts"
        clauses, params = [], []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if search:
            clauses.append("(title LIKE ? OR source LIKE ? OR description LIKE ?)")
            like = f"%{search}%"
            params.extend([like, like, like])
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        return [self._to_alert(r) for r in self.db.query(sql, params)]

    def count_alerts(self, *, status: str | None = None, severity: str | None = None) -> int:
        sql = "SELECT COUNT(*) FROM alerts"
        clauses, params = [], []
        if status:
            clauses.append("status = ?"); params.append(status)
        if severity:
            clauses.append("severity = ?"); params.append(severity)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        return int(self.db.scalar(sql, params) or 0)

    def count_by_status(self) -> dict[str, int]:
        rows = self.db.query("SELECT status, COUNT(*) AS n FROM alerts GROUP BY status")
        return {r["status"]: r["n"] for r in rows}

    def count_open_by_severity(self) -> dict[str, int]:
        rows = self.db.query(
            "SELECT severity, COUNT(*) AS n FROM alerts WHERE status = ? GROUP BY severity",
            (AlertStatus.OPEN.value,),
        )
        return {r["severity"]: r["n"] for r in rows}

    def find_similar_open_alert(self, title: str, source: str, *, dedupe_window_seconds: int) -> Alert | None:
        """Locate an OPEN alert with same title+source inside the dedupe window."""
        from core.utils import iso_in_past
        since = iso_in_past(seconds=dedupe_window_seconds)
        row = self.db.query_one(
            "SELECT * FROM alerts WHERE title = ? AND source = ? AND status = ? "
            "AND last_seen_at >= ? ORDER BY id DESC LIMIT 1",
            (title, source, AlertStatus.OPEN.value, since),
        )
        return self._to_alert(row) if row else None

    def recent(self, limit: int = 5) -> list[Alert]:
        return self.list_alerts(limit=limit)

    # -------------------------------------------------------------- writes

    def create_alert(self, alert: Alert) -> Alert:
        now = utc_now_iso()
        new_id = self.db.execute(
            "INSERT INTO alerts(created_at, title, severity, source, description, status, "
            "occurrences, last_seen_at, details) VALUES(?, ?, ?, ?, ?, ?, 1, ?, ?)",
            (
                now, alert.title,
                alert.severity.value if isinstance(alert.severity, Severity) else str(alert.severity),
                alert.source, alert.description, AlertStatus.OPEN.value, now,
                json_dumps(alert.details),
            ),
        )
        alert.id = new_id
        alert.created_at = now
        alert.last_seen_at = now
        return alert

    def record_occurrence(self, alert_id: int, *, escalate_to: str | None = None) -> None:
        if escalate_to:
            self.db.execute(
                "UPDATE alerts SET occurrences = occurrences + 1, last_seen_at = ?, severity = ? WHERE id = ?",
                (utc_now_iso(), escalate_to, alert_id),
            )
        else:
            self.db.execute(
                "UPDATE alerts SET occurrences = occurrences + 1, last_seen_at = ? WHERE id = ?",
                (utc_now_iso(), alert_id),
            )

    def set_status(self, alert_id: int, status: str, *, actor: str | None = None) -> None:
        now = utc_now_iso()
        if status == AlertStatus.ACKNOWLEDGED.value:
            self.db.execute(
                "UPDATE alerts SET status = ?, acknowledged_by = ?, acknowledged_at = ? WHERE id = ?",
                (status, actor, now, alert_id),
            )
        elif status == AlertStatus.RESOLVED.value:
            self.db.execute(
                "UPDATE alerts SET status = ?, resolved_at = ?, acknowledged_by = COALESCE(acknowledged_by, ?) "
                "WHERE id = ?",
                (status, now, actor, alert_id),
            )
        else:
            self.db.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))

    def reopen(self, alert_id: int) -> None:
        self.db.execute(
            "UPDATE alerts SET status = ?, resolved_at = NULL WHERE id = ?",
            (AlertStatus.OPEN.value, alert_id),
        )
