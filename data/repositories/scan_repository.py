from __future__ import annotations

from core.constants import ScanStatus
from core.utils import utc_now_iso
from data.database import DatabaseManager
from data.models import PortRecord, ScanRecord


class ScanRepository:
    def __init__(self, db: DatabaseManager):
        self.db = db

    # ------------------------------------------------------------- mapping

    @staticmethod
    def _to_record(row: dict) -> ScanRecord:
        return ScanRecord(
            id=row["id"],
            user_id=row["user_id"],
            username=row["username"] or "",
            target=row["target"],
            resolved_ip=row["resolved_ip"] or "",
            scan_type=row["scan_type"],
            port_spec=row["port_spec"],
            status=row["status"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            total_ports=row["total_ports"],
            open_ports=row["open_ports"],
            error=row["error"],
        )

    # ------------------------------------------------------------- queries

    def get_scan(self, scan_id: int) -> ScanRecord | None:
        row = self.db.query_one("SELECT * FROM scans WHERE id = ?", (scan_id,))
        return self._to_record(row) if row else None

    def get_ports(self, scan_id: int, *, only_open: bool = False) -> list[PortRecord]:
        sql = "SELECT port, state, service, banner, latency_ms FROM scan_ports WHERE scan_id = ?"
        if only_open:
            sql += " AND state = 'OPEN'"
        sql += " ORDER BY port"
        return [
            PortRecord(
                port=r["port"],
                state=r["state"],
                service=r["service"] or "",
                banner=r["banner"] or "",
                latency_ms=r["latency_ms"],
            )
            for r in self.db.query(sql, (scan_id,))
        ]

    def list_scans(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        user_id: int | None = None,
        status: str | None = None,
        search: str | None = None,
    ) -> list[ScanRecord]:
        sql = "SELECT * FROM scans"
        clauses, params = [], []
        if user_id is not None:
            clauses.append("user_id = ?")
            params.append(user_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        if search:
            clauses.append("(target LIKE ? OR username LIKE ? OR resolved_ip LIKE ?)")
            like = f"%{search}%"
            params.extend([like, like, like])
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY started_at DESC, id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        return [self._to_record(r) for r in self.db.query(sql, params)]

    def count_scans(self, *, status: str | None = None, since: str | None = None) -> int:
        sql = "SELECT COUNT(*) FROM scans"
        clauses, params = [], []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if since:
            clauses.append("started_at >= ?")
            params.append(since)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        return int(self.db.scalar(sql, params) or 0)

    def running_scan_ids(self) -> list[int]:
        rows = self.db.query("SELECT id FROM scans WHERE status = ?", (ScanStatus.RUNNING.value,))
        return [r["id"] for r in rows]

    # -------------------------------------------------------------- writes

    def create_scan(
        self,
        *,
        user_id: int | None,
        username: str,
        target: str,
        resolved_ip: str,
        scan_type: str,
        port_spec: str,
        total_ports: int,
    ) -> int:
        return self.db.execute(
            "INSERT INTO scans(user_id, username, target, resolved_ip, scan_type, port_spec, "
            "status, started_at, total_ports) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                user_id, username, target, resolved_ip, scan_type, port_spec,
                ScanStatus.RUNNING.value, utc_now_iso(), total_ports,
            ),
        )

    def add_port_results(self, scan_id: int, ports: list[PortRecord]) -> None:
        if not ports:
            return
        self.db.execute_many(
            "INSERT INTO scan_ports(scan_id, port, state, service, banner, latency_ms) "
            "VALUES(?, ?, ?, ?, ?, ?)",
            [
                (scan_id, p.port, p.state, p.service, p.banner[:512], p.latency_ms)
                for p in ports
            ],
        )

    def finish_scan(
        self,
        scan_id: int,
        *,
        status: ScanStatus,
        open_ports: int = 0,
        error: str | None = None,
    ) -> None:
        self.db.execute(
            "UPDATE scans SET status = ?, finished_at = ?, open_ports = ?, error = ? WHERE id = ?",
            (status.value, utc_now_iso(), open_ports, error, scan_id),
        )

    def mark_stale_running(self) -> int:
        """On startup, any scan left RUNNING by a previous crash is failed."""
        stale = self.db.query("SELECT id FROM scans WHERE status = ?", (ScanStatus.RUNNING.value,))
        if stale:
            self.db.execute(
                "UPDATE scans SET status = ?, finished_at = ?, error = ? WHERE status = ?",
                (ScanStatus.FAILED.value, utc_now_iso(), "Application terminated during scan",
                 ScanStatus.RUNNING.value),
            )
        return len(stale)

    def delete_scan(self, scan_id: int) -> None:
        self.db.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
