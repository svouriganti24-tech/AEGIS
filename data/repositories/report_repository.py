from __future__ import annotations

from core.utils import json_dumps, json_loads, utc_now_iso
from data.database import DatabaseManager
from data.models import ReportRecord


class ReportRepository:
    def __init__(self, db: DatabaseManager):
        self.db = db

    @staticmethod
    def _to_record(row: dict) -> ReportRecord:
        return ReportRecord(
            id=row["id"],
            title=row["title"],
            report_type=row["report_type"],
            generated_by=row["generated_by"] or "",
            generated_at=row["generated_at"],
            content_format=row["content_format"],
            file_path=row["file_path"],
            summary=row["summary"] or "",
            data=json_loads(row["data"]),
        )

    def get_report(self, report_id: int) -> ReportRecord | None:
        row = self.db.query_one("SELECT * FROM reports WHERE id = ?", (report_id,))
        return self._to_record(row) if row else None

    def list_reports(self, *, limit: int = 100) -> list[ReportRecord]:
        rows = self.db.query(
            "SELECT * FROM reports ORDER BY generated_at DESC, id DESC LIMIT ?", (limit,)
        )
        return [self._to_record(r) for r in rows]

    def count_reports(self) -> int:
        return int(self.db.scalar("SELECT COUNT(*) FROM reports") or 0)

    def last_generated_at(self) -> str | None:
        return self.db.scalar("SELECT MAX(generated_at) FROM reports")

    def create_report(self, record: ReportRecord) -> ReportRecord:
        new_id = self.db.execute(
            "INSERT INTO reports(title, report_type, generated_by, generated_at, content_format, "
            "file_path, summary, data) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record.title, record.report_type, record.generated_by,
                record.generated_at or utc_now_iso(), record.content_format,
                record.file_path, record.summary, json_dumps(record.data),
            ),
        )
        record.id = new_id
        return record

    def delete_report(self, report_id: int) -> None:
        self.db.execute("DELETE FROM reports WHERE id = ?", (report_id,))
