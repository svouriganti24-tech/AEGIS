from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ReportRecord:
    """Metadata + payload reference for a generated report."""

    id: int | None = None
    title: str = ""
    report_type: str = "FULL_ASSESSMENT"      # FULL_ASSESSMENT / SCAN_REPORT
    generated_by: str = ""
    generated_at: str = ""
    content_format: str = "TXT"               # TXT / HTML / JSON
    file_path: str = ""
    summary: str = ""
    data: dict = field(default_factory=dict)  # structured snapshot for re-rendering

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "title": self.title,
            "report_type": self.report_type,
            "generated_by": self.generated_by,
            "generated_at": self.generated_at,
            "content_format": self.content_format,
            "file_path": self.file_path,
            "summary": self.summary,
        }
