from __future__ import annotations

from core.utils import utc_now_iso
from data.database import DatabaseManager
from data.models import AppSetting


class SettingsRepository:
    """Key/value store for persisted user-facing settings."""

    def __init__(self, db: DatabaseManager):
        self.db = db

    def get(self, key: str, default: str | None = None) -> str | None:
        row = self.db.query_one("SELECT value FROM settings WHERE key = ?", (key,))
        return row["value"] if row else default

    def get_bool(self, key: str, default: bool = False) -> bool:
        value = self.get(key)
        if value is None:
            return default
        return value.lower() in {"1", "true", "yes"}

    def get_int(self, key: str, default: int) -> int:
        try:
            return int(self.get(key, default))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return default

    def get_float(self, key: str, default: float) -> float:
        try:
            return float(self.get(key, default))  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return default

    def set(self, key: str, value: str | int | float | bool, *, updated_by: str | None = None) -> None:
        self.db.execute(
            "INSERT INTO settings(key, value, updated_at, updated_by) VALUES(?, ?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, "
            "updated_at=excluded.updated_at, updated_by=excluded.updated_by",
            (key, str(value), utc_now_iso(), updated_by),
        )

    def all_settings(self) -> list[AppSetting]:
        rows = self.db.query("SELECT * FROM settings ORDER BY key")
        return [
            AppSetting(key=r["key"], value=r["value"], updated_at=r["updated_at"] or "",
                       updated_by=r["updated_by"])
            for r in rows
        ]
