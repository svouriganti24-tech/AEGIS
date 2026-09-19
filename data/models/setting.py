from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AppSetting:
    """A single persisted key/value setting with audit metadata."""

    key: str
    value: str = ""
    updated_at: str = ""
    updated_by: str | None = None
