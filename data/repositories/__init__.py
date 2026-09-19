"""Repository layer: the ONLY place raw SQL is allowed.

Each repository maps one aggregate to the database and returns rich domain
models, so services and the GUI never see SQL, rows or cursors.
"""

from __future__ import annotations

from .user_repository import UserRepository
from .scan_repository import ScanRepository
from .event_repository import EventRepository
from .alert_repository import AlertRepository
from .report_repository import ReportRepository
from .settings_repository import SettingsRepository

__all__ = [
    "UserRepository",
    "ScanRepository",
    "EventRepository",
    "AlertRepository",
    "ReportRepository",
    "SettingsRepository",
]
