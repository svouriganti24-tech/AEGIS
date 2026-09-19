"""Domain models shared across layers (pure dataclasses, no persistence logic)."""

from __future__ import annotations

from .user import User
from .scan import PortRecord, ScanRecord
from .event import SecurityEvent
from .alert import Alert
from .report import ReportRecord
from .setting import AppSetting

__all__ = [
    "User",
    "ScanRecord",
    "PortRecord",
    "SecurityEvent",
    "Alert",
    "ReportRecord",
    "AppSetting",
]
