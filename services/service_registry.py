"""Service registry: the dependency container wired once in ``main.py``.

The GUI receives this object and never constructs backend components itself,
keeping the layers strictly separated.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.config import AppConfig
from data.database import DatabaseManager
from data.repositories import (
    AlertRepository,
    EventRepository,
    ReportRepository,
    ScanRepository,
    SettingsRepository,
    UserRepository,
)
from security.alerts.alert_manager import AlertManager
from security.monitoring.event_processor import EventProcessor
from security.detection.threat_detector import ThreatDetector
from security.detection.rules_engine import RulesEngine


@dataclass
class ServiceRegistry:
    """Wired application context handed to the GUI."""

    config: AppConfig
    db: DatabaseManager
    users: UserRepository
    scans: ScanRepository
    events: EventRepository
    alerts: AlertRepository
    reports: ReportRepository
    settings: SettingsRepository
    rules_engine: RulesEngine
    detector: ThreatDetector
    alert_manager: AlertManager
    event_processor: EventProcessor
    auth: "AuthService"            # noqa: F821 - forward refs resolved at runtime
    scan: "ScanService"            # noqa: F821
    password: "PasswordService"    # noqa: F821
    threat: "ThreatService"        # noqa: F821
    report: "ReportService"        # noqa: F821

    def shutdown(self) -> None:
        """Orderly shutdown: cancel scans, stop the event pipeline, close DB."""
        try:
            self.scan.shutdown()
        except Exception:  # noqa: BLE001
            pass
        try:
            self.event_processor.stop()
        except Exception:  # noqa: BLE001
            pass
        try:
            self.db.close()
        except Exception:  # noqa: BLE001
            pass
