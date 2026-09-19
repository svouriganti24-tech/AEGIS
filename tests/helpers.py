"""Shared test fixtures: isolated runtime on a temp directory."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

# Ensure the project root is importable regardless of how tests are launched.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.config import AppConfig                     # noqa: E402
from core.logger import setup_logging                 # noqa: E402
from data.database import DatabaseManager             # noqa: E402
from data.repositories import (                       # noqa: E402
    AlertRepository,
    EventRepository,
    ReportRepository,
    ScanRepository,
    SettingsRepository,
    UserRepository,
)
from data.seed import ensure_default_admin            # noqa: E402
from security.alerts.alert_manager import AlertManager  # noqa: E402
from security.detection.rules_engine import RulesEngine  # noqa: E402
from security.detection.threat_detector import ThreatDetector  # noqa: E402
from security.monitoring.event_processor import EventProcessor  # noqa: E402
from security.password.password_analyzer import PasswordAnalyzer  # noqa: E402
from auth.authentication import AuthenticationService, PasswordHasher  # noqa: E402

from services import (                                # noqa: E402
    AuthService,
    PasswordService,
    ReportService,
    ScanService,
    ThreatService,
)


def make_config(tmp: str) -> AppConfig:
    cfg = AppConfig.load(base_dir=tmp)
    cfg.db_path = os.path.join(tmp, "test.db")
    cfg.reports_dir = os.path.join(tmp, "reports")
    cfg.ensure_directories()
    cfg.validate()
    setup_logging(cfg.log_dir, "ERROR", console=False)
    return cfg


def make_runtime(tmp: str | None = None, *, fast_hash: bool = True, seed: bool = False):
    """Build a fully wired backend on a temp directory.

    Returns ``(registry, tmp_path)``. ``fast_hash`` reduces PBKDF2 iterations
    for speed; tests of hashing itself construct their own hasher.
    """
    tmp = tmp or tempfile.mkdtemp(prefix="aegis-test-")
    cfg = make_config(tmp)
    iterations = 10_000 if fast_hash else cfg.password_hash_iterations

    db = DatabaseManager(cfg.db_path)
    users, scans = UserRepository(db), ScanRepository(db)
    events, alerts = EventRepository(db), AlertRepository(db)
    reports, settings = ReportRepository(db), SettingsRepository(db)

    hasher = PasswordHasher(iterations)
    rules = RulesEngine()
    detector = ThreatDetector(rules)
    alert_manager = AlertManager(alerts)
    processor = EventProcessor(events, detector, alert_manager)

    auth_core = AuthenticationService(
        users, hasher,
        session_timeout_minutes=cfg.session_timeout_minutes,
        max_login_attempts=cfg.max_login_attempts,
        lockout_minutes=cfg.lockout_minutes,
        min_password_length=cfg.min_password_length,
    )
    auth_core._on_event = (
        lambda et, src, desc, sev, username, details: processor.submit(
            et, src, desc, sev, username=username, details=details)
    )

    auth = AuthService(auth_core, cfg)
    scan = ScanService(scans, cfg, processor)
    password = PasswordService(PasswordAnalyzer(), cfg, processor)
    threat = ThreatService(events, alert_manager, processor)
    report = ReportService(reports, scans, events, alerts, cfg, processor)

    from services import ServiceRegistry
    registry = ServiceRegistry(
        config=cfg, db=db, users=users, scans=scans, events=events, alerts=alerts,
        reports=reports, settings=settings, rules_engine=rules, detector=detector,
        alert_manager=alert_manager, event_processor=processor,
        auth=auth, scan=scan, password=password, threat=threat, report=report,
    )
    ensure_default_admin(users, hasher)
    return registry, tmp
