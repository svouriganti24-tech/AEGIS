#!/usr/bin/env python3
"""Aegis CyberSuite — application entry point.

Usage::

    python main.py                 # launch the GUI (seeds demo data on first run)
    python main.py --no-seed       # skip the demo dataset
    python main.py --cli-demo      # run a text-mode pipeline demo instead of the GUI
    python -m unittest discover -s tests   # run the test suite

Startup order follows the dependency graph: config → logging → database →
repositories → security engine → services → GUI. Shutdown reverses it.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


from core.config import AppConfig
from core.constants import APP_NAME, APP_VERSION, EventType, Roles, Severity
from core.exceptions import CyberSecError
from core.logger import get_logger, setup_logging
from data.database import DatabaseManager
from data.repositories import (
    AlertRepository,
    EventRepository,
    ReportRepository,
    ScanRepository,
    SettingsRepository,
    UserRepository,
)
from data.seed import ensure_default_admin, seed_demo_data
from security.alerts.alert_manager import AlertManager
from security.detection.rules_engine import RulesEngine
from security.detection.threat_detector import ThreatDetector
from security.monitoring.event_processor import EventProcessor
from security.password.password_analyzer import PasswordAnalyzer
from auth.authentication import AuthenticationService, PasswordHasher


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="aegis", description=f"{APP_NAME} v{APP_VERSION} — desktop cybersecurity console")
    parser.add_argument("--no-seed", action="store_true",
                        help="do not create the demo dataset on first run")
    parser.add_argument("--db-path", default=None, help="override the SQLite database path")
    parser.add_argument("--log-level", default=None,
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
                        help="override the log level")
    parser.add_argument("--cli-demo", action="store_true",
                        help="run a text-mode end-to-end pipeline demo and exit")
    return parser.parse_args(argv)


def build_runtime(config: AppConfig):
    """Construct the full backend object graph (database → services)."""
    db = DatabaseManager(config.db_path)
    users = UserRepository(db)
    scans = ScanRepository(db)
    events = EventRepository(db)
    alerts = AlertRepository(db)
    reports = ReportRepository(db)
    settings = SettingsRepository(db)

    rules_engine = RulesEngine()
    detector = ThreatDetector(rules_engine)
    alert_manager = AlertManager(
        alerts,
        dedupe_window_seconds=config.alert_dedupe_window_seconds,
        escalation_threshold=config.alert_escalation_threshold,
    )
    processor = EventProcessor(events, detector, alert_manager)

    def emit(event_type, source, description, severity, username, details):
        processor.submit(event_type, source, description, severity,
                         username=username, details=details)

    auth_core = AuthenticationService(
        users,
        PasswordHasher(config.password_hash_iterations),
        session_timeout_minutes=config.session_timeout_minutes,
        max_login_attempts=config.max_login_attempts,
        lockout_minutes=config.lockout_minutes,
        min_password_length=config.min_password_length,
        on_event=emit,
    )

    # Import here so this module stays import-light for tests.
    from services import (
        AuthService,
        PasswordService,
        ReportService,
        ScanService,
        ServiceRegistry,
        ThreatService,
    )

    auth = AuthService(auth_core, config)
    scan = ScanService(scans, config, processor)
    password = PasswordService(PasswordAnalyzer(), config, processor)
    threat = ThreatService(events, alert_manager, processor)
    report = ReportService(reports, scans, events, alerts, config, processor)

    registry = ServiceRegistry(
        config=config, db=db, users=users, scans=scans, events=events, alerts=alerts,
        reports=reports, settings=settings, rules_engine=rules_engine,
        detector=detector, alert_manager=alert_manager, event_processor=processor,
        auth=auth, scan=scan, password=password, threat=threat, report=report,
    )
    return registry


def bootstrap(config: AppConfig, registry, *, seed: bool) -> None:
    """First-run provisioning: default admin + optional demo dataset."""
    ensure_default_admin(registry.users, registry.auth.core.hasher)
    if seed and config.seed_demo_data:
        created = seed_demo_data(registry.db, registry.users, registry.scans,
                                 registry.events, registry.alerts, registry.settings,
                                 registry.auth.core.hasher)
        if created:
            get_logger("main").info("Demo dataset seeded")
    else:
        get_logger("main").info("Demo seeding skipped (--no-seed or disabled)")


def run_cli_demo(registry) -> int:
    """Text-mode proof that the whole pipeline works end to end."""
    print(f"\n=== {APP_NAME} v{APP_VERSION} — pipeline demo ===\n")
    registry.event_processor.start()

    admin = registry.users.get_by_username("admin")
    assert admin is not None, "default admin missing"

    print("[1/6] Password analysis")
    for candidate in ("Tr0ub4dor&3", "correct horse battery staple", "123456"):
        analysis = registry.password.analyze(admin, candidate)
        print(f"   {candidate!r:>34} → score {analysis['score']:>3}/100 · {analysis['verdict']}")

    print("[2/6] Network scan on 127.0.0.1 (top 30 ports)")
    scan_id = registry.scan.start_scan(admin, "127.0.0.1", "Top 30 common ports")
    import time
    deadline = time.time() + 60
    while time.time() < deadline:
        record = registry.scans.get_scan(scan_id)
        if record.status != "RUNNING":
            break
        time.sleep(0.3)
    print(f"   scan #{scan_id} → {record.status}, {record.open_ports} open port(s)")

    print("[3/6] Simulated brute-force burst (6 failed logins)")
    for i in range(6):
        try:
            registry.auth.core.authenticate("phantom-user", f"bad-{i}")
        except CyberSecError:
            pass
    import time
    time.sleep(1.0)

    print("[4/6] Alerts")
    for alert in registry.alert_manager.open_alerts(limit=10):
        print(f"   [{alert.severity.value:>8}] #{alert.id} {alert.title} (source: {alert.source})")

    print("[5/6] Security report (HTML)")
    record = registry.report.generate(admin, "CLI Demo Report", period_days=7,
                                      content_format="HTML")
    print(f"   written → {record.file_path}")

    print("[6/6] Event log tail")
    for event in registry.events.recent(6):
        print(f"   [{event.severity.value:>8}] {event.event_type:<22} {event.description[:60]}")

    registry.shutdown()
    print("\nDemo complete — launch the GUI with:  python main.py\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    config = AppConfig.load()
    config.resolve_paths()
    if args.db_path:
        config.db_path = args.db_path
    if args.no_seed:
        config.seed_demo_data = False
    if args.log_level:
        config.log_level = args.log_level
    try:
        config.validate()
    except CyberSecError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2
    config.ensure_directories()
    setup_logging(config.log_dir, config.log_level)

    log = get_logger("main")
    log.info("Starting %s v%s (db=%s)", APP_NAME, APP_VERSION, config.db_path)

    try:
        registry = build_runtime(config)
        bootstrap(config, registry, seed=True)
        registry.event_processor.start()
        stale = registry.scans.mark_stale_running()
        if stale:
            log.warning("Marked %d stale scan(s) as failed from a previous run", stale)

        if args.cli_demo:
            return run_cli_demo(registry)

        from gui.app import CyberSecApp
        app = CyberSecApp(registry, config)
        app.mainloop()
        return 0
    except CyberSecError as exc:
        print(f"Startup failed: {exc}", file=sys.stderr)
        log.error("Startup failed: %s", exc)
        return 1
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


# ---------------------------------------------------------------------------
# Vercel / WSGI web entry point
# ---------------------------------------------------------------------------
# The original application is a Tkinter desktop application, so it cannot be
# rendered directly by a browser. Vercel can run a Python WSGI callable; the
# exported ``app`` below fixes the deployment error without changing the
# desktop GUI.
#
# Web endpoints intentionally expose only non-sensitive application metadata.
# The full desktop security console remains available with ``python main.py``.
def app(environ, start_response):
    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET").upper()

    if method == "GET" and path == "/api/health":
        body = (
            '{"ok":true,'
            f'"application":"{APP_NAME}",'
            f'"version":"{APP_VERSION}",'
            '"runtime":"vercel-python",'
            '"desktop_gui":"tkinter"}'
        ).encode("utf-8")
        headers = [("Content-Type", "application/json; charset=utf-8"),
                   ("Content-Length", str(len(body)))]
        start_response("200 OK", headers)
        return [body]

    if method == "GET" and path in ("/", ""):
        body = f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{APP_NAME}</title>
<style>
body{{font-family:system-ui,-apple-system,sans-serif;margin:0;background:#0b1020;color:#e8edf7}}
main{{max-width:850px;margin:70px auto;padding:28px}}
.card{{background:#141b2d;border:1px solid #2b3550;border-radius:18px;padding:28px}}
.ok{{display:inline-block;padding:6px 10px;border-radius:999px;background:#173b2a;color:#8ef0b5}}
h1{{margin-top:18px}}.muted{{color:#aeb8cc}}
code{{background:#0b1020;padding:3px 7px;border-radius:6px}}
a{{color:#8ab4ff}}
</style></head><body><main><div class="card">
<span class="ok">Deployment online</span>
<h1>{APP_NAME}</h1>
<p class="muted">The Vercel Python entry point is running successfully.</p>
<p>The original desktop security console remains available locally with <code>python main.py</code>.</p>
<p>Health check: <a href="/api/health">/api/health</a></p>
</div></main></body></html>""".encode("utf-8")
        headers = [("Content-Type", "text/html; charset=utf-8"),
                   ("Content-Length", str(len(body)))]
        start_response("200 OK", headers)
        return [body]

    body = b"Not Found"
    start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8"),
                                     ("Content-Length", str(len(body)))])
    return [body]


if __name__ == "__main__":
    sys.exit(main())
