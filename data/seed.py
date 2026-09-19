"""First-run seeding: default admin account + optional demo dataset.

Seeding writes *real* rows through the normal repositories so the dashboard
renders live backend data on the very first launch (and in the demo). It can
be disabled with ``--no-seed`` or config ``seed_demo_data = false``.
"""

from __future__ import annotations

import random
from datetime import timedelta

from core.constants import AlertStatus, EventType, Roles, Severity
from core.logger import get_logger
from core.utils import iso, utc_now
from data.database import DatabaseManager
from data.models import Alert, SecurityEvent
from data.repositories import (
    AlertRepository,
    EventRepository,
    ScanRepository,
    SettingsRepository,
    UserRepository,
)

log = get_logger("data.seed")

DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "Admin@123"
DEFAULT_ANALYST_PASSWORD = "Analyst@123"
DEFAULT_VIEWER_PASSWORD = "Viewer@123"


def ensure_default_admin(
    users: UserRepository, hasher, *, username: str = DEFAULT_ADMIN_USERNAME,
    password: str = DEFAULT_ADMIN_PASSWORD,
) -> bool:
    """Create the initial administrator account when the user table is empty.

    Returns True when a new account was created.
    """
    if users.count_users() > 0:
        return False
    users.create_user(username, hasher.hash_password(password), Roles.ADMIN.value)
    log.warning(
        "Created default administrator account '%s' with initial password '%s' — "
        "change this password immediately after first login.", username, password,
    )
    return True


def seed_demo_data(
    db: DatabaseManager,
    users: UserRepository,
    scans: ScanRepository,
    events: EventRepository,
    alerts: AlertRepository,
    settings: SettingsRepository,
    hasher,
) -> bool:
    """Populate a realistic 7-day demo dataset if the database is empty."""
    if events.count_events() > 0 or scans.count_scans() > 0:
        return False

    rng = random.Random(1337)
    now = utc_now()

    # ------------------------------------------------------------------ users
    demo_users = [
        ("analyst", DEFAULT_ANALYST_PASSWORD, Roles.ANALYST.value),
        ("viewer", DEFAULT_VIEWER_PASSWORD, Roles.VIEWER.value),
    ]
    for username, password, role in demo_users:
        if users.get_by_username(username) is None:
            users.create_user(username, hasher.hash_password(password), role)
    admin = users.get_by_username(DEFAULT_ADMIN_USERNAME)

    # ------------------------------------------------------------------ scans
    demo_scans = [  # (username, target, port_spec, open_count, total, days_ago)
        (Roles.ADMIN.value, "127.0.0.1", "Top 30 common ports", 4, 6, 2.0),
        (Roles.ADMIN.value, "192.168.1.1", "Web services", 2, 11, 1.4),
        ("analyst", "10.0.0.14", "Databases & dev", 1, 5, 0.6),
    ]
    for username, target, port_spec, open_count, total, days_ago in demo_scans:
        started = now - timedelta(days=days_ago, minutes=rng.randint(0, 40))
        finished = started + timedelta(seconds=rng.uniform(1.5, 9.0))
        owner = users.get_by_username(username)
        scan_id = db.execute(
            "INSERT INTO scans(user_id, username, target, resolved_ip, scan_type, port_spec, "
            "status, started_at, finished_at, total_ports, open_ports) "
            "VALUES(?, ?, ?, ?, 'TCP_CONNECT', ?, 'COMPLETED', ?, ?, ?, ?)",
            (owner.id if owner else None, username, target, target, port_spec,
             iso(started), iso(finished), total, open_count),
        )
        common_open = {22: "ssh", 80: "http", 443: "https", 3306: "mysql", 8080: "http-proxy"}
        chosen = rng.sample(sorted(common_open), k=min(open_count, len(common_open)))
        db.execute_many(
            "INSERT INTO scan_ports(scan_id, port, state, service, banner, latency_ms) "
            "VALUES(?, ?, 'OPEN', ?, ?, ?)",
            [
                (scan_id, p, common_open[p],
                 f"{common_open[p].upper()} service detected",
                 round(rng.uniform(0.4, 12.0), 2))
                for p in chosen
            ],
        )

    # ----------------------------------------------------------------- events
    def _event(days_ago: float, event_type: str, source: str, description: str,
               severity: Severity, username: str | None = None, details: dict | None = None):
        events.add_event(
            _backdated_event(days_ago, event_type, source, description, severity, username, details)
        )

    _event(6.9, EventType.SYSTEM_START, "system", "Application initialised (demo dataset)", Severity.INFO)
    _event(6.5, EventType.AUTH_REGISTER, DEFAULT_ADMIN_USERNAME,
           "Demo accounts provisioned: analyst, viewer", Severity.INFO, DEFAULT_ADMIN_USERNAME)

    # A normal working pattern for the analyst
    for days_ago in (5.8, 4.2, 3.1, 2.4, 1.1, 0.3):
        _event(days_ago, EventType.AUTH_LOGIN_SUCCESS, "analyst",
               "Successful login", Severity.LOW, "analyst", {"method": "password"})
        _event(days_ago + 0.05, EventType.PORT_SCAN, "192.168.1.1",
               "Scheduled scan of gateway: 11 ports scanned, 2 open", Severity.INFO, "analyst",
               {"open_count": 2, "total": 11})

    # A brute-force burst from an outside address yesterday evening
    burst_start = 1.05
    for i in range(7):
        _event(burst_start + i * 0.0005, EventType.AUTH_LOGIN_FAILURE, "203.0.113.66",
               f"Failed login attempt for user 'admin' from 203.0.113.66 (attempt {i + 1}/7)",
               Severity.LOW, "admin", {"attempt": i + 1, "remote": "203.0.113.66"})
    _event(burst_start + 0.006, EventType.ALERT_RAISED, "203.0.113.66",
           "Brute-force pattern detected: 7 failed logins within 5 minutes", Severity.HIGH)
    _event(1.0, EventType.AUTH_LOCKOUT, "admin",
           "Account 'admin' locked for 15 minutes after repeated failures", Severity.MEDIUM, "admin")

    # Reconnaissance pattern
    for i in range(4):
        _event(0.9 + i * 0.002, EventType.PORT_SCAN, "198.51.100.23",
               f"Rapid repeated scanning against 198.51.100.23 (sweep {i + 1}/4)", Severity.LOW)

    # Occasional unusual-hour activity
    _event(2.2, EventType.AUTH_LOGIN_SUCCESS, "analyst",
           "Successful login during unusual hours (02:40 local)", Severity.LOW, "analyst")

    _event(0.05, EventType.PASSWORD_ANALYSIS, "analyst",
           "Password analysed: verdict WEAK (score 31/100)", Severity.LOW, "analyst",
           {"score": 31, "verdict": "WEAK"})

    # ----------------------------------------------------------------- alerts
    alerts.create_alert(Alert(
        title="Brute-force authentication attempts",
        severity=Severity.HIGH,
        source="203.0.113.66",
        description="7 failed login attempts against user 'admin' within 5 minutes "
                    "from 203.0.113.66. Account lockout policy triggered.",
        details={"rule": "brute-force", "attempts": 7, "window_seconds": 300},
    ))
    sweep = alerts.create_alert(Alert(
        title="Repeated port scanning activity",
        severity=Severity.MEDIUM,
        source="198.51.100.23",
        description="4 rapid scans against 198.51.100.23 within a short window — "
                    "possible reconnaissance sweep.",
        details={"rule": "port-sweep", "scans": 4},
    ))
    alerts.set_status(sweep.id, AlertStatus.ACKNOWLEDGED.value, actor=DEFAULT_ADMIN_USERNAME)

    resolved = alerts.create_alert(Alert(
        title="Unusual-hour account access",
        severity=Severity.LOW,
        source="analyst",
        description="Successful login at 02:40 local time, outside the usual activity pattern.",
        details={"rule": "off-hours"},
    ))
    alerts.set_status(resolved.id, AlertStatus.RESOLVED.value, actor=DEFAULT_ADMIN_USERNAME)

    # --------------------------------------------------------------- settings
    settings.set("seeded_demo_data", "true", updated_by="system")
    settings.set("org_name", "Aegis Demo Environment", updated_by="system")

    log.info("Seeded demo dataset: %s", db.table_counts())
    return True


def _backdated_event(days_ago, event_type, source, description, severity, username=None, details=None):
    return SecurityEvent(
        timestamp=iso(utc_now() - timedelta(days=days_ago)),
        event_type=event_type,
        source=source,
        description=description,
        severity=severity,
        username=username,
        details=details or {},
    )
