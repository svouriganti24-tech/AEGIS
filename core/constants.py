"""Application-wide constants, enumerations and tuning knobs.

Every module imports from here instead of hard-coding magic values, so the
behaviour of the whole application can be tuned from a single place.
"""

from __future__ import annotations

from enum import Enum

# ---------------------------------------------------------------------------
# Application identity
# ---------------------------------------------------------------------------

APP_NAME = "Aegis CyberSuite"
APP_ID = "cybersec-app"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = "Desktop cybersecurity toolkit: port scanning, password analysis, threat detection and reporting."

# ---------------------------------------------------------------------------
# Storage / logging defaults
# ---------------------------------------------------------------------------

DATA_DIR_NAME = "data_store"
DB_FILE_NAME = "aegis.db"
LOG_DIR_NAME = "logs"
REPORTS_DIR_NAME = "generated_reports"
LOG_FILE_NAME = "aegis.log"
LOG_MAX_BYTES = 1_500_000
LOG_BACKUP_COUNT = 5
LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """Unified severity scale shared by events, alerts, rules and reports."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def weight(self) -> int:
        return _SEVERITY_WEIGHT[self]

    def escalated(self, steps: int = 1) -> "Severity":
        """Return the severity ``steps`` levels higher (capped at CRITICAL)."""
        order = list(Severity)
        idx = min(len(order) - 1, order.index(self) + max(0, steps))
        return order[idx]

    def __lt__(self, other: "Severity") -> bool:
        return self.weight < other.weight

    def __le__(self, other: "Severity") -> bool:
        return self.weight <= other.weight


_SEVERITY_WEIGHT = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def max_severity(*severities: Severity) -> Severity:
    """Return the highest of the given severities (INFO if none)."""
    result = Severity.INFO
    for sev in severities:
        if sev is not None and sev.weight > result.weight:
            result = sev
    return result


class ScanStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class AlertStatus(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


class Roles(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class PortState(str, Enum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    FILTERED = "FILTERED"


# ---------------------------------------------------------------------------
# Security event taxonomy
# ---------------------------------------------------------------------------


class EventType:
    """Canonical event-type strings persisted to the security event log."""

    SYSTEM_START = "SYSTEM_START"
    SYSTEM_STOP = "SYSTEM_STOP"
    AUTH_LOGIN_SUCCESS = "AUTH_LOGIN_SUCCESS"
    AUTH_LOGIN_FAILURE = "AUTH_LOGIN_FAILURE"
    AUTH_LOGOUT = "AUTH_LOGOUT"
    AUTH_REGISTER = "AUTH_REGISTER"
    AUTH_PASSWORD_CHANGED = "AUTH_PASSWORD_CHANGED"
    AUTH_LOCKOUT = "AUTH_LOCKOUT"
    USER_MANAGEMENT = "USER_MANAGEMENT"
    PORT_SCAN = "PORT_SCAN"
    PASSWORD_ANALYSIS = "PASSWORD_ANALYSIS"
    THREAT_DETECTED = "THREAT_DETECTED"
    ALERT_RAISED = "ALERT_RAISED"
    ALERT_ACKNOWLEDGED = "ALERT_ACKNOWLEDGED"
    ALERT_RESOLVED = "ALERT_RESOLVED"
    SETTINGS_CHANGED = "SETTINGS_CHANGED"
    REPORT_GENERATED = "REPORT_GENERATED"
    REPORT_EXPORTED = "REPORT_EXPORTED"
    EVENT_RECORDED = "EVENT_RECORDED"
    VALIDATION_ERROR = "VALIDATION_ERROR"


EVENT_TYPE_GROUPS = {
    "Authentication": [
        EventType.AUTH_LOGIN_SUCCESS,
        EventType.AUTH_LOGIN_FAILURE,
        EventType.AUTH_LOGOUT,
        EventType.AUTH_REGISTER,
        EventType.AUTH_PASSWORD_CHANGED,
        EventType.AUTH_LOCKOUT,
    ],
    "Scanning": [EventType.PORT_SCAN],
    "Password analysis": [EventType.PASSWORD_ANALYSIS],
    "Threats & alerts": [
        EventType.THREAT_DETECTED,
        EventType.ALERT_RAISED,
        EventType.ALERT_ACKNOWLEDGED,
        EventType.ALERT_RESOLVED,
    ],
    "System & administration": [
        EventType.SYSTEM_START,
        EventType.SYSTEM_STOP,
        EventType.USER_MANAGEMENT,
        EventType.SETTINGS_CHANGED,
        EventType.REPORT_GENERATED,
        EventType.REPORT_EXPORTED,
        EventType.EVENT_RECORDED,
        EventType.VALIDATION_ERROR,
    ],
}

# Event types that are pipeline-internal and must not be re-analysed by the
# detection engine (prevents infinite feedback loops).
INTERNAL_EVENT_TYPES = {EventType.THREAT_DETECTED, EventType.ALERT_RAISED}

# Substrings that make an event description inherently suspicious.
SUSPICIOUS_KEYWORDS = {
    "unauthorized": Severity.HIGH,
    "exploit": Severity.HIGH,
    "injection": Severity.HIGH,
    "overflow": Severity.MEDIUM,
    "privilege escalation": Severity.HIGH,
    "malformed": Severity.MEDIUM,
    "tamper": Severity.MEDIUM,
    "eavesdrop": Severity.MEDIUM,
}

# ---------------------------------------------------------------------------
# Permissions / RBAC
# ---------------------------------------------------------------------------


class Permissions:
    VIEW_DASHBOARD = "dashboard.view"
    RUN_SCAN = "scan.run"
    CANCEL_SCAN = "scan.cancel"
    ANALYZE_PASSWORD = "password.analyze"
    VIEW_ALERTS = "alerts.view"
    MANAGE_ALERTS = "alerts.manage"
    VIEW_LOGS = "logs.view"
    VIEW_REPORTS = "reports.view"
    GENERATE_REPORT = "reports.generate"
    DELETE_REPORT = "reports.delete"
    VIEW_SETTINGS = "settings.view"
    MANAGE_SETTINGS = "settings.manage"
    VIEW_USERS = "users.view"
    MANAGE_USERS = "users.manage"


# ---------------------------------------------------------------------------
# Limits and tuning knobs (safe defaults; overridable via settings/config)
# ---------------------------------------------------------------------------

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
SESSION_TIMEOUT_MINUTES = 30
PASSWORD_HASH_ITERATIONS = 200_000
MIN_PASSWORD_LENGTH = 8

DEFAULT_SCAN_TIMEOUT = 1.0
DEFAULT_SCAN_THREADS = 32
MAX_SCAN_THREADS = 128
MAX_PORTS_PER_SCAN = 4096
MAX_CONCURRENT_SCANS = 2
SCAN_BANNER_PROBE_TIMEOUT = 0.35

EVENT_QUEUE_MAXSIZE = 10_000
EVENT_WORKER_POLL_INTERVAL = 0.05

# Detection thresholds
BRUTE_FORCE_THRESHOLD = 5            # failed logins ...
BRUTE_FORCE_WINDOW_SECONDS = 300     # ... within this window
REPEATED_SCAN_THRESHOLD = 3          # scans against one target ...
REPEATED_SCAN_WINDOW_SECONDS = 600   # ... within this window
EVENT_RATE_THRESHOLD = 40            # any events from one source ...
EVENT_RATE_WINDOW_SECONDS = 60       # ... within this window
OPEN_PORT_ADVISORY_THRESHOLD = 20    # open ports in one scan that warrant a LOW advisory

# Alert behaviour
ALERT_DEDUPE_WINDOW_SECONDS = 600
ALERT_ESCALATION_THRESHOLD = 3       # every N occurrences escalate one level
DETECTION_COOLDOWN_SECONDS = 20

# UI
UI_THEME = "clam"
UI_WINDOW_WIDTH = 1360
UI_WINDOW_HEIGHT = 840
UI_SIDEBAR_WIDTH = 224
UI_SESSION_CHECK_SECONDS = 30

# ---------------------------------------------------------------------------
# Severity palette (hex) shared by GUI and HTML reports
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    Severity.INFO: "#60A5FA",
    Severity.LOW: "#34D399",
    Severity.MEDIUM: "#FBBF24",
    Severity.HIGH: "#FB923C",
    Severity.CRITICAL: "#EF4444",
}

PORT_STATE_COLORS = {
    PortState.OPEN: "#34D399",
    PortState.CLOSED: "#64748B",
    PortState.FILTERED: "#94A3B8",
}
