"""Input validation for every user-supplied value entering the system.

The GUI performs convenience validation, but these functions are the single
source of truth — services call them again so that the backend stays safe
even when driven by tests, scripts or future non-GUI frontends.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Iterable

from core.exceptions import InvalidPortSpecError, InvalidTargetError, ValidationError
from core.utils import clamp

_USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.?$"
)

MIN_PORT = 1
MAX_PORT = 65535

# Human-friendly port presets (label -> ports or None meaning "all").
PORT_PRESETS: dict[str, list[int] | None] = {
    "Top 30 common ports": [
        21, 22, 23, 25, 53, 67, 68, 80, 110, 119, 123, 135, 137, 138, 139,
        143, 161, 389, 443, 445, 465, 514, 587, 636, 993, 995, 1433, 1521,
        3306, 3389, 5432, 5900, 6379, 8080, 8443,
    ],
    "Web services": [80, 443, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000],
    "Well-known (1-1023)": list(range(1, 1024)),
    "Databases & dev": [1433, 1521, 3306, 5432, 5984, 6379, 8086, 9200, 11211, 27017, 5000, 8000],
    "Remote access": [22, 23, 3389, 5900, 5901, 5800, 4899, 2222],
    "All ports (1-65535)": None,
}


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


def validate_username(username: str) -> str:
    username = (username or "").strip()
    if not username:
        raise ValidationError("Username is required.")
    if not _USERNAME_RE.match(username):
        raise ValidationError(
            "Username must be 3-32 characters and contain only letters, digits, '.', '_' or '-'."
        )
    return username


def validate_registration_password(password: str, min_length: int = 8) -> str:
    """Basic account-password policy (deep analysis lives in the analyzer)."""
    if not password or not isinstance(password, str):
        raise ValidationError("Password is required.")
    if len(password) < min_length:
        raise ValidationError(f"Password must be at least {min_length} characters long.")
    if password.lower() in {"password", "12345678", "qwerty123", "admin1234"}:
        raise ValidationError("That password is far too common. Choose something unique.")
    classes = sum(
        (
            any(c.islower() for c in password),
            any(c.isupper() for c in password),
            any(c.isdigit() for c in password),
            any(not c.isalnum() for c in password),
        )
    )
    if classes < 3:
        raise ValidationError(
            "Password must mix at least three of: lowercase, uppercase, digits, symbols."
        )
    return password


def validate_role(role: str, allowed: Iterable[str] = ("admin", "analyst", "viewer")) -> str:
    role = (role or "").strip().lower()
    if role not in allowed:
        raise ValidationError(f"Role must be one of: {', '.join(sorted(allowed))}.")
    return role


# ---------------------------------------------------------------------------
# Scanning inputs
# ---------------------------------------------------------------------------


def validate_target(target: str) -> str:
    """Validate and normalise a scan target (IPv4/IPv6/hostname/localhost)."""
    target = (target or "").strip().rstrip(".")
    if not target:
        raise InvalidTargetError("A target host is required.")
    if len(target) > 253:
        raise InvalidTargetError("Target is too long to be a valid host.")
    # Try IP literal first (fast, no DNS involved).
    for version in (4, 6):
        try:
            ipaddress.ip_address(target)
            return target
        except ValueError:
            continue
    # Hostname / FQDN form.
    if target.lower() in {"localhost"} or _HOSTNAME_RE.match(target):
        return target.lower()
    raise InvalidTargetError(
        f"'{target}' is not a valid IPv4/IPv6 address or hostname."
    )


def resolve_host_label(target: str) -> str:
    """Best-effort DNS resolution label used in scan metadata (never raises)."""
    try:
        infos = socket.getaddrinfo(target, None)
        return infos[0][4][0] if infos else target
    except OSError:
        return target


def parse_port_spec(spec: str, *, max_ports: int = 4096) -> list[int]:
    """Parse a port specification into a sorted, de-duplicated port list.

    Accepted forms:
      * ``80``                       single port
      * ``80,443,8080``              comma-separated ports
      * ``1-1024``                   inclusive range
      * ``22, 80, 6000-6010``        mixed list (commas/spaces)
      * a preset label such as ``Top 30 common ports`` or ``all``
    """
    if spec is None:
        raise InvalidPortSpecError("A port specification is required.")
    raw = spec.strip()
    if not raw:
        raise InvalidPortSpecError("A port specification is required.")

    lowered = raw.lower()
    if lowered in {"all", "all ports", "all ports (1-65535)"}:
        return list(range(1, MAX_PORT + 1))

    if raw in PORT_PRESETS or raw in PORT_PRESETS.keys():
        preset = PORT_PRESETS.get(raw)
        if preset is None:  # "All ports" preset
            return list(range(1, MAX_PORT + 1))
        return sorted(preset)

    ports: set[int] = set()
    for token in re.split(r"[,\s]+", raw):
        if not token:
            continue
        if "-" in token:
            bounds = token.split("-", 1)
            if len(bounds) != 2 or not all(b.isdigit() for b in bounds):
                raise InvalidPortSpecError(f"Invalid port range '{token}'.")
            lo, hi = int(bounds[0]), int(bounds[1])
            if lo > hi:
                lo, hi = hi, lo
            if lo < MIN_PORT or hi > MAX_PORT:
                raise InvalidPortSpecError(
                    f"Range '{token}' is outside {MIN_PORT}-{MAX_PORT}."
                )
            ports.update(range(lo, hi + 1))
        else:
            if not token.isdigit():
                raise InvalidPortSpecError(f"Invalid port '{token}'.")
            port = int(token)
            if not (MIN_PORT <= port <= MAX_PORT):
                raise InvalidPortSpecError(f"Port {port} is outside {MIN_PORT}-{MAX_PORT}.")
            ports.add(port)

    if not ports:
        raise InvalidPortSpecError("No ports were specified.")
    if len(ports) > max_ports:
        raise InvalidPortSpecError(
            f"{len(ports)} ports requested; the limit is {max_ports}. "
            "Use a narrower range or preset."
        )
    return sorted(ports)


# ---------------------------------------------------------------------------
# Generic sanitisation
# ---------------------------------------------------------------------------


def sanitize_text(value: str | None, max_length: int = 2000) -> str:
    """Strip control characters and cap length for anything stored/displayed."""
    if value is None:
        return ""
    cleaned = "".join(ch for ch in str(value) if ch == "\n" or ch == "\t" or not ord(ch) < 32)
    cleaned = cleaned.replace("\x00", "")
    return cleaned[:max_length].strip()


def validate_positive_int(value: int, name: str, lo: int = 1, hi: int = 1_000_000) -> int:
    try:
        ivalue = int(value)
    except (TypeError, ValueError):
        raise ValidationError(f"{name} must be an integer.")
    if not (lo <= ivalue <= hi):
        raise ValidationError(f"{name} must be between {lo} and {hi}.")
    return ivalue


def validate_timeout(value: float) -> float:
    try:
        fvalue = float(value)
    except (TypeError, ValueError):
        raise ValidationError("Timeout must be a number.")
    return clamp(fvalue, 0.05, 30.0)


def validate_setting_value(key: str, value) -> object:
    """Whitelist + type-check user-editable settings before they are applied."""
    numeric_settings = {
        "session_timeout_minutes": (1, 1440),
        "max_login_attempts": (1, 20),
        "lockout_minutes": (1, 1440),
        "default_scan_timeout": (0.05, 30),
        "max_scan_threads": (1, MAX_SCAN_THREADS),
        "max_ports_per_scan": (8, 65535),
        "max_concurrent_scans": (1, 8),
        "brute_force_threshold": (2, 100),
        "brute_force_window_seconds": (30, 86400),
        "event_rate_threshold": (5, 1000),
    }
    if key in numeric_settings:
        lo, hi = numeric_settings[key]
        try:
            num = float(value)
        except (TypeError, ValueError):
            raise ValidationError(f"Setting '{key}' must be a number.")
        if not (lo <= num <= hi):
            raise ValidationError(f"Setting '{key}' must be between {lo} and {hi}.")
        return int(num) if float(num).is_integer() else num
    if key in {"allow_self_registration", "seed_demo_data"}:
        return bool(value) if isinstance(value, bool) else str(value).lower() in {"1", "true", "yes"}
    if key == "self_registration_role":
        return validate_role(str(value), allowed=("viewer", "analyst"))
    # Unknown keys are rejected rather than blindly stored.
    raise ValidationError(f"Unknown setting '{key}'.")
