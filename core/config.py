"""Application configuration: typed defaults + JSON persistence.

The configuration file lives next to the application data so users can tune
behaviour (session timeout, scan parameters, detection thresholds) without
touching code. Sensitive values are never stored here.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

from core.constants import (
    ALERT_DEDUPE_WINDOW_SECONDS,
    ALERT_ESCALATION_THRESHOLD,
    APP_ID,
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW_SECONDS,
    DATA_DIR_NAME,
    DB_FILE_NAME,
    DEFAULT_SCAN_THREADS,
    DEFAULT_SCAN_TIMEOUT,
    DETECTION_COOLDOWN_SECONDS,
    EVENT_RATE_THRESHOLD,
    EVENT_RATE_WINDOW_SECONDS,
    LOG_DIR_NAME,
    MAX_LOGIN_ATTEMPTS,
    MAX_PORTS_PER_SCAN,
    MAX_SCAN_THREADS,
    OPEN_PORT_ADVISORY_THRESHOLD,
    PASSWORD_HASH_ITERATIONS,
    REPEATED_SCAN_THRESHOLD,
    REPEATED_SCAN_WINDOW_SECONDS,
    REPORTS_DIR_NAME,
    SESSION_TIMEOUT_MINUTES,
)


@dataclass
class DetectionConfig:
    brute_force_threshold: int = BRUTE_FORCE_THRESHOLD
    brute_force_window_seconds: int = BRUTE_FORCE_WINDOW_SECONDS
    repeated_scan_threshold: int = REPEATED_SCAN_THRESHOLD
    repeated_scan_window_seconds: int = REPEATED_SCAN_WINDOW_SECONDS
    event_rate_threshold: int = EVENT_RATE_THRESHOLD
    event_rate_window_seconds: int = EVENT_RATE_WINDOW_SECONDS
    open_port_advisory_threshold: int = OPEN_PORT_ADVISORY_THRESHOLD
    detection_cooldown_seconds: int = DETECTION_COOLDOWN_SECONDS


@dataclass
class AppConfig:
    """Central, serializable application configuration."""

    # -- identity / storage -------------------------------------------------
    app_name: str = APP_ID
    data_dir: str = ""          # resolved at load time
    db_path: str = ""           # resolved at load time
    log_dir: str = ""           # resolved at load time
    reports_dir: str = ""       # resolved at load time
    log_level: str = "INFO"

    # -- authentication / session -------------------------------------------
    session_timeout_minutes: int = SESSION_TIMEOUT_MINUTES
    max_login_attempts: int = MAX_LOGIN_ATTEMPTS
    lockout_minutes: int = 15
    password_hash_iterations: int = PASSWORD_HASH_ITERATIONS
    min_password_length: int = 8
    allow_self_registration: bool = True
    self_registration_role: str = "viewer"

    # -- scanning ------------------------------------------------------------
    default_scan_timeout: float = DEFAULT_SCAN_TIMEOUT
    max_scan_threads: int = DEFAULT_SCAN_THREADS
    max_ports_per_scan: int = MAX_PORTS_PER_SCAN
    max_concurrent_scans: int = 2

    # -- detection / alerts ---------------------------------------------------
    detection: DetectionConfig = field(default_factory=DetectionConfig)
    alert_dedupe_window_seconds: int = ALERT_DEDUPE_WINDOW_SECONDS
    alert_escalation_threshold: int = ALERT_ESCALATION_THRESHOLD

    # -- first-run behaviour ---------------------------------------------------
    seed_demo_data: bool = True

    # ------------------------------------------------------------------ utils

    def ensure_directories(self) -> None:
        for attr in ("data_dir", "log_dir", "reports_dir"):
            path = Path(getattr(self, attr))
            path.mkdir(parents=True, exist_ok=True)

    def resolve_paths(self, base_dir: str | None = None) -> None:
        base = Path(base_dir) if base_dir else Path(__file__).resolve().parent.parent
        self.data_dir = str(base / DATA_DIR_NAME)
        self.log_dir = str(base / LOG_DIR_NAME)
        self.reports_dir = str(base / REPORTS_DIR_NAME)
        self.db_path = str(Path(self.data_dir) / DB_FILE_NAME)

    def validate(self) -> None:
        problems = []
        if self.session_timeout_minutes < 1:
            problems.append("session_timeout_minutes must be >= 1")
        if self.max_login_attempts < 1:
            problems.append("max_login_attempts must be >= 1")
        if not (0.05 <= self.default_scan_timeout <= 30):
            problems.append("default_scan_timeout must be between 0.05 and 30 seconds")
        if not (1 <= self.max_scan_threads <= MAX_SCAN_THREADS):
            problems.append(f"max_scan_threads must be between 1 and {MAX_SCAN_THREADS}")
        if self.min_password_length < 4:
            problems.append("min_password_length must be >= 4")
        if problems:
            from core.exceptions import ConfigurationError
            raise ConfigurationError("; ".join(problems))

    # ------------------------------------------------------- (de)serialization

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def save(self, path: str | Path | None = None) -> None:
        path = Path(path) if path else self._config_file()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, base_dir: str | None = None, path: str | Path | None = None) -> "AppConfig":
        cfg = cls()
        cfg.resolve_paths(base_dir)
        config_file = Path(path) if path else cls._config_file(base_dir)
        if config_file.exists():
            try:
                raw = json.loads(config_file.read_text(encoding="utf-8"))
                cfg._apply(raw)
            except (json.JSONDecodeError, OSError, TypeError, ValueError):
                # Fall back to defaults on a corrupt config file.
                pass
        # Environment overrides (handy for CI / demos)
        if os.environ.get("CYBERSEC_DB_PATH"):
            cfg.db_path = os.environ["CYBERSEC_DB_PATH"]
            cfg.data_dir = str(Path(cfg.db_path).parent)
        if os.environ.get("CYBERSEC_LOG_LEVEL"):
            cfg.log_level = os.environ["CYBERSEC_LOG_LEVEL"].upper()
        if os.environ.get("CYBERSEC_NO_SEED", "").lower() in {"1", "true", "yes"}:
            cfg.seed_demo_data = False
        return cfg

    def _apply(self, raw: dict[str, Any]) -> None:
        for f in fields(self):
            if f.name not in raw:
                continue
            value = raw[f.name]
            if f.name == "detection" and isinstance(value, dict):
                for inner, val in value.items():
                    if hasattr(self.detection, inner):
                        setattr(self.detection, inner, val)
            elif isinstance(value, (int, float, str, bool)):
                setattr(self, f.name, value)

    @staticmethod
    def _config_file(base_dir: str | None = None) -> Path:
        base = Path(base_dir) if base_dir else Path(__file__).resolve().parent.parent
        return base / DATA_DIR_NAME / "config.json"
