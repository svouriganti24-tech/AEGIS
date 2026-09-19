"""Centralised logging built on :mod:`logging` with rotating file output."""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from core.constants import LOG_BACKUP_COUNT, LOG_FILE_NAME, LOG_FORMAT, LOG_MAX_BYTES

_CONFIGURED = False
_ROOT_LOGGER_NAME = "cybersec"


def setup_logging(log_dir: str | Path, level: str = "INFO", console: bool = True) -> logging.Logger:
    """Configure the application root logger exactly once.

    Returns the root application logger. Child loggers are obtained via
    :func:`get_logger` and inherit both handlers.
    """
    global _CONFIGURED
    root = logging.getLogger(_ROOT_LOGGER_NAME)
    root.setLevel(getattr(logging, str(level).upper(), logging.INFO))
    root.propagate = False

    if not _CONFIGURED:
        formatter = logging.Formatter(LOG_FORMAT)

        log_path = Path(log_dir)
        log_path.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_path / LOG_FILE_NAME, maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT, encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

        if console:
            console_handler = logging.StreamHandler(sys.stderr)
            console_handler.setFormatter(formatter)
            root.addHandler(console_handler)
        _CONFIGURED = True
    else:
        for handler in root.handlers:
            handler.setLevel(root.level)
    return root


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced logger, e.g. ``get_logger('security.scanner')``."""
    if not name.startswith(_ROOT_LOGGER_NAME):
        name = f"{_ROOT_LOGGER_NAME}.{name}"
    return logging.getLogger(name)
