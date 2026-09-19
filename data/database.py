"""Thread-safe SQLite persistence foundation.

Design notes
------------
* The whole application shares **one connection** guarded by an
  :class:`threading.RLock`. SQLite in WAL mode handles this pattern well for
  a desktop app and avoids the complexity of per-thread connections.
* All SQL lives in the repositories; this class only provides safe primitives
  (``execute`` / ``query`` / transactions) and schema management.
* Every write is parameterised — no string interpolation of user input.
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from core.exceptions import DatabaseError, RecordNotFoundError
from core.logger import get_logger

log = get_logger("data.database")

SCHEMA_VERSION = 1

_SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    username         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash    TEXT NOT NULL,
    role             TEXT NOT NULL DEFAULT 'viewer',
    is_active        INTEGER NOT NULL DEFAULT 1,
    created_at       TEXT NOT NULL,
    last_login_at    TEXT,
    failed_attempts  INTEGER NOT NULL DEFAULT 0,
    locked_until     TEXT
);

CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username      TEXT,
    target        TEXT NOT NULL,
    resolved_ip   TEXT,
    scan_type     TEXT NOT NULL DEFAULT 'TCP_CONNECT',
    port_spec     TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'PENDING',
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    total_ports   INTEGER NOT NULL DEFAULT 0,
    open_ports    INTEGER NOT NULL DEFAULT 0,
    error         TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_status  ON scans(status);

CREATE TABLE IF NOT EXISTS scan_ports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    port        INTEGER NOT NULL,
    state       TEXT NOT NULL,
    service     TEXT,
    banner      TEXT,
    latency_ms  REAL
);
CREATE INDEX IF NOT EXISTS idx_scan_ports_scan ON scan_ports(scan_id);

CREATE TABLE IF NOT EXISTS security_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT NOT NULL,
    event_type   TEXT NOT NULL,
    source       TEXT NOT NULL DEFAULT '',
    description  TEXT NOT NULL DEFAULT '',
    severity     TEXT NOT NULL DEFAULT 'INFO',
    username     TEXT,
    status       TEXT NOT NULL DEFAULT 'NEW',
    details      TEXT,
    internal     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_events_ts       ON security_events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_events_type     ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_source   ON security_events(source);

CREATE TABLE IF NOT EXISTS alerts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at       TEXT NOT NULL,
    title            TEXT NOT NULL,
    severity         TEXT NOT NULL,
    source           TEXT NOT NULL DEFAULT '',
    description      TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL DEFAULT 'OPEN',
    occurrences      INTEGER NOT NULL DEFAULT 1,
    last_seen_at     TEXT NOT NULL,
    acknowledged_by  TEXT,
    acknowledged_at  TEXT,
    resolved_at      TEXT,
    details          TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_status   ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);

CREATE TABLE IF NOT EXISTS reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    title           TEXT NOT NULL,
    report_type     TEXT NOT NULL DEFAULT 'FULL_ASSESSMENT',
    generated_by    TEXT NOT NULL DEFAULT '',
    generated_at    TEXT NOT NULL,
    content_format  TEXT NOT NULL DEFAULT 'TXT',
    file_path       TEXT NOT NULL DEFAULT '',
    summary         TEXT NOT NULL DEFAULT '',
    data            TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL DEFAULT '',
    updated_at  TEXT,
    updated_by  TEXT
);
"""


class DatabaseManager:
    """Owns the SQLite connection and exposes thread-safe primitives."""

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        self._lock = threading.RLock()
        self._conn: sqlite3.Connection | None = None
        self.connect()

    # ------------------------------------------------------------- lifecycle

    def connect(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        try:
            self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            with self._lock:
                self._conn.execute("PRAGMA journal_mode=WAL")
                self._conn.execute("PRAGMA synchronous=NORMAL")
                self._conn.execute("PRAGMA foreign_keys=ON")
                self._conn.executescript(_SCHEMA)
                self._conn.execute(
                    "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (str(SCHEMA_VERSION),),
                )
                self._conn.commit()
        except sqlite3.Error as exc:  # pragma: no cover - catastrophic
            raise DatabaseError(f"Could not open database: {exc}") from exc
        log.info("Database ready at %s (schema v%s)", self.db_path, SCHEMA_VERSION)

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.commit()
                finally:
                    self._conn.close()
                    self._conn = None

    @property
    def is_connected(self) -> bool:
        return self._conn is not None

    # ------------------------------------------------------------ primitives

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Yield the connection inside an atomic commit/rollback block."""
        if self._conn is None:
            raise DatabaseError("Database connection is closed.")
        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except sqlite3.Error as exc:
                self._conn.rollback()
                raise DatabaseError(f"Transaction failed: {exc}") from exc
            except BaseException:
                # Any non-SQL failure must still undo partial writes.
                self._conn.rollback()
                raise

    def execute(self, sql: str, params: tuple | list = ()) -> int:
        """Execute a write statement; returns ``lastrowid``."""
        with self.transaction() as conn:
            cur = conn.execute(sql, params)
            return int(cur.lastrowid or 0)

    def execute_many(self, sql: str, seq: list[tuple | list]) -> None:
        with self.transaction() as conn:
            conn.executemany(sql, seq)

    def query(self, sql: str, params: tuple | list = ()) -> list[dict]:
        """Run a read statement; returns a list of dict rows."""
        if self._conn is None:
            raise DatabaseError("Database connection is closed.")
        with self._lock:
            cur = self._conn.execute(sql, params)
            return [dict(row) for row in cur.fetchall()]

    def query_one(self, sql: str, params: tuple | list = ()) -> dict | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    def scalar(self, sql: str, params: tuple | list = ()) -> Any:
        row = self.query_one(sql, params)
        return next(iter(row.values())) if row else None

    # ------------------------------------------------------------- utilities

    @staticmethod
    def require(row: dict | None, entity: str, record_id: object) -> dict:
        if row is None:
            raise RecordNotFoundError(f"{entity} #{record_id} was not found.")
        return row

    def table_counts(self) -> dict[str, int]:
        counts = {}
        for table in ("users", "scans", "scan_ports", "security_events", "alerts", "reports", "settings"):
            counts[table] = int(self.scalar(f"SELECT COUNT(*) FROM {table}") or 0)
        return counts
