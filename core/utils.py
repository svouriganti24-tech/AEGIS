"""Small shared utilities used across every layer of the application."""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

_SLUG_RE = re.compile(r"[^a-zA-Z0-9_-]+")


# ---------------------------------------------------------------------------
# Time helpers — everything is persisted as timezone-aware ISO-8601 UTC strings
# so lexicographic comparison in SQL equals chronological comparison.
# ---------------------------------------------------------------------------


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat(timespec="seconds")


def iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def parse_iso(value: str | None) -> datetime | None:
    """Parse an ISO-8601 string; returns a timezone-aware UTC datetime."""
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def iso_in_past(minutes: int = 0, days: int = 0, seconds: int = 0) -> str:
    delta = timedelta(days=days, minutes=minutes, seconds=seconds)
    return iso(utc_now() - delta) or utc_now_iso()


def within_window(timestamp_iso: str | None, window_seconds: int, *, now: datetime | None = None) -> bool:
    """True if ``timestamp_iso`` falls within the last ``window_seconds``."""
    ts = parse_iso(timestamp_iso)
    if ts is None:
        return False
    now = now or utc_now()
    return (now - ts) <= timedelta(seconds=window_seconds)


def humanize_duration(seconds: float) -> str:
    """Render a duration in human-readable form ('3.2 seconds', '4 days', ...)."""
    if seconds is None or seconds < 0:
        return "unknown"
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.1f} seconds".replace(".0 ", " ")
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.1f} minutes".replace(".0 ", " ")
    hours = minutes / 60
    if hours < 48:
        return f"{hours:.1f} hours".replace(".0 ", " ")
    days = hours / 24
    if days < 365:
        return f"{days:.1f} days".replace(".0 ", " ")
    years = days / 365.25
    if years < 1000:
        return f"{years:.1f} years".replace(".0 ", " ")
    return "millions of years"


def humanize_timestamp(iso_string: str | None) -> str:
    """Render an ISO timestamp as a compact local-time string for tables."""
    dt = parse_iso(iso_string)
    if dt is None:
        return "-"
    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------


def slugify(text: str, fallback: str = "report") -> str:
    text = _SLUG_RE.sub("-", (text or "").strip().lower()).strip("-")
    return text or fallback


def clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def truncate(text: str | None, limit: int = 200) -> str:
    text = text or ""
    return text if len(text) <= limit else text[: limit - 1] + "…"


def chunked(items: Iterable, size: int):
    batch = []
    for item in items:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


# ---------------------------------------------------------------------------
# JSON helpers (details columns are stored as JSON text)
# ---------------------------------------------------------------------------


def json_dumps(data: Any) -> str:
    try:
        return json.dumps(data, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return "{}"


def json_loads(text: str | None) -> dict:
    if not text:
        return {}
    try:
        loaded = json.loads(text)
        return loaded if isinstance(loaded, dict) else {"value": loaded}
    except (TypeError, ValueError):
        return {}
