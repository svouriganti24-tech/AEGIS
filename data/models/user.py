from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class User:
    """An application account."""

    id: int | None = None
    username: str = ""
    password_hash: str = ""
    role: str = "viewer"
    is_active: bool = True
    created_at: str = ""
    last_login_at: str | None = None
    failed_attempts: int = 0
    locked_until: str | None = None

    @property
    def is_locked(self) -> bool:
        from core.utils import parse_iso, utc_now
        if not self.locked_until:
            return False
        locked_until = parse_iso(self.locked_until)
        return locked_until is not None and locked_until > utc_now()

    def to_dict(self, include_private: bool = False) -> dict:
        data = {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at,
            "last_login_at": self.last_login_at,
        }
        if include_private:
            data.update(
                {
                    "password_hash": self.password_hash,
                    "failed_attempts": self.failed_attempts,
                    "locked_until": self.locked_until,
                }
            )
        return data
