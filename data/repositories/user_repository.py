from __future__ import annotations

from core.constants import Roles
from core.utils import utc_now_iso
from data.database import DatabaseManager
from data.models import User


class UserRepository:
    def __init__(self, db: DatabaseManager):
        self.db = db

    # ------------------------------------------------------------- helpers

    @staticmethod
    def _to_user(row: dict) -> User:
        return User(
            id=row["id"],
            username=row["username"],
            password_hash=row["password_hash"],
            role=row["role"],
            is_active=bool(row["is_active"]),
            created_at=row["created_at"],
            last_login_at=row["last_login_at"],
            failed_attempts=row["failed_attempts"],
            locked_until=row["locked_until"],
        )

    # ------------------------------------------------------------- queries

    def count_users(self) -> int:
        return int(self.db.scalar("SELECT COUNT(*) FROM users") or 0)

    def get_by_id(self, user_id: int) -> User | None:
        row = self.db.query_one("SELECT * FROM users WHERE id = ?", (user_id,))
        return self._to_user(row) if row else None

    def get_by_username(self, username: str) -> User | None:
        row = self.db.query_one(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)
        )
        return self._to_user(row) if row else None

    def list_users(self) -> list[User]:
        rows = self.db.query("SELECT * FROM users ORDER BY created_at, id")
        return [self._to_user(r) for r in rows]

    # -------------------------------------------------------------- writes

    def create_user(self, username: str, password_hash: str, role: str = Roles.VIEWER.value) -> User:
        now = utc_now_iso()
        new_id = self.db.execute(
            "INSERT INTO users(username, password_hash, role, is_active, created_at) "
            "VALUES(?, ?, ?, 1, ?)",
            (username, password_hash, role, now),
        )
        user = self.get_by_id(new_id)
        assert user is not None
        return user

    def update_last_login(self, user_id: int) -> None:
        self.db.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (utc_now_iso(), user_id))

    def update_password(self, user_id: int, password_hash: str) -> None:
        self.db.execute(
            "UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (password_hash, user_id),
        )

    def set_role(self, user_id: int, role: str) -> None:
        self.db.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))

    def set_active(self, user_id: int, active: bool) -> None:
        self.db.execute("UPDATE users SET is_active = ? WHERE id = ?", (1 if active else 0, user_id))

    def record_failed_attempt(self, user_id: int, max_attempts: int, lockout_minutes: int) -> int:
        """Increment failure counter; lock account when threshold is reached.

        Returns the resulting number of consecutive failures.
        """
        from datetime import timedelta

        from core.utils import iso, parse_iso, utc_now

        with self.db.transaction() as conn:
            row = conn.execute("SELECT failed_attempts FROM users WHERE id = ?", (user_id,)).fetchone()
            attempts = (row["failed_attempts"] if row else 0) + 1
            locked_until = None
            if attempts >= max_attempts:
                locked_until = iso(utc_now() + timedelta(minutes=lockout_minutes))
                conn.execute(
                    "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                    (attempts, locked_until, user_id),
                )
            else:
                conn.execute(
                    "UPDATE users SET failed_attempts = ? WHERE id = ?", (attempts, user_id)
                )
        return attempts

    def reset_failures(self, user_id: int) -> None:
        self.db.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user_id,)
        )

    def clear_expired_lock(self, user: User) -> None:
        """Reset the lockout fields once the lock window has elapsed."""
        if user.locked_until and not user.is_locked:
            self.db.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                (user.id,),
            )
