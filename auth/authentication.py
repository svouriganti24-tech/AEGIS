"""Authentication primitives: password hashing, sessions, account lifecycle.

This module is intentionally free of GUI and service concerns — it works purely
on repositories and raises typed exceptions the upper layers translate into
user feedback.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
from dataclasses import dataclass
from datetime import timedelta

from core.constants import EventType, Roles, Severity
from core.exceptions import (
    AccountDisabledError,
    AccountLockedError,
    AuthorizationError,
    InvalidCredentialsError,
    RecordNotFoundError,
    SessionExpiredError,
    ValidationError,
)
from core.logger import get_logger
from core.utils import iso, parse_iso, utc_now, utc_now_iso
from core.validators import validate_registration_password, validate_username
from data.models import User
from data.repositories import UserRepository

log = get_logger("auth.authentication")


# ---------------------------------------------------------------------------
# Password hashing — PBKDF2-HMAC-SHA256, per-user random salt, constant-time
# verification. No plaintext or reversible material is ever stored.
# ---------------------------------------------------------------------------


class PasswordHasher:
    ALGORITHM = "pbkdf2_sha256"

    def __init__(self, iterations: int = 200_000):
        if iterations < 10_000:
            raise ValidationError("Hash iteration count must be at least 10,000.")
        self.iterations = iterations

    def hash_password(self, password: str) -> str:
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, self.iterations)
        return f"{self.ALGORITHM}${self.iterations}${salt.hex()}${digest.hex()}"

    def verify_password(self, password: str, stored: str) -> bool:
        try:
            algorithm, iterations, salt_hex, digest_hex = stored.split("$", 3)
            if algorithm != self.ALGORITHM:
                return False
            digest = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
            )
            return hmac.compare_digest(digest.hex(), digest_hex)
        except (ValueError, AttributeError):
            return False


# ---------------------------------------------------------------------------
# In-memory session store (desktop app: sessions die with the process)
# ---------------------------------------------------------------------------


@dataclass
class SessionEntry:
    token: str
    user_id: int
    username: str
    role: str
    created_at: str
    expires_at: str

    @property
    def expired(self) -> bool:
        expires = parse_iso(self.expires_at)
        return expires is None or expires <= utc_now()


class SessionStore:
    def __init__(self, timeout_minutes: int = 30):
        self.timeout_minutes = timeout_minutes
        self._sessions: dict[str, SessionEntry] = {}
        self._lock = threading.RLock()

    def create(self, user: User) -> SessionEntry:
        entry = SessionEntry(
            token=secrets.token_urlsafe(32),
            user_id=user.id or 0,
            username=user.username,
            role=user.role,
            created_at=utc_now_iso(),
            expires_at=iso(utc_now() + timedelta(minutes=self.timeout_minutes)) or "",
        )
        with self._lock:
            self._sessions[entry.token] = entry
        return entry

    def get(self, token: str) -> SessionEntry:
        with self._lock:
            entry = self._sessions.get(token)
            if entry is None:
                raise SessionExpiredError("Session not recognised.")
            if entry.expired:
                self._sessions.pop(token, None)
                raise SessionExpiredError()
            return entry

    def refresh(self, token: str) -> SessionEntry:
        with self._lock:
            entry = self.get(token)
            entry.expires_at = iso(utc_now() + timedelta(minutes=self.timeout_minutes)) or ""
            return entry

    def drop(self, token: str) -> None:
        with self._lock:
            self._sessions.pop(token, None)

    def drop_for_user(self, user_id: int) -> int:
        with self._lock:
            stale = [t for t, s in self._sessions.items() if s.user_id == user_id]
            for token in stale:
                self._sessions.pop(token, None)
            return len(stale)

    def purge_expired(self) -> int:
        with self._lock:
            stale = [t for t, s in self._sessions.items() if s.expired]
            for token in stale:
                self._sessions.pop(token, None)
            return len(stale)

    def active_count(self) -> int:
        with self._lock:
            return len([s for s in self._sessions.values() if not s.expired])


# ---------------------------------------------------------------------------
# Authentication service (domain level)
# ---------------------------------------------------------------------------


class AuthenticationService:
    """Registration, login with lockout, sessions and password management."""

    def __init__(
        self,
        users: UserRepository,
        hasher: PasswordHasher | None = None,
        *,
        session_timeout_minutes: int = 30,
        max_login_attempts: int = 5,
        lockout_minutes: int = 15,
        min_password_length: int = 8,
        on_event=None,
    ):
        self.users = users
        self.hasher = hasher or PasswordHasher()
        self.sessions = SessionStore(session_timeout_minutes)
        self.max_login_attempts = max_login_attempts
        self.lockout_minutes = lockout_minutes
        self.min_password_length = min_password_length
        self._on_event = on_event  # callback(event_type, source, description, severity, username, details)

    # ------------------------------------------------------------ plumbing

    def _emit(self, event_type: str, source: str, description: str,
              severity: Severity = Severity.INFO, username: str | None = None,
              details: dict | None = None) -> None:
        if self._on_event:
            try:
                self._on_event(event_type, source, description, severity, username, details or {})
            except Exception:  # noqa: BLE001 - eventing must never break auth
                log.exception("Event callback failed")

    def _require_actor(self, actor: User | None, permission_held: bool) -> User:
        if actor is None:
            raise AuthorizationError("Authentication required.")
        if not permission_held:
            raise AuthorizationError("You do not have permission to perform this action.")
        return actor

    # -------------------------------------------------------- registration

    def register(self, username: str, password: str, role: str = Roles.VIEWER.value,
                 *, actor: User | None = None, allow_privileged: bool = False) -> User:
        """Create an account.

        ``allow_privileged=True`` is reserved for administrators creating
        analyst/admin accounts; self-registration is restricted to the
        unprivileged role configured in settings.
        """
        username = validate_username(username)
        validate_registration_password(password, self.min_password_length)

        if role in (Roles.ADMIN.value, Roles.ANALYST.value) and not allow_privileged:
            raise AuthorizationError("Privileged roles can only be assigned by an administrator.")
        if actor is not None and allow_privileged and actor.role != Roles.ADMIN.value:
            raise AuthorizationError("Only administrators can manage users.")

        if self.users.get_by_username(username) is not None:
            raise ValidationError(f"Username '{username}' is already taken.")

        # First account ever created becomes the administrator.
        if self.users.count_users() == 0:
            role = Roles.ADMIN.value
        user = self.users.create_user(username, self.hasher.hash_password(password), role)
        self._emit(EventType.AUTH_REGISTER, username, f"Account '{username}' created with role '{role}'",
                   Severity.INFO, username)
        log.info("Registered user '%s' with role '%s'", username, role)
        return user

    # -------------------------------------------------------------- login

    def authenticate(self, username: str, password: str) -> tuple[User, SessionEntry]:
        username = (username or "").strip()
        if not username or not password:
            raise InvalidCredentialsError()

        user = self.users.get_by_username(username)
        if user is None:
            # Burn comparable time to blunt username enumeration via timing.
            self.hasher.verify_password(password, self.hasher.hash_password("timing-equalizer"))
            raise InvalidCredentialsError()

        if not user.is_active:
            self._emit(EventType.AUTH_LOGIN_FAILURE, username, "Login attempt on disabled account",
                       Severity.MEDIUM, username)
            raise AccountDisabledError(f"Account '{username}' has been disabled.")

        self.users.clear_expired_lock(user)
        user = self.users.get_by_username(username) or user

        if user.is_locked:
            self._emit(EventType.AUTH_LOGIN_FAILURE, username, "Login attempt on locked account",
                       Severity.MEDIUM, username)
            raise AccountLockedError(
                f"Account locked due to repeated failures. Try again after {user.locked_until}."
            )

        if not self.hasher.verify_password(password, user.password_hash):
            attempts = self.users.record_failed_attempt(
                user.id or 0, self.max_login_attempts, self.lockout_minutes
            )
            if attempts >= self.max_login_attempts:
                self._emit(EventType.AUTH_LOCKOUT, username,
                           f"Account '{username}' locked for {self.lockout_minutes} minutes after "
                           f"{attempts} failed attempts", Severity.MEDIUM, username)
            self._emit(
                EventType.AUTH_LOGIN_FAILURE, username,
                f"Failed login attempt ({attempts}/{self.max_login_attempts})",
                Severity.LOW, username, {"attempts": attempts},
            )
            raise InvalidCredentialsError()

        self.users.reset_failures(user.id or 0)
        self.users.update_last_login(user.id or 0)
        session = self.sessions.create(user)
        self._emit(EventType.AUTH_LOGIN_SUCCESS, username, "Successful login",
                   Severity.LOW, username, {"session_active": self.sessions.active_count()})
        log.info("User '%s' authenticated", username)
        return user, session

    # ------------------------------------------------------------ sessions

    def validate_session(self, token: str) -> tuple[SessionEntry, User]:
        entry = self.sessions.get(token)
        user = self.users.get_by_id(entry.user_id)
        if user is None or not user.is_active:
            self.sessions.drop(token)
            raise SessionExpiredError("Account is no longer available.")
        return self.sessions.refresh(token), user

    def logout(self, token: str, *, username: str | None = None) -> None:
        self.sessions.drop(token)
        if username:
            self._emit(EventType.AUTH_LOGOUT, username, "User signed out", Severity.INFO, username)

    # ---------------------------------------------------- password & admin

    def change_password(self, actor: User, current_password: str, new_password: str) -> None:
        stored = self.users.get_by_id(actor.id or 0)
        if stored is None:
            raise RecordNotFoundError("Account no longer exists.")
        if not self.hasher.verify_password(current_password, stored.password_hash):
            raise InvalidCredentialsError("Current password is incorrect.")
        validate_registration_password(new_password, self.min_password_length)
        if current_password == new_password:
            raise ValidationError("The new password must differ from the current one.")
        self.users.update_password(stored.id or 0, self.hasher.hash_password(new_password))
        self._emit(EventType.AUTH_PASSWORD_CHANGED, stored.username,
                   "Password changed by user", Severity.LOW, stored.username)

    def admin_reset_password(self, actor: User, target_user_id: int, new_password: str) -> None:
        self._require_actor(actor, actor.role == Roles.ADMIN.value)
        validate_registration_password(new_password, self.min_password_length)
        target = self.users.get_by_id(target_user_id)
        if target is None:
            raise RecordNotFoundError(f"User #{target_user_id} not found.")
        self.users.update_password(target_user_id, self.hasher.hash_password(new_password))
        self.sessions.drop_for_user(target_user_id)
        self._emit(EventType.USER_MANAGEMENT, target.username,
                   f"Password reset by administrator '{actor.username}'", Severity.MEDIUM, target.username)

    def set_role(self, actor: User, target_user_id: int, role: str) -> None:
        self._require_actor(actor, actor.role == Roles.ADMIN.value)
        from core.validators import validate_role
        role = validate_role(role)
        target = self.users.get_by_id(target_user_id)
        if target is None:
            raise RecordNotFoundError(f"User #{target_user_id} not found.")
        if target.role == Roles.ADMIN.value and role != Roles.ADMIN.value:
            admins = [u for u in self.users.list_users() if u.role == Roles.ADMIN.value and u.is_active]
            if len(admins) <= 1:
                raise ValidationError("Cannot demote the last active administrator.")
        self.users.set_role(target_user_id, role)
        self.sessions.drop_for_user(target_user_id)
        self._emit(EventType.USER_MANAGEMENT, target.username,
                   f"Role changed from '{target.role}' to '{role}' by '{actor.username}'",
                   Severity.MEDIUM, target.username)

    def set_active(self, actor: User, target_user_id: int, active: bool) -> None:
        self._require_actor(actor, actor.role == Roles.ADMIN.value)
        target = self.users.get_by_id(target_user_id)
        if target is None:
            raise RecordNotFoundError(f"User #{target_user_id} not found.")
        if target.id == actor.id and not active:
            raise ValidationError("You cannot disable your own account.")
        if target.role == Roles.ADMIN.value and not active:
            admins = [u for u in self.users.list_users() if u.role == Roles.ADMIN.value and u.is_active]
            if len(admins) <= 1:
                raise ValidationError("Cannot disable the last active administrator.")
        self.users.set_active(target_user_id, active)
        if not active:
            self.sessions.drop_for_user(target_user_id)
        state = "enabled" if active else "disabled"
        self._emit(EventType.USER_MANAGEMENT, target.username,
                   f"Account {state} by '{actor.username}'", Severity.MEDIUM, target.username)
