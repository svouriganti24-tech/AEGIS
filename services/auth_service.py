"""Auth facade: adds session tracking + event emission on top of the auth core."""

from __future__ import annotations

from core.config import AppConfig
from core.exceptions import AuthenticationError, AuthorizationError
from core.logger import get_logger
from data.models import User
from auth.authentication import AuthenticationService, PasswordHasher, SessionEntry
from auth.authorization import Permissions, authorize, permissions_for, role_has

log = get_logger("services.auth")


class AuthService:
    """What the GUI talks to. Holds the *current* user and session token."""

    def __init__(self, core: AuthenticationService, config: AppConfig):
        self.core = core
        self.config = config
        self._current_user: User | None = None
        self._current_token: str | None = None

    # ---------------------------------------------------------- session state

    @property
    def current_user(self) -> User | None:
        return self._current_user

    @property
    def current_token(self) -> str | None:
        return self._current_token

    @property
    def is_authenticated(self) -> bool:
        return self._current_token is not None and self._current_user is not None

    def permissions(self) -> set[str]:
        if self._current_user is None:
            return set()
        return permissions_for(self._current_user.role)

    def has_permission(self, permission: str) -> bool:
        if self._current_user is None:
            return False
        return role_has(self._current_user.role, permission)

    def require(self, permission: str) -> User:
        """Return the current user or raise if missing/unauthorised."""
        if self._current_user is None:
            raise AuthorizationError("You must be signed in.")
        authorize(self._current_user, permission)
        return self._current_user

    # ------------------------------------------------------------- account ops

    def register(self, username: str, password: str, role: str | None = None) -> User:
        role = role or self.config.self_registration_role
        return self.core.register(username, password, role, actor=self._current_user)

    def login(self, username: str, password: str) -> User:
        user, session = self.core.authenticate(username, password)
        self._current_user = user
        self._current_token = session.token
        return user

    def validate_session(self) -> bool:
        """Re-validate the in-memory session; logs out on expiry."""
        if not self._current_token:
            return False
        try:
            entry, user = self.core.validate_session(self._current_token)
            self._current_user = user
            return True
        except AuthenticationError:
            self._clear()
            return False

    def logout(self) -> None:
        if self._current_token:
            self.core.logout(self._current_token, username=self._current_user.username
                             if self._current_user else None)
        self._clear()

    def _clear(self) -> None:
        self._current_user = None
        self._current_token = None

    # ------------------------------------------------------------ delegation

    def change_password(self, current: str, new: str) -> None:
        if self._current_user is None:
            raise AuthorizationError("You must be signed in.")
        self.core.change_password(self._current_user, current, new)

    # ------------------------------------------------------- administration

    def list_users(self) -> list[User]:
        self.require(Permissions.VIEW_USERS)
        return self.core.users.list_users()

    def set_user_role(self, user_id: int, role: str) -> None:
        if self._current_user is None:
            raise AuthorizationError("You must be signed in.")
        self.core.set_role(self._current_user, user_id, role)

    def set_user_active(self, user_id: int, active: bool) -> None:
        if self._current_user is None:
            raise AuthorizationError("You must be signed in.")
        self.core.set_active(self._current_user, user_id, active)

    def reset_user_password(self, user_id: int, new_password: str) -> None:
        if self._current_user is None:
            raise AuthorizationError("You must be signed in.")
        self.core.admin_reset_password(self._current_user, user_id, new_password)

    def hasher(self) -> PasswordHasher:
        return self.core.hasher

    def session_entry(self) -> SessionEntry | None:
        if not self._current_token:
            return None
        try:
            return self.core.sessions.get(self._current_token)
        except AuthenticationError:
            return None
