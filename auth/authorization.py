"""Role-based access control: permission matrix + enforcement helpers."""

from __future__ import annotations

import functools
from typing import Callable

from core.constants import Permissions, Roles
from core.exceptions import AuthorizationError
from data.models import User

#: Role -> set of granted permission strings.
ROLE_PERMISSIONS: dict[str, set[str]] = {
    Roles.ADMIN.value: {
        Permissions.VIEW_DASHBOARD,
        Permissions.RUN_SCAN, Permissions.CANCEL_SCAN,
        Permissions.ANALYZE_PASSWORD,
        Permissions.VIEW_ALERTS, Permissions.MANAGE_ALERTS,
        Permissions.VIEW_LOGS,
        Permissions.VIEW_REPORTS, Permissions.GENERATE_REPORT, Permissions.DELETE_REPORT,
        Permissions.VIEW_SETTINGS, Permissions.MANAGE_SETTINGS,
        Permissions.VIEW_USERS, Permissions.MANAGE_USERS,
    },
    Roles.ANALYST.value: {
        Permissions.VIEW_DASHBOARD,
        Permissions.RUN_SCAN, Permissions.CANCEL_SCAN,
        Permissions.ANALYZE_PASSWORD,
        Permissions.VIEW_ALERTS, Permissions.MANAGE_ALERTS,
        Permissions.VIEW_LOGS,
        Permissions.VIEW_REPORTS, Permissions.GENERATE_REPORT,
        Permissions.VIEW_SETTINGS,
    },
    Roles.VIEWER.value: {
        Permissions.VIEW_DASHBOARD,
        Permissions.ANALYZE_PASSWORD,
        Permissions.VIEW_ALERTS,
        Permissions.VIEW_LOGS,
        Permissions.VIEW_REPORTS,
        Permissions.VIEW_SETTINGS,
    },
}


def role_has(role: str | Roles, permission: str) -> bool:
    role_value = role.value if isinstance(role, Roles) else str(role)
    return permission in ROLE_PERMISSIONS.get(role_value, set())


def permissions_for(role: str | Roles) -> set[str]:
    role_value = role.value if isinstance(role, Roles) else str(role)
    return set(ROLE_PERMISSIONS.get(role_value, set()))


def authorize(actor: User | None, permission: str) -> None:
    """Raise :class:`AuthorizationError` unless ``actor`` holds ``permission``."""
    if actor is None:
        raise AuthorizationError("Authentication required.")
    if not role_has(actor.role, permission):
        raise AuthorizationError(
            f"Role '{actor.role}' does not have the required permission '{permission}'."
        )


def require_permission(permission: str) -> Callable:
    """Decorator for service methods taking ``actor`` as first positional arg.

    Example::

        @require_permission(Permissions.RUN_SCAN)
        def start_scan(self, actor, ...): ...
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(self, actor: User | None, *args, **kwargs):
            authorize(actor, permission)
            return func(self, actor, *args, **kwargs)
        return wrapper
    return decorator
