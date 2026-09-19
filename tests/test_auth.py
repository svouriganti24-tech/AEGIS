"""Tests for authentication, sessions, lockout and authorization."""

from __future__ import annotations

import unittest

from core.constants import Permissions, Roles, Severity
from core.exceptions import (
    AccountLockedError,
    AuthorizationError,
    InvalidCredentialsError,
    SessionExpiredError,
    ValidationError,
)
from auth.authentication import PasswordHasher, SessionStore
from auth.authorization import authorize, permissions_for, role_has
from tests.helpers import make_runtime


class HasherTests(unittest.TestCase):
    def test_roundtrip(self):
        hasher = PasswordHasher(iterations=10_000)
        stored = hasher.hash_password("S3cret!pass")
        self.assertTrue(stored.startswith("pbkdf2_sha256$"))
        self.assertTrue(hasher.verify_password("S3cret!pass", stored))
        self.assertFalse(hasher.verify_password("wrong", stored))

    def test_unique_salts(self):
        hasher = PasswordHasher(iterations=10_000)
        self.assertNotEqual(hasher.hash_password("same"), hasher.hash_password("same"))

    def test_malformed_hash_is_rejected(self):
        hasher = PasswordHasher(iterations=10_000)
        self.assertFalse(hasher.verify_password("x", "garbage"))


class SessionStoreTests(unittest.TestCase):
    def test_expiry(self):
        store = SessionStore(timeout_minutes=0)  # immediately stale
        entry = store.create(type("U", (), {"id": 1, "username": "u", "role": "viewer"})())
        self.assertEqual(store.active_count(), 0)
        with self.assertRaises(SessionExpiredError):
            store.get(entry.token)

    def test_drop_for_user(self):
        store = SessionStore(timeout_minutes=5)
        user = type("U", (), {"id": 7, "username": "u", "role": "viewer"})()
        a = store.create(user)
        b = store.create(user)
        self.assertEqual(store.drop_for_user(7), 2)
        with self.assertRaises(SessionExpiredError):
            store.get(a.token)
        with self.assertRaises(SessionExpiredError):
            store.get(b.token)


class AuthFlowTests(unittest.TestCase):
    def setUp(self):
        self.registry, self.tmp = make_runtime()
        self.core = self.registry.auth.core

    def tearDown(self):
        self.registry.shutdown()

    def test_default_admin_exists(self):
        admin = self.core.users.get_by_username("admin")
        self.assertIsNotNone(admin)
        self.assertEqual(admin.role, Roles.ADMIN.value)

    def test_register_validations(self):
        with self.assertRaises(ValidationError):
            self.core.register("ab", "ValidPass1!")            # too short username
        with self.assertRaises(ValidationError):
            self.core.register("goodname", "short")             # weak password
        with self.assertRaises(AuthorizationError):
            self.core.register("goodname", "ValidPass1!", "admin")  # privilege escalation
        user = self.core.register("goodname", "ValidPass1!")
        self.assertEqual(user.role, Roles.VIEWER.value)

    def test_login_success_and_failure(self):
        user, session = self.core.authenticate("admin", "Admin@123")
        self.assertEqual(user.username, "admin")
        self.assertTrue(session.token)
        with self.assertRaises(InvalidCredentialsError):
            self.core.authenticate("admin", "nope")

    def test_unknown_user_indistinguishable(self):
        with self.assertRaises(InvalidCredentialsError):
            self.core.authenticate("ghost", "whatever1!")

    def test_lockout_after_max_attempts(self):
        for i in range(self.core.max_login_attempts):
            with self.assertRaises(InvalidCredentialsError):
                self.core.authenticate("admin", f"bad-{i}")
        with self.assertRaises(AccountLockedError):
            self.core.authenticate("admin", "Admin@123")  # correct password, still locked

    def test_disabled_account_rejected(self):
        user = self.core.users.get_by_username("admin")
        self.core.users.set_active(user.id, False)
        with self.assertRaises(Exception) as ctx:
            self.core.authenticate("admin", "Admin@123")
        self.assertIn("disabled", str(ctx.exception).lower())

    def test_session_roundtrip_and_logout(self):
        _, session = self.core.authenticate("admin", "Admin@123")
        entry, user = self.core.validate_session(session.token)
        self.assertEqual(user.username, "admin")
        self.core.logout(session.token)
        with self.assertRaises(SessionExpiredError):
            self.core.validate_session(session.token)

    def test_change_password(self):
        self.core.change_password(self.core.users.get_by_username("admin"),
                                  "Admin@123", "NewPass#2026")
        with self.assertRaises(InvalidCredentialsError):
            self.core.authenticate("admin", "Admin@123")
        user, _ = self.core.authenticate("admin", "NewPass#2026")
        self.assertIsNotNone(user)

    def test_admin_guards(self):
        self.core.register("viewer1", "ViewerPass1!")
        viewer = self.core.users.get_by_username("viewer1")
        admin = self.core.users.get_by_username("admin")
        with self.assertRaises(AuthorizationError):
            self.core.admin_reset_password(viewer, admin.id, "Whatever#1")
        with self.assertRaises(ValidationError):
            self.core.set_active(admin, admin.id, False)   # cannot disable self
        with self.assertRaises(ValidationError):
            self.core.set_role(admin, admin.id, "viewer")  # cannot demote last admin


class RBACTests(unittest.TestCase):
    def test_matrix_shape(self):
        admin = permissions_for(Roles.ADMIN)
        viewer = permissions_for(Roles.VIEWER)
        self.assertTrue(Permissions.MANAGE_USERS in admin)
        self.assertNotIn(Permissions.RUN_SCAN, viewer)
        self.assertTrue(Permissions.VIEW_LOGS in viewer)

    def test_role_has(self):
        self.assertTrue(role_has("analyst", Permissions.GENERATE_REPORT))
        self.assertFalse(role_has("viewer", Permissions.GENERATE_REPORT))
        self.assertFalse(role_has("nonexistent", Permissions.VIEW_LOGS))

    def test_authorize_raises_without_actor(self):
        with self.assertRaises(AuthorizationError):
            authorize(None, Permissions.VIEW_LOGS)

    def test_service_level_enforcement(self):
        registry, _ = make_runtime()
        try:
            user = registry.auth.core.register("viewer2", "ViewerPass1!")
            with self.assertRaises(AuthorizationError):
                registry.scan.start_scan(user, "127.0.0.1", "80")
        finally:
            registry.shutdown()


if __name__ == "__main__":
    unittest.main()
