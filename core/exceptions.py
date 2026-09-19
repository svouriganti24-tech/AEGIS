"""Custom exception hierarchy for the whole application.

Raising typed exceptions (instead of bare ``ValueError``/``RuntimeError``)
lets each layer catch precisely what it can handle and lets the GUI present
meaningful messages to the user.
"""

from __future__ import annotations


class CyberSecError(Exception):
    """Base class for every application-specific error."""

    #: default user-facing message; subclasses override
    user_message = "An unexpected application error occurred."

    def __init__(self, message: str | None = None, *, user_message: str | None = None):
        super().__init__(message or self.user_message)
        if user_message:
            self.user_message = user_message

    @property
    def message(self) -> str:
        return str(self)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class ValidationError(CyberSecError):
    user_message = "The provided input is invalid."


class InvalidTargetError(ValidationError):
    user_message = "The target host is not a valid IP address or hostname."


class InvalidPortSpecError(ValidationError):
    user_message = "The port specification is invalid."


# ---------------------------------------------------------------------------
# Authentication / authorization
# ---------------------------------------------------------------------------


class AuthenticationError(CyberSecError):
    user_message = "Authentication failed."


class InvalidCredentialsError(AuthenticationError):
    user_message = "Invalid username or password."


class AccountLockedError(AuthenticationError):
    user_message = "Account is temporarily locked due to failed login attempts."


class AccountDisabledError(AuthenticationError):
    user_message = "This account has been disabled."


class SessionExpiredError(AuthenticationError):
    user_message = "Your session has expired. Please sign in again."


class AuthorizationError(CyberSecError):
    user_message = "You do not have permission to perform this action."


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


class DatabaseError(CyberSecError):
    user_message = "A database error occurred."


class RecordNotFoundError(DatabaseError):
    user_message = "The requested record was not found."


class DuplicateRecordError(DatabaseError):
    user_message = "A record with the same unique value already exists."


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


class ScanError(CyberSecError):
    user_message = "The scan could not be completed."


class ScanTargetUnresolvableError(ScanError):
    user_message = "The target host could not be resolved."


class ScanTimeoutError(ScanError):
    user_message = "The scan operation timed out."


class ScanLimitReachedError(ScanError):
    user_message = "The maximum number of concurrent scans is already running."


class ScanCancelledError(ScanError):
    user_message = "The scan was cancelled."


# ---------------------------------------------------------------------------
# Miscellaneous domains
# ---------------------------------------------------------------------------


class PasswordAnalysisError(CyberSecError):
    user_message = "The password could not be analysed."


class ReportError(CyberSecError):
    user_message = "The report could not be generated."


class ConfigurationError(CyberSecError):
    user_message = "The application configuration is invalid."


class EventProcessingError(CyberSecError):
    user_message = "A security event could not be processed."
