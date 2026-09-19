"""Password analysis facade: privacy-aware event emission + result shaping."""

from __future__ import annotations

from auth.authorization import Permissions, require_permission
from core.config import AppConfig
from core.constants import EventType, Severity
from data.models import User
from security.monitoring.event_processor import EventProcessor
from security.password.password_analyzer import PasswordAnalyzer


class PasswordService:
    def __init__(self, analyzer: PasswordAnalyzer, config: AppConfig, events: EventProcessor):
        self.analyzer = analyzer
        self.config = config
        self.events = events

    @require_permission(Permissions.ANALYZE_PASSWORD)
    def analyze(self, actor: User, password: str) -> dict:
        """Analyse a password; logs a metadata-only audit event.

        The password itself (nor any hash of it) is ever persisted — only the
        score, verdict and length are recorded.
        """
        analysis = self.analyzer.analyze(password)
        result = analysis.to_dict()
        self.events.submit(
            EventType.PASSWORD_ANALYSIS,
            actor.username,
            f"Password analysed: verdict {result['verdict']} "
            f"(score {result['score']}/100, length {result['length']})",
            Severity.INFO,
            username=actor.username,
            details={"score": result["score"], "verdict": result["verdict"],
                     "length": result["length"]},
        )
        return result

    def strength_label(self, score: int) -> str:
        """Convenience label used by the GUI meter."""
        if score >= 80:
            return "STRONG"
        if score >= 60:
            return "GOOD"
        if score >= 40:
            return "FAIR"
        if score >= 20:
            return "WEAK"
        return "CRITICAL"
