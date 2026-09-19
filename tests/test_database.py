"""Tests for the SQLite layer and repositories."""

from __future__ import annotations

import unittest

from core.constants import AlertStatus, ScanStatus, Severity
from data.database import DatabaseManager
from data.models import PortRecord, ReportRecord, SecurityEvent
from tests.helpers import make_runtime


class DatabaseManagerTests(unittest.TestCase):
    def setUp(self):
        self.registry, self.tmp = make_runtime()
        self.db = self.registry.db

    def tearDown(self):
        self.registry.shutdown()

    def test_schema_initialized(self):
        tables = {row["name"] for row in
                  self.db.query("SELECT name FROM sqlite_master WHERE type='table'")}
        expected = {"users", "scans", "scan_ports", "security_events", "alerts", "reports",
                    "settings", "schema_meta"}
        self.assertTrue(expected.issubset(tables))

    def test_transaction_rollback_on_error(self):
        before = self.registry.users.count_users()
        try:
            with self.db.transaction():
                self.db._conn.execute(
                    "INSERT INTO users(username, password_hash, role, created_at) "
                    "VALUES('txuser', 'h', 'viewer', '2026-01-01T00:00:00')")
                raise RuntimeError("boom")
        except RuntimeError:
            pass
        self.assertEqual(self.registry.users.count_users(), before)


class UserRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.registry, _ = make_runtime()
        self.repo = self.registry.users

    def tearDown(self):
        self.registry.shutdown()

    def test_create_and_fetch_case_insensitive(self):
        self.repo.create_user("CaseUser", "hash", "viewer")
        self.assertIsNotNone(self.repo.get_by_username("caseuser"))

    def test_failed_attempts_lockout_flow(self):
        user = self.repo.create_user("lockme", "hash", "viewer")
        for attempt in range(1, 4):
            attempts = self.repo.record_failed_attempt(user.id, 3, 15)
        self.assertEqual(attempts, 3)
        refreshed = self.repo.get_by_username("lockme")
        self.assertTrue(refreshed.is_locked)
        self.repo.reset_failures(user.id)
        self.assertFalse(self.repo.get_by_username("lockme").is_locked)


class ScanRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.registry, _ = make_runtime()
        self.repo = self.registry.scans
        self.scan_id = self.repo.create_scan(
            user_id=None, username="tester", target="127.0.0.1", resolved_ip="127.0.0.1",
            scan_type="TCP_CONNECT", port_spec="80,443", total_ports=2)

    def tearDown(self):
        self.registry.shutdown()

    def test_scan_lifecycle(self):
        self.repo.add_port_results(self.scan_id, [
            PortRecord(port=80, state="OPEN", service="http", latency_ms=1.2),
            PortRecord(port=443, state="CLOSED"),
        ])
        self.repo.finish_scan(self.scan_id, status=ScanStatus.COMPLETED, open_ports=1)
        record = self.repo.get_scan(self.scan_id)
        self.assertEqual(record.status, "COMPLETED")
        self.assertEqual(record.open_ports, 1)
        ports = self.repo.get_ports(self.scan_id)
        self.assertEqual(len(ports), 2)
        self.assertEqual(ports[0].port, 80)
        open_only = self.repo.get_ports(self.scan_id, only_open=True)
        self.assertEqual([p.port for p in open_only], [80])

    def test_filters_and_counts(self):
        self.repo.finish_scan(self.scan_id, status=ScanStatus.COMPLETED)
        self.assertEqual(self.repo.count_scans(status="COMPLETED"), 1)
        self.assertEqual(self.repo.count_scans(status="FAILED"), 0)
        found = self.repo.list_scans(search="127.0.0.1")
        self.assertTrue(found)

    def test_cascade_delete_ports(self):
        self.repo.add_port_results(self.scan_id, [PortRecord(port=80, state="OPEN")])
        self.repo.delete_scan(self.scan_id)
        self.assertEqual(self.repo.get_ports(self.scan_id), [])


class EventRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.registry, _ = make_runtime()
        self.repo = self.registry.events
        self.db = self.registry.db

    def tearDown(self):
        self.registry.shutdown()

    def test_add_and_filter(self):
        self.repo.add_event(SecurityEvent(event_type="T1", source="a", description="one",
                                          severity=Severity.LOW))
        self.repo.add_event(SecurityEvent(event_type="T2", source="b", description="two",
                                          severity=Severity.HIGH))
        low = self.repo.list_events(severity="LOW")
        self.assertEqual(len(low), 1)
        self.assertEqual(low[0].event_type, "T1")
        self.assertEqual(self.repo.count_events(severity="HIGH"), 1)
        by_type = self.repo.count_by_type()
        self.assertEqual(by_type[0]["event_type"], "T1")

    def test_details_roundtrip(self):
        event = SecurityEvent(event_type="T", source="s", description="d",
                              severity=Severity.INFO, details={"k": "v", "n": 5})
        stored = self.repo.add_event(event)
        loaded = self.repo.get_event(stored.id)
        self.assertEqual(loaded.details, {"k": "v", "n": 5})

    def test_window_counter(self):
        from core.utils import iso_in_past
        self.repo.add_event(SecurityEvent(event_type="T", source="win", description="d",
                                          severity=Severity.INFO))
        self.assertEqual(self.repo.count_events_for_source("win", window_seconds=300), 1)
        # backdated event outside the window
        old = SecurityEvent(event_type="T", source="win", description="old",
                            severity=Severity.INFO)
        old = self.repo.add_event(old)
        self.db.execute("UPDATE security_events SET timestamp=? WHERE id=?",
                        (iso_in_past(days=2), old.id))
        self.assertEqual(self.repo.count_events_for_source("win", window_seconds=300), 1)

    def test_severity_aggregation(self):
        self.repo.add_event(SecurityEvent(event_type="T", source="s", description="d",
                                          severity=Severity.MEDIUM))
        counts = self.repo.count_by_severity()
        self.assertGreaterEqual(counts.get("MEDIUM", 0), 1)


class AlertReportSettingsTests(unittest.TestCase):
    def setUp(self):
        self.registry, _ = make_runtime()
        self.alerts = self.registry.alerts
        self.reports = self.registry.reports
        self.settings = self.registry.settings

    def tearDown(self):
        self.registry.shutdown()

    def test_alert_status_counts(self):
        alert = self.alerts.create_alert(type("A", (), {
            "title": "t", "severity": Severity.HIGH, "source": "s",
            "description": "d", "status": "OPEN", "details": {},
            "id": None, "created_at": "", "last_seen_at": ""})())
        self.alerts.set_status(alert.id, AlertStatus.ACKNOWLEDGED.value, actor="admin")
        counts = self.alerts.count_by_status()
        self.assertEqual(counts.get("ACKNOWLEDGED"), 1)

    def test_dedupe_lookup_respects_window(self):
        from data.models import Alert
        created = self.alerts.create_alert(Alert(title="Port sweep", source="host",
                                                 severity=Severity.MEDIUM, description="d"))
        found = self.alerts.find_similar_open_alert("Port sweep", "host",
                                                    dedupe_window_seconds=600)
        self.assertIsNotNone(found)
        self.assertEqual(found.id, created.id)
        self.assertIsNone(self.alerts.find_similar_open_alert("Other", "host",
                                                              dedupe_window_seconds=600))

    def test_report_roundtrip(self):
        record = self.reports.create_report(ReportRecord(
            title="Demo", report_type="FULL_ASSESSMENT", generated_by="admin",
            content_format="HTML", file_path="/tmp/demo.html", summary="s",
            data={"key": "value"}))
        loaded = self.reports.get_report(record.id)
        self.assertEqual(loaded.data, {"key": "value"})
        self.assertEqual(self.reports.count_reports(), 1)
        self.reports.delete_report(record.id)
        self.assertEqual(self.reports.count_reports(), 0)

    def test_settings_upsert(self):
        self.settings.set("k1", "v1", updated_by="admin")
        self.settings.set("k1", "v2", updated_by="admin")
        self.assertEqual(self.settings.get("k1"), "v2")
        self.assertTrue(self.settings.get_bool("k1", False) is False)  # 'v2' not truthy
        self.settings.set("flag", "true")
        self.assertTrue(self.settings.get_bool("flag"))
        self.assertEqual(self.settings.get_int("missing", 42), 42)


if __name__ == "__main__":
    unittest.main()
