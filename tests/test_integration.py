"""End-to-end integration test: wiring → auth → scan → detection → alert → report."""

from __future__ import annotations

import socket
import time
import unittest

from core.constants import ScanStatus, Severity
from tests.helpers import make_runtime


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.registry, self.tmp = make_runtime()
        self.registry.event_processor.start()
        self.admin = self.registry.auth.login("admin", "Admin@123")
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(1)
        self.open_port = self.srv.getsockname()[1]

    def tearDown(self):
        try:
            self.srv.close()
        except OSError:
            pass
        self.registry.shutdown()

    def _wait_for_scan(self, scan_id: int, timeout: float = 30.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            record = self.registry.scans.get_scan(scan_id)
            if record.status != ScanStatus.RUNNING.value:
                return record
            time.sleep(0.2)
        self.fail("scan did not finish in time")

    def test_full_pipeline(self):
        # ---- 1. password analysis through the service (RBAC pass)
        result = self.registry.password.analyze(self.admin, "correct-horse-turbine-42!")
        self.assertGreaterEqual(result["score"], 60)
        weak = self.registry.password.analyze(self.admin, "123456")
        self.assertTrue(weak["is_common"])

        # ---- 2. scan a live localhost port through the service
        scan_id = self.registry.scan.start_scan(self.admin, "127.0.0.1", str(self.open_port))
        record = self._wait_for_scan(scan_id)
        self.assertEqual(record.status, ScanStatus.COMPLETED.value)
        self.assertEqual(record.open_ports, 1)
        ports = self.registry.scans.get_ports(scan_id, only_open=True)
        self.assertEqual(ports[0].port, self.open_port)

        # ---- 3. authorization boundary: viewer may not scan
        viewer = self.registry.auth.core.register("int_viewer", "ViewerPass1!")
        with self.assertRaises(Exception):
            self.registry.scan.start_scan(viewer, "127.0.0.1", "80")

        # ---- 4. brute-force burst triggers an alert via the async pipeline
        for i in range(7):
            try:
                self.registry.auth.core.authenticate("int_viewer", f"wrong-{i}")
            except Exception:
                pass
        deadline = time.time() + 5
        while time.time() < deadline:
            if self.registry.alert_manager.open_count() >= 1:
                break
            time.sleep(0.1)
        open_alerts = self.registry.alert_manager.open_alerts(limit=10)
        self.assertTrue(open_alerts, "brute-force alert was not raised")
        self.assertTrue(any(a.title == "Brute-force authentication attempts" for a in open_alerts))

        # ---- 5. alert lifecycle through ThreatService (permission-checked)
        target = open_alerts[0]
        acked = self.registry.threat.acknowledge_alert(self.admin, target.id)
        self.assertEqual(acked.status, "ACKNOWLEDGED")
        resolved = self.registry.threat.resolve_alert(self.admin, target.id)
        self.assertEqual(resolved.status, "RESOLVED")

        # ---- 6. dashboard stats read from live backend data
        dash = self.registry.threat.dashboard_stats()
        self.assertGreaterEqual(dash["events_24h"], 1)
        scan_stats = self.registry.scan.stats()
        self.assertGreaterEqual(scan_stats["total"], 1)

        # ---- 7. report generation (HTML + TXT + JSON) and re-render from snapshot
        html_report = self.registry.report.generate(
            self.admin, "Integration Report", period_days=7, content_format="HTML")
        self.assertTrue(html_report.file_path.endswith(".html"))
        record, content = self.registry.report.get_report_content(self.admin, html_report.id)
        self.assertTrue(content.startswith("<!DOCTYPE html>"))
        self.assertIn("Integration Report", content)

        txt_report = self.registry.report.generate(
            self.admin, "Scan Focused", report_type="SCAN_REPORT", scan_id=scan_id,
            content_format="TXT")
        _, txt_content = self.registry.report.get_report_content(self.admin, txt_report.id)
        self.assertIn("127.0.0.1", txt_content)
        self.assertIn("RECOMMENDATIONS", txt_content)

        json_report = self.registry.report.generate(
            self.admin, "JSON Export", period_days=7, content_format="JSON")
        import json
        _, json_content = self.registry.report.get_report_content(self.admin, json_report.id)
        payload = json.loads(json_content)
        self.assertEqual(payload["title"], "JSON Export")
        self.assertTrue(payload["recommendations"])

        # ---- 8. events persisted with correct taxonomy
        page = self.registry.threat.events_page(self.admin, limit=200)
        types = {e.event_type for e in page.items}
        self.assertIn("PORT_SCAN", types)
        self.assertIn("AUTH_LOGIN_FAILURE", types)
        self.assertIn("PASSWORD_ANALYSIS", types)


if __name__ == "__main__":
    unittest.main()
