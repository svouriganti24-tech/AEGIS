"""Tests for the port scanner engine and input validation."""

from __future__ import annotations

import socket
import threading
import unittest

from core.constants import PortState
from core.exceptions import InvalidPortSpecError, InvalidTargetError, ScanTargetUnresolvableError
from core.validators import parse_port_spec, validate_target
from security.scanner.models import ScanTarget
from security.scanner.port_scanner import PortScanner


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    return port, sock  # caller keeps the socket open


class PortSpecTests(unittest.TestCase):
    def test_single_port(self):
        self.assertEqual(parse_port_spec("80"), [80])

    def test_comma_list(self):
        self.assertEqual(parse_port_spec("443,80,8080"), [80, 443, 8080])

    def test_range(self):
        self.assertEqual(parse_port_spec("10-13"), [10, 11, 12, 13])

    def test_mixed(self):
        self.assertEqual(parse_port_spec("22, 80, 6000-6002"), [22, 80, 6000, 6001, 6002])

    def test_preset(self):
        ports = parse_port_spec("Web services")
        self.assertIn(443, ports)
        self.assertNotIn(22, ports)

    def test_all_keyword(self):
        self.assertEqual(len(parse_port_spec("all")), 65535)

    def test_out_of_range_rejected(self):
        with self.assertRaises(InvalidPortSpecError):
            parse_port_spec("70000")

    def test_garbage_rejected(self):
        with self.assertRaises(InvalidPortSpecError):
            parse_port_spec("http")

    def test_over_limit_rejected(self):
        with self.assertRaises(InvalidPortSpecError):
            parse_port_spec("1-65535", max_ports=1024)


class TargetValidationTests(unittest.TestCase):
    def test_ipv4(self):
        self.assertEqual(validate_target("192.168.1.10"), "192.168.1.10")

    def test_ipv6(self):
        self.assertEqual(validate_target("::1"), "::1")

    def test_localhost(self):
        self.assertEqual(validate_target("localhost"), "localhost")

    def test_hostname(self):
        self.assertEqual(validate_target("scanme.example.org"), "scanme.example.org")

    def test_invalid_rejected(self):
        for bad in ("", "not a host!!", "-leading", "a" * 300, "under_score"):
            with self.assertRaises(InvalidTargetError):
                validate_target(bad)


class ScanModelTests(unittest.TestCase):
    def test_scan_target_sorts_and_dedupes(self):
        target = ScanTarget(host="127.0.0.1", ports=[443, 80, 80, 22])
        self.assertEqual(target.ports, [22, 80, 443])

    def test_statistics_counts_states(self):
        from security.scanner.models import PortProbeResult, ScanResult
        result = ScanResult(target="h")
        result.results = [
            PortProbeResult(port=1, state=PortState.OPEN),
            PortProbeResult(port=2, state=PortState.CLOSED),
            PortProbeResult(port=3, state=PortState.CLOSED),
            PortProbeResult(port=4, state=PortState.FILTERED),
        ]
        result.ports_scanned = 4
        stats = result.statistics()
        self.assertEqual(stats["open"], 1)
        self.assertEqual(stats["closed"], 2)
        self.assertEqual(stats["filtered"], 1)
        self.assertEqual(stats["ports_scanned"], 4)


class LiveScanTests(unittest.TestCase):
    """Scans against a real socket bound on localhost (fast + safe)."""

    def setUp(self):
        self.port, self.server_sock = _free_port()
        self.server_sock.listen(1)
        self.scanner = PortScanner(timeout=0.4, max_threads=8)

    def tearDown(self):
        try:
            self.server_sock.close()
        except OSError:
            pass

    def test_open_port_detected(self):
        result = self.scanner.scan(ScanTarget(host="127.0.0.1", ports=[self.port]))
        self.assertEqual(result.status.value, "COMPLETED")
        open_ports = [r.port for r in result.open_ports]
        self.assertIn(self.port, open_ports)

    def test_closed_port_detected(self):
        # Bind then close: the port is (almost certainly) refused afterwards.
        port, sock = _free_port()
        sock.close()
        result = self.scanner.scan_single_port("127.0.0.1", port)
        self.assertIn(result.state, (PortState.CLOSED, PortState.FILTERED))

    def test_progress_callback_fires(self):
        seen = []
        result = self.scanner.scan(
            ScanTarget(host="127.0.0.1", ports=[self.port, self.port + 1]),
            progress_callback=lambda done, total: seen.append((done, total)),
        )
        self.assertTrue(seen)
        self.assertEqual(seen[-1][1], 2)

    def test_cancel_event_stops_scan(self):
        import threading
        cancel = threading.Event()
        cancel.set()
        result = self.scanner.scan(
            ScanTarget(host="127.0.0.1", ports=[self.port] * 5), cancel_event=cancel)
        self.assertEqual(result.status.value, "CANCELLED")

    def test_unresolvable_host_raises(self):
        with self.assertRaises(ScanTargetUnresolvableError):
            self.scanner.scan(ScanTarget(host="no-such-host.invalid", ports=[80]))

    def test_result_dict_serialisable(self):
        result = self.scanner.scan(ScanTarget(host="127.0.0.1", ports=[self.port]))
        import json
        payload = json.dumps(result.to_dict())
        self.assertIn('"OPEN"', payload)


if __name__ == "__main__":
    unittest.main()
