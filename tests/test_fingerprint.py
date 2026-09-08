"""Tests for the protocol-specific fingerprint engine."""
import unittest
from phantom.automation.fingerprint.probes import (
    FingerprintEngine,
    FingerprintResult,
    fingerprint_service,
    fingerprint_all,
    PROBE_MAP,
    PORT_SERVICE_MAP,
)


class TestFingerprintResult(unittest.TestCase):
    """Unit tests for FingerprintResult dataclass."""

    def test_default_values(self):
        r = FingerprintResult(host="127.0.0.1", port=22, protocol="tcp", service="ssh")
        self.assertEqual(r.host, "127.0.0.1")
        self.assertEqual(r.port, 22)
        self.assertEqual(r.service, "ssh")
        self.assertEqual(r.product, "")
        self.assertEqual(r.version, "")
        self.assertDictEqual(r.extra, {})

    def test_ok_false_by_default(self):
        r = FingerprintResult(host="127.0.0.1", port=22, protocol="tcp", service="ssh")
        self.assertFalse(r.ok)

    def test_ok_with_product(self):
        r = FingerprintResult(host="127.0.0.1", port=22, protocol="tcp", service="ssh",
                              product="OpenSSH", version="8.9")
        self.assertTrue(r.ok)

    def test_ok_with_raw_banner(self):
        r = FingerprintResult(host="127.0.0.1", port=22, protocol="tcp", service="ssh",
                              raw_banner="SSH-2.0-OpenSSH_8.9")
        self.assertTrue(r.ok)

    def test_ok_with_extra(self):
        r = FingerprintResult(host="127.0.0.1", port=22, protocol="tcp", service="ssh",
                              extra={"key": "val"})
        self.assertTrue(r.ok)

    def test_to_dict(self):
        r = FingerprintResult(host="10.0.0.1", port=3306, protocol="tcp",
                              service="mysql", product="MySQL", version="8.0",
                              extra={"auth": "native"}, raw_banner="8.0.35",
                              error="", took_ms=12.3)
        d = r.to_dict()
        self.assertEqual(d["host"], "10.0.0.1")
        self.assertEqual(d["port"], 3306)
        self.assertEqual(d["service"], "mysql")
        self.assertEqual(d["product"], "MySQL")
        self.assertEqual(d["version"], "8.0")
        self.assertEqual(d["extra"], {"auth": "native"})
        self.assertEqual(d["took_ms"], 12.3)

    def test_error_result_not_ok(self):
        r = FingerprintResult(host="10.0.0.1", port=22, protocol="tcp", service="ssh",
                              error="connection refused")
        self.assertFalse(r.ok)


class TestProbeMap(unittest.TestCase):
    """Verify all expected probes are registered."""

    def test_all_17_protocols_registered(self):
        expected = {
            "ssh", "smb", "mysql", "mssql", "postgresql",
            "redis", "mongodb", "rdp", "ftp", "smtp",
            "snmp", "ldap", "docker", "kubernetes", "dns",
            "http", "https",
        }
        self.assertEqual(set(PROBE_MAP.keys()), expected)

    def test_port_service_map_completeness(self):
        """Every port in PORT_SERVICE_MAP maps to a known probe or is intentionally unprobed."""
        probed = set(PROBE_MAP.keys())
        for port, svc in PORT_SERVICE_MAP.items():
            if svc in probed:
                # This is correct — service can be mapped from port and has a probe
                pass
            else:
                # Service exists only as port mapping, no probe (e.g., oracle, rpc)
                self.assertIn(svc, ["https", "rpc", "netbios", "ldaps", "oracle", "winrm", "docker-tls"])


class TestFingerprintEngine(unittest.TestCase):
    """Test the engine's non-network logic."""

    def setUp(self):
        self.engine = FingerprintEngine(timeout=1.0)

    def test_raw_probe_connection_refused(self):
        """Raw probe against a closed port returns error."""
        result = self.engine._raw_probe("127.0.0.1", 65432)
        self.assertIsInstance(result, FingerprintResult)
        self.assertIn("connection refused", result.error or "")
        self.assertFalse(result.ok)

    def test_probe_unknown_service(self):
        """Probing an unmapped port falls back to raw probe."""
        result = self.engine.probe("127.0.0.1", 65432)
        # Either None (can't connect) or a result with error
        if result is not None:
            self.assertFalse(result.ok or result.error == "")

    def test_probe_by_service_name(self):
        """Explicit service name lookup works."""
        result = self.engine.probe("127.0.0.1", 22, service="ssh")
        if result is not None:
            self.assertIn(result.service, ("ssh", "unknown"))  # may fall back to raw

    def test_probe_all_accumulates(self):
        """probe_all adds results to the engine."""
        self.engine.probe_all("127.0.0.1", [22, 80, 443, 65432])
        # Results may be empty if all ports are closed, but no error should occur
        self.assertIsInstance(self.engine.results, list)

    def test_to_worldmodel_empty(self):
        """Feeding empty results to WorldModel is safe."""
        from phantom.automation.belief import WorldModel
        wm = WorldModel("10.0.0.1")
        count = self.engine.to_worldmodel(wm, "10.0.0.1")
        self.assertEqual(count, 0)
        self.assertFalse(wm.has_any("fingerprint"))

    def test_to_worldmodel_adds_services(self):
        """Results with host+port+product are added to WorldModel."""
        from phantom.automation.belief import WorldModel
        engine = FingerprintEngine()
        engine.results = [
            FingerprintResult(host="10.0.0.1", port=22, protocol="tcp",
                              service="ssh", product="OpenSSH", version="8.9"),
            FingerprintResult(host="10.0.0.1", port=3306, protocol="tcp",
                              service="mysql", product="MySQL", version="8.0"),
            FingerprintResult(host="10.0.0.1", port=9999, protocol="tcp",
                              service="unknown", error="refused"),
        ]
        wm = WorldModel("10.0.0.1")
        count = engine.to_worldmodel(wm, "10.0.0.1")
        self.assertEqual(count, 2)
        self.assertTrue(wm.has_any("fingerprint"))

    def test_fingerprint_all_helper(self):
        """fingerprint_all handles empty port list."""
        results = fingerprint_all("127.0.0.1", [])
        self.assertIsInstance(results, list)

    def test_fingerprint_service_helper(self):
        """fingerprint_service returns None for closed port."""
        result = fingerprint_service("127.0.0.1", 65432, timeout=0.5)
        self.assertIsNone(result)


class TestHttpProbe(unittest.TestCase):
    """Pure-Python HTTP probe parses Server/title/CMS without curl."""

    def test_http_probe_fingerprints_server_and_title(self):
        import socket as _socket
        import threading

        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: Apache-Coyote/1.1\r\n"
            b"Content-Type: text/html\r\n\r\n"
            b"<html><head><title>Altoro Mutual</title></head>"
            b"<body>Welcome to the demo bank</body></html>"
        )
        server = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        server.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def serve():
            conn, _ = server.accept()
            conn.recv(4096)
            conn.sendall(response)
            conn.close()

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            from phantom.automation.fingerprint.probes import _probe_http
            result = _probe_http("127.0.0.1", port, timeout=3.0)
            self.assertEqual(result.product, "Apache-Coyote/1.1")
            self.assertEqual(result.extra.get("status"), "200")
            self.assertEqual(result.extra.get("title"), "Altoro Mutual")
            self.assertEqual(result.extra.get("cms"), "apache")
        finally:
            server.close()

    def test_http_probe_empty_response_sets_error(self):
        import socket
        import threading

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def serve():
            conn, _ = server.accept()
            conn.recv(4096)
            conn.close()  # no response

        threading.Thread(target=serve, daemon=True).start()
        try:
            from phantom.automation.fingerprint.probes import _probe_http
            result = _probe_http("127.0.0.1", port, timeout=3.0)
            self.assertFalse(result.ok)
            self.assertTrue(result.error)
        finally:
            server.close()


if __name__ == "__main__":
    unittest.main()