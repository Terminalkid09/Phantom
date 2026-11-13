"""The dead drop is the beacon's last-resort endpoint source.

Two things must hold: the record round-trips (and refuses anything that is
not one), and the FORMAT is identical on both sides — the Python codec and
the beacon's ``network.h`` cannot drift, or the beacon silently never
rotates. The C++ side is pinned by reading its constants here.
"""
import http.server
import os
import re
import tempfile
import threading
import unittest

from phantom.utils import dead_drop

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_NETWORK_H = os.path.join(_ROOT, "phantom", "payloads", "beacon", "src",
                          "network.h")


class TestRecordCodec(unittest.TestCase):
    def test_round_trip_https(self):
        rec = dead_drop.encode_record("c2.example.net", 8443, True)
        self.assertEqual(dead_drop.decode_record(rec),
                         {"host": "c2.example.net", "port": 8443,
                          "use_ssl": True})

    def test_round_trip_http(self):
        rec = dead_drop.encode_record("10.0.0.5", 8080, False)
        self.assertFalse(dead_drop.decode_record(rec)["use_ssl"])

    def test_whitespace_around_the_payload_is_tolerated(self):
        rec = dead_drop.encode_record("h", 443, True)
        self.assertIsNotNone(dead_drop.decode_record(f"\n  {rec}\n"))

    def test_garbage_is_refused(self):
        for bad in ("", "not base64 !!", "AAAA", None):
            self.assertIsNone(dead_drop.decode_record(bad), bad)

    def test_a_wrong_name_is_refused(self):
        import base64

        wrong = base64.b64encode(
            bytes(b ^ dead_drop.DD_KEY for b in b"xx|h|443|1")).decode()
        self.assertIsNone(dead_drop.decode_record(wrong))

    def test_a_bad_port_is_refused(self):
        import base64

        for port in ("0", "99999", "abc"):
            rec = base64.b64encode(bytes(
                b ^ dead_drop.DD_KEY for b in f"phx1|h|{port}|1".encode()
            )).decode()
            self.assertIsNone(dead_drop.decode_record(rec), port)

    def test_an_empty_host_is_refused(self):
        with self.assertRaises(ValueError):
            dead_drop.encode_record("", 443)


class TestFileTarget(unittest.TestCase):
    def test_publish_then_fetch(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "sub", "dd.txt")
            self.assertTrue(dead_drop.publish(path, "c2.example", 443, True))
            self.assertEqual(dead_drop.fetch(path),
                             {"host": "c2.example", "port": 443,
                              "use_ssl": True})

    def test_fetch_missing_file_is_none(self):
        self.assertIsNone(dead_drop.fetch("/nonexistent/nope"))


class _PutHandler(http.server.BaseHTTPRequestHandler):
    body = b""

    def do_PUT(self):  # noqa: N802 (http.server API)
        _PutHandler.body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(200)
        self.end_headers()

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(_PutHandler.body)

    def log_message(self, *args):  # silence
        return


class TestHttpTarget(unittest.TestCase):
    def setUp(self):
        self.server = http.server.HTTPServer(("127.0.0.1", 0), _PutHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_publish_then_fetch_over_http(self):
        url = f"http://127.0.0.1:{self.port}/dd"
        self.assertTrue(dead_drop.publish(url, "c2.example", 8443, True))
        self.assertEqual(dead_drop.fetch(url),
                         {"host": "c2.example", "port": 8443, "use_ssl": True})

    def test_publish_to_a_dead_server_is_false(self):
        # nothing listening on this port pid: publish must REPORT failure,
        # never pretend the fallback is live
        self.assertFalse(dead_drop.publish(
            "http://127.0.0.1:1/dd", "h", 1, timeout=1.0))


class TestCppFormatContract(unittest.TestCase):
    """The beacon must implement the SAME record format as this module."""

    @classmethod
    def setUpClass(cls):
        with open(_NETWORK_H, encoding="utf-8") as fh:
            cls.src = fh.read()

    def test_the_xor_key_matches(self):
        m = re.search(r"#define\s+C2_DEADDROP_KEY\s+0x([0-9A-Fa-f]+)",
                      self.src)
        self.assertIsNotNone(m, "network.h must define C2_DEADDROP_KEY")
        self.assertEqual(int(m.group(1), 16), dead_drop.DD_KEY)

    def test_the_record_name_matches(self):
        # the prefix the C++ decoder checks
        self.assertIn(f'"{dead_drop._NAME}|"', self.src)

    def test_the_beacon_has_the_last_ring_hook(self):
        self.assertIn("refresh_from_dead_drop", self.src)
        self.assertIn("bool refresh_from_dead_drop(C2Config& cfg)", self.src)


if __name__ == "__main__":
    unittest.main()
