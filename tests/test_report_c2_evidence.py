"""Manual report must carry live C2 evidence and artifacts.

Live defect 2026-10-20: `use report` after a beacon session produced a report
with no beacon, no task output and no camera/screenshot artifact because the
manual generator read only `session.results`. These tests pin the collector
and the two renderings (operator gallery, client-safe hashes).
"""
import base64
import os
import tempfile
import unittest
from unittest import mock

from phantom.core.session import session
from phantom.modules import report as R

# 1x1 transparent PNG
_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8"
    "z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")


class _FakeC2:
    def __init__(self, beacon_id, artifact_path):
        self.beacon_id = beacon_id
        self.artifact_path = artifact_path

    def get_beacons(self):
        return {self.beacon_id: {
            "ip": "10.0.0.5", "hostname": "victim-pc",
            "os": "Windows 11", "user": "victim", "arch": "x64",
            "local_ips": "10.0.0.5", "last_seen": "2026-10-20T12:00:00",
        }}

    def get_results(self, beacon_id):
        assert beacon_id == self.beacon_id
        return [{
            "task_id": "20261020120000-deadbeef",
            "command": "screenshot",
            "output": f"[Screenshot captured — saved to {self.artifact_path}]",
            "time": "2026-10-20T12:00:01",
        }, {
            "task_id": "20261020120002-cafebabe",
            "command": "gps",
            "output": "GPS: lat=45.4642 lon=9.1900 accuracy=12m",
            "time": "2026-10-20T12:00:03",
        }]


class TestManualReportC2Evidence(unittest.TestCase):
    def setUp(self):
        self._target = session.target
        session.target = "10.0.0.5"
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "shot.png")
        with open(self.path, "wb") as fh:
            fh.write(_PNG)
        self.c2 = _FakeC2("B-TEST", self.path)
        self.patcher = mock.patch(
            "phantom.core.c2_server.c2_state", self.c2)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        session.target = self._target
        self.tmp.cleanup()

    def test_selected_by_target_and_hashed(self):
        ev = R._c2_evidence("10.0.0.5")
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["beacon_id"], "B-TEST")
        art = ev[0]["tasks"][0]["artifact"]
        self.assertTrue(art["exists"])
        self.assertEqual(art["size"], len(_PNG))
        self.assertEqual(len(art["sha256"]), 64)

    def test_operator_markdown_has_tasks_and_paths(self):
        md = "\n".join(R._c2_markdown())
        self.assertIn("C2 Beacon Evidence", md)
        self.assertIn("20261020120000-deadbeef", md)
        self.assertIn(self.path, md)
        self.assertIn("SHA-256", md)

    def test_operator_html_embeds_the_image(self):
        html = R._c2_section_html(embed_images=True)
        self.assertIn("C2 Beacon Evidence", html)
        self.assertIn("data:image/png;base64,", html)
        self.assertIn("<img", html)

    def test_client_summary_has_no_raw_command_output(self):
        md = "\n".join(R._c2_client_markdown())
        self.assertIn("C2 Beacon Session", md)
        self.assertIn("shot.png", md)
        self.assertIn("SHA-256", md)
        self.assertIn("GPS", md)
        self.assertNotIn("screenshot", md)  # commands stay operator-side

    def test_raw_html_is_self_contained(self):
        html = R._raw_html("# operator\n\nC2 Beacon Evidence")
        self.assertIn("data:image/png;base64,", html)
        self.assertIn("Phantom Operator Report", html)


if __name__ == "__main__":
    unittest.main()
