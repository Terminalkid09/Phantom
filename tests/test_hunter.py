"""Tests: behavioural vulnerability hunter (stealth scan + bug-class
probes + NVD version-lag with TTL cache)."""
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from phantom.core.session import session
from phantom.automation.exploit.hunter import VersionLag


def _reset():
    session.target = "10.0.0.1"
    session.scope = []
    session.results = {}
    session.notes = []
    session.history = []
    session.mode = "recon"
    session.knowledge_base["os_info"] = {}
    session.knowledge_base["target_type"] = None
    session.knowledge_base["aggressive"] = False
    from phantom.automation.exploit.resolver import get_resolver
    from phantom.automation.exploit.hunter import get_lag
    get_resolver().clear()
    get_lag().clear()


class TestVersionLag(unittest.TestCase):

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.cache_path = os.path.join(self.dir, "lag.json")
        _reset()

    def tearDown(self):
        try:
            os.remove(self.cache_path)
        except OSError:
            pass

    def _lag(self):
        return VersionLag(cache_path=self.cache_path)

    def _cpe_payload(self, versions):
        products = []
        for v in versions:
            products.append({"cpe": {
                "cpe23Uri": f"cpe:2.3:a:apache:http_server:{v}",
                "versionStartIncluding": v,
            }})
        return json.dumps({"products": products}).encode()

    def test_fetch_latest_takes_max_version(self):
        class _Resp:
            def __init__(self, data):
                self._data = data

            def read(self):
                return self._data

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        resp = _Resp(self._cpe_payload(["2.4.6", "2.4.49", "2.4.58"]))
        with patch("urllib.request.urlopen", return_value=resp):
            self.assertEqual(self._lag().latest("apache"), "2.4.58")

    def test_unknown_product_skips_lag(self):
        self.assertEqual(self._lag().latest("totally_unknown"), "")

    def test_version_lag_major(self):
        with patch.object(VersionLag, "_fetch_latest",
                          lambda self, p: "2.4.58"):
            lag = self._lag().version_lag("apache", "2.4.49")
        self.assertEqual(lag["latest"], "2.4.58")
        self.assertEqual(lag["lag_major"], 0)  # same major: still older

    def test_version_lag_reports_major_gap(self):
        with patch.object(VersionLag, "_fetch_latest",
                          lambda self, p: "3.2.1"):
            lag = self._lag().version_lag("apache", "2.4.49")
        self.assertEqual(lag["lag_major"], 1)

    def test_no_lag_when_current_is_latest(self):
        with patch.object(VersionLag, "_fetch_latest",
                          lambda self, p: "2.4.49"):
            self.assertIsNone(self._lag().version_lag("apache", "2.4.49"))

    def test_network_failure_is_silent(self):
        with patch.object(VersionLag, "_fetch_latest",
                          side_effect=OSError("offline")):
            self.assertEqual(self._lag().latest("apache"), "")

    def test_cache_prevents_repeat_fetch(self):
        calls = []

        def fake_fetch(self, product):
            calls.append(product)
            return "2.4.58"
        with patch.object(VersionLag, "_fetch_latest", fake_fetch):
            lag = self._lag()
            lag.latest("apache")
            lag.latest("apache")
        self.assertEqual(len(calls), 1)


class TestHuntGroups(unittest.TestCase):

    def setUp(self):
        _reset()

    def test_behavioural_hunt_merged_into_exploit(self):
        from phantom.modules import suggest
        session.add_result("scan", {
            "cmd": "80/tcp open  http  Apache httpd 2.4.49\n",
        })
        groups = suggest.exploit_suggestion_group()
        assert "SUGGESTED (hunt:traversal:80)" in groups
        assert "SUGGESTED (hunt:sqli:80)" in groups

    def test_version_lag_row_emitted_for_old_product(self):
        from phantom.modules import suggest
        from phantom.automation.exploit.hunter import get_lag
        get_lag().clear()
        session.add_result("scan", {
            "cmd": "443/tcp open  ssl/http  nginx 1.18.0\n",
        })
        with patch.object(VersionLag, "_fetch_latest",
                          lambda self, p: "1.28.0"):
            groups = suggest.exploit_suggestion_group()
        assert "SUGGESTED (hunt:version-lag:nginx)" in groups
        note = groups["SUGGESTED (hunt:version-lag:nginx)"][0]
        assert "1.28.0" in note
        assert "behind latest" in note
        assert "nginx 1.18.0" in note  # product not duplicated

    def test_no_version_lag_row_when_current(self):
        from phantom.modules import suggest
        session.add_result("scan", {
            "cmd": "443/tcp open  ssl/http  nginx 1.18.0\n",
        })
        with patch.object(VersionLag, "_fetch_latest",
                          lambda self, p: "1.18.0"):
            groups = suggest.exploit_suggestion_group()
        assert not any("version-lag" in k for k in groups)

    def test_misconfig_one_request_each(self):
        from phantom.automation.exploit.hunter import (
            misconfig_suggestion_group)
        session.add_result("scan", {
            "cmd": "6379/tcp open  redis\n",
        })
        groups = misconfig_suggestion_group()
        cmds = groups["SUGGESTED (hunt:no-auth:redis)"]
        assert len(cmds) == 1
        assert "info" in cmds[0]


if __name__ == "__main__":
    unittest.main()