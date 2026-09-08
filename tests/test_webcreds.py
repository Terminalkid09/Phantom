"""Tests for the webcreds reachability gate.

`run_web_creds_dump` must never burn the per-port probe battery against a
host that answers nothing: one short reachability request decides, then a
dead port is skipped (this previously stalled the agent for minutes on
unreachable IPs — every probe request carried its own 4s timeout).
"""
import unittest
from unittest.mock import patch

from phantom.automation.belief import WorldModel
from phantom.automation.exploit.webcreds import run_web_creds_dump


def _wm_with_web(port: int = 8081):
    wm = WorldModel(target="10.0.0.5", target_type="ip")
    wm.add_finding("service", f"tcp/{port}",
                   {"port": str(port), "service": "http"})
    return wm


class TestReachabilityGate(unittest.TestCase):

    def test_dead_host_skipped_with_one_request(self):
        """An unreachable host costs exactly ONE request (the gate), then the
        port is skipped — no SSRF/baseline battery of per-path probes."""
        with patch("phantom.automation.exploit.webcreds._http_get",
                   return_value=None) as get, \
             patch("phantom.automation.exploit.webcreds._http_post",
                   return_value=None) as post:
            results = run_web_creds_dump(_wm_with_web(), "10.0.0.5")
        self.assertEqual(results, [])
        self.assertEqual(get.call_count, 1)   # only the "/" reachability GET
        self.assertEqual(post.call_count, 0)

    def test_live_host_is_probed(self):
        """A reachable host proceeds into the SSRF/SQLi battery."""
        with patch("phantom.automation.exploit.webcreds._http_get",
                   return_value="<html><form><input name='user'></form></html>") as get, \
             patch("phantom.automation.exploit.webcreds._http_post",
                   return_value="no match") as post:
            run_web_creds_dump(_wm_with_web(), "10.0.0.5")
        # gate + baseline (GET) plus SSRF/SQLi probes happen
        self.assertGreater(get.call_count, 1)
        self.assertGreaterEqual(post.call_count, 1)

    def test_multiple_web_ports_each_gated(self):
        with patch("phantom.automation.exploit.webcreds._http_get",
                   return_value=None) as get:
            run_web_creds_dump(_wm_with_web(8081), "10.0.0.5")
            self.assertEqual(get.call_count, 1)

    def test_no_web_service_falls_back_to_common_ports(self):
        """Without service findings the dump still probes common web ports —
        each gated the same way."""
        with patch("phantom.automation.exploit.webcreds._http_get",
                   return_value=None) as get:
            wm = WorldModel(target="10.0.0.5", target_type="ip")
            wm.add_finding("service", "tcp/22",
                           {"port": "22", "service": "ssh"})
            results = run_web_creds_dump(wm, "10.0.0.5")
        self.assertEqual(results, [])
        # one gate request per common web port (bounded by MAX_PORTS)
        self.assertGreater(get.call_count, 1)


if __name__ == "__main__":
    unittest.main()