"""AD chain WITHOUT a beacon: the domain can be enumerated and attacked
directly from the operator box when the scan sees an AD surface
(LDAP/Kerberos) — no beacon foothold required.

Covers the dual-channel AD execution (`cap.category == "ad"`): when no
beacon session exists the command runs operator-side through the runtime,
and the planner still builds beacon_deploy as a dependency only when the
AD surface is not directly reachable.
"""
import unittest

from tests.test_automation_post import TARGET, _fake_runner, _make_agent


class TestAdOperatorSideE2E(unittest.TestCase):
    """Goal 'ad' with the DC surface visible in the scan (port 389) and NO
    way to establish a beacon (no creds): ad_enum must run directly from the
    operator, never through a beacon."""

    def _ad_scan_runner(self):
        """nmap reports an AD surface (389 ldap) + a web port, so
        _has_ad_service() is satisfied by the scan alone."""
        base = _fake_runner()

        def runner(cmd, timeout=None):
            if "nmap" in cmd:
                from unittest.mock import Mock
                res = Mock()
                res.ok = True
                res.stdout = (
                    "80/tcp open http Apache httpd 2.4.49\n"
                    "389/tcp open ldap\n"
                    "88/tcp open kerberos-sec")
                res.stderr = ""
                return res
            return base(cmd)
        return runner

    def test_ad_enum_runs_operator_side_without_beacon(self):
        from phantom.automation.guidance.kit import _has_ad_service
        runner = self._ad_scan_runner()
        # no C2 simulator: a beacon can never be established (also no creds
        # to deploy one)
        agent = _make_agent(runner=runner,
                            cred_discoverer=lambda service: None,
                            tools={"nmap", "sshpass", "curl", "nc",
                                   "ldapsearch"})
        result = agent.run(goal="ad", max_iterations=25)

        actions = [a["capability"] for a in agent.wm.actions_taken]
        self.assertIn("ad_enum", actions)
        # the AD chain must NOT depend on a beacon here
        self.assertNotIn("beacon_deploy", actions)
        self.assertFalse(agent.wm.has_any("beacon"), "beacon must not exist")
        # domain facts produced operator-side
        ad_facts = [f for f in agent.wm.all_findings()
                    if f.kind == "ad_domain"]
        self.assertTrue(ad_facts, "no ad_domain finding")
        self.assertEqual(ad_facts[0].value.get("domain"), "corp.local")
        self.assertTrue(result["ad_domains"], result)

    def test_precondition_satisfied_by_scan_alone(self):
        """_has_ad_service() is True for a scan that saw LDAP/Kerberos."""
        from phantom.automation.guidance import kit
        from phantom.automation.belief import WorldModel
        wm = WorldModel(target=TARGET)
        wm.add_finding("service", "tcp/389",
                       {"port": "389", "service": "ldap"})
        self.assertTrue(kit._has_ad_service()(wm))

    def test_precondition_not_satisfied_without_ad_surface(self):
        """No AD ports, no domain, no beacon -> the operator-side AD chain
        stays deferred (must not run blindly)."""
        from phantom.automation.guidance import kit
        from phantom.automation.belief import WorldModel
        wm = WorldModel(target=TARGET)
        wm.add_finding("service", "tcp/80",
                       {"port": "80", "service": "http"})
        self.assertFalse(kit._has_ad_service()(wm))


class TestWebRceE2E(unittest.TestCase):
    """Goal 'deliver' with NO credentials anywhere: the web app has an
    arbitrary-file-upload -> RCE. The agent must skip credential hunting,
    confirm code execution (web_rce), deliver the beacon through the RCE
    (beacon_via_rce) and install persistence — all without a single pair.
    """

    def setUp(self):
        from tests.test_automation_post import _reset_c2
        _reset_c2()
        self.events = []

    def _ssti_app_hunt_runner(self):
        """Hermetic hunt runner: a tiny web app that reflects query values
        and evaluates `${7*7}` as 49 (template injection). Keeps the agent
        E2E offline — without it the anomaly engine would curl the fake
        target IP and burn minutes on connect timeouts."""
        from phantom.automation.exploit.anomaly import ProbeResult

        def runner(method, url, body="", timeout=5.0):
            if "${7*7}" in url:
                body_txt = "<h1>49</h1>"
            elif "?" in url:
                val = url.split("?", 1)[1].split("=", 1)[-1]
                body_txt = f"<h1>{val}</h1>"
            elif url.endswith("/"):
                body_txt = '<a href="/report?name=alice">report</a>'
            else:
                body_txt = "404 not found"
            status = 200 if body_txt != "404 not found" else 404
            return ProbeResult(status=status, size=len(body_txt),
                               elapsed=0.005, body=body_txt, headers={})
        return runner

    def _web_rce_runner(self):
        from tests.test_automation_post import _fake_runner
        from unittest.mock import Mock
        from phantom.core.c2_server import c2_state
        base = _fake_runner()
        _registered = [False]

        def runner(cmd, timeout=None):
            s = str(cmd)
            if "nmap" in s:
                res = Mock(); res.ok = True
                res.stdout = "8081/tcp open http Apache httpd 2.4.49"
                res.stderr = ""
                return res
            if "sshpass" in s and "scp" not in s and "nohup" not in s:
                # ssh brute always fails: no valid creds exist
                res = Mock(); res.ok = True
                res.stdout = "Permission denied"
                res.stderr = ""
                return res
            if "/upload" in s and "grep -o" in s:
                # the RCE probe: upload executed -> marker in the response
                import re
                m = re.search(r"(PHANTOM_RCE_\d+)", s)
                res = Mock(); res.ok = True
                res.stdout = f"{m.group(1)}:0" if m else ""
                res.stderr = ""
                return res
            if "/upload" in s and "PHANTOM_RCE_DELIVERED" in s:
                # beacon delivered through the RCE -> it checks in
                if not _registered[0]:
                    c2_state.update_beacon("beacon-rce",
                                           {"ip": "10.0.0.5", "os": "Linux 5.15"})
                    _registered[0] = True
                res = Mock(); res.ok = True
                res.stdout = "PHANTOM_RCE_DELIVERED"
                res.stderr = ""
                return res
            return base(cmd)
        return runner

    def test_deliver_via_web_rce_without_creds(self):
        from unittest.mock import patch
        from tests.test_automation_post import _c2_simulator, _make_agent
        import threading
        runner = self._web_rce_runner()
        # web_creds probes the fake target IP in-process with urllib; bound
        # its per-request/gobal budget tightly so the E2E stays fast even
        # when the agent briefly falls back to credential hunting.
        with patch("phantom.automation.exploit.webcreds.PER_REQUEST_TIMEOUT", 0.5), \
             patch("phantom.automation.exploit.webcreds.GLOBAL_BUDGET_SECONDS", 15.0):
            agent = _make_agent(runner=runner, events=self.events,
                                cred_discoverer=lambda service: None,
                                tools={"nmap", "curl", "sshpass", "nc"},
                                hunt_runner=self._ssti_app_hunt_runner())
            stop = threading.Event()
            sim = threading.Thread(target=_c2_simulator,
                                   args=(runner, stop), daemon=True)
            sim.start()
            try:
                result = agent.run(goal="deliver", max_iterations=40)
            finally:
                stop.set()
                sim.join(timeout=3)

        actions = [a["capability"] for a in agent.wm.actions_taken]
        self.assertIn("web_rce", actions)
        self.assertIn("beacon_via_rce", actions)
        footholds = [f for f in agent.wm.all_findings()
                     if f.kind == "rce_foothold"]
        self.assertTrue(footholds, "no rce_foothold finding")
        self.assertTrue(result["beacon_established"], result)


if __name__ == "__main__":
    unittest.main()