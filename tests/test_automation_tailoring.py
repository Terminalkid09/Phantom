"""Tests for per-target tailoring of the kill chain (B2)."""
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.guidance.commands import make_registry
from phantom.automation.guidance.stealth import StealthEngine, StealthConfig
from phantom.automation.guidance.tailoring import TailoringEngine
from phantom.automation.planner import Planner, GOAL_FACTS


class TestTailoringEngine(unittest.TestCase):

    def test_network_target_defaults(self):
        eng = TailoringEngine.for_target("10.0.0.5", "ip")
        self.assertEqual(eng.chain_label, "network")
        self.assertIn("bt_scan", eng.banned)
        # web_creds is preferred over ssh_login on network targets: it
        # extracts creds via SSRF/SQLi without the brute-force fingerprint.
        self.assertEqual(eng.source_order("creds", ["ssh_login", "breach_check"]),
                         ["web_creds", "ssh_login", "breach_check"])

    def test_identity_target_reorders_creds(self):
        eng = TailoringEngine.for_target("bob@corp.example", "email")
        self.assertEqual(eng.chain_label, "identity")
        order = eng.source_order("creds", ["ssh_login", "breach_check"])
        self.assertEqual(order, ["breach_check", "ssh_login"])

    def test_banned_filtered_from_order(self):
        eng = TailoringEngine.for_target("10.0.0.5", "ip")
        order = eng.source_order("bt_device", ["bt_scan", "other"])
        self.assertNotIn("bt_scan", order)
        self.assertIn("other", order)

    def test_unknown_fact_keeps_defaults(self):
        eng = TailoringEngine.for_target("mail.corp.example", "domain")
        self.assertEqual(eng.source_order("pivot", ["lateral_pivot", "smb_pivot"]),
                         ["lateral_pivot", "smb_pivot"])

    def test_classify_when_type_empty(self):
        eng = TailoringEngine.for_target("+39 333 111 2233")
        self.assertEqual(eng.chain_label, "identity")

    def test_suggest_exploit_from_service_finding(self):
        eng = TailoringEngine.for_target("10.0.0.5", "ip")
        wm = WorldModel(target="10.0.0.5")
        wm.add_finding("service", "apache@2.4.49",
                       {"software": "apache", "version": "2.4.49"})
        hint = eng.suggest_exploit(wm)
        self.assertIsNotNone(hint)
        self.assertEqual(hint["cve"], "CVE-2021-41773")
        self.assertEqual(hint["msf_module"],
                         "exploit/multi/http/apache_normalize_path_rce")

    def test_suggest_exploit_no_fingerprint(self):
        eng = TailoringEngine.for_target("10.0.0.5", "ip")
        self.assertIsNone(eng.suggest_exploit(WorldModel(target="10.0.0.5")))

    def test_suggest_exploit_unmatched_version(self):
        eng = TailoringEngine.for_target("10.0.0.5", "ip")
        wm = WorldModel(target="10.0.0.5")
        wm.add_finding("service", "apache@2.4.48",
                       {"software": "apache", "version": "2.4.48"})
        self.assertIsNone(eng.suggest_exploit(wm))


class TestPlannerTailoring(unittest.TestCase):

    def setUp(self):
        self.registry = make_registry()
        self.wm = WorldModel(target="10.0.0.5", target_type="ip")
        self.stealth = StealthEngine(self.wm, StealthConfig())

    def _planner(self, target, target_type=""):
        tailoring = TailoringEngine.for_target(target, target_type)
        return Planner(self.registry, self.stealth, tailoring=tailoring)

    def test_network_plan_never_uses_banned_capability(self):
        plan = self._planner("10.0.0.5", "ip").plan(self.wm, goal="harvest")
        ids = [s.capability.id for s in plan.steps]
        self.assertNotIn("bt_scan", ids)
        self.assertIn("cookie_stealer", ids)  # beacon-side harvest survives

    def test_identity_plan_uses_identity_chain(self):
        wm = WorldModel(target="bob@corp.example", target_type="email")
        planner = self._planner("bob@corp.example", "email")
        plan = planner.plan(wm, goal="beacon")
        ids = [s.capability.id for s in plan.steps]
        # identity chain: OSINT -> phish -> poll -> breach, never network scan
        self.assertIn("osint_identity", ids)
        self.assertIn("breach_check", ids)
        self.assertIn("poll_hits", ids)
        self.assertNotIn("scan_tcp", ids)
        self.assertNotIn("ssh_login", ids)

    def test_identity_creds_source_is_breach(self):
        wm = WorldModel(target="bob@corp.example", target_type="email")
        wm.add_finding("victim_ip", "v", {"ip": "10.0.0.5"})
        plan = self._planner("bob@corp.example", "email").plan(wm, goal="beacon")
        ids = [s.capability.id for s in plan.steps]
        # with the machine known, creds must still come from breach_check,
        # not from brute force against the unknown host
        self.assertIn("breach_check", ids)
        self.assertNotIn("ssh_login", ids)

    def test_plan_carries_exploit_hint(self):
        wm = WorldModel(target="10.0.0.5", target_type="ip")
        wm.add_finding("service", "apache@2.4.49",
                       {"software": "apache", "version": "2.4.49"})
        plan = self._planner("10.0.0.5", "ip").plan(wm, goal="beacon")
        self.assertIsNotNone(plan.exploit_hint)
        self.assertEqual(plan.exploit_hint["cve"], "CVE-2021-41773")

    def test_no_tailoring_means_no_hint_and_no_ban(self):
        planner = Planner(self.registry, self.stealth)  # no tailoring arg
        wm = WorldModel(target="10.0.0.5")
        wm.add_finding("service", "apache@2.4.49",
                       {"software": "apache", "version": "2.4.49"})
        plan = planner.plan(wm, goal="harvest")
        self.assertIsNone(plan.exploit_hint)
        self.assertIn("bt_scan", [s.capability.id for s in plan.steps])

    def test_unbanned_network_harvest_keeps_socks(self):
        plan = self._planner("10.0.0.5", "ip").plan(self.wm, goal="harvest")
        ids = [s.capability.id for s in plan.steps]
        self.assertIn("socks_proxy", ids)


if __name__ == "__main__":
    unittest.main()
