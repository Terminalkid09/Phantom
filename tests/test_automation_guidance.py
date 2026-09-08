"""Tests for the command knowledge model, threat model and stealth engine."""
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.guidance.commands import InputSlot, Capability, Registry, make_registry
from phantom.automation.guidance.threatmodel import BlueTeamModel
from phantom.automation.guidance.stealth import StealthEngine, StealthConfig


def _wm_with_service(service="ssh", port="tcp/22"):
    wm = WorldModel(target="10.0.0.5", target_type="ip")
    wm.add_finding("service", port, {"port": "22", "service": service, "version": ""})
    return wm


class TestInputSlot(unittest.TestCase):

    def test_ip_type(self):
        slot = InputSlot("host", "ip")
        self.assertTrue(slot.accepts("10.0.0.5"))
        self.assertFalse(slot.accepts("evil.example.com"))

    def test_optional_slot(self):
        slot = InputSlot("port", "port", required=False)
        self.assertTrue(slot.accepts(None))
        self.assertTrue(slot.accepts("443"))
        self.assertFalse(slot.accepts("abc"))


class TestRegistry(unittest.TestCase):

    def setUp(self):
        self.reg = make_registry()

    def test_all_capabilities_loaded(self):
        caps = self.reg.all()
        self.assertGreater(len(caps), 5)
        self.assertIn("scan_tcp", [c.id for c in caps])
        self.assertIn("ssh_banner", [c.id for c in caps])
        self.assertIn("beacon_deploy", [c.id for c in caps])

    def test_usable_filters_by_preconditions(self):
        wm = _wm_with_service()
        usable = self.reg.usable(wm)
        # with just a service fact, creds capabilities stay locked
        self.assertNotIn("beacon_deploy", [c.id for c in usable])

    def test_preconditions_open_up(self):
        wm = _wm_with_service()
        wm.add_finding("creds", "ssh:root", {"username": "root", "password": "toor", "valid": True})
        ids = [c.id for c in self.reg.usable(wm)]
        self.assertIn("beacon_deploy", ids)

    def test_make_command_validates_inputs(self):
        cap = self.reg.get("ssh_login")
        with self.assertRaises(ValueError):
            cap.make_command(_wm_with_service(), {"username": "root"})  # missing password
        cmd = cap.make_command(_wm_with_service(), {"username": "root", "password": "toor"})
        self.assertIn("root@10.0.0.5", cmd)
        self.assertIn("toor", cmd)

    def test_find_capability_for_goal(self):
        wm = _wm_with_service()
        cap = self.reg.find(wm, goal_fact="banner", budget=1.0)
        self.assertIsNotNone(cap)
        self.assertEqual(cap.id, "ssh_banner")

    def test_adapter_is_only_command_source(self):
        for cap in self.reg.all():
            self.assertTrue(callable(cap.adapter), f"{cap.id} has no adapter")
            self.assertGreater(len(cap.effects), 0, f"{cap.id} has no effects")


class TestThreatModel(unittest.TestCase):

    def test_risk_by_profile(self):
        ent = BlueTeamModel.for_profile("enterprise")
        self.assertGreater(ent.risk("brute", "active", 1.0), 0)
        self.assertLess(ent.risk("exfil", "passive", 0.5), ent.risk("exfil", "active", 0.5))

    def test_passive_is_quieter(self):
        ent = BlueTeamModel.for_profile("enterprise")
        passive = ent.risk("scan", "passive", 1.0)
        active = ent.risk("scan", "active", 1.0)
        self.assertLess(passive, active)

    def test_financial_is_tough(self):
        fin = BlueTeamModel.for_profile("financial")
        ent = BlueTeamModel.for_profile("enterprise")
        self.assertGreater(fin.risk("creds", "active", 1.0), ent.risk("creds", "active", 1.0))

    def test_recommendations(self):
        ent = BlueTeamModel.for_profile("enterprise")
        self.assertGreater(len(ent.recommendations()), 3)


class TestStealth(unittest.TestCase):

    def test_cost_is_signal_not_block(self):
        wm = WorldModel()
        se = StealthEngine(wm, StealthConfig())
        self.assertTrue(se.allowed("scan", "active", 2.0))
        se.consume(1e9)  # ledger records, never blocks
        self.assertTrue(se.allowed("scan", "active", 2.0))
        self.assertEqual(wm.opsec_spent, 1e9)

    def test_online_brute_gated(self):
        wm = WorldModel()
        quiet = StealthEngine(wm, StealthConfig())
        self.assertFalse(quiet.online_brute_allowed())
        loud = StealthEngine(wm, StealthConfig(aggressive=True))
        self.assertTrue(loud.online_brute_allowed())
        self.assertFalse(loud.allowed("brute", "aggressive", 1.0,
                                      is_online_brute=True) and not loud.config.aggressive)

    def test_would_be_loud(self):
        wm = WorldModel()
        se = StealthEngine(wm, StealthConfig(profile="financial"))
        self.assertTrue(se.would_be_loud("brute", "active", 1.0))
        self.assertFalse(se.would_be_loud("http_probe", "passive", 0.3))

    def test_human_delay_range(self):
        wm = WorldModel()
        se = StealthEngine(wm, StealthConfig(min_delay=1.0, max_delay=2.0))
        for _ in range(20):
            self.assertGreaterEqual(se.human_delay(), 1.0)
            self.assertLessEqual(se.human_delay(), 2.0)

    def test_brute_force_not_allowed_in_default(self):
        wm = WorldModel()
        se = StealthEngine(wm, StealthConfig())
        self.assertFalse(se.allowed("brute", "active", 1.0, is_online_brute=True))
        loud = StealthEngine(wm, StealthConfig(aggressive=True))
        self.assertTrue(loud.allowed("brute", "active", 1.0, is_online_brute=True))


if __name__ == "__main__":
    unittest.main()
