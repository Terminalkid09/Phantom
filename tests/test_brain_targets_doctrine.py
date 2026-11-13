"""Fase 1 gate tests: brain target ledger + doctrine.

The acceptance criterion we agreed on: the SAME planner, given three
different input classes (IP / username / domain), produces three
class-correct chain shapes — and mid-run discoveries only become
activatable pivots when provenance authorizes them.
"""
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.brain import doctrine
from phantom.automation.brain.targets import (
    CLASS_AD, CLASS_IDENTITY, CLASS_MOBILE, CLASS_NETWORK, CLASS_WEB,
    TargetLedger,
    classify,
)
from phantom.automation.guidance.commands import make_registry
from phantom.automation.guidance.stealth import StealthConfig, StealthEngine
from phantom.automation.planner import GOAL_FACTS, Planner


def _first_submitted(target: str):
    """Mirror the agent's real submission path: plan_strategic with the
    class-correct WorldModel, keep only steps whose preconditions hold on
    the empty world (the rest is deferred), order by _priority."""
    from phantom.automation.agent import AutonomousAgent
    from phantom.automation.runtime.toolchain import ToolRegistry
    from phantom.core.c2_server import c2_state
    c2_state.beacons.clear()
    tt = {CLASS_NETWORK: "ip", CLASS_WEB: "domain",
          CLASS_IDENTITY: "username"}[classify(target)]
    ag = AutonomousAgent(target, tt, "enterprise", False, False, False, False,
                         on_event=None,
                         toolchain=ToolRegistry(installed={"nmap", "curl", "nc"}))
    plan = ag.planner.plan_strategic(ag.wm, goal="complete_kill_chain",
                                     ledger=ag.ledger)
    submitted = []
    for step in reversed(plan.steps):
        try:
            if not all(p(ag.wm) for p in step.capability.preconditions):
                continue
        except Exception:
            pass
        submitted.append((step.capability.id, ag._priority(step),
                          step.capability.category))
    submitted.sort(key=lambda x: -x[1])
    return submitted


class TestClassification(unittest.TestCase):
    def test_deterministic_classes(self):
        cases = {
            "10.0.0.9": CLASS_NETWORK,
            "192.168.1.0/24": CLASS_NETWORK,
            "corp.com": CLASS_WEB,
            "https://corp.com/admin": CLASS_WEB,
            "bob@corp.com": CLASS_IDENTITY,
            # a phone is a DEVICE: CLASS_MOBILE, whose stages still start with
            # identity/OSINT but then branch on Android vs iOS delivery
            "+39 333 1234567": CLASS_MOBILE,
            "mario.rossi": CLASS_IDENTITY,   # no TLD -> NOT a domain
            "testfire.net": CLASS_WEB,
        }
        for value, expected in cases.items():
            self.assertEqual(classify(value), expected, value)

    def test_classification_is_stable(self):
        for value in ("10.0.0.9", "bob@corp.com", "corp.com", "mario.rossi"):
            self.assertEqual(classify(value), classify(value))


class TestDoctrine(unittest.TestCase):
    def test_identity_forbids_footprint(self):
        self.assertFalse(doctrine.allows("identity", "footprint"))
        self.assertTrue(doctrine.allows("identity", "social"))
        self.assertTrue(doctrine.allows("identity", "beacon"))

    def test_network_forbids_identity(self):
        self.assertFalse(doctrine.allows("network", "identity"))
        self.assertTrue(doctrine.allows("network", "footprint"))

    def test_person_is_readonly(self):
        self.assertFalse(doctrine.allows("person", "beacon"))
        self.assertFalse(doctrine.allows("person", "creds"))
        self.assertTrue(doctrine.allows("person", "identity"))

    def test_chain_shapes_differ_per_class(self):
        shapes = {c: doctrine.chain_preview(c) for c in
                  ("identity", "network", "cloud", "ad")}
        self.assertEqual(len(set(shapes.values())), 4)


class TestThreeChainGate(unittest.TestCase):
    """THE gate: same agent, three inputs, three class-correct chains."""

    def test_ip_starts_with_recon(self):
        submitted = _first_submitted("10.0.0.9")
        self.assertTrue(submitted, "IP target produced no submitable steps")
        top_id, _prio, category = submitted[0]
        self.assertIn(category, ("recon", "service"),
                      f"IP chain must open with recon, got {top_id}")

    def test_username_starts_with_osint_not_scan(self):
        submitted = _first_submitted("mario.rossi")
        self.assertTrue(submitted, "username target produced no steps")
        top_id, _prio, category = submitted[0]
        self.assertNotIn(top_id, ("scan_tcp", "version_detect", "os_detect"),
                         "a username must never open with a port scan")
        self.assertEqual(category, "osint")

    def test_domain_opens_web_surface_or_recon(self):
        submitted = _first_submitted("testfire.net")
        self.assertTrue(submitted, "domain target produced no steps")
        top_id, _prio, category = submitted[0]
        self.assertIn(category, ("recon", "osint", "service", "social"),
                      f"domain chain opened with unexpected {top_id}")

    def test_three_chains_are_distinct(self):
        ip_top = _first_submitted("10.0.0.9")[0][0]
        user_top = _first_submitted("mario.rossi")[0][0]
        self.assertNotEqual(ip_top, user_top)

    def test_ledger_records_correct_primary_class(self):
        for value, cls in (("10.0.0.9", CLASS_NETWORK),
                           ("mario.rossi", CLASS_IDENTITY),
                           ("testfire.net", CLASS_WEB)):
            led = TargetLedger(value)
            self.assertEqual(led.chain_class(), cls)


class TestLedgerScopeAndPivots(unittest.TestCase):
    def test_out_of_scope_discovery_is_not_activatable(self):
        led = TargetLedger("10.0.0.9", scope_list=["10.0.0.0/24"])
        e = led.register("172.20.0.5", source="discovered:pivot",
                         fact_kind="pivot", cls=CLASS_NETWORK,
                         origin="10.0.0.9")
        self.assertIsNone(e)                     # never even registered
        self.assertFalse(led.activatable("172.20.0.5"))

    def test_discovered_ad_inherits_scope_from_authorized_origin(self):
        led = TargetLedger("10.0.0.9", scope_list=["10.0.0.0/24"])

        class F:
            kind = "ad_domain"
            value = {"domain": "corp.local"}
            target = "10.0.0.9"
            key = "corp.local"

        new = led.reclassify_on_facts([F()])
        self.assertEqual([n.value for n in new], ["corp.local"])
        self.assertEqual(new[0].cls, CLASS_AD)
        self.assertTrue(led.activatable("corp.local"))
        self.assertEqual(led.initial.pivots, ["corp.local"])

    def test_identity_chain_harvests_in_scope_victim(self):
        led = TargetLedger("bob@corp.com", scope_list=["10.0.0.0/24"])

        class V:
            kind = "victim_ip"
            value = {"ip": "10.0.0.77"}
            target = "bob@corp.com"
            key = "10.0.0.77"

        new = led.reclassify_on_facts([V()])
        self.assertTrue(new and led.activatable("10.0.0.77"))

    def test_pivot_from_unauthorized_origin_is_blocked(self):
        led = TargetLedger("10.9.9.9", scope_list=["10.0.0.0/24"])

        class P:
            kind = "pivot"
            value = {"host": "172.20.0.5"}
            target = "10.9.9.9"
            key = "172.20.0.5"

        self.assertEqual(led.reclassify_on_facts([P()]), [])

    def test_identity_subjects_bypass_machine_scope(self):
        led = TargetLedger("bob@corp.com", scope_list=["0.0.0.0/0"])
        e = led.register("someone-else@web.com", source="discovered:osint",
                         fact_kind="identity", origin="bob@corp.com")
        self.assertIsNotNone(e)
        self.assertTrue(led.activatable("someone-else@web.com"))

    def test_register_is_idempotent_and_keeps_trail(self):
        led = TargetLedger("10.0.0.9", scope_list=["10.0.0.0/24"])
        a = led.register("corp.local", cls=CLASS_AD, origin="10.0.0.9",
                         source="discovered:ad_domain", inherit_scope=True)
        b = led.register("corp.local", cls=CLASS_AD, origin="10.0.0.9",
                         source="discovered:ad_domain", inherit_scope=True)
        self.assertIs(a, b)
        self.assertEqual(led.initial.pivots, ["corp.local"])

    def test_to_dict_roundtrip(self):
        led = TargetLedger("bob@corp.com", scope_list=["10.0.0.0/24"])
        d = led.to_dict()
        self.assertEqual(d["initial"], "bob@corp.com")
        self.assertTrue(any(t["class"] == CLASS_IDENTITY
                            for t in d["targets"]))


if __name__ == "__main__":
    unittest.main()
