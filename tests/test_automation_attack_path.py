"""Tests for the BloodHound-style attack-path graph."""
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.attack_path import (
    AttackPathGraph,
    build_attack_path,
    pivot_plan,
)


def _wm(creds=None, privileged=False, domain="", peers=None):
    wm = WorldModel(target="10.0.0.5", target_type="ip")
    for user in (creds or []):
        wm.add_finding("creds", f"creds:{user}",
                       {"username": user, "password": "x", "valid": True},
                       confidence=0.8, source="offline_brute")
    if privileged:
        wm.add_finding("system_privilege", "escalated",
                       {"identity": "root"}, confidence=0.9)
    if domain:
        wm.add_finding("ad_hint", "domain", {"domain": domain},
                       confidence=0.7)
    return wm


class TestAttackPathGraph(unittest.TestCase):

    def test_nodes_and_typed_edges(self):
        wm = _wm(creds=["admin"], domain="corp.local", peers=["10.0.0.6"])
        g = build_attack_path(wm, peers=["10.0.0.6"])
        kinds = {n["kind"] for n in g.nodes}
        self.assertIn("host", kinds)
        self.assertIn("account", kinds)
        self.assertIn("domain", kinds)
        rels = {e["rel"] for e in g.edges}
        self.assertIn("has_creds", rels)
        self.assertIn("reaches", rels)
        # "reaches" is context, never a traversable pivot step
        reaches = [e for e in g.edges if e["rel"] == "reaches"]
        self.assertTrue(all(not e["traversable"] for e in reaches))

    def test_pivot_plan_next_peers(self):
        wm = _wm(creds=["admin"], peers=["10.0.0.6", "10.0.0.7"])
        plan = pivot_plan(wm, peers=["10.0.0.6", "10.0.0.7"])
        self.assertEqual(plan["foothold_accounts"], ["account:admin"])
        self.assertEqual(plan["next_peers"], ["10.0.0.6", "10.0.0.7"])
        self.assertFalse(plan["reached_privileged"])

    def test_pivot_plan_reaches_privileged(self):
        wm = _wm(creds=["admin"], privileged=True, domain="corp.local")
        plan = pivot_plan(wm)
        self.assertTrue(plan["reached_privileged"])
        self.assertTrue(plan["path_to_privileged"])

    def test_shortest_path_uses_only_traversable_edges(self):
        g = AttackPathGraph()
        g.add_edge("host", "a", "account", "u", "has_creds")
        g.add_edge("account", "u", "host", "b", "has_creds")
        g.add_edge("account", "u", "domain", "d", "admin_on")
        path = g.shortest_path(g._key("host", "a"), {"account:u"})
        self.assertEqual(path, ["host:a", "account:u"])

    def test_no_path_without_creds(self):
        wm = _wm(domain="corp.local")  # domain but no creds
        plan = pivot_plan(wm)
        self.assertFalse(plan["reached_privileged"])
        self.assertEqual(plan["next_peers"], [])


if __name__ == "__main__":
    unittest.main()
