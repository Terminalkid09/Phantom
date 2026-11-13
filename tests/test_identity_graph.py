"""I4 — identity field graph.

Nodes are identity fields, edges are deductions. The graph answers "which
field do I widen FIRST": the frontier (fields reachable from what we know),
ordered by the critical path to "the person is mapped" plus a BOUNDED
info-gain bonus (R3: it can only reorder near-ties), with unauthorised
probes demoted rather than dropped.
"""
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.brain.identity_graph import (
    FieldNode, IdentityFieldGraph, _KIND_RANK,
)
from phantom.automation.brain.identity import (
    KIND_DOMAIN_CANDIDATE, KIND_EMAIL_CANDIDATE, KIND_EMAIL_MASKED,
    KIND_EMAIL_VERIFIED, KIND_IDENTITY, IdentityReasoner,
)
from phantom.automation.reasoning import ReasoningEngine


def _node(nid, kind, *, known=False, conf=0.5, cost=1.0, contact="none",
          cap="", reason=""):
    return FieldNode(node_id=nid, kind=kind, known=known, confidence=conf,
                     cost=cost, contact=contact, capability=cap, reason=reason)


def _order(graph, **kw):
    return [p.node_id for p in graph.next_fields(**kw)]


class TestStructure(unittest.TestCase):

    def test_known_field_seeds_the_graph(self):
        wm = WorldModel(target="jdoe", target_type="username")
        wm.add_finding(KIND_EMAIL_MASKED, "email_masked:m***e@corp.com",
                       {"masked": "m***e@corp.com", "prefix": "m", "suffix": "e",
                        "domain": "corp.com", "length": 6},
                       confidence=0.8, source="reset")
        g = IdentityFieldGraph.from_world(wm)
        known = [n for n in g.nodes if n.known]
        self.assertTrue(any(n.kind == KIND_EMAIL_MASKED for n in known))

    def test_edges_are_rank_increasing(self):
        wm = WorldModel(target="jdoe@corp.com", target_type="email")
        wm.add_finding(KIND_IDENTITY, "identity:jdoe",
                       {"email": "jdoe@corp.com"}, confidence=0.7)
        g = IdentityFieldGraph.from_world(wm)
        self.assertTrue(g.is_dag())
        for a, b in g.edges:
            self.assertLess(_KIND_RANK[g._by_id[a].kind],
                            _KIND_RANK[g._by_id[b].kind])

    def test_known_nodes_are_not_on_the_frontier(self):
        g = IdentityFieldGraph(
            [_node("root", KIND_IDENTITY, known=True),
             _node("d:corp.com", KIND_DOMAIN_CANDIDATE)],
            [("root", "d:corp.com")])
        self.assertIn("d:corp.com", _order(g))
        self.assertNotIn("root", _order(g))

    def test_frontier_requires_a_known_ancestor(self):
        # a field whose only ancestor is itself unknown is NOT widen-able yet
        g = IdentityFieldGraph(
            [_node("d:x.com", KIND_DOMAIN_CANDIDATE),
             _node("c:a@x.com", KIND_EMAIL_CANDIDATE)],
            [("d:x.com", "c:a@x.com")])
        self.assertNotIn("c:a@x.com", _order(g))


class TestCriticalPath(unittest.TestCase):

    def test_critical_path_ends_at_a_terminal(self):
        wm = WorldModel(target="jdoe@corp.com", target_type="email")
        wm.add_finding(KIND_EMAIL_VERIFIED, "email_verified:jdoe@corp.com",
                       {"email": "jdoe@corp.com"}, confidence=0.9)
        g = IdentityFieldGraph.from_world(wm)
        self.assertTrue(g.terminal_nodes())
        last = g.critical_path()[-1]
        self.assertIn(g._by_id[last].kind,
                      {KIND_EMAIL_VERIFIED, "breach_exposure",
                       "service_account", "identity_widened"})

    def test_critical_path_is_deterministic(self):
        wm = WorldModel(target="jdoe@corp.com", target_type="email")
        wm.add_finding(KIND_IDENTITY, "identity:jdoe",
                       {"email": "jdoe@corp.com"}, confidence=0.7)
        self.assertEqual(IdentityFieldGraph.from_world(wm).critical_path(),
                         IdentityFieldGraph.from_world(wm).critical_path())


class TestRanking(unittest.TestCase):

    def test_info_gain_prefers_the_field_that_unlocks_more(self):
        # a longer spine elsewhere removes the critical-path nudge, so the
        # difference between x and y is purely the info-gain bonus
        g = IdentityFieldGraph(
            [_node("rootA", KIND_IDENTITY, known=True),
             _node("x", KIND_DOMAIN_CANDIDATE, conf=0.5, cost=0.5),
             _node("y", KIND_DOMAIN_CANDIDATE, conf=0.5, cost=0.5),
             _node("y1", KIND_EMAIL_CANDIDATE),
             _node("y2", KIND_EMAIL_CANDIDATE),
             _node("rootB", KIND_IDENTITY, known=True),
             _node("p", KIND_DOMAIN_CANDIDATE),
             _node("q", KIND_EMAIL_CANDIDATE),
             _node("r", KIND_EMAIL_VERIFIED)],
            [("rootA", "x"), ("rootA", "y"), ("y", "y1"), ("y", "y2"),
             ("rootB", "p"), ("p", "q"), ("q", "r")])
        self.assertNotIn("x", g.critical_ids())
        self.assertNotIn("y", g.critical_ids())
        gains = {p.node_id: p.info_gain for p in g.next_fields()}
        self.assertEqual(gains["x"], 0)
        self.assertEqual(gains["y"], 2)
        self.assertLess(_order(g).index("y"), _order(g).index("x"))

    def test_info_gain_is_bounded(self):
        # a cheap, confident field beats an uncertain high-gain one: the
        # bonus can only reorder near-ties (R3)
        g = IdentityFieldGraph(
            [_node("root", KIND_IDENTITY, known=True),
             _node("a", KIND_DOMAIN_CANDIDATE, conf=1.0, cost=1.0),
             _node("b", KIND_EMAIL_CANDIDATE, conf=0.1, cost=0.5),
             _node("b1", KIND_EMAIL_VERIFIED),
             _node("b2", KIND_EMAIL_VERIFIED)],
            [("root", "a"), ("root", "b"), ("b", "b1"), ("b", "b2")])
        scores = {p.node_id: p.score for p in g.next_fields()}
        self.assertGreater(scores["a"], scores["b"])
        self.assertLess(_order(g).index("a"), _order(g).index("b"))

    def test_contact_field_is_discounted(self):
        g = IdentityFieldGraph(
            [_node("root", KIND_IDENTITY, known=True),
             _node("m", KIND_DOMAIN_CANDIDATE, conf=0.5, contact="none"),
             _node("n", KIND_DOMAIN_CANDIDATE, conf=0.5, contact="contact")],
            [("root", "m"), ("root", "n")])
        scores = {p.node_id: p.score for p in g.next_fields()}
        self.assertGreater(scores["m"], scores["n"])

    def test_unauthorised_active_probe_is_demoted(self):
        g = IdentityFieldGraph(
            [_node("root", KIND_IDENTITY, known=True),
             _node("a", KIND_DOMAIN_CANDIDATE, conf=0.8, cost=0.5,
                   contact="active", cap="email_verify"),
             _node("p", KIND_DOMAIN_CANDIDATE, conf=0.4, cost=1.0,
                   contact="none", cap="osint_identity")],
            [("root", "a"), ("root", "p")])
        allowed = {p.node_id: p.score
                   for p in g.next_fields(allow_active=True)}
        blocked = {p.node_id: p.score
                   for p in g.next_fields(allow_active=False)}
        self.assertLess(blocked["a"], allowed["a"])
        # demotion never REMOVES the field: it is still named
        self.assertIn("a", _order(g, allow_active=False))


class TestReasoningWiring(unittest.TestCase):

    def _wm(self):
        wm = WorldModel(target="jdoe", target_type="username")
        wm.add_finding(KIND_IDENTITY, "identity:jdoe",
                       {"username": "jdoe", "full_name": "John Doe"},
                       confidence=0.7, source="osint")
        wm.add_finding(KIND_EMAIL_MASKED, "email_masked:m***e@corp.com",
                       {"masked": "m***e@corp.com", "prefix": "m", "suffix": "e",
                        "domain": "corp.com", "length": 6},
                       confidence=0.8, source="reset")
        return wm

    def test_graph_rank_drives_the_preference_order(self):
        wm = self._wm()
        derivations = IdentityReasoner().reason(wm)
        rank = ReasoningEngine._identity_field_rank(derivations, wm,
                                                    False, False)
        self.assertTrue(rank)
        top = min(rank, key=rank.get)
        # the engine's hypotheses (the planner preferences) start with the
        # capability the field graph ranks first
        res = ReasoningEngine().run(wm)
        caps = [h.capability_id for h in res.hypotheses]
        self.assertTrue(caps)
        self.assertEqual(caps[0], top)

    def test_graph_guides_and_never_blocks(self):
        wm = WorldModel(target="jdoe@corp.com", target_type="email")
        res = ReasoningEngine().run(wm)
        # with no identity field at all the graph is empty and the engine
        # still runs to completion
        self.assertEqual([h for h in res.hypotheses
                          if h.capability_id == "phish_identity"], [])


if __name__ == "__main__":
    unittest.main()
