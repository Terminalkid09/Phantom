"""B3 — arbitrating between PLAN VARIANTS on their DAGs.

B3 delivered the plan as a DAG; it left the arbitration between competing
plans open. This pins that arbitration: variants are scored on their graphs
under the current signals, the planner's own pick stays the default, and a
variant only displaces it when it clearly beats it (bounded margin).
"""
import unittest

from phantom.automation.brain.lenses import WorldSignals
from phantom.automation.brain.plan_arbiter import (
    PlanArbiter, PlanVariant, build_variants, readings_for, weights_for,
)
from phantom.automation.brain.plan_graph import PlanGraph


class _Cap:
    def __init__(self, cid, category, effects=(), contact="", cost=1.0,
                 risk=0.0):
        self.id, self.category = cid, category
        self.effects, self.contact = tuple(effects), contact
        self.opsec_cost, self.detection_risk = cost, risk


class _Step:
    def __init__(self, cap):
        self.capability = cap


class _Plan:
    def __init__(self, caps, complete=True, strategy=""):
        self.steps = [_Step(c) for c in caps]
        self.complete = complete
        self.strategy = strategy


def _variant(vid, caps, label="", goal_facts=("beacon",)):
    plan = _Plan(caps)
    return PlanVariant(variant_id=vid, label=label or vid, plan=plan,
                       graph=PlanGraph.from_plan(plan, goal_facts=goal_facts),
                       goal_facts=goal_facts)


def _quiet():
    return _variant("quiet", [
        _Cap("osint_identity", "osint", ("identity",), "none", cost=0.4,
             risk=0.0),
        _Cap("email_candidates", "osint", ("email_candidate",), "none",
             cost=0.1, risk=0.0),
        _Cap("beacon_via_rce", "beacon", ("beacon",), "exploit", cost=2.0,
             risk=0.2),
    ], label="quiet non-contact first")


def _loud():
    return _variant("loud", [
        _Cap("scan_tcp", "recon", ("service",), "recon", cost=1.0, risk=0.4),
        _Cap("service_exploit", "exploit", ("rce_foothold",), "exploit",
             cost=8.0, risk=0.8),
        _Cap("beacon_deploy", "beacon", ("beacon",), "exploit", cost=5.0,
             risk=0.6),
    ], label="loud exploit first")


class TestReadings(unittest.TestCase):

    def test_readings_are_bounded(self):
        for v in (_quiet(), _loud()):
            for lens, value in readings_for(v).items():
                self.assertGreaterEqual(value, 0.0, lens)
                self.assertLessEqual(value, 1.0, lens)

    def test_contact_reading_is_inverse_contact_class(self):
        self.assertGreater(readings_for(_quiet())["contact"],
                           readings_for(_loud())["contact"])

    def test_stealth_tracks_detection_risk(self):
        self.assertGreater(readings_for(_quiet())["stealth"],
                           readings_for(_loud())["stealth"])

    def test_cost_reading_prefers_cheaper(self):
        self.assertGreater(readings_for(_quiet())["cost"],
                           readings_for(_loud())["cost"])

    def test_progress_requires_the_goal_fact(self):
        no_goal = _variant("nog", [_Cap("scan_tcp", "recon", ("service",))],
                           goal_facts=("beacon",))
        self.assertLess(readings_for(no_goal)["progress"],
                        readings_for(_quiet())["progress"])


class TestWeights(unittest.TestCase):

    def test_breaker_shifts_weight_to_stealth(self):
        calm = weights_for(WorldSignals())
        loud = weights_for(WorldSignals(breaker_tripped=True,
                                        noise_ratio=1.2))
        self.assertGreater(loud["stealth"], calm["stealth"])
        self.assertLess(loud["progress"], calm["progress"])

    def test_blind_shifts_weight_to_evidence(self):
        blind = weights_for(WorldSignals(visibility=False))
        seen = weights_for(WorldSignals(visibility=True))
        self.assertGreater(blind["evidence"], seen["evidence"])

    def test_weights_normalise(self):
        self.assertAlmostEqual(sum(weights_for(WorldSignals()).values()),
                               1.0, places=6)


class TestArbitration(unittest.TestCase):

    def test_default_holds_when_it_is_best(self):
        choice = PlanArbiter().choose([_quiet(), _loud()], prefer="quiet")
        self.assertEqual(choice.winner.variant_id, "quiet")
        self.assertFalse(choice.decided)

    def test_a_clearly_better_variant_displaces_the_default(self):
        # loud is the default; under a tripped breaker the quiet plan wins
        sig = WorldSignals(breaker_tripped=True, noise_ratio=1.2)
        choice = PlanArbiter().choose([_loud(), _quiet()], sig=sig,
                                      prefer="loud")
        self.assertEqual(choice.winner.variant_id, "quiet")
        self.assertTrue(choice.decided)
        self.assertIn("beats the default", choice.rule)

    def test_margin_keeps_the_default_on_near_ties(self):
        a = _quiet()
        b = _quiet()
        b.variant_id = "quiet2"
        choice = PlanArbiter().choose([a, b], prefer="quiet")
        self.assertEqual(choice.winner.variant_id, "quiet")
        self.assertFalse(choice.decided)

    def test_no_variants_is_none_not_a_crash(self):
        self.assertIsNone(PlanArbiter().choose([]))

    def test_deterministic_tie_break(self):
        a = _quiet()
        b = _quiet()
        a.variant_id, b.variant_id = "zzz", "aaa"
        c1 = PlanArbiter().choose([a, b], prefer="zzz")
        c2 = PlanArbiter().choose([b, a], prefer="zzz")
        self.assertEqual(c1.winner.variant_id, c2.winner.variant_id)

    def test_explain_and_to_dict_are_complete(self):
        choice = PlanArbiter().choose([_quiet(), _loud()], prefer="quiet")
        self.assertIn("plan arbiter", choice.explain())
        d = choice.to_dict()
        for key in ("winner", "rule", "decided", "scores", "readings",
                    "variants"):
            self.assertIn(key, d)


class TestBuildVariants(unittest.TestCase):

    def test_real_planner_variants_are_valid_dags(self):
        from phantom.automation.agent import AutonomousAgent
        a = AutonomousAgent("10.0.0.5", target_type="ip")
        plan = a.planner.plan_strategic(a.wm, goal="deliver", ledger=a.ledger)
        variants = build_variants(a.planner, a.wm, "deliver", prefs=[],
                                  ledger=a.ledger, goal_facts=a._goal_facts(),
                                  primary=plan)
        self.assertTrue(variants)
        self.assertEqual(variants[0].variant_id, "primary")
        for v in variants:
            self.assertTrue(v.graph.is_dag())

    def test_primary_variant_is_the_plan_handed_in(self):
        from phantom.automation.agent import AutonomousAgent
        a = AutonomousAgent("10.0.0.5", target_type="ip")
        plan = a.planner.plan_strategic(a.wm, goal="deliver", ledger=a.ledger)
        variants = build_variants(a.planner, a.wm, "deliver", prefs=[],
                                  ledger=a.ledger, goal_facts=a._goal_facts(),
                                  primary=plan)
        self.assertIs(variants[0].plan, plan)

    def test_dead_capabilities_never_return_through_a_variant(self):
        # regression: the extra variants re-plan WITHOUT the run's dead set
        # unless it is threaded through, which lets a killed move (e.g. a
        # novelty-dead scan_tcp) come back in a variant that then wins and
        # executes a move the run had already ruled out.
        from phantom.automation.agent import AutonomousAgent
        a = AutonomousAgent("10.0.0.5", target_type="ip")
        dead = frozenset({"scan_tcp"})
        plan = a.planner.plan_strategic(a.wm, goal="footprint",
                                        ledger=a.ledger, dead=dead)
        variants = build_variants(
            a.planner, a.wm, "footprint", prefs=[], ledger=a.ledger,
            goal_facts=a._goal_facts(), primary=plan, dead=dead)
        for v in variants:
            caps = {s.capability.id for s in v.plan.steps}
            self.assertNotIn("scan_tcp", caps)


class TestAgentWiring(unittest.TestCase):

    def test_arbitrate_plan_keeps_the_default_when_nothing_wins(self):
        from phantom.automation.agent import AutonomousAgent
        a = AutonomousAgent("10.0.0.5", target_type="ip")
        plan = a.planner.plan_strategic(a.wm, goal="deliver", ledger=a.ledger)
        out = a._arbitrate_plan(plan, "deliver", [])
        self.assertIsNotNone(out)
        # the choice is recorded for the report
        self.assertIsNotNone(a._plan_choice)
        self.assertIn("scores", a._plan_choice)

    def test_a_working_plan_is_never_silently_rewritten(self):
        # the default plan is complete -> even a clearly better variant only
        # guides (recorded), it does not replace the run's plan
        from phantom.automation.agent import AutonomousAgent
        a = AutonomousAgent("10.0.0.5", target_type="ip")
        plan = a.planner.plan_strategic(a.wm, goal="deliver", ledger=a.ledger)
        plan.complete = True
        out = a._arbitrate_plan(plan, "deliver", [])
        self.assertIs(out, plan)

    def test_identity_field_model_only_when_identity_context_exists(self):
        from phantom.automation.agent import AutonomousAgent
        ip = AutonomousAgent("10.0.0.5", target_type="ip")
        self.assertIsNone(ip._identity_field_plan())
        user = AutonomousAgent("jdoe", target_type="username")
        user.wm.add_finding("identity", "identity:jdoe",
                            {"username": "jdoe", "full_name": "John Doe"},
                            confidence=0.7, source="osint")
        model = user._identity_field_plan()
        self.assertIsNotNone(model)
        self.assertTrue(model["nodes"])
        self.assertTrue(model["next"])


class TestStreamAndReport(unittest.TestCase):

    def test_new_events_render(self):
        from phantom.core.stream_contract import render_event
        r1 = render_event("identity_field", {
            "nodes": [{"known": True}, {"known": False}],
            "edges": [[0, 1]], "next": ["email_candidate:handle:jdoe"],
            "critical_path": ["identity:jdoe"]}, verbose=True)
        self.assertIsNotNone(r1)
        self.assertIn("Identity field graph", r1.head)
        r2 = render_event("plan_variants", {
            "winner": "quiet", "label": "quiet first",
            "rule": "beats the default", "scores": {"quiet": 0.9, "loud": 0.5}},
            verbose=True)
        self.assertIsNotNone(r2)
        self.assertIn("Plan variants", r2.head)

    def test_report_carries_both_models(self):
        from phantom.automation.agent import AutonomousAgent
        from phantom.automation.reporting import RawReport
        a = AutonomousAgent("jdoe", target_type="username")
        a.wm.add_finding("identity", "identity:jdoe", {"username": "jdoe"},
                         confidence=0.7, source="osint")
        a._plan_choice = {"winner": "primary", "scores": {}}
        a._identity_field_model = a._identity_field_plan()
        raw = RawReport.from_agent(a)
        self.assertEqual(raw.plan_choice, {"winner": "primary", "scores": {}})
        self.assertIsNotNone(raw.identity_field)
        self.assertIn("plan_choice", raw.to_dict())
        self.assertIn("identity_field", raw.to_dict())


if __name__ == "__main__":
    unittest.main()
