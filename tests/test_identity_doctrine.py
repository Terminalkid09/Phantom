"""I3 — identity doctrine: phishing is the LAST resort.

The operator's rule: map everything non-contact first; contact only when
that is exhausted. These tests pin the DEMOTION (never removal), the
non-contact ladder, and the explicit-consent override.
"""
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.brain.targets import TargetLedger
from phantom.automation.guidance.commands import make_registry
from phantom.automation.guidance.stealth import StealthConfig, StealthEngine
from phantom.automation.guidance.strategy import (
    STRATEGIES, ProfileDetector, TargetModel, applicable_strategies,
)
from phantom.automation.planner import Planner


def _plan(wm, goal="complete_kill_chain"):
    se = StealthEngine(wm, StealthConfig())
    pl = Planner(make_registry(), se)
    led = TargetLedger(wm.target, scope_list=[])
    return pl.plan_strategic(wm, goal=goal, ledger=led)


class TestDemotion(unittest.TestCase):

    def test_identity_delivery_is_last_without_consent(self):
        stages = applicable_strategies(TargetModel(target_type="email",
                                                   is_identity=True))
        self.assertEqual(stages[-1].id, "identity_beacon")

    def test_delivery_not_removed(self):
        ids = {s.id for s in applicable_strategies(
            TargetModel(target_type="email", is_identity=True))}
        self.assertIn("identity_beacon", ids)

    def test_explicit_contact_consent_restores_weight_order(self):
        # a beacon foothold brings low-weight post stages into the list, so
        # the demotion (or lack of it) is actually OBSERVABLE: without
        # consent the delivery stage is pushed past even cleanup_ops, with
        # consent it sits at its weighted position and cleanup is last.
        kw = dict(target_type="email", is_identity=True, has_beacon=True)
        without = applicable_strategies(TargetModel(**kw))
        self.assertEqual(without[-1].id, "identity_beacon")
        with_consent = applicable_strategies(TargetModel(
            contact_allowed=True, **kw))
        ids = [s.id for s in with_consent]
        self.assertLess(ids.index("identity_beacon"), len(ids) - 1)
        self.assertEqual(ids[-1], "cleanup_ops")

    def test_network_unaffected(self):
        stages = applicable_strategies(TargetModel(target_type="ip",
                                                   is_network=True))
        self.assertEqual([s.id for s in stages][:3],
                         ["network_footprint", "network_creds",
                          "network_beacon"])


class TestNonContactLadder(unittest.TestCase):

    def test_field_expansion_sits_before_breach_and_delivery(self):
        ids = [s.id for s in applicable_strategies(
            TargetModel(target_type="email", is_identity=True))]
        self.assertLess(ids.index("identity_field"), ids.index("identity_breach"))
        self.assertLess(ids.index("identity_field"),
                        ids.index("identity_beacon"))

    def test_goal_filter_still_reaches_contact(self):
        """An explicit beacon goal is an operator choice: it still plans the
        contact chain, because demotion is a DEFAULT, not a prohibition."""
        wm = WorldModel(target="jdoe@corp.com", target_type="email")
        plan = _plan(wm, goal="beacon")
        self.assertTrue(plan.complete)
        self.assertIn("phish_identity", [s.capability.id for s in plan.steps])

    def test_consent_read_from_worldmodel(self):
        wm = WorldModel(target="jdoe@corp.com", target_type="email")
        wm.identity_consent = {"active": True, "contact": True}
        self.assertTrue(ProfileDetector.detect(wm).contact_allowed)
        wm2 = WorldModel(target="jdoe@corp.com", target_type="email")
        wm2.identity_consent = {"active": True, "contact": False}
        self.assertFalse(ProfileDetector.detect(wm2).contact_allowed)


class TestPlanOrdering(unittest.TestCase):

    def test_fresh_identity_still_starts_osint(self):
        wm = WorldModel(target="jdoe@corp.com", target_type="email")
        plan = _plan(wm)
        self.assertEqual(plan.steps[0].capability.id, "osint_identity")

    def test_enrich_goal_is_reachable_and_non_contact(self):
        """The DEEPEN worker (goal 'enrich') must reach the identity-field
        primitives and NOT the contact capabilities."""
        from phantom.automation.goals import GOAL_FACTS
        facts = GOAL_FACTS["enrich"]
        for f in ("email_candidate", "email_verified", "service_account"):
            self.assertIn(f, facts)
        for f in ("phish", "dm_sent"):
            self.assertNotIn(f, facts)
        wm = WorldModel(target="jdoe@corp.com", target_type="email")
        wm.add_finding("identity", "identity:jdoe", {"email": "jdoe@corp.com"},
                       confidence=0.7)
        plan = _plan(wm, goal="enrich")
        ids = [s.capability.id for s in plan.steps]
        self.assertTrue(any(i in ids for i in ("email_candidates",
                                               "email_verify",
                                               "breach_correlate")), ids)
        self.assertNotIn("phish_identity", ids)


if __name__ == "__main__":
    unittest.main()
