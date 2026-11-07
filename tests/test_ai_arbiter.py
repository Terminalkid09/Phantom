"""The arbiter's accept/reject policy, and the planner seam that uses it.

Every case here is a POLICY decision the operator has to be able to predict:
which proposal wins, which is refused and why, and what happens when nobody
proposes anything. The old behaviour — a preference list that was either
unused or invisible — cannot be tested this way, which is exactly why it
looked fine for weeks while the model was never asked.
"""

from __future__ import annotations

import types
import unittest

from phantom.automation.ai.arbiter import Arbiter, Proposal, Verdict


class Capability:
    """The planner-facing shape of a capability (only what the arbiter reads)."""

    def __init__(self, cid: str, *, category: str = "recon",
                 stealth: str = "passive", cost: float = 0.5,
                 risk: float = 0.1, forceful: bool = False,
                 ready: bool = True, effect: str = "service") -> None:
        self.id = cid
        self.category = category
        self.stealth_level = stealth
        self.opsec_cost = cost
        self.detection_risk = risk
        self.forceful = forceful
        self.effects = [effect]
        self.preconditions = [self._ready] if ready else [self._never]

    @staticmethod
    def _ready(world) -> bool:
        return True

    @staticmethod
    def _never(world) -> bool:
        return False


def _caps(*names, **kw) -> list:
    return [Capability(name, **{k: v for k, v in kw.items()
                                if k in ("category", "stealth", "forceful")})
            for name in names]


class ArbiterPolicyTests(unittest.TestCase):
    def _arb(self, authority="nudge", **kw) -> Arbiter:
        return Arbiter(authority=authority, audit=False, **kw)

    def test_proposal_for_an_unknown_move_is_rejected(self):
        caps = _caps("scan_tcp", "curl_probe")
        verdict = self._arb().adjudicate(
            "service", caps, caps[0],
            proposals=[Proposal("not_a_capability", 0.99)])
        self.assertIs(verdict.chosen, caps[0])
        self.assertFalse(verdict.changed)
        self.assertEqual(verdict.decisions[0].verdict, "rejected")
        self.assertIn("may run for this fact", verdict.decisions[0].reason)

    def test_confidence_below_the_authority_floor_is_rejected(self):
        caps = _caps("scan_tcp", "curl_probe")
        verdict = self._arb(authority="nudge").adjudicate(
            "service", caps, caps[0],
            proposals=[Proposal("curl_probe", 0.20)])
        self.assertIs(verdict.chosen, caps[0])
        self.assertIn("below the 'nudge' floor", verdict.rejected[0].reason)

    def test_accepted_proposal_changes_the_pick_within_the_bound(self):
        caps = _caps("scan_tcp", "curl_probe", "version_detect")
        verdict = self._arb().adjudicate(
            "service", caps, caps[0],
            proposals=[Proposal("curl_probe", 0.90, "web surface confirmed")])
        self.assertIs(verdict.chosen, caps[1])
        self.assertTrue(verdict.changed)
        self.assertIn("accepted curl_probe over scan_tcp", verdict.reason)

    def test_a_proposal_beyond_the_bound_is_rejected(self):
        caps = _caps("a", "b", "c", "d")
        # d is three positions away; nudge allows two.
        verdict = self._arb().adjudicate(
            "service", caps, caps[0], proposals=[Proposal("d", 0.95)])
        self.assertIs(verdict.chosen, caps[0])
        self.assertIn("allows 2", verdict.rejected[0].reason)

    def test_authority_observe_refuses_every_proposal(self):
        caps = _caps("scan_tcp", "curl_probe")
        verdict = self._arb(authority="observe").adjudicate(
            "service", caps, caps[0], proposals=[Proposal("curl_probe", 1.0)])
        self.assertIs(verdict.chosen, caps[0])
        self.assertIn("no measured advantage", verdict.rejected[0].reason)

    def test_loud_move_is_refused_while_the_noise_breaker_is_tripped(self):
        caps = [_caps("scan_tcp")[0],
                Capability("brute_ssh", category="brute", stealth="aggressive")]
        verdict = self._arb().adjudicate(
            "creds", caps, caps[0], proposals=[Proposal("brute_ssh", 0.99)],
            noise_breaker=True)
        self.assertIs(verdict.chosen, caps[0])
        self.assertIn("noise breaker", verdict.rejected[0].reason)

    def test_no_proposal_is_an_abstention_not_an_agreement(self):
        caps = _caps("scan_tcp")
        arb = self._arb()
        verdict = arb.adjudicate("service", caps, caps[0], proposals=[])
        self.assertEqual(verdict.decisions[0].verdict, "abstained")
        self.assertEqual(arb.summary()["abstained"], 1)
        self.assertIn("no usable proposal", arb.summary()["note"])

    def test_unavailable_proposer_is_reported_as_such(self):
        caps = _caps("scan_tcp")
        arb = Arbiter(authority="nudge", proposer=None, audit=False)
        arb.adjudicate("service", caps, caps[0])
        summary = arb.summary()
        self.assertEqual(summary["asked"], 0)
        self.assertGreaterEqual(summary["abstained"], 1)
        self.assertIn("never asked", summary["note"])

    def test_agreement_is_recorded_without_a_change(self):
        caps = _caps("scan_tcp", "curl_probe")
        verdict = self._arb().adjudicate(
            "service", caps, caps[0], proposals=[Proposal("scan_tcp", 0.9)])
        self.assertFalse(verdict.changed)
        self.assertIn("agreed", verdict.reason)
        self.assertEqual(verdict.decisions[-1].verdict, "agreement")

    def test_summary_counts_every_verdict(self):
        caps = _caps("a", "b", "c")
        arb = self._arb()
        arb.adjudicate("f", caps, caps[0],
                       proposals=[Proposal("b", 0.9), Proposal("zzz", 0.9)])
        summary = arb.summary()
        self.assertEqual(summary["accepted"], 1)
        self.assertEqual(summary["rejected"], 1)
        self.assertEqual(summary["changed"], 1)
        self.assertEqual(summary["changed_decisions"][0]["chosen"], "b")


class _Registry:
    def __init__(self, caps):
        self._caps = {c.id: c for c in caps}

    def get(self, cid):
        return self._caps.get(cid)

    def all(self):
        return list(self._caps.values())


class _World:
    target = "10.0.0.5"
    target_type = "ip"
    findings = []

    def has_any(self, fact, **kw):
        return False

    def find(self, *a, **k):
        return []

    def noise_breaker_tripped(self):
        return False


class PlannerArbiterTests(unittest.TestCase):
    def _planner(self, caps, arbiter):
        from phantom.automation.planner import Planner
        stealth = types.SimpleNamespace(allowed=lambda *a, **k: True)
        planner = Planner(_Registry(caps), stealth)
        planner.arbiter = arbiter
        return planner

    def test_planner_runs_the_accepted_move(self):
        caps = _caps("scan_tcp", "curl_probe")
        arb = Arbiter(authority="nudge", audit=False)
        planner = self._planner(caps, arb)
        chosen = planner._pick_source("service", used=set(), wm=_World())
        self.assertEqual(chosen.id, "scan_tcp")

    def test_an_unready_move_can_never_be_chosen_by_the_model(self):
        ready = Capability("scan_tcp")
        unready = Capability("curl_probe", ready=False)
        arb = Arbiter(authority="nudge", audit=False,
                      proposer=lambda fact, caps: [Proposal("curl_probe", 1.0)])
        planner = self._planner([ready, unready], arb)
        chosen = planner._pick_source("service", used=set(), wm=_World())
        self.assertEqual(chosen.id, "scan_tcp")

    def test_a_proposal_can_change_which_ready_move_runs(self):
        caps = _caps("scan_tcp", "curl_probe")
        arb = Arbiter(authority="nudge", audit=False,
                      proposer=lambda fact, caps: [Proposal("curl_probe", 0.9)])
        planner = self._planner(caps, arb)
        chosen = planner._pick_source("service", used=set(), wm=_World())
        self.assertEqual(chosen.id, "curl_probe")
        self.assertTrue(planner.last_verdict.changed)


class PlanningSchemaTests(unittest.TestCase):
    def test_planner_schema_requires_confidence_and_rejects_commands(self):
        from phantom.automation.ai.schemas import validate

        self.assertEqual(validate("planner", {"ranked": [
            {"id": "scan_tcp", "confidence": 0.7}]}), [])
        self.assertTrue(validate("planner", {"ranked": [{"id": "scan_tcp"}]}))
        bad = validate("planner", {"ranked": [
            {"id": "scan_tcp", "confidence": 0.7, "command": "id"}]})
        self.assertTrue(any("execution-shaped" in e for e in bad))


if __name__ == "__main__":
    unittest.main()
