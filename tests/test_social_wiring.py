"""Phase 2 wiring: candidate addresses and the DM conversation state.

Two properties matter and are pinned here:

* the social path generates candidates OFFLINE and only spends the
  password-reset oracle with explicit consent, and every marker carries a
  MASK (a generated address is not identity proof);
* the DM state machine persists across calls: the link stays held until
  rapport, a hostile reply closes the thread, and a closed/handoff flow is
  a REFUSAL for the later stage rather than an extra send.
"""
from __future__ import annotations

import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.social.engine import SocialEngine
from phantom.automation.social.social_dm import FakeDMTransport


class TestEmailCandidatesWiring(unittest.TestCase):

    def _engine(self):
        eng = SocialEngine()
        eng._discovered.update({"emails": ["mario.rossi@acme.it"],
                                "name": "Mario Rossi",
                                "platform": "linkedin"})
        return eng

    def test_generation_is_offline_and_masked(self):
        eng = self._engine()
        import phantom.automation.social.email_candidates as ec
        old = ec.verify
        try:
            ec.verify = lambda *a, **k: (_ for _ in ()).throw(
                AssertionError("verification must not run without consent"))
            ok, lines = eng.email_candidates()
        finally:
            ec.verify = old
        self.assertTrue(ok, lines)
        self.assertTrue(any(l.startswith("EMAIL_CANDIDATE:") for l in lines))
        self.assertFalse(any("mario.rossi@acme.it" in l for l in lines),
                         lines)
        self.assertTrue(all("masked=" in l for l in lines
                            if l.startswith("EMAIL_CANDIDATE:")), lines)

    def test_verification_without_confirmation_sends_nothing(self):
        eng = self._engine()
        ok, lines = eng.email_candidates(verify=True, confirm=None)
        self.assertTrue(ok, lines)
        self.assertTrue(any("EMAIL_VERIFIED: none (refused" in l
                            for l in lines), lines)

    def test_verification_with_consent_uses_the_oracle(self):
        eng = self._engine()
        asked = []

        def fake_oracle(email, **_kwargs):
            asked.append(email)
            return [type("V", (), {"verdict": "exists",
                                   "evidence": "reset accepted"})()]

        ok, lines = eng.email_candidates(
            verify=True, confirm=lambda *_a: True, oracle=fake_oracle,
            max_verify=2)
        self.assertTrue(ok, lines)
        self.assertTrue(asked)
        verified = [l for l in lines if l.startswith("EMAIL_VERIFIED:")]
        self.assertEqual(len(verified), 2)
        self.assertTrue(all("exists=1" in l for l in verified), verified)
        self.assertFalse(any("mario.rossi@acme.it" in l for l in lines))


class TestEmailMarkersInterpret(unittest.TestCase):

    def test_a_masked_candidate_becomes_a_finding_without_the_address(self):
        from phantom.automation.guidance.kit import _social_interp
        wm = WorldModel(target="@mario", target_type="username")
        out = ("EMAIL_CANDIDATE: email=m*********@acme.it "
               "masked=m*********@acme.it pattern=first.last "
               "domain=corporate score=0.95")
        findings = _social_interp(out, wm, {})
        cand = [f for f in findings if f.kind == "email_candidate"][0]
        self.assertEqual(cand.value["masked"], "m*********@acme.it")
        self.assertEqual(cand.value["email"], "m*********@acme.it")
        self.assertNotIn("mario.rossi", str(cand.to_dict()))

    def test_a_verified_marker_carries_the_exists_token(self):
        from phantom.automation.guidance.kit import _social_interp
        wm = WorldModel(target="@mario", target_type="username")
        out = ("EMAIL_VERIFIED: email=m***@acme.it masked=m***@acme.it "
               "exists=1 reason=reset_accepted")
        findings = _social_interp(out, wm, {})
        ver = [f for f in findings if f.kind == "email_verified"][0]
        self.assertEqual(ver.value["exists"], "1")
        self.assertGreater(ver.confidence, 0.8)


class TestDMFlowWiring(unittest.TestCase):

    def test_no_link_on_the_first_message_and_state_persists(self):
        eng = SocialEngine()
        ok, lines = eng.dm_observe("@mario", "")
        self.assertTrue(ok, lines)
        self.assertIn("action=send", lines[0])
        self.assertIn("link_allowed=0", lines[0])
        # reply 1: rapport, still no link
        ok, lines = eng.dm_observe("@mario", "ok grazie")
        self.assertIn("stage=rapport", lines[0])
        self.assertIn("link_allowed=0", lines[0])
        # reply 2: pretext, still no link
        ok, lines = eng.dm_observe("@mario", "certo, dimmi")
        self.assertIn("stage=pretext", lines[0])
        self.assertIn("link_allowed=0", lines[0])
        # reply 3: now the link is defensible
        ok, lines = eng.dm_observe("@mario", "va bene")
        self.assertIn("stage=link", lines[0])
        self.assertIn("link_allowed=1", lines[0])
        self.assertEqual(eng.dm_flow_status("@mario")["state"], "link")

    def test_a_hostile_reply_closes_the_flow(self):
        eng = SocialEngine()
        eng.dm_observe("@mario")
        ok, lines = eng.dm_observe("@mario", "fuck off, scam")
        self.assertTrue(ok, lines)
        self.assertIn("action=stop", lines[0])
        self.assertEqual(eng.dm_flow_status("@mario")["state"], "closed")

    def test_a_proof_request_hands_off_to_the_operator(self):
        eng = SocialEngine()
        eng.dm_observe("@mario")
        ok, lines = eng.dm_observe("@mario", "who are you? prove it")
        self.assertTrue(ok, lines)
        self.assertIn("action=handoff", lines[0])
        self.assertEqual(eng.dm_flow_status("@mario")["state"], "handoff")

    def test_a_closed_flow_refuses_the_stage_two_link(self):
        from unittest import mock
        import phantom.automation.social.social_dm as dm_mod
        eng = SocialEngine()
        eng.dm_observe("@mario")
        eng.dm_observe("@mario", "report you")
        fake = FakeDMTransport()
        with mock.patch.object(dm_mod, "get_dm_transport",
                               return_value=fake):
            ok, lines = eng.dm_second_stage(["@mario"])
        self.assertFalse(ok, lines)
        self.assertEqual(fake.sent, [])
        self.assertTrue(any("dm_flow_closed" in l for l in lines), lines)

    def test_the_decision_is_a_typed_finding(self):
        from phantom.automation.guidance.kit import _social_interp
        wm = WorldModel(target="@mario", target_type="username")
        out = ("DM_DECISION: handle=@mario action=handoff stage=none "
               "state=handoff link_allowed=0 delay_s=0 "
               "reason=operator_takes_over")
        findings = _social_interp(out, wm, {})
        decision = [f for f in findings if f.kind == "dm_decision"][0]
        self.assertEqual(decision.value["action"], "handoff")
        self.assertFalse(decision.value["link_allowed"])
        self.assertGreaterEqual(decision.confidence, 0.8)


if __name__ == "__main__":
    unittest.main()
