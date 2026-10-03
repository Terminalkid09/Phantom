"""I1 — identity-field reasoning (brain/identity.py + reasoning wiring).

The operator's manual loop, pinned as deterministic rules: a thin field
(handle, masked reset email) must yield DEDUCTIONS the planner can use,
with no domain guessing, no gating kinds, and a non-contact-first ladder.
"""
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.brain.identity import (
    IdentityReasoner, local_part, domain_of, mask_shape, name_parts,
    handle_variants, KIND_EMAIL_CANDIDATE, KIND_EMAIL_MASKED,
    KIND_EMAIL_VERIFIED, KIND_DOMAIN_CANDIDATE, KIND_SERVICE_ACCOUNT,
    KIND_IDENTITY_WIDENED, KIND_BREACH_EXPOSURE, KIND_CREDS,
)
from phantom.automation.reasoning import ReasoningEngine


def _wm(target="someuser", target_type="username"):
    return WorldModel(target=target, target_type=target_type)


class TestParsing(unittest.TestCase):

    def test_local_part_and_domain(self):
        self.assertEqual(local_part("Mario.Rossi@Example.com"), "mario.rossi")
        self.assertEqual(domain_of("mario@example.com"), "example.com")
        self.assertEqual(local_part("nope"), "")
        self.assertEqual(domain_of("nope"), "")

    def test_mask_shape(self):
        shape = mask_shape("m***o@gmail.com")
        self.assertEqual(shape["prefix"], "m")
        self.assertEqual(shape["suffix"], "o")
        self.assertEqual(shape["domain"], "gmail.com")
        self.assertEqual(shape["length"], 5)

    def test_name_parts_drops_particles(self):
        self.assertEqual(name_parts("Mario de Rossi"), ["mario", "rossi"])

    def test_handle_variants(self):
        v = handle_variants("mario.rossi")
        self.assertIn("mario.rossi", v)
        self.assertIn("mariorossi", v)


class TestNoDomainGuessing(unittest.TestCase):

    def test_no_candidates_without_an_observed_domain(self):
        """A bare handle must NOT produce gmail.com candidates."""
        wm = _wm()
        deriv = IdentityReasoner().reason(wm)
        emails = [d for d in deriv if d.kind == KIND_EMAIL_CANDIDATE
                  and d.value.get("email")]
        self.assertEqual(emails, [], "guessed a domain from nothing")


class TestCandidateGeneration(unittest.TestCase):

    def test_name_plus_observed_domain_yields_candidates(self):
        wm = _wm(target="mario.rossi", target_type="username")
        wm.add_finding("profile", "profile:mario.rossi",
                       {"username": "mario.rossi", "platform": "instagram",
                        "full_name": "Mario Rossi"}, confidence=0.8)
        wm.add_finding(KIND_DOMAIN_CANDIDATE, "domain_candidate:acme-corp.io",
                       {"domain": "acme-corp.io", "observed": True},
                       confidence=0.8)
        deriv = IdentityReasoner().reason(wm)
        addrs = {d.value["email"] for d in deriv
                 if d.kind == KIND_EMAIL_CANDIDATE and d.value.get("email")}
        self.assertIn("mario.rossi@acme-corp.io", addrs)
        self.assertIn("mariorossi@acme-corp.io", addrs)
        self.assertIn("mrossi@acme-corp.io", addrs)

    def test_candidate_generation_is_bounded(self):
        wm = _wm()
        wm.add_finding("profile", "profile:x",
                       {"username": "x", "full_name": "A B C D E"}, confidence=0.8)
        for i in range(20):
            wm.add_finding(KIND_DOMAIN_CANDIDATE, f"domain_candidate:d{i}.com",
                           {"domain": f"d{i}.com"}, confidence=0.8)
        r = IdentityReasoner(max_candidates=25)
        emails = [d for d in r.reason(wm)
                  if d.kind == KIND_EMAIL_CANDIDATE and d.value.get("email")]
        self.assertLessEqual(len(emails), 25)


class TestMaskedResetLeak(unittest.TestCase):

    def test_masked_email_reveals_domain_and_shape(self):
        wm = _wm()
        wm.add_finding(KIND_EMAIL_MASKED, "email_masked:m***o@gmail.com",
                       {"masked": "m***o@gmail.com"}, confidence=0.8)
        deriv = IdentityReasoner().reason(wm)
        kinds = {d.kind for d in deriv}
        self.assertIn(KIND_DOMAIN_CANDIDATE, kinds)
        dom = [d for d in deriv if d.kind == KIND_DOMAIN_CANDIDATE][0]
        self.assertEqual(dom.value["domain"], "gmail.com")


class TestVerifiedExpansion(unittest.TestCase):

    def test_verified_email_widens_identity_and_domains(self):
        wm = _wm()
        wm.add_finding(KIND_EMAIL_VERIFIED, "email_verified:mario.rossi@corp.io",
                       {"email": "mario.rossi@corp.io", "exists": True},
                       confidence=0.9)
        deriv = IdentityReasoner().reason(wm)
        widened = {d.value.get("handle") for d in deriv
                   if d.kind == KIND_IDENTITY_WIDENED}
        self.assertIn("mario.rossi", widened)
        self.assertIn("mariorossi", widened)
        self.assertTrue(any(d.kind == KIND_SERVICE_ACCOUNT for d in deriv))
        doms = {d.value.get("domain") for d in deriv
                if d.kind == KIND_DOMAIN_CANDIDATE}
        self.assertIn("corp.io", doms)


class TestBreachCorrelation(unittest.TestCase):

    def test_breach_links_local_part_and_reuse(self):
        wm = _wm()
        wm.add_finding(KIND_BREACH_EXPOSURE, "breach:acme",
                       {"email": "mario.rossi@corp.io", "breach": "acme"},
                       confidence=0.6)
        wm.add_finding(KIND_CREDS, "breach:mario.rossi@corp.io",
                       {"username": "mario.rossi@corp.io", "password": "x",
                        "source": "breach", "service": "leak"}, confidence=0.6)
        deriv = IdentityReasoner().reason(wm)
        self.assertTrue(any(d.kind == KIND_IDENTITY_WIDENED for d in deriv))
        reuse = [d for d in deriv if d.kind == KIND_SERVICE_ACCOUNT
                 and d.value.get("reused") is False]
        self.assertTrue(reuse, "no credential-reuse derivation")


class TestConsentLadder(unittest.TestCase):

    def test_active_verification_gated_by_consent(self):
        wm = _wm()
        wm.add_finding(KIND_EMAIL_CANDIDATE, "email_candidate:a@b.com",
                       {"email": "a@b.com"}, confidence=0.3)
        closed = IdentityReasoner(active_consent=False).reason(wm)
        verify = [d for d in closed if d.value.get("stage") == "verify"][0]
        self.assertIsNone(verify.hypothesis, "active probe proposed without consent")
        open_ = IdentityReasoner(active_consent=True).reason(wm)
        verify = [d for d in open_ if d.value.get("stage") == "verify"][0]
        self.assertIsNotNone(verify.hypothesis)
        self.assertEqual(verify.hypothesis["capability_id"], "email_verify")

    def test_contact_is_last_resort_only(self):
        wm = _wm()
        # nothing mapped yet: no contact proposal even with consent
        d0 = IdentityReasoner(contact_consent=True).reason(wm)
        self.assertFalse(any(d.value.get("stage") == "contact" for d in d0))
        # full ladder mapped + a verified address + breach, no service found
        wm.add_finding("identity", "identity:x", {"username": "x"}, confidence=0.8)
        wm.add_finding(KIND_EMAIL_VERIFIED, "email_verified:a@b.com",
                       {"email": "a@b.com"}, confidence=0.9)
        wm.add_finding(KIND_BREACH_EXPOSURE, "breach:z",
                       {"email": "a@b.com", "breach": "z"}, confidence=0.6)
        d1 = IdentityReasoner(contact_consent=True).reason(wm)
        contact = [d for d in d1 if d.value.get("stage") == "contact"]
        self.assertTrue(contact, "contact never proposed")
        self.assertEqual(contact[0].hypothesis["capability_id"], "phish_identity")


class TestReasoningWiring(unittest.TestCase):

    def test_engine_registers_candidate_findings_without_gating(self):
        wm = _wm()
        wm.add_finding(KIND_EMAIL_MASKED, "email_masked:m***o@gmail.com",
                       {"masked": "m***o@gmail.com"}, confidence=0.8)
        eng = ReasoningEngine()
        eng.run(wm)
        # the domain was deduced and stored as a NON-gating candidate
        self.assertTrue(wm.find(KIND_DOMAIN_CANDIDATE))
        for f in wm.all_findings():
            self.assertTrue(f.source in ("reasoning", "perception",
                                         "identity_reasoning"))

    def test_engine_proposes_osint_first_no_contact(self):
        wm = _wm()
        eng = ReasoningEngine()
        eng.run(wm)
        ids = {h.capability_id for h in wm.hypotheses}
        self.assertIn("osint_identity", ids)
        self.assertNotIn("phish_identity", ids,
                         "contact proposed before any mapping")


if __name__ == "__main__":
    unittest.main()
