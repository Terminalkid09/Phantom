"""I2 — identity-field primitives (identity_ops.py + capability wiring).

Pins the consent model (active probes refused by default), the bounded,
no-guess candidate generation, honest catch-all detection, and the
non-contact ordering of the capability set.
"""
import os
import unittest
from unittest import mock

from phantom.automation.belief import WorldModel
from phantom.automation import identity_ops
from phantom.automation.identity_ops import (
    email_candidates, reset_enum, verify_emails, breach_correlate,
    active_consent_enabled, contact_consent_enabled, VerifyResult,
    MAX_PROBES,
)
from phantom.automation.guidance.commands import make_registry


def _wm(target="someuser", target_type="username"):
    return WorldModel(target=target, target_type=target_type)


class TestConsentGate(unittest.TestCase):

    def tearDown(self):
        os.environ.pop("PHANTOM_IDENTITY_ACTIVE", None)
        os.environ.pop("PHANTOM_IDENTITY_CONTACT", None)

    def test_default_closed(self):
        self.assertFalse(active_consent_enabled(_wm()))
        self.assertFalse(contact_consent_enabled(_wm()))

    def test_wm_stamp_opens(self):
        wm = _wm()
        wm.identity_consent = {"active": True, "contact": False}
        self.assertTrue(active_consent_enabled(wm))
        self.assertFalse(contact_consent_enabled(wm))

    def test_env_opens(self):
        os.environ["PHANTOM_IDENTITY_ACTIVE"] = "1"
        self.assertTrue(active_consent_enabled(_wm()))

    def test_reset_enum_refused_without_consent(self):
        ok, lines = reset_enum(_wm(), service_url="https://x/reset")
        self.assertFalse(ok)
        self.assertIn("consent", lines[0])

    def test_verify_refused_without_consent(self):
        ok, lines = verify_emails(_wm(), ["a@b.com"])
        self.assertFalse(ok)
        self.assertIn("consent", lines[0])


class TestCandidateGeneration(unittest.TestCase):

    def test_no_domain_no_candidates(self):
        ok, lines = email_candidates(_wm())
        self.assertFalse(ok)
        self.assertIn("OBSERVED domain", lines[0])

    def test_candidates_from_observed_domain(self):
        wm = _wm(target="mario.rossi", target_type="username")
        wm.add_finding("profile", "profile:mario.rossi",
                       {"username": "mario.rossi", "full_name": "Mario Rossi"},
                       confidence=0.8)
        wm.add_finding("domain_candidate", "domain_candidate:acme-corp.io",
                       {"domain": "acme-corp.io"}, confidence=0.8)
        ok, lines = email_candidates(wm)
        self.assertTrue(ok)
        blob = "\n".join(lines)
        self.assertIn("mario.rossi@acme-corp.io", blob)
        self.assertIn("mariorossi@acme-corp.io", blob)

    def test_bounded(self):
        wm = _wm()
        wm.add_finding("profile", "profile:x",
                       {"username": "x", "full_name": "A B C D E"}, confidence=0.8)
        for i in range(30):
            wm.add_finding("domain_candidate", f"domain_candidate:d{i}.com",
                           {"domain": f"d{i}.com"}, confidence=0.8)
        ok, lines = email_candidates(wm)
        self.assertLessEqual(len(lines), MAX_PROBES)


class TestVerifyCatchAll(unittest.TestCase):

    def tearDown(self):
        os.environ.pop("PHANTOM_IDENTITY_ACTIVE", None)

    def _consent(self):
        wm = _wm()
        wm.identity_consent = {"active": True}
        return wm

    def test_verified_hit(self):
        wm = self._consent()
        with mock.patch.object(identity_ops, "_mx_hosts", return_value=["mx.x"]), \
             mock.patch.object(identity_ops, "_rcpt_probe") as probe:
            def side(mx, addr, sender):
                return VerifyResult(addr, "zz-" not in addr, "rcpt 250 ok")
            probe.side_effect = side
            ok, lines = verify_emails(wm, ["mario@acme-corp.io"])
        self.assertTrue(ok)
        self.assertIn("exists=1", lines[0])

    def test_catch_all_reported_inconclusive(self):
        wm = self._consent()
        with mock.patch.object(identity_ops, "_mx_hosts", return_value=["mx.x"]), \
             mock.patch.object(identity_ops, "_rcpt_probe") as probe:
            # every address accepted -> catch-all
            probe.side_effect = lambda mx, addr, sender: VerifyResult(addr, True, "rcpt 250")
            ok, lines = verify_emails(wm, ["mario@acme-corp.io"])
        self.assertFalse(ok)
        self.assertIn("catch-all", lines[0])

    def test_no_mx(self):
        wm = self._consent()
        with mock.patch.object(identity_ops, "_mx_hosts", return_value=[]):
            ok, lines = verify_emails(wm, ["mario@acme-corp.io"])
        self.assertFalse(ok)
        self.assertIn("no-mx", lines[0])


class TestBreachCorrelate(unittest.TestCase):

    def test_widens_identity(self):
        wm = _wm()
        wm.add_finding("email_verified", "email_verified:mario.rossi@acme-corp.io",
                       {"email": "mario.rossi@acme-corp.io"}, confidence=0.9)
        ok, lines = breach_correlate(wm)
        self.assertTrue(ok)
        blob = "\n".join(lines)
        self.assertIn("BREACH_EXPOSURE:", blob)
        self.assertIn("IDENTITY_WIDENED: handle=mariorossi", blob)


class TestCapabilityWiring(unittest.TestCase):

    def test_primitives_registered_passive_first(self):
        r = make_registry()
        for cid in ("email_candidates", "reset_enum", "email_verify",
                    "breach_correlate"):
            self.assertIsNotNone(r.get(cid), f"{cid} not registered")
        self.assertEqual(r.get("email_candidates").stealth_level, "passive")
        self.assertEqual(r.get("reset_enum").stealth_level, "active")
        self.assertEqual(r.get("email_verify").stealth_level, "active")
        self.assertEqual(r.get("breach_correlate").stealth_level, "passive")

    def test_agent_refuses_active_without_consent(self):
        from phantom.automation.agent import AutonomousAgent
        agent = AutonomousAgent(target="mario", target_type="username")
        cap = agent.registry.get("email_verify")
        events = []
        agent._emit = lambda kind, **d: events.append((kind, d))
        ok = agent._execute_social_capability(cap, {"addresses": "a@b.com"})
        self.assertFalse(ok)
        self.assertTrue(any(k == "blocked" for k, _ in events))


if __name__ == "__main__":
    unittest.main()
