"""Tests for realistic sender derivation + Cyrillic homoglyph obfuscation."""
import unittest

from phantom.automation.social.spoof import (
    apply,
    derive_sender,
    homoglyph,
    obfuscate,
)


class TestHomoglyph(unittest.TestCase):

    def test_visually_identical_but_different_bytes(self):
        out = homoglyph("LinkedIn Security", ratio=1.0, seed=0)
        # same display length, but contains Cyrillic lookalikes
        self.assertEqual(len(out), len("LinkedIn Security"))
        self.assertNotEqual(out, "LinkedIn Security")
        self.assertTrue(any(ord(c) > 0x400 for c in out))

    def test_naive_keyword_filter_defeated(self):
        out = homoglyph("account blocked", ratio=1.0, seed=0)
        self.assertNotIn("account", out)
        self.assertNotIn("blocked", out)

    def test_deterministic(self):
        self.assertEqual(homoglyph("hello", ratio=0.5, seed=7),
                         homoglyph("hello", ratio=0.5, seed=7))

    def test_ratio_zero_keeps_text(self):
        self.assertEqual(homoglyph("hello", ratio=0.0), "hello")

    def test_address_never_obfuscated(self):
        # apply() must keep the address byte-exact (an obfuscated address
        # would not route); only display + subject are obfuscated
        display, addr, subj = apply("IT Security Team",
                                    "no-reply@acme.it",
                                    "Your account is blocked",
                                    seed=3)
        self.assertEqual(addr, "no-reply@acme.it")
        self.assertNotEqual(display, "IT Security Team")
        self.assertNotEqual(subj, "Your account is blocked")


class TestDeriveSender(unittest.TestCase):

    def _dossier(self, **kw):
        base = {"name": "", "emails": [], "phones": [], "platform": "",
                "company": "", "profile": {}}
        base.update(kw)
        return base

    def test_company_internal_account(self):
        d = self._dossier(emails=["mario.rossi@acme.it"], company="Acme")
        display, addr = derive_sender(d, "it_helpdesk")
        self.assertIn("IT Service Desk", display)
        self.assertEqual(addr, "it-helpdesk@acme.it")

    def test_service_the_target_uses(self):
        d = self._dossier(emails=["mario.rossi@gmail.com"], platform="linkedin")
        display, addr = derive_sender(d, "security_alert")
        self.assertEqual(display, "LinkedIn Security")
        self.assertEqual(addr, "security@linkedin.com")

    def test_colleague_person_when_discovered(self):
        d = self._dossier(emails=["mario.rossi@acme.it",
                                  "giulia.bianchi@acme.it"])
        display, addr = derive_sender(d, "doc_share")
        self.assertIn("Giulia Bianchi", display)
        self.assertEqual(addr, "giulia.bianchi@acme.it")

    def test_last_resort_attacker_mailbox(self):
        d = self._dossier(emails=["mario.rossi@gmail.com"])
        display, addr = derive_sender(d, "", persona_email="p@grr.la")
        self.assertEqual(addr, "p@grr.la")
        self.assertEqual(display, "IT Security Team")

    def test_configured_from_wins(self):
        d = self._dossier(emails=["mario.rossi@acme.it"], company="Acme")
        display, addr = derive_sender(d, "it_helpdesk",
                                      configured="ops@attacker.net")
        self.assertEqual(addr, "ops@attacker.net")

    def test_free_mail_never_impersonated(self):
        d = self._dossier(emails=["mario.rossi@gmail.com"], platform="")
        _, addr = derive_sender(d, "it_helpdesk")
        self.assertNotIn("gmail.com", addr)


if __name__ == "__main__":
    unittest.main()
