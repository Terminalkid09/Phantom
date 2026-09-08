"""Tests for the social-engineering layer: persona, mailers, grabber, engine."""
import unittest
from unittest.mock import Mock, patch

from phantom.automation.social.persona import (
    Persona,
    GuerrillaMail,
    TempMailProvider,
    carrier_sms_address,
    carrier_from_phone,
    normalize_carrier,
)
from phantom.automation.social.mailers import Mailer, MailConfig, env_mail_config
from phantom.automation.social.grabbit import IpGrabber, GrabLink, VictimHit
from phantom.automation.social.engine import SocialEngine
from phantom.automation.social.tracker import (
    HitStore,
    TrackingServer,
    public_base_url,
)


class _FakeProvider(TempMailProvider):
    def __init__(self, address="persona.x@grr.la", email_id="42"):
        self.address, self.email_id = address, email_id
        self.created = self.destroyed = 0
        self.mails = []

    def create(self):
        self.created += 1
        return {"address": self.address, "email_id": self.email_id}

    def fetch_inbox(self, email_id, timeout=30.0):
        return list(self.mails)

    def destroy(self, email_id):
        self.destroyed += 1


class TestGuerrillaMail(unittest.TestCase):

    def test_create_and_fetch(self):
        def _fetch(uri):
            if "get_email_address" in uri:
                return {"email_addr": "x@guerrillamail.com", "email_id": 7}
            if "fetch_email" in uri:
                return {"list": [{"mail_id": "m1", "mail_from": "victim@corp.com",
                                  "mail_subject": "Verify", "mail_body": "code=123"}]}
            return {}
        fetcher = Mock(side_effect=_fetch)
        gm = GuerrillaMail(fetcher=fetcher)
        inbox = gm.create()
        self.assertEqual(inbox["address"], "x@guerrillamail.com")
        mails = gm.fetch_inbox("7")
        self.assertEqual(mails[0]["subject"], "Verify")
        self.assertIn("code=123", mails[0]["body"])
        gm.destroy("7")
        calls = [c.args[0] for c in fetcher.call_args_list]
        self.assertTrue(any("forget_email" in c for c in calls))


class TestPersona(unittest.TestCase):

    def test_generate_uses_provider(self):
        provider = _FakeProvider()
        persona = Persona.generate(provider=provider)
        self.assertEqual(persona.email, "persona.x@grr.la")
        self.assertEqual(provider.created, 1)
        self.assertIn(" ", persona.name)

    def test_generate_without_provider(self):
        persona = Persona.generate(provider=_FakeProvider())
        self.assertTrue("@" in persona.email)

    def test_wait_for_message_filters_by_subject(self):
        provider = _FakeProvider()
        provider.mails = [{"id": "1", "from_": "a", "subject": "Your code is 1234", "body": ""}]
        persona = Persona(name="X Y", email="a@grr.la", email_id="42", provider=provider)
        msg = persona.wait_for_message(subject_hint="code", timeout=1)
        self.assertIsNotNone(msg)
        self.assertIn("1234", msg["subject"])

    def test_wait_for_message_timeout(self):
        persona = Persona(name="X Y", email="a@grr.la", email_id="42", provider=_FakeProvider())
        self.assertIsNone(persona.wait_for_message(timeout=0.5))

    def test_destroy(self):
        provider = _FakeProvider()
        persona = Persona(name="X Y", email="a@grr.la", email_id="42", provider=provider)
        persona.destroy()
        self.assertEqual(provider.destroyed, 1)

    def test_to_finding(self):
        persona = Persona(name="Alex Reed", email="alex@grr.la")
        f = persona.to_finding("10.0.0.9")
        self.assertEqual(f.kind, "persona")
        self.assertEqual(f.value["name"], "Alex Reed")


class TestCarrierSms(unittest.TestCase):

    def test_known_carrier(self):
        self.assertEqual(carrier_sms_address("+1-555-123-4567", "verizon"),
                         "15551234567@vtext.com")

    def test_unknown_carrier(self):
        self.assertIsNone(carrier_sms_address("15551234567", "nonexistentcarrier"))

    def test_garbage_phone(self):
        self.assertIsNone(carrier_sms_address("abc", "verizon"))

    def test_normalize_human_carrier(self):
        # phonenumbers returns "AT&T Mobility" — normalize to the att gateway
        self.assertEqual(normalize_carrier("AT&T Mobility"), "att")
        self.assertEqual(normalize_carrier("Verizon Wireless"), "verizon")
        self.assertEqual(normalize_carrier("T-Mobile USA"), "tmobile")

    def test_carrier_sms_address_via_alias(self):
        self.assertEqual(carrier_sms_address("15551234567", "AT&T Mobility"),
                         "15551234567@txt.att.net")

    def test_carrier_from_phone_offline(self):
        # phonenumbers metadata can't map a bare test number, but it must not raise
        self.assertIsNone(carrier_from_phone("+39 02 1234567"))  # landline: no carrier


class TestMailer(unittest.TestCase):

    def test_send_email_calls_transport(self):
        sent = {}
        def transport(sender, to, subject, body):
            sent.update(sender=sender, to=to, subject=subject, body=body)
            return True
        m = Mailer(transport=transport)
        ok = m.send_email("pers@mail.com", "victim@corp.com", "Hello", "Click this")
        self.assertTrue(ok)
        self.assertEqual(sent["to"], "victim@corp.com")

    def test_send_sms_uses_gateway(self):
        def transport(sender, to, subject, body):
            self.assertIn("@vtext.com", to)
            return True
        m = Mailer(transport=transport)
        self.assertTrue(m.send_sms("Alex", "15551234567", "verizon", "Hi!"))

    def test_send_sms_unknown_carrier_fails(self):
        m = Mailer(transport=Mock())
        self.assertFalse(m.send_sms("Alex", "15551234567", "nocarrier", "Hi!"))

    def test_smtp_without_credentials_returns_false(self):
        m = Mailer(MailConfig(username="", password=""), transport=None)
        self.assertFalse(m.send_email("a@b.c", "d@e.f", "s", "b"))

    def test_sms_short_link_truncates(self):
        msg = Mailer.sms_short_link("X" * 150, "https://t.co/abc", max_len=160)
        self.assertLessEqual(len(msg), 160)
        self.assertIn("https://t.co/abc", msg)

    def test_env_mail_config_reads_vars(self):
        with patch.dict("os.environ", {
                "PHANTOM_SMTP_HOST": "smtp-relay.brevo.com",
                "PHANTOM_SMTP_PORT": "587",
                "PHANTOM_SMTP_USER": "u",
                "PHANTOM_SMTP_PASSWORD": "p",
                "PHANTOM_SMTP_TLS": "1"}):
            cfg = env_mail_config()
        self.assertEqual(cfg.smtp_host, "smtp-relay.brevo.com")
        self.assertEqual(cfg.smtp_port, 587)
        self.assertEqual(cfg.username, "u")
        self.assertTrue(cfg.use_tls)


class TestIpGrabber(unittest.TestCase):

    def test_create_link(self):
        grabber = IpGrabber(creator=lambda code: f"https://s.example/{code}")
        link = grabber.create_link("phish")
        self.assertIn("phish-", link.code)
        self.assertEqual(link.short_url, f"https://s.example/{link.code}")

    def test_poll_hits_deduplicates(self):
        hits = [VictimHit(ip="203.0.113.9", user_agent="Mozilla")]
        grabber = IpGrabber(fetcher=lambda code: hits)
        link = grabber.create_link()
        found = grabber.poll_hits(link, timeout=2)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].ip, "203.0.113.9")

    def test_to_findings(self):
        grabber = IpGrabber()
        hits = [VictimHit(ip="203.0.113.9")]
        fs = grabber.to_findings(hits, "bob@corp.com")
        self.assertEqual(fs[0].kind, "victim_ip")
        self.assertEqual(fs[0].key, "203.0.113.9")

    def test_self_hosted_roundtrip_without_socket(self):
        # Inject a server whose store records hits; the grabber must build a
        # real URL and read hits back from the store — no placeholder URL.
        store = HitStore()
        server = TrackingServer(host="127.0.0.1", port=0, redirect_url="https://decoy",
                                store=store)
        grabber = IpGrabber(server=server)
        with patch("phantom.automation.social.grabbit.public_base_url",
                   return_value="https://track.example"):
            link = grabber.create_link()
        self.assertEqual(link.short_url, f"https://track.example/{link.code}")
        store.record(link.code, "203.0.113.42", "Mozilla/5.0")
        found = grabber.poll_hits(link, timeout=1)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].ip, "203.0.113.42")


class TestHitStore(unittest.TestCase):

    def test_record_and_hits(self):
        store = HitStore()
        store.record("c1", "1.2.3.4", "UA")
        store.record("c1", "5.6.7.8", "UA2")
        store.record("c2", "9.9.9.9", "UA3")
        self.assertEqual([h.ip for h in store.hits("c1")], ["1.2.3.4", "5.6.7.8"])
        self.assertEqual([h.ip for h in store.hits("c2")], ["9.9.9.9"])


class TestPublicBaseUrl(unittest.TestCase):

    def test_configured_url_wins(self):
        with patch.dict("os.environ", {"PHANTOM_TRACK_URL": "https://t.example"}):
            self.assertEqual(public_base_url("0.0.0.0", 8080), "https://t.example")

    def test_fallback_uses_host(self):
        with patch.dict("os.environ", {"PHANTOM_TRACK_URL": ""}):
            self.assertEqual(public_base_url("1.2.3.4", 9999), "http://1.2.3.4:9999")

    def test_wildcard_host_becomes_localhost(self):
        with patch.dict("os.environ", {"PHANTOM_TRACK_URL": ""}):
            self.assertEqual(public_base_url("0.0.0.0", 8080), "http://127.0.0.1:8080")


class _FakeGrabber:
    """Deterministic grabber stand-in for engine tests."""
    def __init__(self):
        self.hits = []
    def create_link(self, label="phish"):
        return GrabLink(short_url="https://t.example/x", code="x")
    def poll_hits(self, link, timeout=90):
        return list(self.hits)


class _FakePersonaCls:
    """A Persona stand-in with a generate() classmethod for engine tests."""
    @classmethod
    def generate(cls, provider=None):
        return Persona(name="Alex Reed", email="alex@grr.la", email_id="42")


class TestSocialEngine(unittest.TestCase):

    def test_phone_osint_emits_identity(self):
        engine = SocialEngine()
        ok, lines = engine.osint("+15551234567", "phone")
        self.assertTrue(ok)
        self.assertTrue(any(l.startswith("IDENTITY:") and "phone=" in l for l in lines))

    def test_phone_osint_invalid_falls_back(self):
        engine = SocialEngine()
        ok, lines = engine.osint("garbage", "phone")
        self.assertTrue(ok)
        self.assertTrue(any(l.startswith("IDENTITY:") for l in lines))

    def test_breach_without_source_reports_error(self):
        engine = SocialEngine()
        with patch.dict("os.environ", {}, clear=True):
            ok, lines = engine.breach("bob@corp.com", "email")
        self.assertTrue(ok)
        self.assertTrue(any(l.startswith("ERROR:") for l in lines))

    def test_persona_uses_email_id_field(self):
        engine = SocialEngine()
        engine._persona = _FakePersonaCls
        engine._persona_inst = None
        ok, lines = engine.persona()
        self.assertTrue(ok)
        # PERSONA marker carries the mailbox id (the email_id field), no crash
        self.assertTrue(any(l.startswith("PERSONA:") for l in lines))
        self.assertIn("mailbox=42", lines[0])

    def test_username_phish_does_not_self_phish(self):
        # No email discovered -> must fail, never target the persona mailbox
        engine = SocialEngine()
        ok, lines = engine.phish("bob_smith", "username")
        self.assertFalse(ok)
        self.assertTrue(any("email discovered" in l or "ERROR" in l for l in lines))

    def test_username_phish_targets_discovered_email(self):
        engine = SocialEngine()
        engine._remember("emails", "bob@corp.com")
        engine._mailer = Mailer(transport=lambda s, t, sub, b: True,
                                config=MailConfig(username="", password=""))
        ok, lines = engine.phish("bob_smith", "username")
        self.assertTrue(ok)
        self.assertTrue(any("to=bob@corp.com" in l for l in lines))
        self.assertTrue(any("channel=email" in l for l in lines))

    def test_phone_phish_requires_carrier(self):
        engine = SocialEngine()
        with patch.dict("os.environ", {}, clear=True):
            ok, lines = engine.phish("+15551234567", "phone")
        self.assertFalse(ok)
        self.assertTrue(any("carrier" in l for l in lines))

    def test_phone_phish_with_env_carrier_sends_sms(self):
        sent = {}
        def transport(sender, to, subject, body):
            sent.update(to=to, body=body)
            return True
        engine = SocialEngine()
        engine._mailer = Mailer(transport=transport,
                                config=MailConfig(username="", password=""))
        with patch.dict("os.environ", {"PHANTOM_SMS_CARRIER": "verizon"}):
            ok, lines = engine.phish("+15551234567", "phone")
        self.assertTrue(ok)
        self.assertTrue(any("channel=sms" in l for l in lines))
        self.assertIn("@vtext.com", sent["to"])


if __name__ == "__main__":
    unittest.main()
