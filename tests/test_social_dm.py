"""Tests for the social DM engine: pretext library, transports, launcher,
SocialEngine.dm(), marker interpretation and the agent capability."""
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.social.engine import SocialEngine
from phantom.automation.social.social_dm import (
    DMTransport,
    FakeDMTransport,
    dm_delivery_report,
    dm_pretext_ids,
    get_dm_transport,
    launch_dm,
    render_dm_pretext,
)


class TestDMPretexts(unittest.TestCase):

    def test_all_pretexts_render_short_and_clean(self):
        for pid in dm_pretext_ids():
            text = render_dm_pretext(
                pid, {"name": "Mario", "platform": "linkedin"},
                link="http://t/abc")
            self.assertIsNotNone(text, pid)
            self.assertIn("http://t/abc", text, pid)
            self.assertNotIn("{", text, pid)
            self.assertNotIn("None", text, pid)
            self.assertLessEqual(len(text), 320, pid)  # DM length

    def test_unknown_pretext_and_missing_context(self):
        self.assertIsNone(render_dm_pretext("nope", {}, link="http://t/x"))
        text = render_dm_pretext("recruiter", {}, link="http://t/x")
        self.assertIn("there", text)  # degrades, no crash
        self.assertNotIn("None", text)


class TestDMTransportSelection(unittest.TestCase):

    def test_console_transport_always_available(self):
        self.assertIsNotNone(get_dm_transport("console"))

    def test_no_env_means_no_auto_transport(self):
        import phantom.automation.social.social_dm as dm_mod
        old_t, old_d = (dm_mod.TelegramDMTransport.__init__,
                        dm_mod.DiscordDMTransport.__init__)
        try:
            def _t(self, token=""):
                self.token = ""
            dm_mod.TelegramDMTransport.__init__ = _t
            dm_mod.DiscordDMTransport.__init__ = lambda self, webhook="": (
                setattr(self, "webhook", ""))
            self.assertIsNone(get_dm_transport("auto"))
        finally:
            dm_mod.TelegramDMTransport.__init__ = old_t
            dm_mod.DiscordDMTransport.__init__ = old_d

    def test_telegram_transport_requires_token(self):
        import phantom.automation.social.social_dm as dm_mod
        old = dm_mod.TelegramDMTransport.__init__
        try:
            dm_mod.TelegramDMTransport.__init__ = lambda self, token="": (
                setattr(self, "token", token or "123:abc"))
            t = get_dm_transport("telegram")
            self.assertIsNotNone(t)
            self.assertEqual(t.platform, "telegram")
            self.assertEqual(t.token, "123:abc")
        finally:
            dm_mod.TelegramDMTransport.__init__ = old


class TestLaunchDM(unittest.TestCase):

    def test_launch_sends_and_reports(self):
        fake = FakeDMTransport()
        ok, lines = launch_dm(["@mario"], pretext="recruiter",
                              link="http://t/abc", transport=fake)
        self.assertTrue(ok, lines)
        self.assertEqual(len(fake.sent), 1)
        self.assertIn("http://t/abc", fake.sent[0][1])
        self.assertTrue(any(l.startswith("DM_SENT:") for l in lines), lines)
        report = dm_delivery_report(lines)
        self.assertEqual(report["sent"], 1)
        self.assertEqual(report["delivered"], 1)
        self.assertEqual(report["platforms"], ["fake"])

    def test_multi_target_each_gets_own_dm(self):
        fake = FakeDMTransport()
        ok, lines = launch_dm(["@a", "@b"], pretext="security_verify",
                              link="http://t/x", transport=fake)
        self.assertTrue(ok, lines)
        self.assertEqual(len(fake.sent), 2)
        self.assertEqual(dm_delivery_report(lines)["sent"], 2)

    def test_no_transport_degrades_without_hanging(self):
        import phantom.automation.social.social_dm as dm_mod
        with unittest.mock.patch.object(
                dm_mod, "get_dm_transport", return_value=None):
            ok, lines = launch_dm(["@a"], pretext="security_verify",
                                  link="http://t/x")
        self.assertFalse(ok)
        self.assertTrue(any("no_dm_transport" in l for l in lines), lines)

    def test_unknown_pretext_rejected(self):
        ok, lines = launch_dm(["@a"], pretext="nope", link="http://t/x",
                              transport=FakeDMTransport())
        self.assertFalse(ok)
        self.assertTrue(any("unknown_dm_pretext" in l for l in lines), lines)

    def test_failed_transport_marks_delivered_0(self):
        class _Dead(DMTransport):
            platform = "dead"

            def send(self, target, text, timeout=15.0):
                return False
        ok, lines = launch_dm(["@a"], pretext="prize", link="http://t/x",
                              transport=_Dead())
        self.assertFalse(ok)
        self.assertTrue(any("delivered=0" in l for l in lines), lines)


class TestSocialEngineDM(unittest.TestCase):

    class _FakeGrabber:
        def create_link(self, label="phish", prefix=""):
            from phantom.automation.social.grabbit import GrabLink
            code = f"{label}-x"
            return GrabLink(short_url=f"http://track.local/{prefix}{code}",
                            code=code)

        def create_login_link(self, label="login"):
            return self.create_link(label=label, prefix="l/")

    def _engine(self, fake_transport):
        eng = SocialEngine()
        eng._grabber = self._FakeGrabber()
        eng._discovered.update({"emails": ["mario.rossi@acme.it"],
                                "platform": "linkedin"})
        import phantom.automation.social.social_dm as dm_mod
        self._patcher = unittest.mock.patch.object(
            dm_mod, "get_dm_transport", return_value=fake_transport)
        self._patcher.start()
        self.addCleanup(self._patcher.stop)
        return eng

    def test_engine_dm_sends_marker_per_target(self):
        fake = FakeDMTransport()
        eng = self._engine(fake)
        ok, lines = eng.dm(["@mario"], pretext="recruiter")
        self.assertTrue(ok, lines)
        self.assertEqual(len(fake.sent), 1)
        joined = "\n".join(lines)
        self.assertIn("DM_SENT: to=@mario platform=fake", joined)
        self.assertIn("http://track.local/", joined)

    def test_engine_dm_unknown_pretext_rejected(self):
        eng = self._engine(FakeDMTransport())
        ok, lines = eng.dm(["@mario"], pretext="nope")
        self.assertFalse(ok)
        self.assertTrue(any("unknown_dm_pretext" in l for l in lines), lines)

    def test_engine_dm_no_transport_error(self):
        eng = self._engine(None)  # get_dm_transport returns None
        ok, lines = eng.dm(["@mario"])
        self.assertFalse(ok)
        self.assertTrue(any("no_dm_transport" in l for l in lines), lines)


class TestDMInterp(unittest.TestCase):

    def test_dm_sent_marker_to_finding(self):
        from phantom.automation.guidance.kit import _social_interp
        wm = WorldModel(target="@mario", target_type="username")
        out = ("DM_SENT: to=@mario platform=telegram "
               "link=http://t/l/c delivered=1")
        findings = _social_interp(out, wm, {})
        dm = [f for f in findings if f.kind == "dm_sent"]
        self.assertEqual(len(dm), 1)
        self.assertTrue(dm[0].value["delivered"])
        self.assertEqual(dm[0].value["platform"], "telegram")
        self.assertEqual(dm[0].confidence, 0.8)

    def test_undelivered_dm_lower_confidence(self):
        from phantom.automation.guidance.kit import _social_interp
        wm = WorldModel(target="@mario", target_type="username")
        out = "DM_SENT: to=@mario platform=fake link=http://t/x delivered=0"
        findings = _social_interp(out, wm, {})
        dm = [f for f in findings if f.kind == "dm_sent"]
        self.assertEqual(len(dm), 1)
        self.assertFalse(dm[0].value["delivered"])
        self.assertLess(dm[0].confidence, 0.8)

    def test_dm_launch_capability_registered(self):
        from phantom.automation.guidance.commands import make_registry
        cap = make_registry().get("dm_launch")
        self.assertIsNotNone(cap)
        self.assertEqual(cap.category, "social")
        self.assertIn("dm_sent", cap.effects)
        # planner knows dm_sent is produced by dm_launch
        from phantom.automation.planner import _FACT_SOURCES
        self.assertIn("dm_launch", _FACT_SOURCES["dm_sent"])


if __name__ == "__main__":
    unittest.main()
