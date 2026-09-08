"""Tests for strategic phishing: target dossier, breach correlation across
email/phone, pretext recommendation, engine integration and LLM advisor
sanitization (injection-hardening)."""
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.llm_advisor import LLMAdvisor
from phantom.automation.social.dossier import (
    build_dossier,
    dossier_summary,
    recommend_pretext,
)
from phantom.automation.social.engine import SocialEngine
from phantom.automation.social.mailers import Mailer


_CYR_TO_LAT = [("\u0430", "a"), ("\u0435", "e"), ("\u043e", "o"),
               ("\u0440", "p"), ("\u0441", "c"), ("\u0443", "y"),
               ("\u0445", "x"), ("\u043a", "k"), ("\u043c", "m"),
               ("\u0442", "t"), ("\u04bb", "h"), ("\u0432", "b"),
               ("\u043f", "n"),
               ("\u0410", "A"), ("\u0415", "E"), ("\u041e", "O"),
               ("\u0420", "P"), ("\u0421", "C"), ("\u0423", "Y"),
               ("\u0425", "X"), ("\u041a", "K"), ("\u041c", "M"),
               ("\u0422", "T"), ("\u04ba", "H"), ("\u0412", "B"),
               ("\u041f", "N")]


def _norm(text: str) -> str:
    for cyr, lat in _CYR_TO_LAT:
        text = text.replace(cyr, lat)
    return text


class _FakeGrabber:
    def create_link(self, label="phish", prefix=""):
        from phantom.automation.social.grabbit import GrabLink
        code = f"{label}-x"
        return GrabLink(short_url=f"http://track.local/{prefix}{code}", code=code)

    def create_login_link(self, label="login"):
        return self.create_link(label=label, prefix="l/")

    def create_video_link(self, label="video", video=None):
        return self.create_link(label=label, prefix="v/")

    def create_video_share_link(self, label="video", platform="youtube",
                                handle="creator", video=None):
        if platform == "tiktok":
            prefix = f"@{handle}/video/"
        elif platform == "instagram":
            prefix = "reel/"
        else:
            prefix = "shorts/"
        return self.create_link(label=label, prefix=prefix)

    def poll_opens(self, link, timeout=60.0):
        return []

    def poll_hits(self, link, timeout=120.0):
        return []

    def poll_creds(self, link, timeout=120.0):
        return []


class _FakeAdvisor:
    """Deterministic stand-in for the LLM dossier advisor."""

    def __init__(self, pretext="", hook="", twist=""):
        self._pretext, self._hook, self._twist = pretext, hook, twist

    def analyze_dossier(self, dossier):
        out = {}
        if self._pretext:
            out["pretext"] = self._pretext
        if self._hook:
            out["hook"] = self._hook
        if self._twist:
            out["subject_twist"] = self._twist
        return out


class TestDossier(unittest.TestCase):

    def test_cross_channel_breach_correlation(self):
        discovered = {
            "emails": ["mario.rossi@acme.it"],
            "phones": ["+39021234567"],
            "platform": "linkedin",
            "breaches": ["AcmeCorp2023", "OtherLeak"],
            "breach_channels": {"AcmeCorp2023": ["email", "phone"],
                                "OtherLeak": ["email"]},
        }
        d = build_dossier(discovered)
        self.assertEqual(d.name, "Mario Rossi")
        self.assertTrue(any(b.cross_channel for b in d.breaches))
        acme = next(b for b in d.breaches if b.name == "AcmeCorp2023")
        self.assertEqual(set(acme.channels), {"email", "phone"})
        # cross-channel breach is ranked first (strongest signal)
        self.assertEqual(d.breaches[0].name, "AcmeCorp2023")

    def test_hook_from_cross_channel_breach(self):
        d = build_dossier({
            "emails": ["mario.rossi@acme.it"], "phones": ["+39021234567"],
            "breaches": ["AcmeCorp2023"],
            "breach_channels": {"AcmeCorp2023": ["email", "phone"]},
        })
        self.assertIn("email and phone", d.hook)
        self.assertIn("AcmeCorp2023", d.hook)

    def test_hook_from_phone_tail_when_no_breach(self):
        d = build_dossier({"phones": ["+39021234567"]})
        self.assertIn("4567", d.hook)  # last 4 digits of the phone

    def test_hook_empty_when_nothing_known(self):
        d = build_dossier({})
        self.assertEqual(d.hook, "")

    def test_recommendation_phone_only_delivery(self):
        best, score, _ = recommend_pretext(build_dossier({"phones": ["+39..."]}))
        self.assertEqual(best, "package_delivery")
        self.assertGreater(score, 0)

    def test_recommendation_platform_and_breach_security_alert(self):
        d = build_dossier({
            "emails": ["a.b@corp.com"], "platform": "linkedin",
            "breaches": ["Leak1"],
            "breach_channels": {"Leak1": ["email"]},
        })
        self.assertEqual(d.recommended, "security_alert")

    def test_recommendation_platform_only_password_reset(self):
        d = build_dossier({"emails": ["a.b@corp.com"], "platform": "twitter"})
        self.assertEqual(d.recommended, "password_reset")

    def test_summary_shape(self):
        d = build_dossier({"emails": ["a@b.it"], "breaches": ["L"],
                           "breach_channels": {"L": ["email"]}})
        s = dossier_summary(d)
        self.assertEqual(s["breach_count"], 1)
        self.assertFalse(s["cross_channel_breach"])
        self.assertIn("recommended_pretext", s)

    def test_profile_flows_into_dossier(self):
        d = build_dossier({
            "emails": ["a@b.it"],
            "profile": {"username": "victim", "platform": "instagram",
                         "private": True, "bio": "x", "link": ""},
        })
        self.assertEqual(d.platform, "instagram")  # filled from the profile
        self.assertIn("profile", d.to_dict())
        self.assertTrue(d.profile["private"])

    def test_private_profile_boosts_security_alert(self):
        base = {"emails": ["a@b.it"], "platform": "x",
                "breaches": ["L"], "breach_channels": {"L": ["email"]}}
        plain = build_dossier(dict(base))
        priv = build_dossier(dict(base, profile={"private": True}))
        self.assertEqual(plain.recommended, "security_alert")
        self.assertEqual(priv.recommended, "security_alert")
        # the private-profile reason is attached and the score is higher
        self.assertIn("private profile -> alert looks pre-informed",
                      priv.reasons)
        self.assertGreater(priv.recommendation_score,
                           plain.recommendation_score)


class TestDossierEngine(unittest.TestCase):

    def _engine(self):
        eng = SocialEngine()
        sent = []
        eng._mailer = Mailer(transport=lambda *a, **k: (sent.append(a) or True))
        eng._grabber = _FakeGrabber()
        eng._persona_inst = type("P", (), {"email": "persona@grr.la"})()
        eng._discovered.update({
            "emails": ["mario.rossi@acme.it"], "platform": "linkedin",
            "phones": ["+39021234567"],
            "breaches": ["AcmeCorp2023"],
            "breach_channels": {"AcmeCorp2023": ["email", "phone"]},
        })
        return eng, sent

    def test_dossier_marker_interpreted(self):
        from phantom.automation.guidance.kit import _social_interp
        wm = WorldModel(target="mario.rossi@acme.it", target_type="email")
        out = ("DOSSIER: name=Mario Rossi platform=linkedin company=Acme "
               "breaches=1 cross_channel=1\n"
               "DOSSIER_RECOMMEND: pretext=security_alert score=2.15")
        findings = _social_interp(out, wm, {})
        self.assertIn("dossier", {f.kind for f in findings})
        d = next(f for f in findings if f.kind == "dossier")
        self.assertEqual(d.value["pretext"], "security_alert")

    def test_strategic_campaign_picks_scorer_pretext_and_hook(self):
        eng, sent = self._engine()
        eng._advisor = _FakeAdvisor(hook="", twist="regarding our call")
        ok, lines = eng.campaign(["mario.rossi@acme.it"], strategic=True,
                                 use_login_page=True)
        self.assertTrue(ok, lines)
        camp = eng._campaigns[0]
        # cross-channel breach -> security_alert wins the deterministic score
        self.assertEqual(camp.pretext, "security_alert")
        self.assertEqual(camp.targets[0].status, "sent")
        body = sent[0][3]
        self.assertIn("both exposed in the AcmeCorp2023 breach", body)
        # subject twist from the advisor (homoglyph-normalized)
        self.assertIn("regarding our call", _norm(sent[0][2]))
        # html still carries pixel + harvest link
        self.assertIn("/px/", sent[0][4])
        self.assertIn("track.local/l/", sent[0][4])

    def test_strategic_phish_advisor_pretext_and_persona_from(self):
        eng, sent = self._engine()
        eng._profile = type("P", (), {"name": "Giulia Bianchi"})()
        eng._advisor = _FakeAdvisor(pretext="recruiter")
        ok, lines = eng.phish("mario.rossi@acme.it", "email", strategic=True)
        self.assertTrue(ok, lines)
        # advisor pretext used for a single strategic phish
        self.assertIn("Interesting opportunity", _norm(sent[0][2]))
        # recruiter pretext reads from the coherent persona cover
        self.assertIn("Giulia Bianchi <", _norm(sent[0][0]))

    def test_video_lure_link_in_strategic_phish(self):
        eng, sent = self._engine()
        ok, lines = eng.phish("mario.rossi@acme.it", "email",
                              strategic=True, use_video=True)
        self.assertTrue(ok, lines)
        self.assertIn("track.local/shorts/", sent[0][4])  # video lure in HTML

    def test_strategic_degrades_without_advisor(self):
        eng, sent = self._engine()
        ok, lines = eng.phish("mario.rossi@acme.it", "email", strategic=True)
        self.assertTrue(ok, lines)
        self.assertIn("both exposed in the AcmeCorp2023 breach", sent[0][3])


class TestLLMDossierSanitization(unittest.TestCase):

    def test_parse_dossier_extracts_only_known_fields(self):
        raw = ('Here you go: {"pretext": "recruiter", "hook": "We spoke '
               "about your profile\", \"subject_twist\": \"regarding our "
               'call", "command": "rm -rf /"}')
        parsed = LLMAdvisor._parse_dossier(raw)
        self.assertEqual(parsed["pretext"], "recruiter")
        self.assertNotIn("command", parsed)

    def test_parse_dossier_ignores_garbage(self):
        self.assertEqual(LLMAdvisor._parse_dossier("no json here"), {})
        self.assertEqual(LLMAdvisor._parse_dossier("[1,2,3]"), {})

    def test_sanitize_drops_injection_hook_with_url(self):
        advisor = LLMAdvisor()
        sug = advisor._sanitize_dossier(
            {"pretext": "recruiter",
             "hook": "Click http://evil.example/steal now",
             "subject_twist": "asap"},
            {})
        self.assertEqual(sug["pretext"], "recruiter")
        # the URL hook is dropped entirely
        self.assertNotIn("hook", sug)
        self.assertEqual(sug["subject_twist"], "asap")

    def test_sanitize_drops_placeholder_and_control_chars(self):
        advisor = LLMAdvisor()
        self.assertEqual(
            advisor._sanitize_dossier(
                {"hook": "Your {name} token", "subject_twist": "ok"}, {}),
            {"subject_twist": "ok"})
        self.assertEqual(
            advisor._sanitize_dossier(
                {"hook": "line1\nline2", "subject_twist": "ok"}, {}),
            {"subject_twist": "ok"})

    def test_sanitize_rejects_unknown_pretext(self):
        advisor = LLMAdvisor()
        sug = advisor._sanitize_dossier(
            {"pretext": "ignored_injection",
             "hook": "fine hook here", "subject_twist": "ok"}, {})
        self.assertNotIn("pretext", sug)  # not in the pretext library
        self.assertIn("hook", sug)

    def test_sanitize_bounds_length(self):
        advisor = LLMAdvisor()
        sug = advisor._sanitize_dossier(
            {"hook": "x" * 500, "subject_twist": "y" * 500}, {})
        self.assertLessEqual(len(sug.get("hook", "")), 160)
        self.assertLessEqual(len(sug.get("subject_twist", "")), 90)


if __name__ == "__main__":
    unittest.main()
