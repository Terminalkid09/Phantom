"""Tests for profile reverse-engineering (private/public detection, bio/link/
handle extraction, cross-platform mapping) and marker interpretation."""
import unittest
from types import SimpleNamespace

from unittest import mock

from phantom.automation.belief import WorldModel
from phantom.automation.social.engine import SocialEngine

_INSTA_PRIVATE = """<html><head>
<meta name="description" content="This Account is Private">
<title>@victim</title></head><body>This Account is Private
Follow to see their photos and videos.</body></html>"""

_INSTA_PUBLIC = """<html><head>
<meta name="description" content="Digital nomad | @victim | linktr.ee/victim
contact me at hello@victim.io">
<title>@victim</title></head><body>1,234 followers</body></html>"""


def _res(out: str):
    return SimpleNamespace(stdout=out, returncode=0, stderr="")


def _fake_executor(command: str, timeout=0):
    """Deterministic stand-in for the subprocess executor."""
    if "instagram.com" in command:
        if "private" in command or True:
            # public page for the public test, private for the private one
            if "hello@victim.io" not in command:
                return _res(_INSTA_PRIVATE)
            return _res(_INSTA_PUBLIC)
    if "sherlock" in command:
        return _res("")
    # other platforms -> account not found / empty
    return _res("<html>couldn't find this account</html>")


class TestProfileRecon(unittest.TestCase):

    def _engine(self):
        return SocialEngine()

    def test_private_profile_detected(self):
        eng = self._engine()
        with mock.patch("phantom.core.executor.execute_quiet",
                        side_effect=_fake_executor):
            ok, lines = eng.profile_recon("victim", platform="instagram")
        self.assertTrue(ok, lines)
        joined = "\n".join(lines)
        self.assertIn("PROFILE: username=victim platform=instagram private=1",
                      joined)
        self.assertEqual(eng._discovered["profile"]["private"], True)

    def test_public_profile_extracts_bio_link_handle_email(self):
        eng = self._engine()
        bio = eng._extract_bio(_INSTA_PUBLIC, "instagram")
        self.assertIn("Digital nomad", bio)
        self.assertEqual(eng._extract_link(bio), "https://linktr.ee/victim")
        self.assertIn("victim", eng._extract_handles(bio))
        self.assertIn("hello@victim.io",
                      eng._extract_emails(_INSTA_PUBLIC + " " + bio))

    def test_missing_account_no_profile(self):
        eng = self._engine()
        with mock.patch("phantom.core.executor.execute_quiet",
                        side_effect=lambda cmd, **k: _res(
                            "<html>couldn't find this account</html>")):
            ok, lines = eng.profile_recon("ghost", platform="tiktok")
        # contract change 2026-11-05: "no account" is False. It used to be
        # (True, []), which made the caller unable to tell a miss from a
        # hit that carried nothing.
        self.assertFalse(ok)
        self.assertEqual(lines, [])

    def test_boilerplate_bio_is_not_attributed(self):
        """Platform furniture is not a bio and not an attribution.

        Measured 2026-11-05: a personal handle came back as
        `platform=telegram bio=Fast._Secure._Powerful.` — Telegram's own
        tagline, rendered on every handle page.
        """
        from phantom.automation.social.recon import is_platform_boilerplate
        self.assertTrue(is_platform_boilerplate(
            "Fast. Secure. Powerful.", "telegram"))
        self.assertTrue(is_platform_boilerplate(
            "Fast. Secure. Powerful.", "instagram"))  # whole-text rule
        self.assertFalse(is_platform_boilerplate(
            "Digital nomad | photographer, DM me", "instagram"))

        page = ('<html><head><meta name="description" '
                'content="Fast. Secure. Powerful.">'
                '<title>Telegram</title></head>'
                '<body>Telegram</body></html>')
        eng = self._engine()
        with mock.patch("phantom.core.executor.execute_quiet",
                        side_effect=lambda cmd, **k: _res(page)):
            ok, lines = eng.profile_recon("someone", platform="instagram")
        self.assertFalse(ok, lines)
        self.assertEqual(lines, [])
        self.assertFalse(eng._discovered.get("profile"))

    def test_unrelated_accounts_correlate_to_unknown(self):
        """Two handles with nothing shared must NOT be called the same person."""
        from phantom.automation.social.recon import ReconResult, correlate_accounts

        # Different platforms on purpose: same-platform pairs are skipped by
        # design, so a same-platform fixture would prove nothing.
        alice = ReconResult(username="alice_ops", platform="instagram",
                            state="public",
                            bio="Backend engineer building distributed systems")
        bob = ReconResult(username="bob_sea", platform="tiktok",
                          state="public",
                          bio="Marine biologist photographing coral reefs")
        self.assertEqual(correlate_accounts([alice, bob]), [])

        # Positive control: the same function MUST link a pair that carries
        # shared evidence, so the empty result above means "no evidence" and
        # not "the correlation is a no-op".
        one = ReconResult(username="a1", platform="instagram",
                          state="public", avatar_hash="ab" * 16)
        two = ReconResult(username="a2", platform="tiktok",
                          state="public", avatar_hash="ab" * 16)
        linked = correlate_accounts([one, two])
        self.assertTrue(any(lead.kind == "account_link" for lead in linked))

    def test_bio_extractor_variants(self):
        eng = self._engine()
        html = ('<meta property="og:description" content="Artist & '
                'designer">')
        self.assertIn("Artist", eng._extract_bio(html, "instagram"))

    def test_handles_and_emails_regexes(self):
        eng = self._engine()
        text = "Follow @studio.x and @partner for collabs — a@b.co"
        self.assertIn("studio.x", eng._extract_handles(text))
        self.assertIn("a@b.co", eng._extract_emails(text))

    def test_markers_interpreted_to_findings(self):
        from phantom.automation.guidance.kit import _social_interp
        wm = WorldModel(target="victim", target_type="username")
        out = "\n".join([
            "PROFILE: username=victim platform=instagram private=1 "
            "bio=Digital_nomad link=",
            "ACCOUNT_LINK: handle=victim platform=x url=https://x.com/victim",
        ])
        findings = _social_interp(out, wm, {})
        kinds = {f.kind for f in findings}
        self.assertIn("profile", kinds)
        self.assertIn("account_link", kinds)
        prof = next(f for f in findings if f.kind == "profile")
        self.assertTrue(prof.value["private"])
        self.assertEqual(prof.value["platform"], "instagram")


class TestPersonaAudience(unittest.TestCase):

    def _prof(self, **kw):
        from phantom.automation.social.persona import generate_profile
        return generate_profile(seed=123, **kw)

    def test_high_school_audience(self):
        p = self._prof(audience="high", locale="it")
        self.assertEqual(p.audience, "high")
        self.assertGreaterEqual(p.age, 14)
        self.assertLessEqual(p.age, 19)
        self.assertTrue(p.job_title.startswith("Student at"))
        self.assertTrue(p.school)
        self.assertIn(p.school, p.bio)

    def test_middle_school_audience(self):
        p = self._prof(audience="middle")
        self.assertGreaterEqual(p.age, 11)
        self.assertLessEqual(p.age, 14)

    def test_university_audience(self):
        p = self._prof(audience="university")
        self.assertGreaterEqual(p.age, 18)
        self.assertLessEqual(p.age, 25)

    def test_unknown_audience_falls_back_to_professional(self):
        p = self._prof(audience="ceo")  # not in the audience map
        self.assertEqual(p.audience, "professional")
        self.assertGreaterEqual(p.age, 19)

    def test_professional_age_band_still_holds(self):
        from phantom.automation.social.persona import _JOB_TIERS
        p = self._prof()
        tier = next(t for t in _JOB_TIERS if p.job_title in t["titles"])
        self.assertGreaterEqual(p.age, tier["age"][0])
        self.assertLessEqual(p.age, tier["age"][1])

    def test_engine_profile_marker_with_audience(self):
        eng = SocialEngine()
        ok, lines = eng.persona_profile(seed=5, audience="high")
        self.assertTrue(ok, lines)
        joined = "\n".join(lines)
        self.assertIn("PERSONA_PROFILE:", joined)
        self.assertIn("job=Student_at_", joined)


if __name__ == "__main__":
    unittest.main()
