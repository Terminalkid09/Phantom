"""Tests for the coherent social persona cover: profile coherence, avatar
generation, engine integration and marker interpretation."""
import os
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.social.engine import SocialEngine
from phantom.automation.social.persona import (
    _JOB_TIERS,
    generate_avatar,
    generate_profile,
)


class TestPersonaProfile(unittest.TestCase):

    def test_deterministic_with_seed(self):
        a = generate_profile(seed=42)
        b = generate_profile(seed=42)
        self.assertEqual(a.name, b.name)
        self.assertEqual(a.age, b.age)
        self.assertEqual(a.job_title, b.job_title)
        self.assertEqual(a.bio, b.bio)

    def test_age_consistent_with_job_tier(self):
        for seed in range(50):
            p = generate_profile(seed=seed)
            tier = next(t for t in _JOB_TIERS
                        if p.job_title in t["titles"])
            lo, hi = tier["age"]
            self.assertGreaterEqual(p.age, lo, f"{p.job_title} @ {p.age}")
            self.assertLessEqual(p.age, hi, f"{p.job_title} @ {p.age}")
            # an intern is never 47, a founder is never 19 — guaranteed by
            # the band check above, asserted here for the reader
            if "Intern" in p.job_title or "Trainee" in p.job_title:
                self.assertLessEqual(p.age, 25)

    def test_locale_italian_city(self):
        p = generate_profile(seed=7, locale="it")
        self.assertEqual(p.country, "Italy")

    def test_bio_coherent_no_placeholders(self):
        p = generate_profile(seed=11)
        self.assertIn(p.city, p.bio)
        for token in ("{", "}", "None"):
            self.assertNotIn(token, p.bio)

    def test_avatar_renders_or_graceful_none(self):
        p = generate_profile(seed=3)
        path = generate_avatar(p)
        if path is not None:
            self.assertTrue(os.path.exists(path), path)
        else:
            # Pillow missing — acceptable degradation, profile still works
            self.assertIsNone(path)

    def test_profile_to_dict_shape(self):
        p = generate_profile(seed=5)
        d = p.to_dict()
        for k in ("name", "age", "job_title", "city", "bio", "avatar"):
            self.assertIn(k, d)


class TestPersonaProfileEngine(unittest.TestCase):

    def test_engine_emits_persona_profile_marker(self):
        eng = SocialEngine()
        ok, lines = eng.persona_profile(seed=99)
        self.assertTrue(ok, lines)
        joined = "\n".join(lines)
        self.assertTrue(joined.startswith("PERSONA_PROFILE:"), joined)
        self.assertIn("name=", joined)
        self.assertIn("job=", joined)
        self.assertIsNotNone(eng._profile)

    def test_marker_interpreted_to_finding(self):
        from phantom.automation.guidance.kit import _social_interp
        wm = WorldModel(target="mario.rossi@acme.it", target_type="email")
        # marker protocol: values are single tokens (spaces -> underscores)
        out = ("PERSONA_PROFILE: name=Mario_Rossi age=29 "
               "job=Developer location=Milano avatar=/tmp/a.png")
        findings = _social_interp(out, wm, {})
        kinds = {f.kind for f in findings}
        self.assertIn("persona_profile", kinds)
        prof = next(f for f in findings if f.kind == "persona_profile")
        self.assertEqual(prof.value["name"], "Mario_Rossi")
        self.assertEqual(prof.value["age"], "29")


if __name__ == "__main__":
    unittest.main()
