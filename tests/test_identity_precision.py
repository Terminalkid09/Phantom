"""Identity correlation must be PRECISE, not merely plausible.

The failure that harms a third party is a FALSE CONFIRMATION: two different
people declared the same person, and the chain contacts the wrong one. The
module's thresholds were designed for that (`identity_confidence`), but
`recon.correlate_accounts` carried its own numbers — a shared avatar hash was
emitted at confidence 0.85 — so the same pair could read "0.85 linked" in a
report and `UNRELATED` in the confidence marker. These tests pin one scorer
and then MEASURE its precision on a labelled fixture set, because a threshold
nobody measures is a threshold that drifts.

Every pair below is synthetic. Nothing here touches an account.
"""
import unittest

from phantom.automation.social import identity_confidence as IC
from phantom.automation.social.recon import ReconResult, correlate_accounts


def _pair(primary, candidate):
    return correlate_accounts([_result("instagram", primary),
                               _result("tiktok", candidate)])


def _result(platform, data):
    result = ReconResult(username=data.get("username", "x"), platform=platform)
    for field in ("bio", "avatar_hash", "avatar_dhash", "link", "full_name"):
        setattr(result, field, data.get(field, ""))
    result.emails = list(data.get("emails", []))
    for handle in data.get("graph", []):
        result.leads.append(_lead("commenter", handle))
    for handle in data.get("outbound", []):
        result.leads.append(_lead("account_link", handle))
    return result


def _lead(kind, value):
    from phantom.automation.social.recon import Lead
    return Lead(kind, value, "", "", 0.5)


AVATAR = "9f2c1d3b4a5e6f708192a3b4c5d6e7f8"


class TestASingleSignalNeverConfirms(unittest.TestCase):
    def test_a_shared_avatar_alone_is_supporting_only(self):
        """The operator's rule: an avatar proves nothing by itself.

        Memes, platform defaults and stolen pictures are shared avatars on
        unrelated people. 0.85 here is what made a report claim a link.
        """
        leads = _pair({"username": "alice", "avatar_hash": AVATAR},
                      {"username": "bob", "avatar_hash": AVATAR})
        self.assertEqual(len(leads), 1)
        self.assertLess(leads[0].confidence, IC.PROBABLE_THRESHOLD)
        self.assertIn("tier=unrelated", leads[0].evidence)

    def test_a_shared_handle_alone_is_noise(self):
        leads = _pair({"username": "alice"}, {"username": "alice"})
        self.assertTrue(leads and all(l.confidence < IC.PROBABLE_THRESHOLD
                                      for l in leads))

    def test_a_generic_bio_is_not_evidence(self):
        """"student gamer" is thousands of people, not one person twice."""
        leads = _pair({"username": "alice", "bio": "student gamer"},
                      {"username": "bob", "bio": "gamer student"})
        for lead in leads:
            self.assertLess(lead.confidence, IC.PROBABLE_THRESHOLD)


class TestSamePersonProofStillConfirms(unittest.TestCase):
    def test_a_bidirectional_cross_link_confirms(self):
        leads = _pair({"username": "alice", "link": "tiktok.com/@bob"},
                      {"username": "bob", "bio": "instagram: @alice"})
        self.assertEqual(len(leads), 1)
        self.assertGreaterEqual(leads[0].confidence, IC.CONFIRMED_THRESHOLD)
        self.assertIn("tier=confirmed", leads[0].evidence)

    def test_a_shared_email_confirms(self):
        leads = _pair({"username": "alice", "emails": ["a@example.test"]},
                      {"username": "bob", "emails": ["a@example.test"]})
        self.assertGreaterEqual(leads[0].confidence, IC.CONFIRMED_THRESHOLD)

    def test_a_namesake_is_downgraded_not_confirmed(self):
        """Same avatar AND two different real names: a namesake, not self."""
        leads = _pair(
            {"username": "alice", "avatar_hash": AVATAR,
             "full_name": "Alice Rossi", "emails": ["a@example.test"]},
            {"username": "bob", "avatar_hash": AVATAR,
             "full_name": "Bruno Bianchi"})
        self.assertTrue(leads)
        for lead in leads:
            self.assertLess(lead.confidence, IC.CONFIRMED_THRESHOLD)


class TestTheCorrelationUsesOneScorer(unittest.TestCase):
    """The two surfaces must not disagree about the same pair."""

    def test_recon_confidence_equals_the_identity_model_score(self):
        primary = {"username": "alice", "avatar_hash": AVATAR,
                   "bio": "security researcher rome"}
        candidate = {"username": "bob", "avatar_hash": AVATAR,
                     "bio": "security researcher rome"}
        leads = _pair(primary, candidate)
        self.assertEqual(len(leads), 1)
        scored = IC.score_lead(
            "instagram",
            {"username": "alice", "avatar_hash": AVATAR,
             "bio": "security researcher rome", "outbound": [], "graph": [],
             "emails": []},
            {"username": "bob", "avatar_hash": AVATAR,
             "bio": "security researcher rome", "graph": [], "emails": []})
        self.assertAlmostEqual(leads[0].confidence, scored.score, places=6)
        self.assertIn(f"tier={scored.tier}", leads[0].evidence)


# ── the measured number ────────────────────────────────────────────────────
#: (label, primary, candidate). ``label`` is the ground truth of the PAIR:
#: "same" = one person with two accounts, "different" = two people.
PAIRS = (
    ("same", {"username": "a", "link": "tiktok.com/@b"},
     {"username": "b", "bio": "my insta: @a"}),
    ("same", {"username": "a", "emails": ["x@example.test"]},
     {"username": "b", "emails": ["x@example.test"]}),
    # two agreeing signals (avatar + real name in the bio), which is the
    # documented shape of a PROBABLE lead: an avatar alone stays supporting.
    ("same", {"username": "a", "avatar_hash": AVATAR,
              "full_name": "Alice Rossi"},
     {"username": "b", "avatar_hash": AVATAR,
      "full_name": "Alice Rossi", "bio": "Alice Rossi - security, rome"}),
    ("different", {"username": "a", "avatar_hash": AVATAR},
     {"username": "b", "avatar_hash": AVATAR}),
    ("different", {"username": "a", "bio": "student gamer"},
     {"username": "b", "bio": "gamer student"}),
    ("different", {"username": "mario", "full_name": "Mario Rossi"},
     {"username": "mario", "full_name": "Luca Bianchi"}),
    ("different", {"username": "a", "avatar_hash": AVATAR,
                   "full_name": "Alice Rossi"},
     {"username": "b", "avatar_hash": AVATAR,
      "full_name": "Bruno Bianchi"}),
    ("different", {"username": "a", "bio": "chef pizza napoli"},
     {"username": "b", "bio": "devops kubernetes milano"}),
)


class TestMeasuredPrecision(unittest.TestCase):
    def test_no_false_confirmation_on_the_fixture_set(self):
        """The safety-critical metric: precision at CONFIRMED must be 100%.

        A missed link costs a second attempt; a false one contacts an innocent
        third party. The two are not symmetric, so the assertion is absolute
        rather than a ratio.
        """
        false_confirmations = []
        confirmed = 0
        for label, primary, candidate in PAIRS:
            for lead in _pair(primary, candidate):
                if lead.confidence >= IC.CONFIRMED_THRESHOLD:
                    confirmed += 1
                    if label != "same":
                        false_confirmations.append((label, lead.value,
                                                    lead.confidence))
        self.assertEqual(false_confirmations, [],
                         "a DIFFERENT person was confirmed as the same one")
        self.assertGreater(confirmed, 0,
                           "no fixture is confirmable: the metric would be "
                           "vacuous")

    def test_every_true_link_is_at_least_probable(self):
        """Recall at the PROBABLE floor: the operator can still see the link.

        A confirmed-only gate would be safe and useless; a probable tier is
        what keeps a real lead visible without authorising contact.
        """
        missed = []
        for label, primary, candidate in PAIRS:
            if label != "same":
                continue
            leads = _pair(primary, candidate)
            best = max((l.confidence for l in leads), default=0.0)
            if best < IC.PROBABLE_THRESHOLD:
                missed.append((primary.get("username"), candidate.get("username"),
                              best))
        self.assertEqual(missed, [])


if __name__ == "__main__":
    unittest.main()
