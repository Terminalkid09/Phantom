"""Tests for the deep recon engine, hardened-target surface mapping and
anti-detection email hardening — no real network in unit tests (curl paths
are exercised live against the lab only)."""
import json
import re
import unittest
from unittest.mock import patch

import phantom.automation.social.recon as recon
from phantom.automation.social.recon import (
    Lead,
    ReconResult,
    _bio_similarity,
    _username_variants,
    _extract_json_blobs,
    _mine_graph,
    correlate_accounts,
    deep_recon,
)
from phantom.automation.surface import (
    SurfaceAsset,
    SurfaceResult,
    map_surface,
    surface_risk_summary,
)
from phantom.automation.social.mailers import MailConfig, Mailer
from phantom.automation.social.templates import build_html_body


class TestUsernameVariants(unittest.TestCase):
    def test_dots_and_underscores(self):
        v = _username_variants("mario.rossi")
        self.assertIn("mario_rossi", v)
        self.assertIn("mariorossi", v)
        self.assertNotIn("mario.rossi", v)  # base excluded

    def test_bounded(self):
        self.assertLessEqual(len(_username_variants("a_very_long_handle")), 6)

    def test_garbage(self):
        self.assertEqual(_username_variants(""), [])
        # a 2-char base still yields syntactically valid variants (probe
        # candidates, filtered later by the 3+ handle rule in mining)
        self.assertTrue(all(re.fullmatch(r"[a-z0-9._]{3,30}", v)
                            for v in _username_variants("ab")))


class TestBioSimilarity(unittest.TestCase):
    def test_identical(self):
        self.assertEqual(_bio_similarity("digital forensics rome", "digital forensics rome"), 1.0)

    def test_disjoint(self):
        self.assertEqual(_bio_similarity("chef pizza", "devops kubernetes"), 0.0)

    def test_partial(self):
        s = _bio_similarity("security analyst rome", "analyst milan")
        self.assertGreater(s, 0.0)
        self.assertLess(s, 1.0)


class TestCorrelateAccounts(unittest.TestCase):
    def test_avatar_match(self):
        a = ReconResult(username="x", platform="instagram")
        a.avatar_hash = "abc123"
        b = ReconResult(username="x", platform="tiktok")
        b.avatar_hash = "abc123"
        leads = correlate_accounts([a, b])
        self.assertTrue(any(l.evidence.startswith("avatar_match") for l in leads))

    def test_bio_match(self):
        a = ReconResult(username="x", platform="instagram")
        a.bio = "digital forensics analyst rome"
        b = ReconResult(username="y", platform="github")
        b.bio = "analyst rome forensics digital"
        leads = correlate_accounts([a, b])
        self.assertTrue(any(l.evidence.startswith("bio_sim") for l in leads))

    def test_no_match(self):
        a = ReconResult(username="x", platform="instagram")
        b = ReconResult(username="y", platform="github")
        self.assertEqual(correlate_accounts([a, b]), [])


class TestJsonBlobMining(unittest.TestCase):
    IG_BLOB = json.dumps({
        "graphql": {"user": {
            "full_name": "Mario Rossi",
            "profile_pic_url": "https://cdn.instagram.com/p.jpg",
            "edge_followed_by": {"count": 342},
            "edge_follow": {"count": 187},
        }}})

    def test_extract_blobs(self):
        html = f'<html><script type="application/ld+json">{TestJsonBlobMining.IG_BLOB}</script></html>'
        blobs = _extract_json_blobs(html)
        self.assertTrue(blobs)

    def test_mine_counts_and_name(self):
        html = f'<html><script type="application/ld+json">{TestJsonBlobMining.IG_BLOB}</script></html>'
        r = ReconResult(username="mario.rossi", platform="instagram")
        _mine_graph("mario.rossi", "instagram", html, r)
        self.assertEqual(r.followers, "342")
        self.assertEqual(r.full_name, "Mario Rossi")

    def test_commenter_handles(self):
        blob = json.dumps({"commentList": [
            {"text": "great shot @sara_dev, call me"},
            {"text": "@luca.trapani check this"}]})
        html = f'<script type="application/ld+json">{blob}</script>'
        r = ReconResult(username="mario.rossi", platform="instagram")
        _mine_graph("mario.rossi", "instagram", html, r)
        handles = {l.value for l in r.leads if l.kind in ("commenter", "tagged")}
        self.assertIn("sara_dev", handles)
        self.assertIn("luca.trapani", handles)
        self.assertNotIn("mario.rossi", handles)


class TestSecondHop(unittest.TestCase):
    """Second-hop graph mining: a stranger who interacts with BOTH the
    target and a circle member is mutual-graph evidence — and it is the
    path that still works on a PRIVATE target."""

    def _page(self, *handles):
        blob = json.dumps({"commentList": [{"text": f"@{h} hi"}
                                           for h in handles]})
        return f'<script type="application/ld+json">{blob}</script>'

    def test_a_mutual_handle_surfaces(self):
        primary = ReconResult(username="target", platform="instagram")
        primary.leads.append(Lead("commenter", "friend1", "instagram", "e", 0.5))
        primary.leads.append(Lead("commenter", "mutual", "instagram", "e", 0.5))
        with patch.object(recon, "_state_vote",
                          return_value=("public", 0.8, self._page("mutual"))):
            leads = recon._second_hop(primary, "instagram", {})
        mutual = {l.value: l.evidence for l in leads if l.kind == "commenter"}
        self.assertEqual(mutual.get("mutual"),
                         "mutual_graph_2hop_via_friend1")
        self.assertTrue(any(l.value == "friend1"
                            and l.evidence == "second_hop_public"
                            for l in leads))

    def test_no_circle_makes_no_network_calls(self):
        primary = ReconResult(username="t", platform="instagram")
        with patch.object(recon, "_state_vote") as sv:
            self.assertEqual(recon._second_hop(primary, "instagram", {}), [])
            sv.assert_not_called()

    def test_the_pass_is_bounded(self):
        primary = ReconResult(username="t", platform="instagram")
        for i in range(10):
            primary.leads.append(Lead("commenter", f"friend{i:02d}",
                                      "instagram", "e", 0.5))
        with patch.object(recon, "_state_vote",
                          return_value=("public", 0.8, self._page("x"))) as sv:
            recon._second_hop(primary, "instagram", {})
        self.assertLessEqual(sv.call_count, recon._SECOND_HOP_MAX)


class TestStateVote(unittest.TestCase):
    """Private-state voting with mocked curl."""

    def _run(self, bodies):
        calls = {"n": 0}

        def fake_exec(cmd, timeout=None):
            r = type("R", (), {"stdout": bodies[min(calls["n"], len(bodies) - 1)],
                               "stderr": ""})()
            calls["n"] += 1
            return r

        with patch("phantom.core.executor.execute_quiet", side_effect=fake_exec):
            return recon._state_vote("mario.rossi", "instagram")

    def test_private_consensus(self):
        state, conf, _ = self._run(["<html>login \u2022 instagram</html>"] * 2)
        self.assertEqual(state, "private")
        self.assertEqual(conf, 1.0)

    def test_flaky_response_resolved_by_vote(self):
        # first fetch private page, second a real public page: vote splits
        state, conf, _ = self._run(
            ["<html>sign up to see photos</html>",
             "<html>" + "x" * 3000 + "</html>"])
        self.assertIn(state, ("public", "private"))
        self.assertEqual(conf, 0.5)

    def test_missing(self):
        state, conf, _ = self._run(["", ""])
        self.assertEqual(state, "missing")


class TestDeepReconMarkers(unittest.TestCase):
    def test_no_username(self):
        ok, lines = deep_recon("")
        self.assertFalse(ok)
        self.assertTrue(lines[0].startswith("ERROR"))

    def test_markers_from_result(self):
        r = ReconResult(username="mario.rossi", platform="instagram",
                        state="private", state_confidence=1.0, bio="analyst")
        r.leads.append(Lead("account_link", "mariorossi", "tiktok",
                            "variant_probe", 0.55))
        lines = r.markers()
        self.assertTrue(any(l.startswith("RECON_STATE:") for l in lines))
        self.assertTrue(any(l.startswith("PROFILE:") for l in lines))
        self.assertTrue(any(l.startswith("ACCOUNT_LINK:") for l in lines))


class TestSurfaceModel(unittest.TestCase):
    def test_markers(self):
        r = SurfaceResult(domain="acme.com")
        r.assets = [
            SurfaceAsset("ct_host", "dev.acme.com", "seen in 2 certs", 0.7, "crt.sh"),
            SurfaceAsset("mail", "dmarc_missing", "no DMARC", 0.8, "dns_txt"),
            SurfaceAsset("vpn", "vpn.acme.com", "ivanti gateway", 0.85, "fp"),
        ]
        lines = r.markers()
        self.assertTrue(any("SURFACE_DOMAIN:" in l for l in lines))
        self.assertEqual(sum(1 for l in lines if "SURFACE_ASSET:" in l), 3)
        self.assertEqual(r.top(1)[0].kind, "vpn")

    def test_risk_summary(self):
        r = SurfaceResult(domain="acme.com")
        r.assets = [SurfaceAsset("mail", "x", "", 0.8, ""),
                    SurfaceAsset("mail", "y", "", 0.6, "")]
        self.assertEqual(surface_risk_summary(r)["mail"], 0.7)

    def test_map_surface_rejects_garbage(self):
        ok, lines = map_surface("")
        self.assertFalse(ok)
        ok, lines = map_surface("notadomain")
        self.assertFalse(ok)


class TestMailHardening(unittest.TestCase):
    def _mailer(self):
        return Mailer(MailConfig(smtp_host="h", smtp_port=25,
                                 username="u", password="p"),
                      transport=lambda *a, **k: True)

    def test_message_id_on_sender_domain(self):
        m = self._mailer()
        raw = m._build_message("Acme HR <hr@acme-corp.com>", "t@x.com",
                               "sub", "body").decode()
        self.assertIn("Message-ID: <", raw)
        self.assertIn("@acme-corp.com>", raw.split("Message-ID: <", 1)[1].split("\n", 1)[0] + ">")
        self.assertNotIn("phantom.local", raw)

    def test_no_phantom_headers(self):
        m = self._mailer()
        raw = m._build_message("A <a@corp.com>", "t@x.com", "s", "b").decode()
        self.assertIn("X-Mailer", raw)
        self.assertIn("Thread-Index", raw)
        self.assertIn("MIME-Version", raw)

    def test_reply_to_preserved(self):
        m = self._mailer()
        raw = m._build_message("A <a@corp.com>", "t@x.com", "s", "b",
                               reply_to="persona@grr.la").decode()
        self.assertIn("Reply-To: persona@grr.la", raw)


class TestHtmlVariation(unittest.TestCase):
    def test_two_sends_differ(self):
        a = build_html_body("s", "para one\n\npara two", "https://l.io/x",
                            "Continue", tracking_pixel="https://l.io/px/1")
        b = build_html_body("s", "para one\n\npara two", "https://l.io/x",
                            "Continue", tracking_pixel="https://l.io/px/1")
        self.assertNotEqual(a, b)  # per-send fingerprint variation

    def test_structure_intact(self):
        html = build_html_body("s", "intro\n\ntail", "https://l.io/x",
                               "Continue", tracking_pixel="https://l.io/px/1")
        self.assertIn("https://l.io/x", html)
        self.assertIn("https://l.io/px/1", html)
        self.assertIn("Continue", html)
        self.assertIn("<!--", html)  # noise comment present


class TestAmbiguity(unittest.TestCase):
    """Two close candidates below CONFIRMED pause for one operator
    decision instead of guessing (and never contact on a guess)."""

    def _scored(self, s1=0.70, s2=0.62):
        r = ReconResult(username="u", platform="tiktok")
        return [("u", "tiktok", "probable", s1, "e1", r),
                ("u2", "instagram", "probable", s2, "e2", r)]

    def test_clear_winner_no_question(self):
        from phantom.automation.social.recon import _resolve_ambiguity
        r = ReconResult(username="u", platform="tiktok")
        scored = [("u", "tiktok", "confirmed", 0.90, "e", r),
                  ("u2", "instagram", "probable", 0.60, "e", r)]
        self.assertEqual(_resolve_ambiguity(scored, ask=None), [])
        scored = [("u", "tiktok", "probable", 0.90, "e", r),
                  ("u2", "instagram", "probable", 0.60, "e", r)]
        self.assertEqual(_resolve_ambiguity(scored, ask=None), [])

    def test_tie_without_hook_records_widen(self):
        from phantom.automation.social.recon import _resolve_ambiguity
        lines = _resolve_ambiguity(self._scored(), ask=None)
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("IDENTITY_AMBIGUOUS:"))
        self.assertIn("decision=widen_once_then_halt", lines[0])

    def test_ask_same_resolves(self):
        from phantom.automation.social.recon import _resolve_ambiguity
        seen = {}

        def ask(desc, cands):
            seen["n"] = len(cands)
            return "same:u@tiktok"

        lines = _resolve_ambiguity(self._scored(), ask=ask)
        self.assertEqual(seen["n"], 2)
        self.assertTrue(lines[0].startswith("IDENTITY_RESOLVED:"))
        self.assertIn("winner=u", lines[0])

    def test_ask_stop_halts(self):
        from phantom.automation.social.recon import _resolve_ambiguity
        lines = _resolve_ambiguity(self._scored(),
                                   ask=lambda d, c: "stop")
        self.assertIn("by=operator_stop", lines[0])

    def test_present_candidate_renders(self):
        from phantom.automation.social.recon import present_candidate
        r = ReconResult(username="u", platform="instagram",
                        state="private", bio="hello world",
                        followers="120", following="80",
                        avatar_url="https://x/y.jpg")
        text = present_candidate(r)
        self.assertIn("@u (instagram)", text)
        self.assertIn("private", text)
        self.assertIn("https://x/y.jpg", text)
        self.assertIn("120", text)


if __name__ == "__main__":
    unittest.main()