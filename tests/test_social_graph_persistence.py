"""The manual social-recon path must PERSIST what it finds, and an absent
profile must never look like an account.

Two defects found by driving the operator's own commands on the live network
(2026-10-16, target `sentinel.dev.team@gmail.com`):

1. `social graph --run` printed four summary marker lines and threw the rest
   away. The per-item markers are the recon's real output (auto mode turns
   them into findings), so the very next `social graph` — offline, no network
   — answered "empty", and `--json`/`--graphml` exported an empty graph
   seconds after a run that had in fact looked at five platforms.
2. A probe that came back `missing` became a 0.70-confidence node labelled
   `platform=instagram`: the console claimed an instagram account for an EMAIL
   ADDRESS. `find("profile")` could not tell "probed, absent" from "found", so
   the same lie satisfied auto mode's DM/follow gates.
"""
import contextlib
import io
import os
import tempfile
import unittest
from unittest.mock import patch

from phantom.core.session import session

MARKERS_PUBLIC = [
    "RECON_STATE: username=polo_1300__ platform=instagram state=public conf=1.00",
    "RECON_STATE: username=polo_1300__ platform=instagram followers=812 "
    "following=430 posts=57",
    "PROFILE: username=polo_1300__ platform=instagram private=0 bio=caffe%20e%20codice link=",
    "ACCOUNT_LINK: handle=polo_1300__ platform=tiktok "
    "url=https://tiktok.com/polo_1300__ evidence=bio_link",
]

MARKERS_ABSENT = [
    "RECON_STATE: username=sentinel.dev.team@gmail.com platform=instagram "
    "state=missing conf=1.00",
]


class TestMarkersReachTheWorldModel(unittest.TestCase):

    def setUp(self):
        self._saved_dir = os.environ.get("PHANTOM_DATA_DIR")
        self._tmp = tempfile.mkdtemp(prefix="phantom-social-")
        os.environ["PHANTOM_DATA_DIR"] = self._tmp
        self._saved_target = session.target
        session.target = "polo_1300__"
        from phantom.core.knowledge import reset_wm
        reset_wm(target="polo_1300__")

    def tearDown(self):
        session.target = self._saved_target
        if self._saved_dir is None:
            os.environ.pop("PHANTOM_DATA_DIR", None)
        else:
            os.environ["PHANTOM_DATA_DIR"] = self._saved_dir

    def test_markers_become_findings(self):
        from phantom.automation.guidance.kit import store_social_markers
        from phantom.core.knowledge import session_wm
        stored = store_social_markers("\n".join(MARKERS_PUBLIC), session_wm())
        self.assertTrue(stored)
        kinds = {f.kind for f in session_wm().all_findings()}
        self.assertIn("profile", kinds)
        self.assertIn("account_link", kinds)

    def test_a_public_profile_is_a_strong_belief(self):
        from phantom.automation.guidance.kit import store_social_markers
        from phantom.core.knowledge import session_wm
        store_social_markers("\n".join(MARKERS_PUBLIC), session_wm())
        profile = next(f for f in session_wm().find("profile")
                       if f.value.get("username") == "polo_1300__")
        self.assertGreaterEqual(profile.confidence, 0.5)
        self.assertEqual(profile.value.get("state"), "public")

    def test_an_absent_profile_is_not_a_belief_in_an_account(self):
        from phantom.automation.guidance.kit import store_social_markers
        from phantom.core.knowledge import session_wm
        store_social_markers("\n".join(MARKERS_ABSENT), session_wm())
        profile = next(f for f in session_wm().find("profile")
                       if f.value.get("state") == "missing")
        self.assertLess(profile.confidence, 0.5)

    def test_run_then_offline_graph_shows_the_same_thing(self):
        """The regression itself: `--run` followed by the offline view."""
        from phantom.core.shell.commands import ops
        with patch("phantom.automation.social.recon.deep_recon",
                   return_value=(True, list(MARKERS_PUBLIC))):
            with contextlib.redirect_stdout(io.StringIO()):
                ops.cmd_social(None, "graph --run")
        with contextlib.redirect_stdout(io.StringIO()) as out:
            ops.cmd_social(None, "graph")
        rendered = out.getvalue()
        self.assertIn("polo_1300__", rendered)
        self.assertNotIn("empty", rendered)

    def test_run_marks_an_absent_probe_as_absent(self):
        from phantom.core.shell.commands import ops
        with patch("phantom.automation.social.recon.deep_recon",
                   return_value=(True, list(MARKERS_ABSENT))):
            with contextlib.redirect_stdout(io.StringIO()):
                ops.cmd_social(None, "graph --run")
        with contextlib.redirect_stdout(io.StringIO()) as out:
            ops.cmd_social(None, "graph")
        rendered = out.getvalue()
        self.assertIn("state=missing", rendered)
        self.assertNotIn("conf=0.70", rendered)

    def test_offline_graph_cannot_invent_a_platform_for_an_absence(self):
        from phantom.automation.social import social_graph as sg
        from phantom.automation.guidance.kit import store_social_markers
        from phantom.core.knowledge import session_wm
        store_social_markers("\n".join(MARKERS_ABSENT), session_wm())
        graph = sg.graph_from_wm(session_wm())
        node = next(iter(graph.nodes.values()))
        self.assertLess(node.confidence, 0.5)


class TestGatesIgnoreAbsentProfiles(unittest.TestCase):

    def setUp(self):
        self._saved = os.environ.get("PHANTOM_DATA_DIR")
        self._tmp = tempfile.mkdtemp(prefix="phantom-socialgate-")
        os.environ["PHANTOM_DATA_DIR"] = self._tmp
        from phantom.core.knowledge import reset_wm
        reset_wm(target="t")

    def tearDown(self):
        if self._saved is None:
            os.environ.pop("PHANTOM_DATA_DIR", None)
        else:
            os.environ["PHANTOM_DATA_DIR"] = self._saved

    def _store(self, markers):
        from phantom.automation.guidance.kit import store_social_markers
        from phantom.core.knowledge import session_wm
        store_social_markers("\n".join(markers), session_wm())
        return session_wm()

    def test_probe_gates_see_through_an_absence(self):
        from phantom.automation.guidance.kit import (_has_real_profile,
                                                    _not_profile_known,
                                                    _private_profile,
                                                    _real_profiles)
        wm = self._store(MARKERS_ABSENT)
        self.assertEqual(_real_profiles(wm), [])
        self.assertTrue(_not_profile_known()(wm))
        self.assertFalse(_has_real_profile()(wm))
        self.assertFalse(_private_profile(wm))

    def test_probe_gates_accept_a_real_account(self):
        from phantom.automation.guidance.kit import (_has_real_profile,
                                                    _not_profile_known,
                                                    _real_profiles)
        wm = self._store(MARKERS_PUBLIC)
        self.assertTrue(_real_profiles(wm))
        self.assertFalse(_not_profile_known()(wm))
        self.assertTrue(_has_real_profile()(wm))


class TestAbsentNodesInTheGraph(unittest.TestCase):

    def test_recon_result_absent_lowers_confidence_and_keeps_the_state(self):
        from phantom.automation.social import social_graph as sg

        class _R:
            username = "someone"
            platform = "instagram"
            state = "missing"
            full_name = ""
            leads = []

        graph = sg.graph_from_recon([_R()])
        node = next(iter(graph.nodes.values()))
        self.assertEqual(node.confidence, 0.25)
        self.assertEqual(node.attrs.get("state"), "missing")
        self.assertIn("state=missing", graph.render())

    def test_recon_result_present_stays_strong(self):
        from phantom.automation.social import social_graph as sg

        class _R:
            username = "polo_1300__"
            platform = "instagram"
            state = "public"
            full_name = "Polo"
            bio = "x"
            link = ""
            leads = []

        graph = sg.graph_from_recon([_R()])
        node = next(iter(graph.nodes.values()))
        self.assertEqual(node.confidence, 0.7)
        self.assertNotIn("state=missing", graph.render())

    def test_private_state_is_shown(self):
        from phantom.automation.social import social_graph as sg
        g = sg.SocialGraph()
        g.add_handle("hidden_one", platform="instagram", state="private",
                     confidence=0.7)
        self.assertIn("state=private", g.render())


if __name__ == "__main__":
    unittest.main()
