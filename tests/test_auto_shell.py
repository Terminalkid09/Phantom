"""Tests for the dedicated AUTO-MODE CLI shell (phantom/core/auto_shell.py)."""
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from phantom.core.auto_shell import (
    AutoShell,
    _context_hint,
    _status_bar,
    build_auto_banner,
)
from phantom.core.session import session


def _shell() -> AutoShell:
    return AutoShell()


class TestBannerAndStatus(unittest.TestCase):

    def test_banner_mentions_auto(self):
        banner = build_auto_banner()
        self.assertIn("PHANTOM.AUTO", banner)
        self.assertIn("Autonomous", banner)

    def test_status_bar_shows_targets_and_flags(self):
        s = _shell()
        s.targets = ["bob@corp.com"]
        s.flags["aggressive"] = True
        s.flags["agents"] = 2
        bar = _status_bar(s.targets, s.flags)
        self.assertIn("1 target", bar)
        self.assertIn("aggressive", bar)
        self.assertIn("-a2", bar)

    def test_context_hint_guides_first_steps(self):
        self.assertIn("targets add", _context_hint([], False))
        self.assertIn("launch", _context_hint(["x"], False))
        self.assertIn("export", _context_hint(["x"], True))


class TestTargets(unittest.TestCase):

    def test_add_rm_list(self):
        s = _shell()
        s.do_targets("add bob@corp.com")
        s.do_targets("add 10.0.0.5,alice@corp.com")
        self.assertEqual(s.targets, ["bob@corp.com", "10.0.0.5", "alice@corp.com"])
        s.do_targets("rm 10.0.0.5")
        self.assertNotIn("10.0.0.5", s.targets)
        s.do_targets("rm 10.0.0.5")  # idempotent, no crash
        self.assertEqual(len(s.targets), 2)

    def test_add_dedupes(self):
        s = _shell()
        s.do_targets("add bob@corp.com")
        s.do_targets("add bob@corp.com")
        self.assertEqual(len(s.targets), 1)

    def test_targets_requires_subcommand(self):
        s = _shell()
        s.do_targets("bogus x")  # must not crash
        self.assertEqual(s.targets, [])


class TestScope(unittest.TestCase):

    def setUp(self):
        self._old = list(session.scope or [])

    def tearDown(self):
        session.scope = self._old

    def test_add_rm(self):
        s = _shell()
        s.do_scope("add 10.0.0.0/8")
        self.assertIn("10.0.0.0/8", session.scope)
        s.do_scope("rm 10.0.0.0/8")
        self.assertNotIn("10.0.0.0/8", session.scope)


class TestFlags(unittest.TestCase):

    def test_show_and_set_bool(self):
        s = _shell()
        s.do_flags("aggressive on")
        self.assertTrue(s.flags["aggressive"])
        s.do_flags("stealth off")
        self.assertFalse(s.flags["stealth"])
        s.do_flags("aggressive bogus")  # invalid -> rejected
        self.assertTrue(s.flags["aggressive"])

    def test_set_agents(self):
        s = _shell()
        s.do_flags("agents 3")
        self.assertEqual(s.flags["agents"], 3)
        s.do_flags("agents 0")
        self.assertEqual(s.flags["agents"], 0)
        s.do_flags("agents banana")  # rejected
        self.assertEqual(s.flags["agents"], 0)

    def test_set_goal_and_profile_validated(self):
        s = _shell()
        s.do_flags("goal creds")
        self.assertEqual(s.flags["goal"], "creds")
        s.do_flags("goal not-a-goal")  # rejected
        self.assertEqual(s.flags["goal"], "creds")
        s.do_flags("profile cloud")
        self.assertEqual(s.flags["profile"], "cloud")
        s.do_flags("profile bogus")  # rejected
        self.assertEqual(s.flags["profile"], "cloud")


class TestRunCommands(unittest.TestCase):

    def test_launch_forwards_flags_to_run_auto_mode(self):
        s = _shell()
        s.do_targets("add 10.0.0.9")
        s.do_flags("aggressive on")
        s.do_flags("agents 2")
        with patch("phantom.core.automode.run_auto_mode") as m:
            s.do_launch("")
            m.assert_called_once()
            kwargs = m.call_args.kwargs
            self.assertEqual(kwargs["targets"], ["10.0.0.9"])
            self.assertTrue(kwargs["aggressive"])
            self.assertEqual(kwargs["agents"], 2)
            self.assertTrue(kwargs["handoff_c2"])

    def test_launch_requires_targets(self):
        s = _shell()
        with patch("phantom.core.automode.run_auto_mode") as m:
            s.do_launch("")
            m.assert_not_called()

    def test_plan_is_dry_run(self):
        s = _shell()
        s.do_targets("add 10.0.0.9")
        with patch("phantom.core.automode.run_auto_mode") as m:
            s.do_plan("")
            m.assert_called_once()
            self.assertTrue(m.call_args.kwargs["plan"])

    def test_resume_reads_checkpoint_target(self):
        s = _shell()
        with tempfile.TemporaryDirectory() as tmp:
            cp = os.path.join(tmp, "checkpoint.json")
            with open(cp, "w", encoding="utf-8") as f:
                json.dump({"target": "10.0.0.9", "wm": {}}, f)
            with patch("phantom.core.automode.run_auto_mode") as m:
                s.do_resume(cp)
                m.assert_called_once()
                self.assertIn("10.0.0.9", s.targets)
                self.assertEqual(m.call_args.kwargs["resume"], cp)

    def test_resume_rejects_missing_file(self):
        s = _shell()
        with patch("phantom.core.automode.run_auto_mode") as m:
            s.do_resume("/nonexistent/checkpoint.json")
            m.assert_not_called()


class TestBundleCommands(unittest.TestCase):

    def test_export_import_round_trip(self):
        old = (session.target, list(session.scope or []))
        s = _shell()
        try:
            session.target = "mario.rossi@acme.it"
            session.scope = ["acme.it"]
            with tempfile.TemporaryDirectory() as tmp:
                pm = os.path.join(tmp, "sess.pm")
                s.do_export(pm)
                self.assertTrue(os.path.isfile(pm))
                s2 = _shell()
                s2.do_import(pm)
                self.assertIn("mario.rossi@acme.it", s2.targets)
        finally:
            session.target, session.scope = old

    def test_back_returns_to_main_shell(self):
        s = _shell()
        self.assertTrue(s.do_back(""))


class TestShellWiring(unittest.TestCase):

    def test_do_auto_without_args_enters_auto_shell(self):
        from phantom.core.shell import PhantomShell
        sh = PhantomShell()
        with patch("phantom.core.auto_shell.run_auto_shell") as m:
            sh.do_auto("")
            m.assert_called_once()

    def test_do_auto_with_args_skips_shell(self):
        from phantom.core.shell import PhantomShell
        sh = PhantomShell()
        with patch("phantom.core.auto_shell.run_auto_shell") as m:
            sh.do_auto("10.0.0.9 --plan")
            m.assert_not_called()


class TestEvents(unittest.TestCase):

    def test_on_event_collects_per_target(self):
        s = _shell()
        s.targets = ["bob@corp.com"]
        s._on_event("waiting", {"target": "bob@corp.com", "message": "sleep"})
        s._on_event("handoff", {"beacon_id": "b-1"})
        self.assertIn("bob@corp.com", s.events)
        self.assertEqual(len(s.events["bob@corp.com"]), 2)
        self.assertEqual(s.events["bob@corp.com"][0]["kind"], "waiting")


if __name__ == "__main__":
    unittest.main()
