"""Tests: three correctness fixes in the self-improvement loop.

* the daily GATE budget must count gate RUNS, not spawns that never ran —
  a failed authoring releases its slot;
* the daily PR budget is claimed ATOMICALLY, right before the push, so
  concurrent workers cannot over-admit and an early failure spends nothing;
* the push never puts the token in the URL or in argv.
"""
import shutil
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

import phantom.automation.evolution.publish as publish_mod
from phantom.automation.evolution.loop import EvolutionState
from phantom.automation.evolution.publish import _push_with_token, publish


class _AuthorResult:
    cap_relpath = "CHANGELOG.md"
    test_relpath = ""
    proposal_relpath = ""
    gate_history = []
    attempts = 1


class _SpyState:
    """Refuses the legacy non-atomic API so a regression fails hard."""

    def __init__(self, limit=2):
        self.limit = limit
        self.prs = 0
        self.calls = []

    def reserve_pr_slot(self):
        self.calls.append("reserve")
        if self.prs >= self.limit:
            return False
        self.prs += 1
        return True

    def can_pr(self):  # pragma: no cover - must never be called
        raise AssertionError("publish must use reserve_pr_slot, not can_pr")

    def count_pr(self):  # pragma: no cover - must never be called
        raise AssertionError("publish must not count_pr after reserving")


class TestGateSlotRelease(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.st = EvolutionState(Path(self.tmp) / "state.json")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_release_gives_the_slot_back(self):
        self.assertTrue(self.st.reserve_gate_slot())
        self.assertTrue(self.st.reserve_gate_slot())
        self.st.release_gate_slot()
        self.assertEqual(self.st._d["gate_runs"], 1)

    def test_release_floors_at_zero(self):
        self.st.release_gate_slot()
        self.assertEqual(self.st._d["gate_runs"], 0)

    def test_reserve_then_release_is_a_no_op_on_the_budget(self):
        self.assertTrue(self.st.reserve_gate_slot())
        self.assertEqual(self.st._d["gate_runs"], 1)
        self.st.release_gate_slot()
        self.assertEqual(self.st._d["gate_runs"], 0)


class TestPrSlotAccounting(unittest.TestCase):

    def test_early_failure_spends_no_pr_slot(self):
        st = _SpyState()
        res = publish("20260101-aa", _AuthorResult(), st,
                      run_git=lambda *a: (False, "boom"))
        self.assertFalse(res.ok)
        self.assertEqual(st.calls, [], "no reservation before the push")

    def test_pr_slot_is_reserved_right_before_the_push(self):
        st = _SpyState(limit=0)   # budget already exhausted
        proj = Path(tempfile.mkdtemp())
        worktree = Path(tempfile.mkdtemp())
        (proj / "CHANGELOG.md").write_text("x", encoding="utf-8")
        try:
            with mock.patch.object(publish_mod, "PROJECT_ROOT", proj), \
                    mock.patch.object(publish_mod, "_wt_dir",
                                      lambda pid: worktree):
                res = publish("20260101-bb", _AuthorResult(), st,
                              run_git=lambda *a: (True, str(worktree)))
        finally:
            shutil.rmtree(proj, ignore_errors=True)
            shutil.rmtree(worktree, ignore_errors=True)
        self.assertFalse(res.ok)
        self.assertIn("budget", res.detail)
        self.assertEqual(st.calls, ["reserve"])


class TestTokenFreePush(unittest.TestCase):

    def test_token_is_only_in_the_environment(self):
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            captured["env"] = kwargs.get("env") or {}
            return types.SimpleNamespace(returncode=1, stdout="",
                                         stderr="remote rejected")

        with mock.patch.object(publish_mod.subprocess, "run", fake_run):
            ok, out = _push_with_token("SECRETTOKEN", "auto-evolution/x")

        self.assertFalse(ok)
        flat = " ".join(str(a) for a in captured["cmd"])
        self.assertNotIn("SECRETTOKEN", flat, "token must not be in argv")
        self.assertNotIn("x-access-token:SECRETTOKEN", flat)
        self.assertEqual(captured["env"].get("PHANTOM_PUSH_TOKEN"),
                         "SECRETTOKEN")
        self.assertNotIn("SECRETTOKEN", out, "git output must be redacted")


if __name__ == "__main__":
    unittest.main()
