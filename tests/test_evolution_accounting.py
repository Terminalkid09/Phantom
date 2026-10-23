"""Tests: three correctness fixes in the self-improvement loop.

* the daily GATE budget must count gate RUNS, not spawns that never ran —
  a failed authoring releases its slot;
* the daily PR budget is claimed ATOMICALLY, right before the push, so
  concurrent workers cannot over-admit and an early failure spends nothing;
* publishing is pinned to Terminalkid09/Phantom and uses local operator
  auth, not a shared token;
* the PR is always a DRAFT and the module has no merge path.
"""
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import phantom.automation.evolution.publish as publish_mod
from phantom.automation.evolution.loop import EvolutionState
from phantom.automation.evolution.publish import publish


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

        def fake_git(*args):
            if args[:2] == ("remote", "get-url"):
                return True, "https://github.com/Terminalkid09/Phantom.git"
            return False, "boom"

        res = publish("20260101-aa", _AuthorResult(), st, run_git=fake_git)
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
                def fake_git(*args):
                    if args[:2] == ("remote", "get-url"):
                        return True, ("https://github.com/"
                                      "Terminalkid09/Phantom.git")
                    return True, str(worktree)

                def fake_gh(*args, **kwargs):
                    if args[:2] == ("auth", "status"):
                        return True, "Logged in"
                    return False, "unexpected"

                res = publish("20260101-bb", _AuthorResult(), st,
                              run_git=fake_git, run_gh=fake_gh)
        finally:
            shutil.rmtree(proj, ignore_errors=True)
            shutil.rmtree(worktree, ignore_errors=True)
        self.assertFalse(res.ok)
        self.assertIn("budget", res.detail)
        self.assertEqual(st.calls, ["reserve"])


class TestPinnedLocalAuth(unittest.TestCase):

    def test_fork_origin_is_refused_before_any_work(self):
        calls = []

        def fake_git(*args):
            calls.append(args)
            if args[:2] == ("remote", "get-url"):
                return True, ("https://github.com/Terminalkid09/"
                              "Phantom-fork.git")
            return True, ""

        res = publish("20260101-ff", _AuthorResult(), _SpyState(),
                      run_git=fake_git)
        self.assertFalse(res.ok)
        self.assertIn("may only target", res.detail)
        self.assertFalse(any(c[:2] == ("worktree", "add") for c in calls))

    def test_source_has_no_shared_token_or_merge_path(self):
        from pathlib import Path as _P
        source = _P(publish_mod.__file__).read_text(encoding="utf-8").lower()
        # The old shared token must not be read, set, or documented as a
        # supported input. Local operator auth is the only path.
        self.assertNotIn("phantom_evolution_token", source)
        self.assertNotIn("phantom_push_token", source)
        # No merge API/command: evolution can only ever open a draft PR.
        self.assertNotIn("pr merge", source)
        self.assertNotIn("/merge", source)

    def test_foreign_origin_is_refused_before_any_work(self):
        calls = []

        def fake_git(*args):
            calls.append(args)
            if args[:2] == ("remote", "get-url"):
                return True, "https://github.com/attacker/Phantom.git"
            return True, ""

        st = _SpyState()
        res = publish("20260101-cc", _AuthorResult(), st, run_git=fake_git)
        self.assertFalse(res.ok)
        self.assertIn("may only target", res.detail)
        self.assertEqual(st.calls, [])
        self.assertFalse(any(c[:2] == ("worktree", "add") for c in calls))

    def test_no_local_auth_keeps_branch_local_and_spends_no_slot(self):
        st = _SpyState()
        proj = Path(tempfile.mkdtemp())
        worktree = Path(tempfile.mkdtemp())
        (proj / "CHANGELOG.md").write_text("x", encoding="utf-8")
        calls = []

        def fake_git(*args):
            calls.append(args)
            if args[:2] == ("remote", "get-url"):
                return True, "https://github.com/Terminalkid09/Phantom.git"
            if args[:2] == ("worktree", "add"):
                return True, "HEAD is now at deadbeef"
            return True, ""

        def fake_gh(*args, **kwargs):
            return False, "not logged in"

        try:
            with mock.patch.object(publish_mod, "PROJECT_ROOT", proj), \
                    mock.patch.object(publish_mod, "_wt_dir",
                                      lambda pid: worktree):
                res = publish("20260101-ee", _AuthorResult(), st,
                              run_git=fake_git, run_gh=fake_gh)
        finally:
            shutil.rmtree(proj, ignore_errors=True)
            shutil.rmtree(worktree, ignore_errors=True)
        self.assertTrue(res.ok)
        self.assertIn("no local GitHub auth", res.detail)
        self.assertIn("gh pr create --draft", res.detail)
        self.assertEqual(st.calls, [], "no PR slot spent without local auth")
        self.assertFalse(any(c[:1] == ("push",) for c in calls),
                         "branch must stay local when gh is not authenticated")

    def test_draft_pr_is_created_with_gh_and_never_merged(self):
        st = _SpyState()
        proj = Path(tempfile.mkdtemp())
        worktree = Path(tempfile.mkdtemp())
        (proj / "CHANGELOG.md").write_text("x", encoding="utf-8")
        gh_calls = []

        def fake_git(*args):
            if args[:2] == ("remote", "get-url"):
                return True, "https://github.com/Terminalkid09/Phantom.git"
            if args[:2] == ("worktree", "add"):
                return True, "HEAD is now at deadbeef"
            return True, ""

        def fake_gh(*args, **kwargs):
            gh_calls.append((args, kwargs))
            if args[:2] == ("auth", "status"):
                return True, "Logged in to github.com account operator"
            if args[:2] == ("pr", "create"):
                return True, "https://github.com/Terminalkid09/Phantom/pull/7"
            return False, "unexpected"

        try:
            with mock.patch.object(publish_mod, "PROJECT_ROOT", proj), \
                    mock.patch.object(publish_mod, "_wt_dir",
                                      lambda pid: worktree):
                res = publish("20260101-dd", _AuthorResult(), st,
                              run_git=fake_git, run_gh=fake_gh)
        finally:
            shutil.rmtree(proj, ignore_errors=True)
            shutil.rmtree(worktree, ignore_errors=True)
        self.assertTrue(res.ok, res.detail)
        self.assertEqual(res.pr_url,
                         "https://github.com/Terminalkid09/Phantom/pull/7")
        create = [args for args, _ in gh_calls if args[:2] == ("pr", "create")]
        self.assertEqual(len(create), 1)
        self.assertIn("--draft", create[0])
        self.assertIn("Terminalkid09/Phantom", create[0])
        self.assertIn("--body-file", create[0])
        flat = " ".join(str(a) for args, _ in gh_calls for a in args)
        self.assertNotIn("merge", flat.lower())
        # the actual git push is instructed not to follow redirects
        # (checked by TestPushRedirectRefusal below)
        # no shared token is ever set or read by publish
        self.assertNotIn("PHANTOM_EVOLUTION_TOKEN", flat)


class TestBetaPinnedRepo(unittest.TestCase):

    def test_beta_fetches_only_the_pinned_repo_with_local_gh(self):
        from phantom.automation.evolution import beta as beta_mod
        calls = []

        def fake_gh(*args, **kwargs):
            calls.append(args)
            return True, ('[{"number": 3, "body": "x", '
                          '"head": {"ref": "auto-evolution/20260101-aa"}}]')

        with mock.patch.object(beta_mod, "_remote_repo",
                               return_value="Terminalkid09/Phantom"), \
                mock.patch.object(beta_mod, "_gh", fake_gh):
            prs = beta_mod.fetch_open_evolution_prs()
        self.assertEqual(len(prs), 1)
        self.assertTrue(calls)
        self.assertIn("repos/Terminalkid09/Phantom/pulls",
                      " ".join(str(a) for a in calls[0]))
        source = Path(beta_mod.__file__).read_text(encoding="utf-8").lower()
        self.assertNotIn("phantom_evolution_token", source)
        self.assertNotIn("urllib.request", source)


class TestPushRedirectRefusal(unittest.TestCase):

    def test_push_disables_http_redirects(self):
        captured = {}

        def fake_git(*args):
            captured["args"] = args
            return True, ""

        from phantom.automation.evolution.publish import _push_branch
        ok, _ = _push_branch(fake_git, "auto-evolution/x")
        self.assertTrue(ok)
        args = captured["args"]
        self.assertIn("-c", args)
        self.assertIn("http.followRedirects=false", args)
        self.assertIn("push", args)
        self.assertIn("origin", args)


if __name__ == "__main__":
    unittest.main()
