"""Regression: publish() must not parse `git worktree add` output as a path.

On Windows (and on Git builds that print "HEAD is now at ..." on stderr)
the old code passed that status line to pathlib and died with WinError 123
before copying the authored dossier. The worktree path is the one we asked
for, not whatever Git chose to print.
"""

from pathlib import Path

import phantom.automation.evolution.publish as publish_mod
from phantom.automation.evolution.author import AuthorResult


def test_publish_uses_requested_worktree_path(tmp_path, monkeypatch):
    monkeypatch.setattr(publish_mod, "PROJECT_ROOT", tmp_path)

    pid = "regression-publish-path"
    rel = f"docs/evolution/{pid}.md"
    source = tmp_path / rel
    source.parent.mkdir(parents=True)
    source.write_text("# reviewed proposal\n", encoding="utf-8")

    calls = []

    def fake_git(*args):
        calls.append(args)
        if args[:2] == ("remote", "get-url"):
            return True, "https://github.com/Terminalkid09/Phantom.git"
        if args[:2] == ("rev-parse", "--verify"):
            return False, ""
        if args[:1] == ("branch",):
            return True, ""
        if args[:2] == ("worktree", "add"):
            Path(args[2]).mkdir(parents=True, exist_ok=True)
            # The exact output that used to be mistaken for the path.
            return True, "HEAD is now at deadbeef initial"
        return True, ""

    def fake_gh(*args, **kwargs):
        if args[:2] == ("auth", "status"):
            return True, "Logged in"
        if args[:2] == ("pr", "create"):
            return True, "https://github.com/Terminalkid09/Phantom/pull/3"
        return False, "unexpected"

    class State:
        @staticmethod
        def reserve_pr_slot():
            return True

    result = publish_mod.publish(
        pid,
        AuthorResult(ok=True, proposal_relpath=rel),
        State(),
        run_git=fake_git,
        run_gh=fake_gh,
    )

    assert result.ok is True, result.detail
    assert result.pr_url.endswith("/pull/3")
    copied = (tmp_path / "data" / "evolution" / f"wt-{pid}" / rel)
    assert copied.is_file()
    assert copied.read_text(encoding="utf-8") == "# reviewed proposal\n"
    assert any(call[:2] == ("worktree", "add") for call in calls)
