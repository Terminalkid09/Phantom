"""The CLI boots into AUTO-MODE; the module workflow is a MODE of it.

Bare `phantom` used to open the manual module shell and auto-mode was a flag.
That meant two entry points with two state paths (target, scope, accumulated
knowledge) and two help tables, which is how `run` after an `auto` came to
start from a blank slate. One entry point keeps one source of truth; the
human-in-the-loop path is one command away (`manual`, or `phantom --manual`).
"""
import json
import sys

import pytest

from phantom import main as cli


def _run(monkeypatch, argv):
    """Invoke main() with argv, recording which shell it opened."""
    monkeypatch.setattr(sys, "argv", argv)
    calls = {}
    monkeypatch.setattr(cli, "run_pentest_shell",
                        lambda args: calls.setdefault("manual", True))
    monkeypatch.setattr("phantom.core.auto_shell.run_auto_shell",
                        lambda: calls.setdefault("auto", True))
    cli.main()
    return calls


def test_bare_phantom_opens_auto_mode(monkeypatch):
    assert _run(monkeypatch, ["phantom"]) == {"auto": True}


def test_manual_flag_opens_the_module_shell(monkeypatch):
    assert _run(monkeypatch, ["phantom", "--manual"]) == {"manual": True}


def test_auto_flag_still_opens_auto_mode(monkeypatch):
    assert _run(monkeypatch, ["phantom", "--auto"]) == {"auto": True}


def test_c2_flag_is_unaffected(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["phantom", "--c2"])
    opened = {}
    monkeypatch.setattr("phantom.core.c2_shell.run_c2",
                        lambda: opened.setdefault("c2", True))
    cli.main()
    assert opened == {"c2": True}


def _checkpoint(tmp_path):
    """A checkpoint the resume policy accepts (right schema, on disk)."""
    from phantom.automation.agent import CHECKPOINT_SCHEMA
    path = tmp_path / "checkpoint.json"
    path.write_text(json.dumps({"schema": CHECKPOINT_SCHEMA}),
                    encoding="utf-8")
    return path


def test_without_supervise_a_crash_is_not_relaunched(tmp_path, monkeypatch):
    cp = _checkpoint(tmp_path)
    calls = []

    def fake_run(**kwargs):
        calls.append(kwargs.get("resume"))
        raise RuntimeError("OOM")

    monkeypatch.setattr(sys, "argv", ["phantom", "--auto", "10.0.0.5",
                                      "--resume", str(cp)])
    monkeypatch.setattr("phantom.core.automode.run_auto_mode", fake_run)
    with pytest.raises(RuntimeError):
        cli.main()
    assert calls == [str(cp)]


def test_supervise_relaunches_a_crashed_run_from_its_checkpoint(
        tmp_path, monkeypatch):
    """The point of `--supervise`: nobody is there to relaunch it."""
    from phantom.utils.auto_resume import counter_path_for
    cp = _checkpoint(tmp_path)
    calls = []

    def fake_run(**kwargs):
        calls.append(kwargs.get("resume"))
        if len(calls) == 1:
            raise RuntimeError("crashed at hour three")

    monkeypatch.setattr(sys, "argv",
                        ["phantom", "--auto", "10.0.0.5", "--supervise",
                         "--max-restarts", "2", "--resume", str(cp)])
    monkeypatch.setattr("phantom.core.automode.run_auto_mode", fake_run)
    cli.main()

    # attempt 1 crashes, attempt 2 resumes and finishes normally
    assert calls == [str(cp), str(cp)]
    with open(counter_path_for(str(cp)), encoding="utf-8") as fh:
        assert json.load(fh)["restarts"] == 0      # budget reset for the next one


def test_supervise_with_resume_latest_starts_from_the_newest_checkpoint(
        tmp_path, monkeypatch):
    """The unattended run: resume the newest engagement AND keep it alive."""
    cp = _checkpoint(tmp_path)
    calls = []

    def fake_run(**kwargs):
        calls.append(kwargs.get("resume"))

    monkeypatch.setattr(sys, "argv",
                        ["phantom", "--auto", "10.0.0.5", "--resume-latest",
                         "--supervise", "--max-restarts", "1"])
    monkeypatch.setattr("phantom.utils.session_bundle.latest_checkpoint",
                        lambda *a, **k: str(cp))
    monkeypatch.setattr("phantom.core.automode.run_auto_mode", fake_run)
    cli.main()
    assert calls == [str(cp)]


def test_supervise_stops_when_the_restart_budget_is_spent(tmp_path, monkeypatch):
    cp = _checkpoint(tmp_path)
    calls = []

    def fake_run(**kwargs):
        calls.append(kwargs.get("resume"))
        raise RuntimeError("crash loop")

    monkeypatch.setattr(sys, "argv",
                        ["phantom", "--auto", "10.0.0.5", "--supervise",
                         "--max-restarts", "1", "--resume", str(cp)])
    monkeypatch.setattr("phantom.core.automode.run_auto_mode", fake_run)
    cli.main()

    # two launches: the second crash finds the budget spent and stops there
    assert calls == [str(cp), str(cp)]


def test_auto_shell_exposes_the_manual_mode():
    from phantom.core.auto_shell import AutoShell
    shell = AutoShell()
    assert hasattr(shell, "do_manual")
    assert "manual" in inspect_command_list(AutoShell)


def inspect_command_list(cls):
    """Every do_* attribute maps to a `help`-listed command."""
    return {name[3:] for name in dir(cls) if name.startswith("do_")}


def test_manual_mode_runs_the_module_shell_and_returns(monkeypatch):
    import phantom.core.auto_shell as auto

    ran = {}

    class FakeShell:
        auto_run = False

        def cmdloop(self):
            ran["loop"] = True

    monkeypatch.setattr("phantom.core.shell.PhantomShell", lambda: FakeShell())
    monkeypatch.setattr("phantom.utils.auto_session.auto_export",
                        lambda: None)

    shell = auto.AutoShell()
    assert shell.do_manual("") is None      # no SystemExit: returns here
    assert ran.get("loop") is True


def test_manual_mode_seeds_the_target_once(monkeypatch):
    import phantom.core.auto_shell as auto
    from phantom.core.session import session

    monkeypatch.setattr(session, "target", "", raising=False)

    class FakeShell:
        auto_run = False

        def cmdloop(self):
            pass

    monkeypatch.setattr("phantom.core.shell.PhantomShell", lambda: FakeShell())
    monkeypatch.setattr("phantom.utils.auto_session.auto_export",
                        lambda: None)
    auto.AutoShell().do_manual("10.0.0.5")
    assert session.target == "10.0.0.5"
