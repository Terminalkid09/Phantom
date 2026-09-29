"""The CLI boots into AUTO-MODE; the module workflow is a MODE of it.

Bare `phantom` used to open the manual module shell and auto-mode was a flag.
That meant two entry points with two state paths (target, scope, accumulated
knowledge) and two help tables, which is how `run` after an `auto` came to
start from a blank slate. One entry point keeps one source of truth; the
human-in-the-loop path is one command away (`manual`, or `phantom --manual`).
"""
import sys

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
