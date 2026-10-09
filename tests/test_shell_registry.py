"""Contract tests for the modular shell (phantom/core/shell/ package).

The split of the monolithic shell.py must preserve the full operator
contract: every command registered, documented, dispatched, and the old
module-level helpers still importable from phantom.core.shell.
"""
import pytest

import phantom.core.shell as SH
from phantom.core.shell import PhantomShell
from phantom.core.shell.registry import command_names

EXPECTED = {
    "save_profile", "load_profile", "list_profiles", "set", "show",
    "note", "notes", "save_session", "load_session", "list_sessions",
    "export_session", "import_session", "history",
    "run", "suggest", "plan", "preflight", "craft", "map", "install",
    "scan_diff", "run_diff",
    "use", "plugins",
    "auto", "agent",
    "c2", "malleable", "ad", "wordlists", "export", "guardrails",
    "help", "config", "setup", "coverage", "doctor", "experience",
    "why", "tool",
    "back", "exit", "quit",
}


def test_registry_matches_expected_command_set():
    assert set(command_names()) == EXPECTED


def test_every_command_is_wired_as_do_method_with_help():
    shell = PhantomShell()
    for name in EXPECTED:
        fn = getattr(shell, f"do_{name}", None)
        assert callable(fn), f"do_{name} missing"
        assert fn.__doc__ and fn.__doc__.strip(), f"do_{name} has no help text"


def test_module_level_helpers_still_importable():
    for attr in ("console", "Console", "build_banner",
                 "build_banner_compact", "build_status_bar",
                 "_context_hint", "_engagement_elapsed",
                 "load_phantom_env"):
        assert hasattr(SH, attr), attr
    assert SH.build_banner().strip()
    assert SH._engagement_elapsed() == "0s"


def test_precmd_hyphen_translation_preserved():
    shell = PhantomShell()
    assert shell.precmd("load-profile test") == "load_profile test"
    assert shell.precmd("") == ""


def test_unknown_command_does_not_raise():
    shell = PhantomShell()
    shell.onecmd("no_such_command_xyz")


def test_quit_delegates_to_exit_help():
    shell = PhantomShell()
    assert shell.do_quit.__doc__ == shell.do_exit.__doc__
