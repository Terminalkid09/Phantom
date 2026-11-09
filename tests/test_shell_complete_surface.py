"""Complete shell surface smoke test.

The manual shell is generated from a registry, the AUTO shell from a second
registry, and the CLI from argparse. This test walks all three so a command or
flag cannot disappear from help/dispatch unnoticed. It only invokes commands
whose job is to read state or print usage; destructive/network operations are
covered by their own focused tests, not by a smoke run.
"""
from __future__ import annotations

import contextlib
import io
import subprocess
import sys

import pytest

from phantom.core.auto_help import COMMANDS as AUTO_COMMANDS
from phantom.core.auto_help import FLAGS
from phantom.core.auto_shell import AutoShell
from phantom.core.shell import PhantomShell
from phantom.core.shell.registry import command_names, normalise_command_line
from phantom.main import build_parser


def _capture(call) -> str:
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        call()
    return buf.getvalue()


def test_every_registered_manual_command_is_wired_and_has_help():
    shell = PhantomShell()
    missing = []
    for name in command_names():
        handler = getattr(shell, f"do_{name}", None)
        if not callable(handler) or not (handler.__doc__ or "").strip():
            missing.append(name)
    assert not missing, f"unwired/undocumented manual commands: {missing}"


def test_help_works_for_every_manual_command():
    shell = PhantomShell()
    missing = []
    for name in command_names():
        text = _capture(lambda name=name: shell.do_help(name))
        if "No help available" in text:
            missing.append(name)
    assert not missing, f"`help <cmd>` has no text for: {missing}"


def test_every_hyphenated_spelling_reaches_the_same_manual_command():
    for name in command_names():
        if "_" not in name:
            continue
        hyphenated = name.replace("_", "-")
        assert normalise_command_line(f"{hyphenated} x") == f"{name} x"


@pytest.mark.parametrize("name,arg", [
    ("help", ""),
    ("show", ""),
    ("show", "scope"),
    ("show", "mode"),
    ("where", ""),
    ("notes", ""),
    ("history", ""),
    ("plugins", ""),
    ("list_profiles", ""),
    ("list_sessions", ""),
    ("guardrails", "list"),
    ("guardrails", "why"),
    ("deps", "report"),
    ("wordlists", "list"),
    ("tool", "list"),
    ("malleable", "show"),
    ("llm", "journal"),
    ("social", "graph"),
    ("coverage", ""),
    ("setup", "status"),
    ("config", "status"),
    ("workflow", "types"),
    ("run", ""),
    ("suggest", ""),
    ("plan", ""),
    ("craft", ""),
    ("install", ""),
    ("scan_diff", ""),
    ("save_profile", ""),
    ("load_profile", ""),
    ("save_session", ""),
    ("load_session", ""),
    ("import_session", ""),
    ("export", ""),
    ("run_diff", ""),
    ("why", ""),
    ("experience", ""),
])
def test_read_only_manual_commands_do_not_raise(name, arg):
    shell = PhantomShell()
    _capture(lambda: getattr(shell, f"do_{name}")(arg))


def test_every_auto_command_has_a_handler_and_help():
    shell = AutoShell()
    missing = []
    for spec in AUTO_COMMANDS:
        handler = getattr(shell, f"do_{spec.handler_name}", None)
        if not callable(handler):
            missing.append(f"{spec.name}: do_{spec.handler_name}")
            continue
        text = _capture(lambda spec=spec: shell.do_help(spec.name))
        if spec.usage.split()[0] not in text:
            missing.append(f"{spec.name}: help/usage")
    assert not missing, f"AUTO command surface gaps: {missing}"


def test_every_auto_flag_is_in_the_table_and_validated_by_the_shell():
    shell = AutoShell()
    text = _capture(lambda: shell.do_flags(""))
    missing = [spec.key for spec in FLAGS if spec.key not in text]
    assert not missing, f"AUTO flags missing from `flags`: {missing}"
    for spec in FLAGS:
        assert spec.accepts().strip()


def test_cli_help_lists_every_parser_option():
    parser = build_parser()
    help_text = parser.format_help()
    missing = []
    for action in parser._actions:
        options = [opt for opt in action.option_strings if opt != "-h"]
        if options and not any(opt in help_text for opt in options):
            missing.append(options)
    assert not missing, f"CLI flags missing from --help: {missing}"


def test_cli_help_exits_zero():
    result = subprocess.run(
        [sys.executable, "-m", "phantom.main", "--help"],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    assert "--manual" in result.stdout
    assert "--auto" in result.stdout
