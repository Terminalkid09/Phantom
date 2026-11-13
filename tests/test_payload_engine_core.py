"""Tests for the manual-core payload module wired to the enterprise
payload engine (reverse / bind multi-dialect synthesis)."""

from unittest.mock import patch

import pytest

from phantom.core.session import session
from phantom.modules.payload import PayloadModule
from phantom.automation.brain.payload import get_payload_engine


@pytest.fixture(autouse=True)
def _clean_session():
    session.target = "10.0.0.5"
    session.lhost = "10.0.0.1"
    session.lport = 4444
    session._notes = []
    yield
    session.target = None


def test_build_commands_include_reverse_and_bind():
    m = PayloadModule()
    cmds = m.build_commands()
    core = " ".join(cmds.get("CORE", []))
    assert "reverse" in core
    assert "bind" in core
    assert "deploy" in core


def test_reverse_synthesizes_enterprise_payload(mocker):
    """do_reverse picks the best dialect for the platform and prints the
    engine-synthesized command (no msfvenom in this path)."""
    m = PayloadModule()
    mocker.patch("phantom.modules.payload.PayloadModule._guess_os",
                 return_value=("Linux 6.1", "x64", "linux"))
    mocker.patch("phantom.modules.payload.PayloadModule._get_lhost",
                 return_value="10.0.0.1")
    # default dialect (first), plain encoder, no listener, no notes crash
    mocker.patch("builtins.input", side_effect=["", "", "n"])
    console = mocker.patch("phantom.modules.payload.console.print")
    session.lport = 4444
    m.do_reverse("")
    printed = " ".join(str(c.args[0]) for c in console.call_args_list)
    # engine command must be the plaintext reverse shell for the best dialect
    assert "/dev/tcp/10.0.0.1/4444" in printed or "10.0.0.1" in printed
    assert "reverse shell via" in printed


def test_reverse_accepts_explicit_lhost_lport(mocker):
    m = PayloadModule()
    mocker.patch("phantom.modules.payload.PayloadModule._guess_os",
                 return_value=("Linux", "x64", "linux"))
    mocker.patch("builtins.input", side_effect=["", "", "n"])
    console = mocker.patch("phantom.modules.payload.console.print")
    m.do_reverse("1.2.3.4 9999")
    printed = " ".join(str(c.args[0]) for c in console.call_args_list)
    assert "1.2.3.4" in printed and "9999" in printed


def test_bind_prints_engine_payload(mocker):
    m = PayloadModule()
    mocker.patch("phantom.modules.payload.PayloadModule._guess_os",
                 return_value=("Windows 10", "x64", "windows"))
    mocker.patch("builtins.input", side_effect=[""])
    console = mocker.patch("phantom.modules.payload.console.print")
    m.do_bind("5555")
    printed = " ".join(str(c.args[0]) for c in console.call_args_list)
    assert "5555" in printed
    assert "bind shell via" in printed


def test_engine_payloads_match_core_output():
    """The engine itself still produces correct payloads for both platforms."""
    eng = get_payload_engine()
    rev = eng.reverse("linux", "10.0.0.1", 4444)
    assert rev.command and "10.0.0.1" in rev.command
    rev_win = eng.reverse("windows", "10.0.0.1", 4444)
    assert rev_win.command and "powershell" in rev_win.command.lower()
    bind = eng.bind("windows", 5555)
    # the powershell variant is base64-encoded; the port lives in the note
    assert "5555" in bind.note
    enc = eng.reverse("linux", "10.0.0.1", 4444, encoder="base64")
    assert "base64 -d" in enc.command