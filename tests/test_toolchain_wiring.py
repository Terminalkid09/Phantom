"""Tests: the toolchain helper is reachable from the CLI and from the API.

Detection and command synthesis are covered in tests/test_toolchain.py. What
these pin is the WIRING, because a helper nobody can call is not a feature: the
`deps` command must exist in the shell that owns the ops registry, the API must
report the same state the CLI prints, and — the part that matters — the HTTP
path must NOT be able to install anything without an explicit confirmation in
the request body.
"""
from __future__ import annotations

import asyncio
import json as _json

import pytest


class _Req:
    """Minimal request double: the handlers only need an async json()."""

    def __init__(self, body=None):
        self._body = body if body is not None else {}

    async def json(self):
        return self._body


def _body(resp):
    return _json.loads(resp.body.decode("utf-8"))


# ── CLI ──────────────────────────────────────────────────────────────────────

def test_deps_is_registered_as_an_ops_command():
    from phantom.core.shell.commands import ops
    assert "deps" in ops.COMMANDS
    assert callable(ops.COMMANDS["deps"])


def test_the_autoshell_can_run_deps():
    from phantom.core.auto_shell import AutoShell
    assert hasattr(AutoShell(), "do_deps")


def test_the_shell_reports_without_installing_anything(capsys):
    from phantom.core.auto_shell import AutoShell
    from phantom.utils import toolchain as tc
    shell = AutoShell()
    shell.do_deps("report")            # must not raise, must not install
    out = capsys.readouterr().out
    assert "environment:" in out and "tools:" in out
    assert tc.detect_env().manager in out


def test_install_asks_first_and_a_non_interactive_shell_says_no(monkeypatch):
    from phantom.core.shell.commands import ops
    from rich.prompt import Confirm

    monkeypatch.setattr(Confirm, "ask", classmethod(
        lambda cls, *a, **k: (_ for _ in ()).throw(RuntimeError("no tty"))))
    assert ops._ask_to_install("nmap", ["apt-get", "install", "-y", "nmap"]) is False

    monkeypatch.setattr(Confirm, "ask", classmethod(lambda cls, *a, **k: False))
    assert ops._ask_to_install("nmap", ["apt-get"]) is False

    monkeypatch.setattr(Confirm, "ask", classmethod(lambda cls, *a, **k: True))
    assert ops._ask_to_install("nmap", ["apt-get"]) is True


def test_an_unknown_subcommand_explains_the_usage(monkeypatch):
    from phantom.core.shell.commands import ops
    seen = {}
    monkeypatch.setattr(ops.notifier, "error",
                        lambda msg: seen.setdefault("error", msg))
    monkeypatch.setattr(ops.notifier, "info",
                        lambda msg: seen.setdefault("info", msg))
    ops.cmd_deps(None, "frobnicate")
    assert "Unknown deps subcommand" in seen["error"]
    assert "Usage" in seen["info"]


# ── API ──────────────────────────────────────────────────────────────────────

def test_the_api_reports_the_same_state_as_the_cli():
    from phantom.api import server
    from phantom.utils import toolchain as tc
    resp = asyncio.run(server.toolchain_get(None))
    body = _body(resp)
    assert resp.status == 200
    assert body["environment"] == tc.detect_env().label()
    assert [m["tool"] for m in body["missing"]] == tc.missing()
    for entry in body["missing"]:
        assert entry["why"] and isinstance(entry["command"], list)


def test_the_api_refuses_to_install_without_confirm():
    from phantom.api import server
    resp = asyncio.run(server.toolchain_post(_Req({"tool": "nmap"})))
    body = _body(resp)
    assert body["ok"] is False
    assert "confirm=true" in body["message"]
    # and it still tells the operator what WOULD have run
    assert isinstance(body["command"], list)


def test_the_api_requires_a_tool_name():
    from phantom.api import server
    resp = asyncio.run(server.toolchain_post(_Req({})))
    assert resp.status == 400
    assert _body(resp)["ok"] is False


def test_the_api_reports_a_failed_install_instead_of_raising(monkeypatch):
    from phantom.api import server
    from phantom.utils import toolchain as tc

    monkeypatch.setattr(tc, "install",
                        lambda tool, env=None, **kw: (False, "boom"))
    resp = asyncio.run(server.toolchain_post(_Req({"tool": "nmap",
                                                   "confirm": True})))
    body = _body(resp)
    assert body["ok"] is False and body["message"] == "boom"


@pytest.mark.parametrize("bad", [None, "", "   ", 7])
def test_the_api_ignores_a_missing_or_non_string_tool(bad):
    from phantom.api import server
    resp = asyncio.run(server.toolchain_post(_Req({"tool": bad})))
    assert resp.status in (200, 400)
    assert _body(resp)["ok"] is False
