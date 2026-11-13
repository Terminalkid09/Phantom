"""An artefact's callback endpoint is DERIVED, and compared with the listener.

Two failures, both silent, both shipped:

1. `use_ssl=True` as a LITERAL in five builder call sites: a dropper generated
   against an HTTP listener said `https://`, fetched nothing and — with the
   bounded retry loop — spent its whole budget knocking on a port that was
   never going to answer. The scheme is configuration, so the call sites are
   now checked, not remembered: `test_no_artefact_builder_hardcodes_tls` walks
   the AST of `phantom/` and fails if one comes back.
2. The PORT was never compared either. `session.lport` decided what the
   artefact embedded, `server_instance.port` decided what was listening, and
   nothing looked at both: an operator generated a beacon for `:8443`, started
   the listener on `:8080`, and found out when no beacon checked in.
   `c2_endpoint_status()` is that comparison, and the HID path warns through
   it.
"""
import ast
import os
from pathlib import Path
from unittest import mock

import pytest

from phantom.utils.network import C2Endpoint, c2_endpoint_status

ROOT = Path(__file__).resolve().parents[1]
BUILDERS = ("generate_dropper", "compile_beacon", "generate_stealth_dropper")


def _bad_calls(path: Path):
    """Builder calls that pass a literal `use_ssl=True`."""
    tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = (getattr(node.func, "id", "")
                or getattr(node.func, "attr", ""))
        if name not in BUILDERS:
            continue
        for kw in node.keywords:
            if kw.arg != "use_ssl":
                continue
            if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                yield node.lineno


def test_no_artefact_builder_hardcodes_tls():
    """The other half of the invariant: fixing them once is not a guarantee."""
    scanned, offenders = 0, []
    for path in (ROOT / "phantom").rglob("*.py"):
        scanned += 1
        for line in _bad_calls(path):
            offenders.append(f"{path.relative_to(ROOT)}:{line}")
    assert scanned > 100, scanned            # a scan that read nothing passes
    assert not offenders, (
        "a builder is handed `use_ssl=True` instead of the listener's real "
        f"scheme: {offenders} — it will say https:// against an HTTP "
        f"listener and never connect")


class _FakeListener:
    """Just enough of the running C2 for the endpoint probe."""

    def __init__(self, port, use_ssl, alive=True):
        self.port = port
        self.use_ssl = use_ssl
        self._alive = alive
        self.thread = self          # `server_instance.thread.is_alive()`

    def is_alive(self):
        return self._alive


def _listener(monkeypatch, port, use_ssl, alive=True):
    fake = _FakeListener(port, use_ssl, alive)
    monkeypatch.setattr("phantom.core.c2_server.server_instance", fake)
    return fake


def _session(monkeypatch, host="10.0.0.5", port=0):
    from phantom.core.session import session
    monkeypatch.setattr(session, "lhost", host, raising=False)
    monkeypatch.setattr(session, "lport", port, raising=False)
    return session


class TestTheEndpointComparison:
    def test_a_matching_listener_has_nothing_to_say(self, monkeypatch):
        _session(monkeypatch, port=8443)
        _listener(monkeypatch, 8443, True)
        ep = c2_endpoint_status()
        assert ep.url == "https://10.0.0.5:8443"
        assert ep.listener_url == "https://10.0.0.5:8443"
        assert ep.warnings() == []

    def test_the_live_listener_wins_over_the_config(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_C2_SSL", "1")
        _session(monkeypatch, port=0)
        _listener(monkeypatch, 8080, False)
        ep = c2_endpoint_status()
        assert ep.use_ssl is False, "the live listener is what the target reaches"
        assert ep.port == 8080, "with no session port, the listener's port is used"

    def test_the_config_decides_when_nothing_is_listening(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_C2_SSL", "0")
        monkeypatch.setenv("PHANTOM_C2_PORT", "9999")
        _session(monkeypatch, port=0)
        _listener(monkeypatch, 8080, True, alive=False)
        ep = c2_endpoint_status()
        assert ep.use_ssl is False and ep.port == 9999
        assert ep.listener_url == ""

    def test_no_listener_is_a_warning_with_the_fix(self, monkeypatch):
        _session(monkeypatch, port=8443)
        _listener(monkeypatch, 0, True, alive=False)
        [warning] = c2_endpoint_status().warnings()
        assert "no listener is running" in warning
        assert "https://10.0.0.5:8443" in warning
        assert "listeners start 8443" in warning

    def test_the_wrong_port_is_a_named_mismatch(self, monkeypatch):
        _session(monkeypatch, port=8443)
        _listener(monkeypatch, 8080, True)
        [warning] = c2_endpoint_status().warnings()
        assert "MISMATCH" in warning
        assert ":8443" in warning and ":8080" in warning
        assert "set lport 8080" in warning

    def test_the_scheme_cannot_disagree_by_construction(self, monkeypatch):
        """Why there is no scheme warning: it IS the listener's scheme.

        A scheme mismatch WAS the bug (a literal `use_ssl=True` against an
        HTTP listener). It is now impossible for the artefact to disagree
        with a LIVE listener, so warning about it would be a branch no input
        can reach — the derivation is the fix, not a missing warning. `c2.ssl`
        only decides when nothing is listening, and then there is no listener
        scheme to disagree with.
        """
        monkeypatch.setenv("PHANTOM_C2_SSL", "1")
        _session(monkeypatch, port=8443)
        _listener(monkeypatch, 8443, False)
        ep = c2_endpoint_status()
        assert ep.use_ssl is False and ep.listener_ssl is False
        assert ep.warnings() == []


class TestTheOperatorIsTold:
    def _hid(self, arg, tmp_path, monkeypatch, listener_port=8080):
        _listener(monkeypatch, listener_port, True)
        from phantom.modules.payload import PayloadModule
        out = os.path.join(str(tmp_path), "artefact")
        with mock.patch("phantom.modules.payload.notifier") as note:
            PayloadModule().do_hid(f"{arg} --out {out}")
        warns = " ".join(str(c) for c in note.warn.call_args_list)
        infos = " ".join(str(c) for c in note.info.call_args_list)
        return warns, infos

    def test_a_board_pointed_at_the_wrong_port_is_told(
            self, tmp_path, monkeypatch):
        """The exact scenario: generate for :8443, listen on :8080."""
        _session(monkeypatch, port=8443)
        warns, _ = self._hid("pico --stager windows --type-into windows",
                             tmp_path, monkeypatch, listener_port=8080)
        assert "MISMATCH" in warns, warns
        assert ":8443" in warns and ":8080" in warns

    def test_a_matching_listener_gets_no_mismatch_noise(self, tmp_path,
                                                        monkeypatch):
        _session(monkeypatch, port=8080)
        warns, _ = self._hid("pico --stager windows --type-into windows",
                             tmp_path, monkeypatch, listener_port=8080)
        assert "MISMATCH" not in warns, warns

    def test_the_inline_mode_is_checked_too(self, tmp_path, monkeypatch):
        _session(monkeypatch, port=8443)
        warns, _ = self._hid("pico --stager windows --type-into windows "
                             "--stager-mode inline",
                             tmp_path, monkeypatch, listener_port=8080)
        assert "MISMATCH" in warns, warns


class TestVerdictsAreNotGuessedAt:
    def test_c2_endpoint_carries_no_defaults_of_its_own(self):
        # the object is a REPORT, not a second place that decides an endpoint
        ep = C2Endpoint("h", 1, True, True, 1, True)
        assert ep.url == "https://h:1" and ep.warnings() == []
        with pytest.raises(TypeError):
            C2Endpoint("h")
