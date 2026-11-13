"""P0 closure tests (docs/ROADMAP.md).

P0-1 — `chain.execute_step()` must report the REAL outcome: a failed
command is a failure, not a success; findings are ingested only from a
command that exited 0; the summary's first line carries the status word
(STEP FAILED / NO FINDINGS / STEP COMPLETED).

P0-3 — `C2Server.start()` must fail fast when the port is taken
(RuntimeError with a bind_error message) instead of leaving a dead
thread and pretending the listener is up.
"""
import pytest

from phantom.core import chain
from phantom.core.knowledge import reset_wm


# ── helpers ──────────────────────────────────────────────────────────────────

def _wm_with_service():
    reset_wm("10.0.0.5")
    from phantom.core.knowledge import session_wm
    wm = session_wm()
    wm.add_finding("service", "s:80", {"port": 80, "service": "http"})
    return wm


@pytest.fixture(autouse=True)
def _plain_http_listener(monkeypatch):
    """The default transport is mTLS (HTTPS + client cert); the P0-3 tests
    exercise the plain HTTP bind path, so flip the flag where c2_server
    actually reads it (imported by name, not via the state module)."""
    monkeypatch.setattr("phantom.core.c2_server.use_mtls", lambda: False)


@pytest.fixture
def no_real_net(monkeypatch):
    """Replace execute_quiet so tests never touch the network; each test
    installs the QuietResult it wants the 'command' to return."""
    from phantom.core.executor import QuietResult
    holder = {}

    def _fake_exec(cmd, target, timeout=30.0, **kw):
        return holder.get("res", QuietResult(cmd=cmd, stdout="", returncode=0))

    monkeypatch.setattr("phantom.core.executor.execute_quiet", _fake_exec)
    return holder


def _step(cap_id="http_probe"):
    return {"op": "test", "cap": cap_id}


# ── P0-1: status honesty ────────────────────────────────────────────────────

def test_execute_step_failed_exit_code_is_failure(no_real_net):
    """Exit != 0 with no findings -> ok=False + STEP FAILED, findings NOT
    ingested (the closed false-success bug)."""
    from phantom.core.executor import QuietResult
    _wm_with_service()
    no_real_net["res"] = QuietResult(cmd="x", stdout="nmap: target down",
                                     returncode=1)
    ok, summary = chain.execute_step(_step(), "10.0.0.5")
    assert ok is False
    assert summary.startswith("STEP FAILED")
    assert "exit code 1" in summary


def test_execute_step_failure_does_not_pollute_worldmodel(no_real_net):
    """A failed command's output must never become evidence: the WM stays
    clean when the step fails (error text is not data)."""
    from phantom.core.executor import QuietResult
    wm = _wm_with_service()
    before = len(wm._findings)
    no_real_net["res"] = QuietResult(cmd="x", stdout="web_header: Apache/2.4",
                                     returncode=1)
    ok, _ = chain.execute_step(_step(), "10.0.0.5")
    assert ok is False
    assert len(wm._findings) == before, "failed command output must not be ingested"


def test_execute_step_timeout_is_failure(no_real_net):
    from phantom.core.executor import QuietResult
    _wm_with_service()
    no_real_net["res"] = QuietResult(cmd="x", stdout="", timed_out=True,
                                     returncode=None)
    ok, summary = chain.execute_step(_step(), "10.0.0.5")
    assert ok is False
    assert "STEP FAILED" in summary and "timed out" in summary


def test_execute_step_guard_refusal_is_failure(no_real_net):
    """Scope/tool guard refusal (error, no output) -> ok=False."""
    from phantom.core.executor import QuietResult
    _wm_with_service()
    no_real_net["res"] = QuietResult(cmd="x", stdout="",
                                     error="out of scope: 10.0.0.5",
                                     returncode=-1)
    ok, summary = chain.execute_step(_step(), "10.0.0.5")
    assert ok is False
    assert "STEP FAILED" in summary and "out of scope" in summary


def test_execute_step_success_no_findings_is_ok_no_findings(no_real_net):
    """Exit 0, interpreter produces nothing -> ok=True + NO FINDINGS (not
    a silent success that looks like data)."""
    from phantom.core.executor import QuietResult
    _wm_with_service()
    no_real_net["res"] = QuietResult(cmd="x", stdout="", returncode=0)
    ok, summary = chain.execute_step(_step(), "10.0.0.5")
    assert ok is True
    assert summary.startswith("NO FINDINGS")


def test_execute_step_success_with_findings_ingests(no_real_net):
    """Exit 0 with interpretable output -> ok=True, findings land in the
    session WorldModel (the happy path keeps working)."""
    from phantom.core.executor import QuietResult
    wm = _wm_with_service()
    before = len(wm._findings)
    no_real_net["res"] = QuietResult(
        cmd="x", returncode=0,
        stdout="Server: nginx/1.24.0\r\nTitle: Welcome")
    ok, summary = chain.execute_step(_step(), "10.0.0.5")
    assert ok is True
    assert summary.startswith("STEP COMPLETED")
    assert len(wm._findings) > before


def test_execute_step_engine_only_still_refused():
    ok, msg = chain.execute_step({"op": "web.x", "cap": None}, "")
    assert ok is False and "engine-only" in msg


# ── P0-3: listener fail-fast bind ───────────────────────────────────────────

def _free_port() -> int:
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_c2_start_raises_when_port_taken():
    """Starting a second listener on an occupied port must RAISE (the old
    code left a dead thread and the shell printed 'Started')."""
    from phantom.core.c2_server import C2Server
    port = _free_port()
    first = C2Server(host="127.0.0.1", port=port, use_ssl=False)
    second = C2Server(host="127.0.0.1", port=port, use_ssl=False)
    try:
        first.start()
        assert first.bind_error is None, f"first listener failed: {first.bind_error}"
        with pytest.raises(RuntimeError, match="cannot bind"):
            second.start()
        assert second.bind_error, "bind_error must be set on the failing server"
        assert not (second.thread and second.thread.is_alive()), \
            "no zombie thread may survive a failed bind"
    finally:
        first.stop()
        second.stop()


def test_c2_start_success_reports_no_bind_error():
    from phantom.core.c2_server import C2Server
    srv = C2Server(host="127.0.0.1", port=_free_port(), use_ssl=False)
    try:
        srv.start()
        assert srv.bind_error is None
    finally:
        srv.stop()


def test_c2_start_uses_configured_host():
    """The configured host is honored (the old code always bound 0.0.0.0);
    binding 127.0.0.1 must actually work and report that host."""
    from phantom.core.c2_server import C2Server
    port = _free_port()
    srv = C2Server(host="127.0.0.1", port=port, use_ssl=False)
    try:
        srv.start()
        assert srv.host == "127.0.0.1"
        import socket
        with socket.create_connection(("127.0.0.1", port), timeout=3):
            pass  # the site is really listening on the configured address
    finally:
        srv.stop()
