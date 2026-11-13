"""Integration tests: the real thing, not a double.

The rest of the suite hands the code a fake runner/transport and asserts on
the call it made. That pins the CONTRACT, and it cannot fail when the code
underneath does not actually work: a fake sender never refuses a connection,
a fake runner never returns a truncated body, a mocked listener never rejects
a real signature. These tests close that gap for the paths this project lives
on, and each one talks to something real:

* the generative fuzz engine against a REAL HTTP server, with NO injected
  sender — the capability builds its own transport and has to find a real
  differential in a real response body;
* the executor running a REAL command, returning its REAL stdout (the mocked
  runner is where "it works" is easiest to fake);
* the C2 engagement state across a REAL PROCESS BOUNDARY: a child interpreter
  records beacons/tasks/results, exits, and this process adopts the file —
  which is what "the listener restarted and nothing was lost" means;
* the crash supervisor driven by a REAL failing process, resuming a REAL
  checkpoint file;
* a session exported to a REAL encrypted file and imported back after every
  in-memory trace of the engagement is gone.

Everything binds 127.0.0.1 on an ephemeral port and uses tmp dirs: no
network, no lab, no external service. A test that needs a real binary says so
with a skip reason instead of pretending.
"""
import http.server
import json
import os
import shutil
import subprocess
import sys
import threading
import urllib.parse

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ── the transport is curl; say so instead of silently faking it ────────────

requires_curl = pytest.mark.skipif(
    shutil.which("curl") is None,
    reason="the capability's live HTTP transport is the curl primitive")


# ── a real HTTP target ─────────────────────────────────────────────────────

class _InjectableView(http.server.BaseHTTPRequestHandler):
    """A tiny app that is clean until a payload looks like an injection."""

    def do_GET(self):
        query = urllib.parse.urlparse(self.path).query
        value = (urllib.parse.parse_qs(query).get("q") or [""])[0]
        hostile = "'" in value or "or 1=1" in value.lower()
        body = (b"<html>MySQLSyntaxErrorException: you have an error in your "
                b"SQL syntax</html>" if hostile else b"<html>ok</html>")
        self.send_response(500 if hostile else 200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):        # keep the test output readable
        pass


@pytest.fixture
def web_target():
    """A real HTTP server on 127.0.0.1, one thread, ephemeral port."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _InjectableView)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield str(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _wm_for_port(port: str):
    from phantom.automation.belief import WorldModel
    wm = WorldModel(target="127.0.0.1", target_type="ip")
    wm.add_finding("service", f"tcp/{port}",
                   {"port": port, "service": "http"}, confidence=0.9,
                   source="scan_tcp")
    return wm


# ── (a) the fuzz engine finds a real signal over a real socket ────────────

@requires_curl
def test_the_fuzz_engine_finds_a_real_signal_with_no_injected_sender(
        web_target):
    """No `sender=` anywhere: the capability's OWN transport is under test."""
    from phantom.automation.brain.fuzz import capability as CAP

    wm = _wm_for_port(web_target)
    lines = CAP.fuzz_engine(wm, {"params": "q", "port": web_target,
                                 "rounds": "1",
                                 # a REALISTIC budget (the capability's own
                                 # default). Every parameter costs one baseline
                                 # request BEFORE a payload goes out, so a
                                 # budget under the parameter count buys
                                 # baselines only — that is its own test below.
                                 "max_requests": "60", "seed": "7"})
    assert CAP.MARKER in lines, lines

    findings = CAP.fuzz_interp(lines, wm, {})
    hits = [f for f in findings if f.value.get("param") == "q"]
    assert hits, lines
    # the oracle's verdict is a CANDIDATE, and it must carry the evidence that
    # made the engine believe it
    assert hits[0].kind == "hunt_anomaly"
    assert hits[0].value.get("evidence"), hits[0].value
    # ...and the MARKER must name the differential the oracle used AND say it
    # was REPRODUCED: the second probe over the same real socket is the
    # evidence, not the status code the interpreter chose to keep.
    line = next(l for l in lines.splitlines() if "param=q" in l)
    assert "signals=error_based" in line, line
    assert "confirmed=true" in line, line


@requires_curl
def test_the_live_transport_says_nothing_when_the_target_is_clean(web_target):
    """The other half of the oracle: no differential, no finding.

    A test that only proves "it finds things" would pass on an engine that
    reports everything.
    """
    from phantom.automation.brain.fuzz import capability as CAP

    wm = _wm_for_port(web_target)
    lines = CAP.fuzz_engine(wm, {"params": "clean", "port": web_target,
                                 "rounds": "1", "max_requests": "60",
                                 "seed": "7"})
    findings = CAP.fuzz_interp("\n".join(lines), wm, {})
    assert findings == [], lines


@requires_curl
def test_a_budget_below_the_parameter_count_buys_baselines_only(web_target):
    """A declared bound is a bound even when honouring it finds nothing.

    `FuzzEngine.run` sends ONE baseline per parameter before the first payload,
    so a 5-request budget over these 8 parameters is spent before a single
    injection goes out. The pass reports that honestly (the `# comment` line,
    no marker, no finding) instead of overrunning its budget to have something
    to show — which is exactly what a test written as "a run always finds
    something" would have hidden.
    """
    from phantom.automation.brain.fuzz import capability as CAP

    wm = _wm_for_port(web_target)
    lines = CAP.fuzz_engine(wm, {
        "params": "q,id,file,url,cmd,path,page,name", "port": web_target,
        "rounds": "3", "max_requests": "5", "seed": "7"})
    assert lines == CAP.NO_OP, lines


@requires_curl
def test_a_declared_budget_slot_reaches_the_engine(web_target):
    """`max_requests` is the operator's bound; it must actually bound."""
    from phantom.automation.brain.fuzz import capability as CAP

    wm = _wm_for_port(web_target)
    calls = []
    real = CAP._live_sender

    def counting_sender(wm_arg, slots_arg, deadline):
        sender = real(wm_arg, slots_arg, deadline)

        def wrapper(param, payload):
            calls.append((param, payload))
            return sender(param, payload)
        return wrapper

    original = CAP._live_sender
    CAP._live_sender = counting_sender
    try:
        CAP.fuzz_engine(wm, {"params": "q,id", "port": web_target,
                             "rounds": "3", "max_requests": "6",
                             "seed": "3"})
    finally:
        CAP._live_sender = original
    assert 0 < len(calls) <= 6, calls


# ── (b) the executor really executes ──────────────────────────────────────

def test_the_executor_runs_a_real_command_and_returns_its_real_stdout():
    from phantom.core.executor import execute_quiet

    result = execute_quiet(
        f'"{sys.executable}" -c "print(\'PHANTOM-INT-OK\')"',
        check_tool=False)
    assert result.returncode == 0, result
    assert "PHANTOM-INT-OK" in (result.stdout or ""), result


def test_the_executor_reports_a_real_failure_as_a_failure():
    from phantom.core.executor import execute_quiet

    result = execute_quiet(
        f'"{sys.executable}" -c "import sys; sys.exit(7)"',
        check_tool=False)
    assert result.returncode == 7, result
    assert not result.ok


def test_the_scope_gate_refuses_a_real_command_before_it_runs():
    """Out of scope is refused by the executor itself, not by a caller."""
    from phantom.core.executor import execute_quiet
    from phantom.core.session import session

    previous = list(session.scope or [])
    try:
        session.scope = ["10.0.0.0/24"]
        result = execute_quiet(f'"{sys.executable}" -c "print(1)"',
                               target_ip="203.0.113.9")
        assert "out of scope" in (result.error or ""), result
        assert result.returncode == -1, result
    finally:
        session.scope = previous


# ── (c) the C2 engagement survives a REAL process boundary ────────────────

def test_the_c2_engagement_survives_a_real_process_restart(tmp_path):
    """A child interpreter records the operation, exits, and we adopt it.

    This is the claim the durability feature makes — "restart the listener and
    nothing is lost" — checked with a real second process rather than a second
    object in the same interpreter.
    """
    state_path = tmp_path / "c2_state.json"
    env = {**os.environ, "PHANTOM_C2_STATE_PATH": str(state_path)}
    child = (
        "from phantom.core.c2_server import c2_state as s\n"
        "s.update_beacon('BEACON-INT-1', {'ip': '10.9.9.9', 'os': 'Linux',\n"
        "                                'hmac_secret': 'SUPERSECRET'})\n"
        "s.queue_task('BEACON-INT-1', 'screenshot')\n"
        "s.add_result('BEACON-INT-1', 'task-int-1', 'PIXELS-OK')\n"
        "s.flush()\n"
    )
    proc = subprocess.run([sys.executable, "-c", child], cwd=REPO_ROOT,
                          capture_output=True, text=True, env=env, timeout=180)
    assert proc.returncode == 0, proc.stderr[-2000:]

    raw = state_path.read_text(encoding="utf-8")
    assert "BEACON-INT-1" in raw
    assert "SUPERSECRET" not in raw, "a beacon secret reached the disk"
    assert "screenshot" in raw

    # a fresh process's C2State: the same load path a restarted listener takes
    from phantom.core.c2_server import C2State
    adopted = C2State()
    beacons = adopted.get_beacons()
    assert "BEACON-INT-1" in beacons, beacons
    assert beacons["BEACON-INT-1"]["ip"] == "10.9.9.9"
    commands = [t["command"] for t in adopted.get_pending_tasks("BEACON-INT-1")]
    assert "screenshot" in commands, commands
    outputs = [r.get("output") for r in adopted.results.get("BEACON-INT-1", [])]
    assert "PIXELS-OK" in outputs, outputs


# ── (d) the supervisor, driven by a real failing process ──────────────────

def test_the_supervisor_relaunches_after_a_real_process_crash(tmp_path):
    from phantom.automation.agent import CHECKPOINT_SCHEMA
    from phantom.utils.auto_supervisor import supervise

    checkpoint = tmp_path / "checkpoint.json"
    checkpoint.write_text(json.dumps({"schema": CHECKPOINT_SCHEMA}),
                          encoding="utf-8")
    counter = tmp_path / "auto_restarts.json"
    launches = []

    def run(resume_from: str):
        launches.append(resume_from)
        if len(launches) == 1:
            # a REAL child dies with a non-zero status, which is how a run
            # actually ends when it is killed
            subprocess.run([sys.executable, "-c", "import sys; sys.exit(3)"],
                           check=True)

    summary = supervise(run, resume=str(checkpoint), max_restarts=2,
                        counter_path=str(counter))
    assert launches == [str(checkpoint), str(checkpoint)], launches
    assert summary["attempts"] == 2
    assert "CalledProcessError" in summary["last_error"], summary
    # a finished run clears its budget so the NEXT crash gets its own
    assert json.loads(counter.read_text(encoding="utf-8"))["restarts"] == 0


def test_the_supervisor_refuses_to_relaunch_without_a_checkpoint(tmp_path):
    from phantom.utils.auto_supervisor import supervise

    launches = []

    def run(resume_from: str):
        launches.append(resume_from)
        raise RuntimeError("crashed with nothing to resume from")

    summary = supervise(run, max_restarts=3,
                        counter_path=str(tmp_path / "auto_restarts.json"))
    assert launches == [""], launches
    assert summary["attempts"] == 1
    assert "no checkpoint" in summary["stopped_reason"], summary


# ── (e) a bundle is a real file, not a memory trick ──────────────────────

def test_a_real_bundle_restores_the_engagement_after_memory_is_gone(tmp_path):
    from phantom.core.knowledge import reset_wm, session_wm
    from phantom.core.session import session
    from phantom.utils.session_bundle import export_session, import_session

    previous = (session.target, list(session.scope or []))
    try:
        reset_wm(target="10.5.5.5")
        session.target = "10.5.5.5"
        session.scope = ["10.5.5.0/24"]
        session_wm().add_finding("service", "tcp/443",
                                 {"port": "443", "service": "https"},
                                 source="scan_tcp")
        # a REAL auto-mode checkpoint on disk: the resume path only exists
        # when the bundle carries one, and that is the half a restart needs
        from phantom.automation.agent import CHECKPOINT_SCHEMA
        from phantom.automation.belief import WorldModel
        # the checkpoint's world model is a REAL one (serialized by the class
        # that owns the format), because the import prefers it over the
        # session's own and a hand-written dict would be a different format
        # from the one the run writes
        checkpoint_wm = WorldModel(target="10.5.5.5")
        checkpoint_wm.add_finding("service", "tcp/443",
                                  {"port": "443", "service": "https"},
                                  source="scan_tcp")
        checkpoint = tmp_path / "checkpoint.json"
        checkpoint_state = {"schema": CHECKPOINT_SCHEMA, "target": "10.5.5.5",
                            "wm": checkpoint_wm.to_dict(),
                            "reasoning": ["scan(the target)"]}
        checkpoint.write_text(json.dumps(checkpoint_state), encoding="utf-8")
        path = export_session(out_path=str(tmp_path / "engagement.pm"),
                              checkpoint=str(checkpoint))
        raw = open(path, "rb").read()
        assert b"10.5.5.5" not in raw, "the bundle is not encrypted at rest"

        # the "restart": no memory of the engagement survives this
        reset_wm(target="")
        session.target = ""
        session.scope = []

        data = import_session(path, resume_dir=str(tmp_path / "staged"))
        assert data["target"] == "10.5.5.5"
        assert data["scope"] == ["10.5.5.0/24"]
        assert data["findings"] == 1, data
        assert session_wm().target == "10.5.5.5"
        # the run can be resumed from the imported checkpoint: a real file, in
        # the directory the caller chose, byte-identical in content to the one
        # that went in
        assert data["checkpoint_source"] == "checkpoint.json"
        assert os.path.isfile(data["resume_path"])
        assert os.path.dirname(data["resume_path"]) == str(tmp_path / "staged")
        with open(data["resume_path"], encoding="utf-8") as handle:
            staged = json.load(handle)
        assert staged["wm"]["target"] == "10.5.5.5"
        assert staged["schema"] == CHECKPOINT_SCHEMA
    finally:
        session.target, session.scope = previous[0], previous[1]
        reset_wm(target="")
