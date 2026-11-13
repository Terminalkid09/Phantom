"""Shared pytest configuration for the Phantom test suite.

Two responsibilities:

1. Excludes standalone integration scripts from collection. These are NOT
   pytest tests — they compile the Windows beacon, boot a real C2 server, do
   live HTTP and (in the deploy case) run a real beacon process with
   keylogger/persistence. They call sys.exit() at module level and are run
   manually (or by the release workflow), never collected by pytest.

2. Stops the process-wide server singletons after EVERY test. Several modules
   keep a module-level instance (`phantom.core.c2_server.server_instance`, the
   craft tracker singleton). A test that starts one and forgets to stop it
   leaks a live listener into the next tests, which then fail only when the
   whole file set runs together — the classic order-dependent flake. Cleaning
   up here makes the suite order-independent instead of papering over each
   symptom in the individual tests.
"""
import atexit
import copy
import os
import shutil
import tempfile

import pytest

collect_ignore = [
    "test_features_final.py",   # standalone beacon+C2 integration script
    "test_real_deploy.py",      # standalone real-beacon deploy script
]

# The C2 engagement state (`data/c2_state.json`) is read by `C2State` when it
# is CONSTRUCTED, and `phantom.core.c2_server` builds its one process-wide
# instance at import time — i.e. during collection, before any fixture can
# run. Pointing the override at a throwaway path HERE is what keeps that
# import from reading (and the whole run from overwriting) the operator's real
# engagement file. `setdefault` so an explicit override still wins.
_C2_TEST_STATE_DIR = tempfile.mkdtemp(prefix="phantom-c2-state-")
os.environ.setdefault("PHANTOM_C2_STATE_PATH",
                      os.path.join(_C2_TEST_STATE_DIR, "c2_state.json"))
atexit.register(shutil.rmtree, _C2_TEST_STATE_DIR, True)


@pytest.fixture(autouse=True)
def _restore_session_knowledge_base():
    """Restore the singleton's KB after every test.

    Measured 2026-11-08 on GitHub's Python 3.11 job:
    ``test_enterprise_kb_fields_accessible`` saw
    ``{'creds_found': [], 'os_info': {}, 'target_type': None}`` because an
    earlier test in the same xdist worker had applied a .pm bundle to the
    global ``session`` without restoring it. The worker layout differs by
    Python version, so 3.10 and 3.12 passed while 3.11 failed. Tests that
    intentionally mutate the KB still do, but the next test starts from the
    KB this one found — the same order-independence rule as the singleton
    cleanups below.
    """
    try:
        from phantom.core.session import session
    except Exception:  # pragma: no cover - renderer contracts run without deps
        yield
        return

    saved = copy.deepcopy(session.knowledge_base)
    yield
    session.knowledge_base = saved


@pytest.fixture(autouse=True)
def _hermetic_fingerprint_probes(monkeypatch):
    """Keep banner probes off the network unless they target loopback.

    Command adapters can synthesise their output at build time: the
    ssh_banner and fingerprint adapters run a real socket probe inside
    ``make_command``. A test that plans those capabilities against a lab IP
    (10.0.0.x) then blocks for the full connect timeout on a host that is
    unroutable-but-not-refusing — which is how a single ``run_swarm`` test
    used to hang the whole suite. The suite is meant to be hermetic, so refuse
    anything that is not loopback: the probe fails fast and the test renders
    its degraded path instead of waiting on the network.

    A test that needs real probe behaviour can still ``monkeypatch``
    ``probes._connect`` itself; that patch is applied after this one.
    """
    try:
        from phantom.automation.fingerprint import probes
    except Exception:  # pragma: no cover - import guard for isolated runs
        yield
        return
    original = probes._connect

    def _connect(host, port, timeout=5.0):
        if host in ("127.0.0.1", "localhost", "::1"):
            return original(host, port, timeout)
        return None

    monkeypatch.setattr(probes, "_connect", _connect)
    yield


@pytest.fixture(autouse=True)
def _allow_unscoped_auto_mode(monkeypatch):
    """A-6: auto-mode now FAILS CLOSED without an engagement scope.

    The suite deliberately exercises the lab path (no scope list) across
    dozens of agent tests, so it opts out here exactly the way an operator
    would. `tests/test_security_fixes.py::test_unscoped_auto_mode_fails_closed`
    removes this override and asserts the refusal.
    """
    monkeypatch.setenv("PHANTOM_ALLOW_UNSCOPED", "1")
    yield


@pytest.fixture(autouse=True)
def _isolate_c2_engagement_state(tmp_path, monkeypatch):
    """Keep the C2 engagement file out of the operator's REAL data dir.

    `C2State` now persists beacons, their queues, the collected results and
    the auto-shell grant to `data/c2_state.json`, and the module keeps ONE
    process-wide instance. Dozens of tests mutate `c2_state` directly and a
    few construct a fresh `C2State` to simulate a restart, so without this
    the suite would write the operator's live engagement file and then read
    it back into unrelated tests.

    Both ends are redirected: the env var for anything constructed during
    the test, and the live singleton's already-resolved path, because that
    singleton was built at import time — before any fixture could run.

    Declared BEFORE `_stop_leaked_servers` on purpose: fixtures tear down in
    reverse, so the server teardown (which flushes the state) still writes to
    the temp file, and the real path is only restored afterwards.
    """
    state_file = tmp_path / "c2_state.json"
    monkeypatch.setenv("PHANTOM_C2_STATE_PATH", str(state_file))
    try:
        from phantom.core.c2_server import c2_state
    except Exception:  # pragma: no cover - import guard for isolated runs
        yield
        return
    previous = getattr(c2_state, "_state_persist_path", "")
    c2_state._state_persist_path = str(state_file)
    c2_state._state_persist_last = 0.0
    c2_state._state_dirty = False
    yield
    c2_state._state_persist_path = previous
    c2_state._state_persist_last = 0.0
    c2_state._state_dirty = False


@pytest.fixture(autouse=True)
def _isolate_audit_log(tmp_path, monkeypatch):
    """Keep the hash-chained audit log out of the operator's real chain.

    ``AuditLog`` defaults to ``<data_dir>/c2_audit.log``, so every test that
    exercises a C2 path appended REAL records to the engagement's immutable
    chain of custody, and tests that assert on it read a file the whole
    suite writes. Measured 2026-11-02 under ``pytest-xdist``:
    ``test_autopersist_honesty`` scans ``audit_log.tail(300)`` for its own
    ``auto_persist_queued`` event and passed alone, then failed in the full
    run because 16 workers had appended more than 300 records after it. The
    singleton is redirected rather than re-created: production code imports
    ``audit_log`` (the instance), so patching the module attribute would not
    reach the call sites.
    """
    try:
        from phantom.utils.audit_log import audit_log
    except Exception:  # pragma: no cover - import guard for isolated runs
        yield
        return
    monkeypatch.setattr(audit_log, "path", str(tmp_path / "c2_audit.log"))
    yield


@pytest.fixture(autouse=True)
def _isolate_sessions_dir(tmp_path_factory, monkeypatch):
    """Keep session snapshots out of the operator's real data dir.

    ``create_app`` mirrors the live session to ``data/sessions/_auto.json``
    on every mutation and on shutdown. Without this, app-level tests leave
    test targets/notes in the file the desktop app restores at boot (and a
    shutdown from an unrelated test overwrites a real engagement). Only the
    session store is redirected; certs, reports and wordlists stay put.

    The directory comes from the session-scoped factory, not ``tmp_path``:
    several CLI tests assert that their own ``tmp_path`` stays empty.
    """
    sessions = tmp_path_factory.mktemp("sessions")
    monkeypatch.setenv("PHANTOM_SESSIONS_DIR", str(sessions))


@pytest.fixture(autouse=True)
def _isolate_pack_registry(tmp_path, monkeypatch):
    """Keep learned CVE packs out of the operator's real data dir.

    ``intake`` persists every resolved weapon and every verdict to
    ``data/exploit_packs.json``. Without this, a unit test that exercises
    ``attempt_cve`` would teach the operator's production ranking, and a
    real engagement's pack could leak into an unrelated test.
    """
    monkeypatch.setenv("PHANTOM_PACKS_PATH",
                       str(tmp_path / "exploit_packs.json"))
    try:
        from phantom.automation.exploit import intake
        intake.reset_cache()
    except Exception:  # pragma: no cover - import guard for isolated runs
        yield
        return
    yield
    intake.reset_cache()


@pytest.fixture(autouse=True)
def _hermetic_anomaly_probes(monkeypatch):
    """Keep the anomaly hunt off the network unless it targets loopback.

    `agent._execute_hunt_capability` runs the REAL hunt, whose default
    transport is `curl` against `<scheme>://<target>:<port>`. A test that
    drives an agent at a lab address therefore performs real probes: with no
    route to 10.0.0.x each one waits for the connect timeout, and the stealth
    pacing delay is NOT counted against the hunt's wall-clock budget, so one
    test held the orchestrator drain for its full 600 s and the suite never
    finished (measured 2026-10-28: `test_automation_exploit_system` hung
    reproducibly, alone and in the full run).

    Same rule as `_hermetic_fingerprint_probes`: the suite is hermetic, a
    non-loopback probe fails fast (an empty result, which the engine already
    treats as "endpoint unreachable"), and a test that needs real behaviour
    can inject its own `runner=`.
    """
    from urllib.parse import urlparse

    try:
        from phantom.automation.exploit import anomaly
    except Exception:  # pragma: no cover - import guard for isolated runs
        yield
        return
    original = anomaly.curl_runner

    def _curl(method, url, body="", timeout=8.0, cookies="", headers=None,
              follow=True):
        host = (urlparse(url).hostname or "").lower()
        if host in ("127.0.0.1", "localhost", "::1"):
            return original(method, url, body, timeout, cookies,
                            headers=headers, follow=follow)
        return anomaly.ProbeResult()

    monkeypatch.setattr(anomaly, "curl_runner", _curl)
    yield


@pytest.fixture(autouse=True)
def _no_real_recon_pacing(monkeypatch):
    """Stop the recon ladder from pacing itself with REAL sleeps in tests.

    The ladder's `quiet`/`blend` profiles sleep 0.5-5 s between chunks, and
    `sleep` defaults to `time.sleep`. Any agent test that escalates to the
    deep scan therefore spends those seconds for real — and a single test
    can spend minutes, which is how the suite stalled inside
    `run_ladder` → `do_sleep` (measured 2026-10-28, twice). The pacing is a
    product behaviour worth testing with an injected recorder (which
    `tests/test_scan_camouflage.py` does); it is not worth spending real
    wall-clock in every agent test, so the suite defaults it to a no-op.
    A test that cares still wins: an explicit `sleep=` is left untouched.
    """
    try:
        from phantom.automation import recon_ladder
    except Exception:  # pragma: no cover - import guard for isolated runs
        yield
        return
    original = recon_ladder.run_ladder

    def _run_ladder(*args, **kwargs):
        kwargs.setdefault("sleep", lambda _seconds: None)
        return original(*args, **kwargs)

    monkeypatch.setattr(recon_ladder, "run_ladder", _run_ladder)
    yield


@pytest.fixture(autouse=True)
def _restore_recon_ladder_profile():
    """Undo the scan profile an agent test handed to a MODULE GLOBAL.

    `agent.py` passes the worker's posture to the recon ladder with
    ``recon_ladder.set_default_profile(...)`` — a process-wide global, which
    nothing restores. After one stealth test the default is ``quiet``, whose
    jitter is 2-5 REAL seconds per chunk: every later ``run_ladder`` call in
    the same process sleeps through it, and the suite stalls inside
    ``do_sleep`` without failing (measured 2026-10-28: the full run was killed
    at 75%). Restoring here makes the suite order-independent; the
    long-lived-process leak itself is the product issue documented in
    docs/Live_Test_2026-10-28.md.
    """
    try:
        from phantom.automation import recon_ladder
    except Exception:  # pragma: no cover - import guard for isolated runs
        yield
        return
    before = getattr(recon_ladder, "_DEFAULT_PROFILE", "balanced")
    yield
    recon_ladder._DEFAULT_PROFILE = before


@pytest.fixture(autouse=True)
def _stop_leaked_servers():
    """Tear down any server a test left running (best-effort, never fails)."""
    # snapshot the config module's cached state so a test that repoints
    # `cfg._CONFIG_PATH` at a temp file cannot decide what the NEXT test reads
    try:
        from phantom.utils import config as cfg
        before = (cfg._CONFIG_PATH, cfg._loaded)
    except Exception:
        cfg, before = None, None
    yield
    # 1) the C2 listener singleton
    try:
        from phantom.core.c2_server import server_instance
        if getattr(server_instance, "thread", None) is not None:
            server_instance.stop()
    except Exception:
        pass
    # 2) the craft tracker singleton (holds a bound port + thread)
    try:
        from phantom.modules import craft
        g = getattr(craft, "_SINGLETON", None)
        server = getattr(g, "_default_server", None)
        if server is not None:
            try:
                server.stop()
            except Exception:
                pass
        craft._SINGLETON = None
    except Exception:
        pass
    # 3) restore the config module's cached state
    if cfg is not None and before is not None:
        try:
            cfg._CONFIG_PATH, cfg._loaded = before
        except Exception:
            pass
