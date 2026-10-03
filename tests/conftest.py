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
import pytest

collect_ignore = [
    "test_features_final.py",   # standalone beacon+C2 integration script
    "test_real_deploy.py",      # standalone real-beacon deploy script
]


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
