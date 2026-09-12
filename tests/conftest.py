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
