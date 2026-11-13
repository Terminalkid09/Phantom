"""P1-B closure tests (docs/ROADMAP.md): P1-3 atomic/process-safe state,
P1-4 atomic gate-slot reservation."""
import json
import threading
from pathlib import Path

from phantom.automation.evolution.loop import (
    EvolutionState, MAX_GATE_RUNS_PER_DAY, MAX_PRS_PER_DAY)


def test_concurrent_gate_reservation_never_over_admits(tmp_path):
    st = EvolutionState(tmp_path / "state.json")
    grants = []
    lock = threading.Lock()

    def worker():
        for _ in range(4):
            got = st.reserve_gate_slot()
            with lock:
                grants.append(got)

    ths = [threading.Thread(target=worker) for _ in range(6)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    # 24 concurrent claims -> exactly the daily budget granted, no more
    assert sum(grants) == MAX_GATE_RUNS_PER_DAY
    assert len(grants) - sum(grants) == 24 - MAX_GATE_RUNS_PER_DAY


def test_state_survives_crash_simulation(tmp_path):
    """A torn write (crash mid-save) must never leave an empty/corrupt file:
    the atomic replace means the file is either the OLD or the NEW version."""
    p = tmp_path / "state.json"
    st = EvolutionState(p)
    st.record_authoring("h1", True)
    good = p.read_text(encoding="utf-8")
    # simulate a crash during a previous non-atomic write: junk on disk
    p.write_text('{"day": "2026-09-13", "gat', encoding="utf-8")
    st2 = EvolutionState(p)          # must not raise, must fall back clean
    assert st2._d.get("day")         # reinitialised
    st2.record_authoring("h2", True)  # and the next save repairs the file
    st3 = EvolutionState(p)
    assert st3.author_success_rate("h2") == 1.0
    assert json.loads(p.read_text(encoding="utf-8"))["schema_version"] == 2


def test_reserve_pr_slot_atomic(tmp_path):
    st = EvolutionState(tmp_path / "state.json")
    assert st.reserve_pr_slot()
    assert st.reserve_pr_slot()
    assert not st.reserve_pr_slot()
    assert not st.can_pr()


def test_mark_authored_persists_via_locked_path(tmp_path):
    p = tmp_path / "state.json"
    st = EvolutionState(p)
    st.mark_authored("abc123", "pid-1")
    st2 = EvolutionState(p)
    assert st2.authored()["abc123"] == "pid-1"
    st2.clear_authored("abc123")
    assert EvolutionState(p).authored() == {}
