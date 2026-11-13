"""Tests: the mid-run crash supervisor (`utils/auto_supervisor.py`).

The supervisor is the piece `--resume-latest` cannot be: a run killed at hour
three of a multi-day engagement must relaunch ITSELF. These tests pin the
boundary that makes that safe:

* only a CRASH relaunches (an exception or a non-zero `SystemExit`);
* `KeyboardInterrupt` is an operator STOP and propagates, never a relaunch;
* the restart budget and the schema gate come from `auto_resume` (no second
  accounting lives here);
* a fresh run adopts only a checkpoint written WHILE IT WAS ALIVE — never an
  older engagement's file, which would resume somebody else's operation;
* a broken event callback cannot break the loop;
* a clean return stops the loop UNLESS the caller supplies `outcome_of` (a
  reader of the run's own result) and that outcome says the engagement
  reached nothing: `completed` != goal reached, and a run that quietly gave
  up at hour three is exactly the unattended case this module exists for.
  The relaunch goes through the SAME budget, so it cannot loop forever.
"""

import json
import os
import time

import pytest

from phantom.utils import auto_resume as AR
from phantom.utils.auto_supervisor import resolve_checkpoint, supervise


# ── fixtures ───────────────────────────────────────────────────────────────

def _write_checkpoint(path):
    """A checkpoint the schema gate ACCEPTS.

    The schema constant is read from `auto_resume._expected_schema`, the
    single source `plan_resume` itself consults (and which degrades to -1,
    skipping the gate, when the agent module cannot be imported).
    """
    schema = AR._expected_schema()[0]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"schema": schema, "wm": {"findings": []}}, fh)
    return str(path)


def _write_counter(path, used: int) -> None:
    """The documented on-disk counter format of auto_resume."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"restarts": int(used)}, fh)


def _read_counter(path) -> int:
    with open(path, encoding="utf-8") as fh:
        return int(json.load(fh).get("restarts", 0))


# ── (a) crash -> one relaunch -> success ──────────────────────────────────

def test_a_crash_relaunches_once_and_a_finished_run_stops(tmp_path):
    cp = _write_checkpoint(tmp_path / "checkpoint.json")
    counter = str(tmp_path / "auto_restarts.json")
    calls, events = [], []

    def run(path):
        calls.append(path)
        if len(calls) == 1:
            raise RuntimeError("boom")

    out = supervise(run, resume=cp, counter_path=counter,
                    on_event=lambda kind, payload: events.append(kind))

    assert calls == [cp, cp], "the relaunch must receive the checkpoint"
    assert out["attempts"] == 2
    assert out["stopped_reason"] == "completed"
    assert out["last_error"].startswith("RuntimeError")
    assert events == ["launch", "relaunch", "launch"]
    # a normal finish clears the budget for the NEXT engagement
    assert _read_counter(counter) == 0


# ── (b) the budget is the policy's, not the supervisor's ──────────────────

def test_b_a_spent_budget_refuses_the_relaunch(tmp_path):
    cp = _write_checkpoint(tmp_path / "checkpoint.json")
    counter = str(tmp_path / "auto_restarts.json")
    _write_counter(counter, 3)
    calls = []

    def run(path):
        calls.append(path)
        raise RuntimeError("boom")

    out = supervise(run, resume=cp, max_restarts=3, counter_path=counter)

    assert len(calls) == 1, "a spent budget must not relaunch"
    assert out["attempts"] == 1
    assert "restart budget exhausted" in out["stopped_reason"]
    assert "3/3" in out["stopped_reason"]


def test_b2_zero_restarts_refuses_every_automatic_resume(tmp_path):
    cp = _write_checkpoint(tmp_path / "checkpoint.json")
    calls = []

    def run(path):
        calls.append(path)
        raise RuntimeError("boom")

    out = supervise(run, resume=cp, max_restarts=0,
                    counter_path=str(tmp_path / "c.json"))

    assert len(calls) == 1
    assert "restart budget exhausted" in out["stopped_reason"]


# ── (c) operator stop ─────────────────────────────────────────────────────

def test_c_keyboard_interrupt_propagates_and_never_relaunches(tmp_path):
    cp = _write_checkpoint(tmp_path / "checkpoint.json")
    calls = []

    def run(path):
        calls.append(path)
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        supervise(run, resume=cp, counter_path=str(tmp_path / "c.json"))

    assert calls == [cp], "a Ctrl+C must never be turned into a relaunch"


# ── (d)/(e) SystemExit: 0 is completion, non-zero is a crash ──────────────

def test_d_system_exit_zero_is_a_normal_finish(tmp_path):
    cp = _write_checkpoint(tmp_path / "checkpoint.json")
    counter = str(tmp_path / "auto_restarts.json")
    _write_counter(counter, 2)          # a spent budget must be reset

    def run(path):
        raise SystemExit(0)

    out = supervise(run, resume=cp, counter_path=counter)

    assert out["attempts"] == 1
    assert out["stopped_reason"] == "completed"
    assert out["last_error"] == ""
    assert _read_counter(counter) == 0


def test_e_system_exit_nonzero_is_a_crash(tmp_path):
    cp = _write_checkpoint(tmp_path / "checkpoint.json")
    calls = []

    def run(path):
        calls.append(path)
        raise SystemExit(3)

    # budget 1: crash -> relaunch -> crash -> refuse. Bounded and provable.
    out = supervise(run, resume=cp, max_restarts=1,
                    counter_path=str(tmp_path / "c.json"))

    assert len(calls) == 2
    assert out["attempts"] == 2
    assert out["last_error"] == "SystemExit(3)"
    assert "restart budget exhausted" in out["stopped_reason"]


# ── (f) a broken callback cannot break the loop ───────────────────────────

def test_f_a_broken_event_callback_does_not_break_the_loop(tmp_path):
    cp = _write_checkpoint(tmp_path / "checkpoint.json")
    calls = []

    def run(path):
        calls.append(path)
        if len(calls) == 1:
            raise RuntimeError("boom")

    def exploded(kind, payload):
        raise ValueError("callback is broken")

    out = supervise(run, resume=cp, counter_path=str(tmp_path / "c.json"),
                    on_event=exploded)

    assert len(calls) == 2
    assert out["stopped_reason"] == "completed"


# ── (g) which checkpoint a relaunch is allowed to use ─────────────────────

def test_g_a_fresh_run_without_a_checkpoint_is_not_resumed(tmp_path,
                                                           monkeypatch):
    old = _write_checkpoint(tmp_path / "old.json")
    past = time.time() - 3600
    os.utime(old, (past, past))
    monkeypatch.setattr("phantom.utils.session_bundle.latest_checkpoint",
                        lambda root=None: str(old))
    calls = []

    def run(path):
        calls.append(path)
        raise RuntimeError("boom")

    out = supervise(run, resume="", max_restarts=3,
                    counter_path=str(tmp_path / "c.json"))

    assert calls == [""], "the first launch of a fresh run gets no checkpoint"
    assert "no checkpoint" in out["stopped_reason"]


def test_g2_a_checkpoint_written_by_this_run_is_adopted(tmp_path, monkeypatch):
    """The realistic crash: the run writes its checkpoint, THEN dies."""
    fresh = tmp_path / "fresh.json"
    monkeypatch.setattr("phantom.utils.session_bundle.latest_checkpoint",
                        lambda root=None: str(fresh))
    calls = []

    def run(path):
        calls.append(path)
        if len(calls) == 1:
            _write_checkpoint(fresh)     # written by the run, then it crashed
            raise RuntimeError("boom")

    out = supervise(run, resume="", max_restarts=3,
                    counter_path=str(tmp_path / "c.json"))

    assert calls == ["", str(fresh)]
    assert out["attempts"] == 2
    assert out["stopped_reason"] == "completed"


def test_g3_resolve_checkpoint_survives_a_broken_discovery(tmp_path,
                                                           monkeypatch):
    def boom(root=None):
        raise OSError("no sessions directory")

    monkeypatch.setattr("phantom.utils.session_bundle.latest_checkpoint", boom)
    assert resolve_checkpoint(since=0.0) == ""


# ── (h)/(i)/(j) the OUTCOME axis: `completed` != goal reached ─────────────

def test_h_a_clean_run_that_reached_nothing_relaunches(tmp_path):
    """The gap the audit named: exit 0, goal not reached, nobody watching."""
    cp = _write_checkpoint(tmp_path / "checkpoint.json")
    counter = str(tmp_path / "auto_restarts.json")
    calls, events = [], []

    def run(path):
        calls.append(path)
        # clean exit, no goal: "the process is gone and it got nowhere"
        return {"goal": "deliver", "outcome": "completed_without_goal"}

    out = supervise(run, resume=cp, max_restarts=2, counter_path=counter,
                    outcome_of=lambda r: (r or {}).get("outcome", ""),
                    on_event=lambda kind, payload: events.append((kind, payload)))

    # 1 launch + 2 relaunches = 3 attempts, then the budget refuses
    assert len(calls) == 3, "an unfinished clean run must be relaunched"
    assert out["attempts"] == 3
    assert out["outcome"] == "completed_without_goal"
    assert "unfinished (completed_without_goal)" in out["stopped_reason"]
    assert "restart budget exhausted" in out["stopped_reason"]
    # the budget is NOT reset by an unfinished run, or this would be a loop
    assert _read_counter(counter) == 2
    kinds = [k for k, _ in events]
    assert kinds.count("relaunch") == 2
    assert kinds[-1] == "stopped"
    assert all(p.get("outcome") == "completed_without_goal"
               for k, p in events if k in ("relaunch", "stopped"))


def test_i_a_clean_run_that_reached_the_goal_stops_and_resets(tmp_path):
    cp = _write_checkpoint(tmp_path / "checkpoint.json")
    counter = str(tmp_path / "auto_restarts.json")
    _write_counter(counter, 3)
    calls = []

    def run(path):
        calls.append(path)
        return {"goal": "deliver", "outcome": "completed_goal"}

    out = supervise(run, resume=cp, max_restarts=3, counter_path=counter,
                    outcome_of=lambda r: r["outcome"])

    assert calls == [cp]
    assert out["attempts"] == 1
    assert out["outcome"] == "completed_goal"
    assert out["stopped_reason"] == "completed"
    assert _read_counter(counter) == 0, "a reached goal is finished work"


@pytest.mark.parametrize("token", ["awaiting_operator", "cancelled"])
def test_j_operator_endings_never_relaunch(tmp_path, token):
    """The next actor is the OPERATOR: relaunching would overrule them."""
    cp = _write_checkpoint(tmp_path / "checkpoint.json")
    calls = []

    def run(path):
        calls.append(path)
        return {"outcome": token}

    out = supervise(run, resume=cp, max_restarts=3,
                    counter_path=str(tmp_path / "c.json"),
                    outcome_of=lambda r: r["outcome"])

    assert calls == [cp]
    assert out["outcome"] == token
    assert out["stopped_reason"] == "completed"


def test_j2_a_partial_run_also_relaunches(tmp_path):
    """`partial` is progress, not completion: still unattended work."""
    cp = _write_checkpoint(tmp_path / "checkpoint.json")
    calls = []

    def run(path):
        calls.append(path)
        return {"outcome": "partial"}

    out = supervise(run, resume=cp, max_restarts=1,
                    counter_path=str(tmp_path / "c.json"),
                    outcome_of=lambda r: r["outcome"])

    assert len(calls) == 2
    assert "unfinished (partial)" in out["stopped_reason"]


# ── (k)/(l)/(m) the reader cannot turn the supervisor into a loop ─────────

def test_k_an_unknown_outcome_ends_the_loop(tmp_path):
    """Never relaunch on a token nobody defined — that is how a loop starts."""
    cp = _write_checkpoint(tmp_path / "checkpoint.json")
    calls = []

    def run(path):
        calls.append(path)
        return {"outcome": "some_future_token"}

    out = supervise(run, resume=cp, max_restarts=3,
                    counter_path=str(tmp_path / "c.json"),
                    outcome_of=lambda r: r["outcome"])

    assert calls == [cp]
    assert out["outcome"] == ""
    assert out["stopped_reason"] == "completed"


def test_l_without_a_reader_a_clean_return_still_stops(tmp_path):
    """Backwards compatible: no `outcome_of` = the old contract."""
    cp = _write_checkpoint(tmp_path / "checkpoint.json")
    calls = []

    def run(path):
        calls.append(path)
        return {"outcome": "completed_without_goal"}

    out = supervise(run, resume=cp, max_restarts=3,
                    counter_path=str(tmp_path / "c.json"))

    assert calls == [cp]
    assert out["outcome"] == ""


def test_m_a_broken_reader_ends_the_loop_instead_of_raising(tmp_path):
    cp = _write_checkpoint(tmp_path / "checkpoint.json")
    calls = []

    def run(path):
        calls.append(path)
        return object()

    def exploded(_result):
        raise ValueError("reader is broken")

    out = supervise(run, resume=cp, max_restarts=3,
                    counter_path=str(tmp_path / "c.json"),
                    outcome_of=exploded)

    assert calls == [cp]
    assert out["stopped_reason"] == "completed"


def test_m2_a_non_dict_result_is_not_an_outcome(tmp_path):
    cp = _write_checkpoint(tmp_path / "checkpoint.json")

    def run(path):
        return None

    out = supervise(run, resume=cp, max_restarts=3,
                    counter_path=str(tmp_path / "c.json"),
                    outcome_of=lambda r: (r or {}).get("outcome", ""))

    assert out["attempts"] == 1
    assert out["outcome"] == ""
