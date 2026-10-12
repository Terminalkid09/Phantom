"""Tests: the mid-run crash supervisor (`utils/auto_supervisor.py`).

The supervisor is the piece `--resume-latest` cannot be: a run killed at hour
three of a multi-day engagement must relaunch ITSELF. These tests pin the
boundary that makes that safe:

* only a CRASH relaunches (an exception or a non-zero `SystemExit`) — a run
  that returned is finished, and looping on it would turn a legitimate halt
  into an endless relaunch;
* `KeyboardInterrupt` is an operator STOP and propagates, never a relaunch;
* the restart budget and the schema gate come from `auto_resume` (no second
  accounting lives here);
* a fresh run adopts only a checkpoint written WHILE IT WAS ALIVE — never an
  older engagement's file, which would resume somebody else's operation;
* a broken event callback cannot break the loop.
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
