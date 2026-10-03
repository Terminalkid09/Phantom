"""Buco 4 — the run's noise is a CONTESTED budget, not an after-the-fact meter.

`opsec_cost`/`detection_risk` already existed per capability, and the noise
circuit breaker OBSERVED the exposure after the fact. What was missing is one
finite pool the cells compete for, so restraint is a resource rather than a
good intention. This file pins:

  * the budget charges to its limit and then refuses, recording WHY;
  * charging is atomic — N threads racing the last unit cannot overspend;
  * the pool follows the OPSEC posture (paranoid < balanced < aggressive);
  * the run defers a capability that would overspend, with a `deferred`
    event, instead of quietly spending it.
"""

import threading

from phantom.automation.brain.cells import NoiseBudget
from phantom.automation.brain.cell_runtime import CellRuntime


# ── the pool ──────────────────────────────────────────────────────────────

def test_a_pool_charges_to_its_limit_then_refuses():
    b = NoiseBudget(limit=3.0)
    assert b.charge("c1", 1.0, capability="scan_tcp") is True
    assert b.charge("c1", 2.0, capability="http_probe") is True
    assert b.remaining() == 0.0
    assert b.charge("c2", 1.0, capability="hunt_web") is False
    assert b.refusals and b.refusals[-1]["capability"] == "hunt_web"
    assert b.to_dict()["refusals"] == 1
    assert b.to_dict()["spent"] == 3.0


def test_a_zero_limit_is_unlimited():
    b = NoiseBudget(limit=0)
    assert b.enforced is False
    assert b.charge("c1", 1000.0) is True
    assert b.remaining() == float("inf")


def test_charging_is_atomic_under_threads():
    b = NoiseBudget(limit=5.0)
    wins = []

    def worker():
        if b.charge("c1", 1.0):
            wins.append(1)

    threads = [threading.Thread(target=worker) for _ in range(40)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(wins) == 5, "exactly the budget must have been spent"
    assert b.spent == 5.0


# ── the posture ───────────────────────────────────────────────────────────

def test_the_budget_follows_the_opsec_posture():
    paranoid = CellRuntime(goal="deliver", target_type="ip", cls="network",
                           paranoid=True).team.budget.limit
    balanced = CellRuntime(goal="deliver", target_type="ip", cls="network"
                           ).team.budget.limit
    aggressive = CellRuntime(goal="deliver", target_type="ip", cls="network",
                             aggressive=True).team.budget.limit
    assert paranoid < balanced < aggressive


def test_an_explicit_budget_wins():
    rt = CellRuntime(goal="deliver", target_type="ip", cls="network",
                     noise_budget=7.0)
    assert rt.team.budget.limit == 7.0


def test_charge_uses_the_capability_cost():
    rt = CellRuntime(goal="deliver", target_type="ip", cls="network",
                     paranoid=True)
    rt.team.budget.limit = 1.5

    class Cap:
        id = "scan_tcp"
        category = "recon"
        opsec_cost = 1.0

    cell = rt.team.cells[0]
    assert rt.charge(cell, Cap()) is True
    assert rt.charge(cell, Cap()) is False          # 2.0 > 1.5
    assert rt.stats()["budget"]["refusals"] == 1
    assert rt.to_dict()["budget"]["limit"] == 1.5


def test_the_roster_event_carries_the_budget():
    events = []
    rt = CellRuntime(goal="deliver", target_type="ip", cls="network",
                     emit=lambda k, d: events.append((k, d)))
    payload = rt.start()
    assert "noise_budget" in payload
    assert payload["noise_budget"]["limit"] > 0


# ── the run defers what it cannot afford ──────────────────────────────────

def test_the_run_defers_an_action_the_budget_cannot_afford():
    from phantom.automation.agent import AutonomousAgent
    from phantom.automation.planner import PlanStep

    events = []
    a = AutonomousAgent("10.0.0.5", target_type="ip",
                        on_event=lambda k, d: events.append((k, d)))
    a._ensure_cells("deliver")
    a._current_stage = "deliver"
    a.cells.team.budget.limit = 0.05         # nothing but a free action fits
    ran = []
    a._execute_capability = lambda step: ran.append(1) or True
    cap = a.registry.get("scan_tcp")
    assert a._exec_with_permit(PlanStep(capability=cap, slot_values={})) is False
    assert ran == []
    reasons = [str(d.get("reason", "")) for k, d in events if k == "deferred"]
    assert any("noise budget" in r for r in reasons), reasons
    # and the permit was RELEASED, so the deferral lost no work
    assert a.cells.team.permit.holders == []


def test_an_affordable_action_runs_and_is_charged():
    from phantom.automation.agent import AutonomousAgent
    from phantom.automation.planner import PlanStep

    a = AutonomousAgent("10.0.0.5", target_type="ip")
    a._ensure_cells("deliver")
    a._current_stage = "deliver"
    before = a.cells.team.budget.spent
    ran = []
    a._execute_capability = lambda step: ran.append(1) or True
    cap = a.registry.get("scan_tcp")
    assert a._exec_with_permit(PlanStep(capability=cap, slot_values={})) is True
    assert ran == [1]
    assert a.cells.team.budget.spent > before
