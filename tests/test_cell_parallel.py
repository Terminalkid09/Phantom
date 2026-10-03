"""Buco 2 — the contact-free cells reason in PARALLEL, for real threads.

Concurrency is a property of the ACTION (the operator's rule): a role that
touches the target is serialised by the egress permit and must NOT be raced,
while a role that touches nothing (OSINT, correlation, local analysis) can
reason at the same time. This file pins:

  * only CONTACT_NONE cells take part in parallel reasoning;
  * the opinions come back in roster order (deterministic, not thread-order);
  * the consensus favours the move with the most SUPPORT (N angles agreeing);
  * an agent with fewer than two quiet cells does not parallelise at all.
"""

import pytest

from phantom.automation.brain.cells import CONTACT_NONE
from phantom.automation.brain.cell_runtime import CellRuntime
from phantom.automation.brain.lenses import CapabilityView, WorldSignals
from phantom.automation.brain.tribunal import Opinion


def _view(cid, **kw):
    base = dict(id=cid, category="osint", opsec_cost=1.0, detection_risk=0.2,
                stealth_level="active", effects=("identity",))
    base.update(kw)
    return CapabilityView(**base)


def _signals(vis=True):
    return WorldSignals(visibility=vis)


def _identity_runtime(events=None):
    return CellRuntime(
        goal="identity", target_type="email", cls="identity",
        strict=True,
        emit=(lambda k, d: events.append((k, d))) if events is not None
        else None)


def _quiet_ids(rt):
    return [c.cell_id for c in rt.team.cells
            if not c.advisory and c.spec.contact == CONTACT_NONE]


# ── only quiet cells parallelise ──────────────────────────────────────────

def test_only_contact_free_cells_take_part():
    # an identity deliver run fields BOTH quiet cells (identity/osint) and
    # target-touching ones (exploit/foothold/recon)
    rt = CellRuntime(goal="deliver", target_type="email", cls="identity")
    all_ids = [c.cell_id for c in rt.team.cells]
    quiet = _quiet_ids(rt)
    loud = [c.cell_id for c in rt.team.cells
            if not c.advisory and c.spec.contact != CONTACT_NONE]
    assert quiet, "this roster must contain quiet cells or the test is vacuous"
    assert loud, "this roster must contain a target-touching role"
    views = {cid: [_view("osint_identity")] for cid in all_ids}
    ops = rt.parallel_opinions(views, {"osint_identity": 1.0}, _signals())
    ids = {o.cell_id for o in ops}
    assert ids, "the quiet cells must have produced opinions"
    assert ids <= set(quiet)
    assert ids.isdisjoint(set(loud)), "a loud role must never be raced"


def test_opinions_come_back_in_roster_order():
    rt = _identity_runtime()
    order = _quiet_ids(rt)
    views = {cid: [_view("osint_identity")] for cid in order}
    ops = rt.parallel_opinions(views, {"osint_identity": 1.0}, _signals())
    assert [o.cell_id for o in ops] == order[:len(ops)]


def test_parallel_reasoning_is_emitted():
    events = []
    rt = _identity_runtime(events)
    order = _quiet_ids(rt)
    views = {cid: [_view("osint_identity")] for cid in order}
    rt.parallel_opinions(views, {"osint_identity": 1.0}, _signals())
    kinds = [k for k, _ in events]
    assert "parallel_reasoning" in kinds
    payload = [d for k, d in events if k == "parallel_reasoning"][-1]
    assert payload["threads"] == len(order)
    assert payload["consensus"] == "osint_identity"


# ── the consensus ─────────────────────────────────────────────────────────

def test_consensus_prefers_the_move_most_cells_support():
    ops = [
        Opinion(cell_id="a", profile="balanced",
                ranking=[("shared", 0.4), ("strong", 9.0)]),
        Opinion(cell_id="b", profile="evidence_first",
                ranking=[("shared", 0.5)]),
        Opinion(cell_id="c", profile="stealth_first",
                ranking=[("shared", 0.6)]),
    ]
    consensus, score = CellRuntime.consensus(ops)
    assert consensus == "shared"          # 3 cells vs 1, despite the score
    assert score > 0


def test_consensus_of_nothing_is_none():
    assert CellRuntime.consensus([]) == (None, 0.0)
    assert CellRuntime.consensus(
        [Opinion(cell_id="a", profile="balanced", ranking=[])]) == (None, 0.0)


# ── the agent guard ───────────────────────────────────────────────────────

def test_an_agent_with_one_quiet_cell_does_not_parallelise():
    """A network roster has at most a report cell with no contact: there is
    nothing to run side by side, and the agent must not spin threads."""
    from phantom.automation.agent import AutonomousAgent
    a = AutonomousAgent("10.0.0.5", target_type="ip")
    a._ensure_cells("deliver")
    a._current_stage = "deliver"
    quiet = [c for c in a.cells.team.cells
             if not c.advisory and c.spec.contact == CONTACT_NONE]
    if len(quiet) >= 2:
        pytest.skip("this roster has several quiet cells")
    prefs = []
    assert a._parallel_reasoning("deliver", prefs) is None
    assert prefs == []


def test_an_identity_roster_parallelises_without_raising():
    from phantom.automation.agent import AutonomousAgent
    events = []
    a = AutonomousAgent("bob@corp.com", target_type="auto",
                        on_event=lambda k, d: events.append((k, d)))
    a._ensure_cells("identity")
    a._current_stage = "identity"
    prefs = []
    con = a._parallel_reasoning("identity", prefs)      # must never raise
    quiet = [c for c in a.cells.team.cells
             if not c.advisory and c.spec.contact == CONTACT_NONE]
    if con is not None:
        assert len(quiet) >= 2
        assert con in prefs
        assert any(k == "parallel_reasoning" for k, _ in events)
