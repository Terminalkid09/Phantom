"""C4 acceptance tests — the gradual migration to the cell loop.

The migration contract: a GOAL may be moved to the strict cell loop ONLY when
the roster's coverage owns every capability category the planner can
legitimately offer for it, on EVERY target class the goal can occur on. That
is not a review opinion — it is a gate:

    coverage gate     every migrated goal, on every class, plans to a set of
                      capability categories its coverage roles all own
    registry truth    every capability category in the registry has an owning
                      role somewhere (an unowned category is exactly what the
                      strict loop refuses mid-chain)
    strict routing    during a migrated goal, a capability the coverage does
                      not own is refused AND reported, not silently skipped
    unmigrated goal   a goal that is not in the ledger keeps the old behaviour
                      exactly

The gate has now earned itself twice, and both findings were real:

  * `ssh_banner`, `smb_enum` and `redis_info` are category `service` — the recon
    role did not own it;
  * `beacon_deploy` is category `beacon` and `ssh_login` is category `creds` —
    NO role owned either, so the strict loop would have refused the two
    capabilities that constitute "reaching the beacon".

Vocabulary note, which is itself a bug that shipped and was caught here: the
agent sets `_current_stage` to the run's GOAL (`_drive_stage(goal)`), not to a
doctrine chain stage. The first ledger held `("footprint",)`, a chain stage, so
`_cell_strict_here()` never became true and the strict loop was inert — switched
on, audited, and never once active. Entries here are goals.
"""

from phantom.automation.brain.cells import (
    CELL_LIBRARY,
    DEEP_LADDER,
    MIGRATED_STAGES,
    STAGE_ROLES,
)
from phantom.automation.brain.cell_runtime import CellRuntime


# every class the ledger's gate is measured against
TARGET_CLASSES = (
    ("10.0.0.5", "ip"),
    ("example.com", "domain"),
    ("10.0.0.0/24", "cidr"),
    ("bob@corp.com", "email"),
    ("bob_smith", "username"),
    ("+391234567890", "phone"),
)


def _agent(target="10.0.0.5", ttype="", **kw):
    from phantom.automation.agent import AutonomousAgent
    return AutonomousAgent(target, target_type=ttype, **kw)


def _candidates(agent, goal, max_steps=40):
    """The capabilities the planner actually offers for a goal."""
    plan = agent.planner.plan_strategic(agent.wm, goal=goal, max_steps=max_steps)
    return list(getattr(plan, "steps", []) or [])


def _categories(steps):
    return {str(s.capability.category) for s in steps}


# ── the gates ─────────────────────────────────────────────────────────────

def test_every_registry_category_has_an_owning_role():
    """No capability category may be left without a role.

    This is the invariant that caught `beacon` (beacon_deploy) and `creds`
    (ssh_login): a category no cell owns is a capability the strict loop
    refuses, and there is no way to notice it by reading a single role.
    """
    from phantom.automation.guidance.commands import make_registry
    registry_cats = {str(getattr(c, "category", ""))
                     for c in make_registry().all()}
    owned: set = set()
    for spec in CELL_LIBRARY.values():
        owned |= set(spec.uses_categories)
    assert registry_cats - owned == set(), (
        f"categories no role owns: {sorted(registry_cats - owned)}")


def test_every_migrated_goal_passes_its_coverage_gate():
    """The gate that decides whether a goal CAN be migrated."""
    for goal in MIGRATED_STAGES:
        for target, ttype in TARGET_CLASSES:
            a = _agent(target, ttype)
            a.cell_loop = True
            a.cell_stages = (goal,)
            a._current_stage = goal
            a._ensure_cells(goal)
            assert a.cells is not None, f"{goal}/{ttype}: no roster"
            steps = _candidates(a, goal)
            assert steps, f"{goal}/{ttype}: no planner candidate"
            gaps = a.cells.missing_coverage_categories(_categories(steps))
            assert gaps == [], (f"goal '{goal}' on {ttype} cannot be migrated: "
                                f"its coverage does not own {gaps}")


def test_every_migrated_goal_routes_every_candidate_when_stage_scoped():
    for goal in MIGRATED_STAGES:
        for target, ttype in TARGET_CLASSES:
            a = _agent(target, ttype)
            a.cell_loop = True
            a.cell_stages = (goal,)
            a._current_stage = goal
            a._ensure_cells(goal)
            refused = [s.capability.id for s in _candidates(a, goal)
                       if a.cells.cell_for(s.capability, goal,
                                           stage_scoped=True) is None]
            assert refused == [], f"{goal}/{ttype} would refuse {refused}"


def test_a_beacon_bound_goal_on_an_identity_target_keeps_recon_coverage():
    """Regression: measured starvation, not a hypothetical.

    An identity chain reaches its beacon by handing the harvested victim IP
    over to the network phase, so a deliver run on an email target DOES scan.
    The doctrine chain for the identity class forbids `footprint`, so a roster
    built from the chain alone owns no `recon` cell — and the strict loop then
    refused `scan_tcp` eleven times in a row and the run never reached its
    beacon. A beacon-bound goal therefore always carries recon coverage.
    """
    a = _agent("bob@corp.com", "email")
    a.cell_loop = True
    a.cell_stages = ("deliver",)
    a._current_stage = "deliver"
    a._ensure_cells("deliver")
    roles = {c.spec.role for c in a.cells.team.acting()}
    assert "recon" in roles, f"no recon cell in the roster: {sorted(roles)}"
    cap = a.registry.get("scan_tcp")
    assert a.cells.cell_for(cap, "deliver", stage_scoped=True) is not None


def test_the_deep_ladder_is_pinned_to_the_agent_ladder():
    """The roster's ladder and the run's ladder are the same ladder.

    They live in different modules (the roster cannot import the agent), so
    this pin is what stops the two from drifting into a roster that covers a
    ladder the run does not walk.
    """
    from phantom.automation.agent import DEEP_STAGES
    assert tuple(DEEP_LADDER) == tuple(DEEP_STAGES)


# ── strict vs lenient ─────────────────────────────────────────────────────

def test_a_category_no_coverage_role_owns_is_refused_and_reported():
    """The strict loop refuses what the roster cannot own — and says why.

    `osint_identity` is category `osint`, which no role of a network chain
    owns. During a migrated goal it is refused; the point is that the refusal
    is an event (auditable), not a silent skip.
    """
    from phantom.automation.planner import PlanStep

    a = _agent()
    a.cell_loop = True
    a.cell_stages = ("deliver",)
    a._ensure_cells("deliver")
    a._current_stage = "deliver"
    assert a.cells.strict is True
    cap = a.registry.get("osint_identity")
    assert cap is not None and cap.category == "osint"
    assert a.cells.cell_for(cap, "deliver", stage_scoped=True) is None
    ran = []
    a._execute_capability = lambda step: ran.append(1) or True
    assert a._exec_with_permit(PlanStep(capability=cap, slot_values={})) is False
    assert ran == []
    assert a.cells.refused == 1
    reasons = [d.get("reason", "") for d in a.sink.by_kind("blocked")]
    assert any("osint" in str(r) for r in reasons), reasons


def test_an_unmigrated_goal_keeps_the_old_behaviour():
    """`--cell-loop` with an explicit list must leave every other goal exactly
    as it was: the same capability runs, routed to no one in particular."""
    from phantom.automation.planner import PlanStep

    a = _agent()
    a.cell_loop = True
    a.cell_stages = ("deliver",)
    a._ensure_cells("ad")                 # `ad` fails the gate: not in the ledger
    a._current_stage = "ad"
    assert a._cell_strict_here() is False
    cap = a.registry.get("osint_identity")       # would be refused if strict
    ran = []
    a._execute_capability = lambda step: ran.append(1) or True
    assert a._exec_with_permit(PlanStep(capability=cap, slot_values={})) is True
    assert ran == [1]
    assert a.cells.refused == 0


def test_cell_loop_alone_defaults_to_the_migration_ledger():
    a = _agent()
    a.cell_loop = True
    a._ensure_cells("deliver")
    assert tuple(a.cell_stages) == tuple(MIGRATED_STAGES)
    assert a.cells.strict is True


def test_an_explicit_stage_list_overrides_the_ledger():
    a = _agent()
    a.cell_loop = True
    a.cell_stages = ("deliver",)
    a._ensure_cells("deliver")
    assert tuple(a.cell_stages) == ("deliver",)
    a._current_stage = "deliver"
    assert a._cell_strict_here() is True
    a._current_stage = "ad"
    assert a._cell_strict_here() is False            # not in the explicit list


def test_cell_loop_off_means_no_strict_path_at_all():
    a = _agent()
    a._ensure_cells("deliver")
    assert a.cells is not None
    assert a.cells.strict is False
    # the roster exists (it adds structure) but is never the authority
    a._current_stage = "deliver"
    assert a._cell_strict_here() is False
    a._current_stage = "identity"
    assert a._cell_strict_here() is False


def test_a_chain_stage_name_is_inert_because_stages_are_goals():
    """The vocabulary bug, pinned so it cannot come back.

    A chain stage (`footprint`) is never a value `_current_stage` takes, so a
    ledger entry naming one silently disables the strict path for the whole
    run. The ledger accepts goal names only, and this test states the reason.
    """
    a = _agent()
    a.cell_loop = True
    a.cell_stages = ("footprint",)
    a._ensure_cells("deliver")
    a._current_stage = "deliver"
    assert a._cell_strict_here() is False


def test_an_advisory_peer_is_never_routed_even_in_a_migrated_goal():
    a = _agent()
    a.cell_loop = True
    a.cell_stages = ("deliver",)
    a._ensure_cells("deliver")
    a._current_stage = "deliver"
    peer = a.cells.on_stall("no_visibility", a.registry.get("scan_tcp"),
                            "deliver")
    assert peer is not None and peer.advisory is True
    cell = a.cells.cell_for(a.registry.get("scan_tcp"), "deliver",
                            stage_scoped=True)
    assert cell is not None and cell.advisory is False


# ── the permit follows the stage ──────────────────────────────────────────

def test_the_permit_follows_the_stage_of_a_migrated_run():
    """A roster holding both a quiet role (identity/osint: no contact) and a
    loud one (recon: contact) must widen while the quiet stage is in flight
    and collapse to ONE the moment the chain reaches the target-touching
    stage. The cap follows the ACTIVE stage, not the roster's loudest member
    forever."""
    cells = CellRuntime(stages=("identity", "footprint"),
                        target_type="identity", cls="identity")
    cells.team.permit.release_all()
    cells.set_stage("identity")
    wide = cells.team.permit.acting_cap
    assert wide == 5, "quiet cells may act in parallel"
    cells.set_stage("footprint")
    assert cells.team.permit.acting_cap == 1, "contact serialises the team"
    assert wide > cells.team.permit.acting_cap


def test_a_stage_whose_roles_are_absent_falls_back_to_the_loudest_cap():
    """Conservative default: asking for a stage no roster role serves must
    NOT accidentally widen the permit."""
    a = _agent()                       # network class: recon/web/exploit cells
    a.cell_loop = True
    a._ensure_cells("deliver")
    a.cells.set_stage("identity")      # no identity cell in this roster
    assert a.cells.team.permit.acting_cap == 1


def test_recon_role_owns_service_enumeration():
    """The first scope fix the gate forced: per-service enumeration is recon."""
    spec = CELL_LIBRARY["recon"]
    assert "service" in spec.uses_categories


def test_every_role_named_by_stage_roles_exists():
    """`STAGE_ROLES` and `CELL_LIBRARY` must not drift: a stage naming a role
    that does not exist plans a roster with a hole in it."""
    used = {r for roles in STAGE_ROLES.values() for r in roles}
    assert used - set(CELL_LIBRARY) == set()
