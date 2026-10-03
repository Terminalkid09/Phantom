"""
phantom.automation.brain.cell_runtime — the run's team, bound and enforced (C2).

`cells.py` defines what a cell IS. This module is what a RUN does with them:

    roster   — built from the doctrine's chain for the target class, so an
               identity engagement fields two quiet cells and a network one
               fields the machine roles;
    permit   — the egress lock, so only the allowed number of cells touch
               the target at once (`admit` / `release`);
    routing  — which cell OWNS a given capability, by category and stage;
    bus      — the scoped request/response channel;
    tribunal — the second opinion when a cell stalls, and its adjudication.

Two modes, deliberately different:

    lenient (default) — a capability no cell owns falls through to the lead
                        (the agent itself). The roster ADDS structure without
                        narrowing the run: nothing an operator could do
                        before becomes impossible.
    strict            — a capability no cell of the run's COVERAGE owns is
                        REFUSED. The coverage is the doctrine chain joined
                        with the goals the run will walk, and the strict loop
                        is the roster's authority over it (C4).

The strict mode is what makes the migration gradual: it is switched on per
GOAL, so the old planning path keeps serving every goal that has not been
moved yet. Narrowing the authority to the single stage in flight looks
principled and starves the chain — see `coverage_roles` for the measurement.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from phantom.automation.brain.bus import CellBus
from phantom.automation.brain.cells import (
    CONTACT_NONE,
    DEEP_LADDER,
    NOISE_BUDGET_DEFAULT,
    Cell,
    CellTeam,
    CellView,
    STAGE_ROLES,
    team_for_goal,
)
from phantom.automation.brain.cells import CELL_LIBRARY  # noqa: F401 — re-export for callers
from phantom.automation.brain.lenses import (
    Arbitrator,
    ReasoningProfile,
    WorldSignals,
    adversarial_profile,
    choose_profile,
)
from phantom.automation.brain.tribunal import Dispute, Opinion, Tribunal

# How long an action waits for the egress permit before the run defers it.
#
# Long on purpose. Serialised contact means "wait your turn", not "give up":
# an action that gives up after a couple of seconds is re-planned, and the
# re-plan changes WHICH capability runs next — a scheduler that reshuffles the
# plan because a colleague was mid-scan is not serialising, it is racing. The
# bound exists only so a genuinely wedged holder cannot block the run forever;
# it is deliberately larger than a normal capability's duration.
PERMIT_WAIT_S = 120.0

# Goals that cannot be satisfied without a host to stand on. Reaching one
# always passes through recon of some address (the target itself, or the
# victim IP an identity chain harvested), whatever the doctrine chain of the
# target class says.
#
# `web` and `exploit` are here for the same measured reason as the beacon
# goals: on an identity-class target the planner still offers `scan_tcp` /
# `http_probe` (it probes a SERVICE on the harvested address), so a roster
# built from the identity chain alone owns no `recon` cell and the strict loop
# would refuse the very first move. Measured with the coverage gate, not assumed.
_HOST_BOUND = frozenset({
    "deliver", "beacon", "post_exploit", "expand", "ad", "crack",
    "lateral", "harvest", "evasion", "deep", "complete_kill_chain",
    "web", "exploit",
})


class CellRuntime:
    """The roster, permit, routing, bus and tribunal of one run."""

    def __init__(self, goal: str = "", target_type: str = "", cls: str = "",
                 stages: Optional[Sequence[str]] = None,
                 aggressive: bool = False, paranoid: bool = False,
                 speed: bool = False, explicit_profile: str = "",
                 strict: bool = False, noise_budget: Optional[float] = None,
                 emit: Optional[Callable[[str, dict], None]] = None) -> None:
        self.goal = goal or "deliver"
        self.cls = cls or ""
        self.target_type = target_type
        self.strict = bool(strict)
        self.emit = emit
        base = choose_profile("enterprise", paranoid=paranoid,
                              aggressive=aggressive, speed=speed,
                              explicit=explicit_profile)
        self.profile: ReasoningProfile = base
        if stages is None:
            stages = self._coverage_stages(cls, goal, target_type)
        self.stages: Tuple[str, ...] = tuple(stages)
        self.team: CellTeam = team_for_goal(
            self.goal, target_type, aggressive=aggressive, paranoid=paranoid,
            speed=speed, explicit_profile=explicit_profile, stages=self.stages)
        # buco 4: the run's noise pool follows the OPSEC posture — a paranoid
        # run has LESS to spend, an aggressive one buys more exposure.
        if noise_budget is None:
            pool = NOISE_BUDGET_DEFAULT
            if paranoid:
                pool *= 0.6
            elif aggressive:
                pool *= 2.0
        else:
            pool = float(noise_budget)
        self.team.budget.limit = max(0.0, float(pool))
        self.bus = CellBus(self.team.cells)
        self.tribunal = Tribunal(base, adversarial_profile(base))
        # how long an action waits for the permit before the run defers it
        self.permit_wait: float = PERMIT_WAIT_S
        self.routed: int = 0
        self.unrouted: int = 0
        self.deferred: int = 0
        self.refused: int = 0

    # ── construction helpers ───────────────────────────────────────────
    @staticmethod
    def _coverage_stages(cls: str, goal: str, target_type: str) -> Tuple[str, ...]:
        """The stages the ROSTER must cover.

        Two vocabularies meet here and both are real:

            * the doctrine CHAIN (`footprint/exploit/creds/beacon`) — what a
              target class is willing to do at all;
            * the run's own GOALS (`deliver/post_exploit/ad/crack/...`) —
              what this particular run will actually walk.

        A roster built from the chain alone has no `post` cell for a network
        target, so the whole post-exploitation half of a deep run has no
        owner. Covering both is what makes the roster authoritative for the
        run instead of authoritative for the chain.
        """
        chain = list(CellRuntime._stages_for(cls, goal, target_type))
        extra: List[str] = []
        if goal in ("deep", "complete_kill_chain"):
            extra.extend(DEEP_LADDER)
        elif goal:
            extra.append(goal)
        # A beacon-bound goal implies a HOST, and a host implies recon: an
        # identity chain reaches its beacon by handing the harvested victim
        # IP over to the network phase, so the roster of an identity-class
        # deliver run must contain the recon role even though the identity
        # chain forbids `footprint` as a chain stage. Without this the strict
        # loop refused `scan_tcp` eleven times on an email target and the run
        # never reached its beacon — measured, not theorised.
        if goal in _HOST_BOUND:
            extra.append("footprint")
        for st in extra:
            if st not in chain:
                chain.append(st)
        return tuple(chain)

    @staticmethod
    def _stages_for(cls: str, goal: str, target_type: str) -> Tuple[str, ...]:
        """The doctrine chain for this class, minus the goals it forbids."""
        if cls:
            try:
                from phantom.automation.brain.doctrine import for_class
                d = for_class(cls)
                allowed = [g for g, _ in d.stages if g not in d.forbidden]
                if allowed:
                    return tuple(allowed)
            except Exception:
                pass
        return ()

    # ── start ──────────────────────────────────────────────────────────
    def start(self) -> dict:
        """Emit the roster and return its summary (the operator sees WHO is
        on the job before anything runs)."""
        payload = {
            "cells": self.team.stats()["roles"],
            "acting_cap": self.team.permit.acting_cap,
            "profile": self.profile.name,
            "search_policy": self.profile.search_policy,
            "chain": list(self.stages),
            "strict": self.strict,
            "noise_budget": self.team.budget.to_dict(),
            "per_cell": [c.to_dict() for c in self.team.cells],
        }
        self._emit("roster", **payload)
        return payload

    def _emit(self, kind: str, **data) -> None:
        if self.emit is None:
            return
        try:
            self.emit(kind, data)
        except Exception:
            pass

    # ── stage ──────────────────────────────────────────────────────────
    def set_stage(self, stage: str) -> None:
        """Declare the stage in flight. The permit cap follows it: during an
        identity/social stage the contact-free cells may act in parallel,
        and the moment the chain reaches a target-touching stage the cap
        collapses to one. This is the operator's rule — concurrency is a
        property of the action — enforced where it belongs."""
        if not stage or stage == getattr(self, "_stage", ""):
            return
        self._stage = stage
        self.team.set_active_stage(stage)
        self._emit("stage_scope", stage=stage,
                   acting_cap=self.team.permit.acting_cap,
                   cells=[c.cell_id for c in self.team._active_acting()])

    # ── routing ────────────────────────────────────────────────────────
    def cell_for(self, cap: Any, stage: str = "",
                 stage_scoped: bool = False) -> Optional[Cell]:
        """The cell that owns a capability: same stage first, then any cell
        that may use its category. Advisory cells are never routed to.

        `stage_scoped` restricts the search to the roles that SERVE the
        stage in flight. That is the C4 migration: during a migrated stage
        the stage's own cells are the authority, so a capability that no
        role of THIS stage can use is refused rather than quietly handed to
        a cell belonging to a later stage.
        """
        category = str(getattr(cap, "category", "") or "")
        if not category:
            return None
        pool = [c for c in self.team.cells
                if not c.advisory and c.may_use(category)]
        if not pool:
            return None
        if stage_scoped:
            roles = self.coverage_roles()
            if roles:
                staged = [c for c in pool if c.spec.role in roles]
                if not staged:
                    return None
                pool = staged
        if stage:
            for c in pool:
                if c.spec.stage == stage:
                    return c
        for c in pool:
            if c.spec.contact != CONTACT_NONE:
                return c
        return pool[0]

    def owns(self, cap: Any, stage: str = "",
             stage_scoped: bool = False) -> bool:
        return self.cell_for(cap, stage, stage_scoped) is not None

    def coverage_roles(self) -> set:
        """The roles the RUN's coverage needs.

        Every stage in `self.stages` — the doctrine chain PLUS the goals this
        run will walk, joined at construction — not only the stage in flight.
        That is the set the coverage gate verified, so it is also the set the
        strict loop may invoke as its authority.

        Narrowing it to the single stage in flight was the first attempt and
        it starves the chain: the capability that DELIVERS a beacon is
        category `beacon`, owned by the `foothold` role, while the stage in
        flight during a deliver run is a goal whose own role set does not
        include half of what the chain still has to do. An empty set means
        "no declared coverage", and the roster stays the authority.
        """
        roles: set = set()
        for st in self.stages:
            roles.update(STAGE_ROLES.get(st, ()))
        return roles

    def missing_coverage_categories(self, categories: Sequence[str]) -> List[str]:
        """The categories the run's coverage has NO cell for.

        This is the gate a GOAL must pass before it is added to
        MIGRATED_STAGES: an empty list means the roster is complete for every
        class the goal can occur on, so switching the strict loop on cannot
        silently drop work.
        """
        roles = self.coverage_roles()
        owned: set = set()
        for c in self.team.cells:
            if not roles or c.spec.role in roles:
                owned |= set(c.spec.uses_categories)
        return sorted({str(cat) for cat in categories if cat not in owned})

    def missing_stage_categories(self, stage: str,
                                 categories: Sequence[str]) -> List[str]:
        """The capability CATEGORIES the stage's own roles cannot use.

        This is the gate a stage must pass BEFORE it is migrated: an empty
        list means the stage's scope is complete and the strict loop can be
        switched on for it without silently dropping work. Callers pass the
        categories of the capabilities the planner can legitimately pick for
        that stage (see the stage-scope test).
        """
        roles = set(STAGE_ROLES.get(stage, ()))
        owned: set = set()
        for c in self.team.cells:
            if c.spec.role in roles:
                owned |= set(c.spec.uses_categories)
        return sorted({str(cat) for cat in categories if cat not in owned})

    # ── noise budget (buco 4) ──────────────────────────────────────────
    def charge(self, cell: Optional[Cell], cap: Any) -> bool:
        """Charge the run's noise pool for an action. False = overspend.

        The cost is the capability's `opsec_cost`, falling back to its
        detection risk when it declares none. Refusal is recorded by the
        budget itself, so "we chose restraint here" is auditable.
        """
        cost = float(getattr(cap, "opsec_cost", 1.0) or 0.0)
        if cost <= 0:
            cost = float(getattr(cap, "detection_risk", 0.0) or 0.0)
        cid = getattr(cell, "cell_id", "") if cell is not None else ""
        return self.team.budget.charge(
            cid, cost, capability=str(getattr(cap, "id", "") or ""))

    # ── permit ─────────────────────────────────────────────────────────
    def admit(self, cell: Optional[Cell], wait: Optional[float] = None) -> bool:
        """Try to take the egress permit for a cell.

        Advisory cells never act; an unowned action (no cell) is not gated
        in lenient mode, because the roster is an addition, not a fence.
        `wait=None` uses the runtime's configured permit wait.
        """
        if cell is None or cell.advisory:
            return cell is None
        if wait is None:
            wait = self.permit_wait
        return self.team.permit.acquire(cell.cell_id, timeout=wait)

    def release(self, cell: Optional[Cell]) -> None:
        if cell is not None and not cell.advisory:
            self.team.permit.release(cell.cell_id)

    # ── stall handling ─────────────────────────────────────────────────
    def on_stall(self, stall_class: str, failed_cap: Any = None,
                 stage: str = "") -> Optional[Cell]:
        """A cell stalled: escalate it (advisory peer for target-touching
        roles) and point the tribunal at the peer's objective."""
        cell = self.cell_for(failed_cap, stage) if failed_cap is not None else None
        if cell is None:
            return None
        peer = self.team.escalate(cell, reason=stall_class or "stalled")
        if peer is None:
            return None
        self.bus.register(peer)
        self.tribunal.peer_profile = peer.profile
        self.tribunal._peer = Arbitrator(peer.profile)   # noqa: SLF001 — peer swap
        self._emit("escalation", **self.team.escalations[-1])
        return peer

    # ── per-cell world view (buco 1) ───────────────────────────────────
    def views_for(self, findings: Sequence[Any]) -> Dict[str, CellView]:
        """Each cell's OWN projection of the shared map.

        The roster used to differ only in the capabilities a cell may USE;
        this is the other half — the facts it may SEE. Reasoning is then
        scoped on the data, not merely on the hands.
        """
        pool = list(findings)
        return {c.cell_id: c.view(pool) for c in self.team.cells}

    def scope_of(self, cell_id: str, findings: Sequence[Any]) -> CellView:
        for c in self.team.cells:
            if c.cell_id == cell_id:
                return c.view(list(findings))
        return CellView(cell_id=cell_id, role="", visible=(), hidden=0)

    def report_scope(self, findings: Sequence[Any]) -> dict:
        """Emit what each cell can and cannot see (auditability)."""
        pool = list(findings)
        views = self.views_for(pool)
        payload = {"shared_facts": len(pool),
                   "cells": {cid: v.to_dict() for cid, v in views.items()}}
        self._emit("cell_scope", **payload)
        return payload

    # ── second opinion ─────────────────────────────────────────────────
    def second_opinion(self, views: Sequence[Any],
                       base_of: Dict[str, float],
                       signals: WorldSignals,
                       lead_cell: str = "lead",
                       peer_views: Optional[Sequence[Any]] = None,
                       peer_signals: Optional[WorldSignals] = None
                       ) -> Optional[Dispute]:
        """Rate the candidate set through both profiles and adjudicate.

        `peer_views`/`peer_signals` are the peer's OWN world (buco 1): when
        given, the peer rates only what it can see, so its opinion is a
        second REASONING over a scoped map, not a relabel of the lead's.
        """
        if not views:
            return None
        peer_cell = next((c.cell_id for c in self.team.advisory_cells()),
                         "peer")
        dispute = self.tribunal.adjudicate(
            views, base_of, signals, lead_cell=lead_cell, peer_cell=peer_cell,
            peer_views=peer_views, peer_signals=peer_signals)
        if not dispute.agreed:
            self._emit("advice", **dispute.to_dict())
        return dispute

    # ── parallel reasoning (buco 2) ────────────────────────────────────
    def parallel_opinions(self, views_by_cell: Dict[str, Sequence[Any]],
                          base_of: Dict[str, float], signals: WorldSignals,
                          max_workers: int = 4) -> List[Opinion]:
        """Rate the SAME candidates in PARALLEL, one thread per QUIET cell.

        Concurrency is a property of the ACTION (the operator's rule): only
        cells with CONTACT_NONE take part; a target-touching role is
        serialised and therefore excluded here. Each cell rates the
        candidates IT is aware of, through its OWN profile, over its OWN
        world view — the `views_by_cell` map is what makes those two facts
        true, so the threads are genuinely independent reasoners rather
        than N copies of the lead.

        Returns the opinions in roster order (deterministic), and emits a
        `parallel_reasoning` event so the operator can see them.
        """
        from concurrent.futures import ThreadPoolExecutor, as_completed
        quiet = {c.cell_id: c for c in self.team.cells
                 if not c.advisory and c.spec.contact == CONTACT_NONE}
        pairs = [(cid, list(views_by_cell.get(cid, ())))
                 for cid in quiet if views_by_cell.get(cid)]
        if not pairs:
            return []
        order = [cid for cid, _ in pairs]
        opinions: List[Opinion] = []
        workers = max(1, min(int(max_workers), len(pairs)))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(self.tribunal.opinion, cid, quiet[cid].profile,
                              vs, base_of, signals): cid
                    for cid, vs in pairs}
            for fut in as_completed(futs):
                try:
                    opinions.append(fut.result())
                except Exception:
                    continue
        opinions.sort(key=lambda o: order.index(o.cell_id))
        consensus, score = self.consensus(opinions)
        self._emit("parallel_reasoning", threads=len(pairs),
                   cells=[o.to_dict() for o in opinions],
                   consensus=consensus, consensus_score=round(score, 4))
        return opinions

    @staticmethod
    def consensus(opinions: Sequence[Opinion]) -> tuple:
        """Merge concurrent opinions: the move with the most SUPPORT wins,
        ties broken by aggregate score.

        Support counts cells that rank a move at all (so N quiet cells
        agreeing beat one cell's strong preference), which is the useful
        reading of "N angles converge". Returns (capability, score) or
        (None, 0.0) when nothing was ranked.
        """
        support: Dict[str, int] = {}
        score: Dict[str, float] = {}
        for op in opinions:
            for cid, value in op.ranking:
                support[cid] = support.get(cid, 0) + 1
                score[cid] = score.get(cid, 0.0) + float(value)
        if not support:
            return None, 0.0
        best = max(support, key=lambda c: (support[c], score[c], c))
        return best, score[best]

    # ── the plan as a DAG (buco 3) ─────────────────────────────────────
    def plan_graph(self, plan: Any,
                   goal_facts: Sequence[str] = ()) -> Optional[dict]:
        """Build and EMIT the run's plan as an explicit DAG.

        The planner hands back an ordered list; this is the same plan seen as
        the run's mental model — nodes, dependency edges, layers and the
        critical path to the goal — so the operator (and the run) can tell a
        move on the critical path from a side branch. Never raises into the
        run.
        """
        try:
            from phantom.automation.brain.plan_graph import PlanGraph
            graph = PlanGraph.from_plan(plan, goal_facts=goal_facts)
            payload = graph.to_dict()
            self._emit("plan_graph", **payload)
            return payload
        except Exception:
            return None

    # ── introspection ──────────────────────────────────────────────────
    def stats(self) -> dict:
        return {"team": self.team.stats(), "bus": self.bus.stats(),
                "tribunal": self.tribunal.stats(), "routed": self.routed,
                "unrouted": self.unrouted, "deferred": self.deferred,
                "refused": self.refused, "strict": self.strict,
                "budget": self.team.budget.to_dict(),
                "chain": list(self.stages)}

    def to_dict(self) -> dict:
        return {"chain": list(self.stages), "profile": self.profile.name,
                "strict": self.strict,
                "budget": self.team.budget.to_dict(),
                "team": self.team.stats(),
                "cells": [c.to_dict() for c in self.team.cells],
                "advice": [d.to_dict() for d in self.tribunal.disagreements()]}
