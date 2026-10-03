"""
phantom.automation.brain.plan_arbiter — arbitrating between PLAN VARIANTS (B3).

B3 delivered the plan as a DAG (``brain/plan_graph.py``): nodes, dependency
edges, layers and the critical path. It was honest about what it did NOT
deliver: the run still took the FIRST plan the backward chain produced. The
planner returns ONE ordered list per (goal, preference) pair, but more than
one plan can reach the same goal — cheaper but louder, quieter but longer,
identity-first vs exploit-first. Choosing among them IS the arbitration B3
left open.

This module closes it, and it does so ON THE DAG rather than on the list,
because the graph is what makes the variants comparable: two plans with the
same steps in a different order are the same DAG; two plans that reach the
goal through different layers are different graphs with different critical
paths, different cost, different contact.

    PlanVariant — one candidate plan + its DAG + a human label.
    PlanChoice  — the winner, every variant's score, and WHY it won.

Scoring is the same discipline as the move arbiter (``lenses.py``): a set of
readings (progress, evidence, stealth, cost, contact) combined with weights
that follow the ENGAGEMENT STATE (events, never a clock). When the engagement
is already loud, stealth weighs more; when the run is blind, evidence does.
A contact-heavy variant is penalised by construction, which is the same
"non-contact first" rule the identity doctrine (I3) enforces one layer down.

Bounded and auditable: the arbiter only ever picks among plans the planner
ALREADY produced (it can never invent a step), every score is recorded, and
when it cannot decide it keeps the first variant (the operator's default).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from phantom.automation.brain.lenses import WorldSignals
from phantom.automation.brain.plan_graph import GOAL_NODE, PlanGraph

# contact classes, most intrusive last — a plan's contact is the MAX over its
# nodes, so a single contact step makes the whole variant a contact variant
_CONTACT_RANK: Dict[str, int] = {
    "": 0, "none": 0, "passive": 0, "recon": 0, "active": 1, "contact": 2,
    "exploit": 2,
}

# opsec cost at which the cost reading bottoms out (a plan is not compared on
# an unbounded scale — 30 units is already "expensive" for this purpose)
_COST_SCALE = 30.0


@dataclass
class PlanVariant:
    """One candidate plan, its DAG, and a human label for the operator."""
    variant_id: str
    label: str
    plan: Any
    graph: PlanGraph
    goal_facts: Tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {"variant": self.variant_id, "label": self.label,
                "steps": [str(getattr(s.capability, "id", ""))
                          for s in getattr(self.plan, "steps", [])],
                "strategy": getattr(self.plan, "strategy", ""),
                "complete": bool(getattr(self.plan, "complete", False)),
                "nodes": len(self.graph.nodes),
                "critical": len(self.graph.critical_path())}


@dataclass
class PlanChoice:
    """The arbitration outcome: the winning variant and every score."""
    winner: PlanVariant
    scores: Dict[str, float] = field(default_factory=dict)
    readings: Dict[str, Dict[str, float]] = field(default_factory=dict)
    rule: str = "first variant (no decisive advantage)"
    decided: bool = False

    def explain(self) -> str:
        order = sorted(self.scores.items(), key=lambda kv: (-kv[1], kv[0]))
        shown = ", ".join(f"{vid}={score:.3f}" for vid, score in order)
        return (f"plan arbiter: chose {self.winner.variant_id} "
                f"[{self.rule}] ({shown})")

    def to_dict(self) -> dict:
        return {"winner": self.winner.variant_id,
                "label": self.winner.label,
                "rule": self.rule,
                "decided": self.decided,
                "scores": {k: round(v, 4) for k, v in self.scores.items()},
                "readings": {k: {kk: round(vv, 4) for kk, vv in v.items()}
                             for k, v in self.readings.items()},
                "variants": [v.to_dict() for v in self._variants]}
    _variants: List[PlanVariant] = field(default_factory=list)


def _plan_cost(plan: Any) -> float:
    total = 0.0
    for step in getattr(plan, "steps", []) or []:
        cap = getattr(step, "capability", step)
        try:
            total += float(getattr(cap, "opsec_cost", 1.0) or 0.0)
        except (TypeError, ValueError):
            total += 1.0
    return total


def _plan_risk(plan: Any) -> float:
    risks = []
    for step in getattr(plan, "steps", []) or []:
        cap = getattr(step, "capability", step)
        try:
            risks.append(float(getattr(cap, "detection_risk", 0.0) or 0.0))
        except (TypeError, ValueError):
            risks.append(0.0)
    return sum(risks) / len(risks) if risks else 0.0


def _plan_contact_ranks(plan: Any, graph: PlanGraph) -> List[int]:
    """The contact rank of every node (falls back to the capability category
    when the graph carried no contact class)."""
    ranks: List[int] = []
    for node in graph.nodes:
        cls = (node.contact or "").lower()
        ranks.append(_CONTACT_RANK.get(cls, 0))
    if ranks:
        return ranks
    for step in getattr(plan, "steps", []) or []:
        cap = getattr(step, "capability", step)
        cat = str(getattr(cap, "category", "") or "").lower()
        if cat == "social":
            ranks.append(_CONTACT_RANK["contact"])
        elif cat in ("exploit", "brute"):
            ranks.append(_CONTACT_RANK["exploit"])
        else:
            ranks.append(0)
    return ranks


def _contact_reading(plan: Any, graph: PlanGraph) -> float:
    """How little contact the plan needs, 0..1 (higher = less contact).

    A blend of the MAX (a single contact step makes the whole plan a contact
    plan — the identity doctrine's rule) and the MEAN (how much of the plan
    is contact), so a one-step contact plan and an all-contact plan are not
    scored alike.
    """
    ranks = _plan_contact_ranks(plan, graph)
    if not ranks:
        return 1.0
    worst = max(ranks) / 2.0
    mean = (sum(ranks) / len(ranks)) / 2.0
    penalty = 0.5 * worst + 0.5 * mean
    return round(max(0.0, 1.0 - penalty), 4)


def _graph_facts(graph: PlanGraph) -> set:
    facts: set = set()
    for node in graph.nodes:
        facts.update(str(e) for e in (node.effects or ()))
    return facts


def readings_for(variant: PlanVariant) -> Dict[str, float]:
    """The five readings of one plan variant (each 0..1, higher is better).

    progress — does the DAG reach the goal facts, and how deep is its spine
    evidence — how many still-wanted facts the plan would newly produce
    stealth  — how quiet the plan is overall (inverse detection risk)
    cost     — inverse opsec cost (cheaper is better)
    contact  — inverse contact class (non-contact first, by construction)
    """
    graph = variant.graph
    goal_facts = set(variant.goal_facts or ())
    facts = _graph_facts(graph)

    if goal_facts:
        reached = len(goal_facts & facts) / len(goal_facts)
    else:
        reached = 1.0 if graph.nodes else 0.0
    # a deeper spine means the plan actually walks toward the goal instead of
    # stopping at one node; normalised on the number of layers it has
    spine = len(graph.critical_path())
    depth = min(1.0, spine / max(1, len(graph.layers()) + 1)) if graph.nodes else 0.0
    progress = 0.7 * reached + 0.3 * depth

    evidence = min(1.0, len(goal_facts & facts) / max(1, len(goal_facts))) \
        if goal_facts else 0.5
    if not graph.nodes:
        evidence = 0.0

    stealth = 1.0 - max(0.0, min(1.0, _plan_risk(variant.plan)))
    cost = 1.0 - max(0.0, min(1.0, _plan_cost(variant.plan) / _COST_SCALE))

    return {"progress": round(progress, 4), "evidence": round(evidence, 4),
            "stealth": round(stealth, 4), "cost": round(cost, 4),
            "contact": _contact_reading(variant.plan, graph)}


# base weights (progress matters most, but a loud/expensive plan is not free)
_BASE_WEIGHTS: Dict[str, float] = {
    "progress": 0.34, "evidence": 0.16, "stealth": 0.20,
    "cost": 0.15, "contact": 0.15,
}

# state adaptations: same vocabulary as the move arbiter (lenses._ADAPTATIONS)
_ADAPTATIONS: Tuple[Tuple[str, str, float], ...] = (
    ("breaker_tripped", "stealth", 2.20),
    ("breaker_tripped", "contact", 1.60),
    ("breaker_tripped", "progress", 0.70),
    ("noise_high", "stealth", 1.40),
    ("blind", "evidence", 1.55),
    ("blind", "progress", 0.90),
    ("foothold", "stealth", 1.30),
    ("foothold", "progress", 0.70),
)


def _conditions(sig: WorldSignals) -> set:
    conds = set()
    if sig.breaker_tripped:
        conds.add("breaker_tripped")
    if sig.noise_ratio >= 0.60:
        conds.add("noise_high")
    if not sig.visibility:
        conds.add("blind")
    if sig.foothold:
        conds.add("foothold")
    return conds


def weights_for(sig: WorldSignals) -> Dict[str, float]:
    raw = dict(_BASE_WEIGHTS)
    conds = _conditions(sig)
    for cond, lens, factor in _ADAPTATIONS:
        if cond in conds:
            raw[lens] = raw.get(lens, 0.0) * factor
    total = sum(raw.values()) or 1.0
    return {k: v / total for k, v in raw.items()}


class PlanArbiter:
    """Chooses among plan variants by scoring their DAGs under the state."""

    def __init__(self, margin: float = 0.02) -> None:
        # how much better a variant must score before it DISPLACES the first
        # (the planner's own pick). A tie keeps the default: the arbiter is a
        # decision aid, not a coin.
        self.margin = max(0.0, float(margin))

    def score(self, variant: PlanVariant,
              sig: WorldSignals) -> Tuple[float, Dict[str, float]]:
        readings = readings_for(variant)
        weights = weights_for(sig)
        value = sum(weights.get(k, 0.0) * readings.get(k, 0.0)
                    for k in readings)
        return value, readings

    def choose(self, variants: Sequence[PlanVariant],
               sig: Optional[WorldSignals] = None,
               prefer: Optional[str] = None) -> Optional[PlanChoice]:
        """Pick a variant. `prefer` names the variant to beat (the default).

        Returns None when there is nothing to arbitrate. Deterministic:
        ties break on variant id, so the same world always chooses the same
        plan.
        """
        variants = [v for v in variants if v is not None]
        if not variants:
            return None
        sig = sig or WorldSignals()
        scored: List[Tuple[float, PlanVariant, Dict[str, float]]] = []
        for v in variants:
            value, readings = self.score(v, sig)
            scored.append((value, v, readings))
        scores = {v.variant_id: value for value, v, _ in scored}
        readings_map = {v.variant_id: r for _, v, r in scored}

        best_value, best_variant, _ = max(
            scored, key=lambda t: (t[0], t[1].variant_id))
        default = next((v for v in variants if v.variant_id == prefer),
                       variants[0])
        default_value = scores.get(default.variant_id, 0.0)

        choice = PlanChoice(winner=default, scores=scores,
                            readings=readings_map)
        choice._variants = list(variants)
        if best_variant.variant_id == default.variant_id:
            choice.rule = "default plan holds (no variant beats it)"
            return choice
        if best_value - default_value <= self.margin:
            choice.rule = (f"within the {self.margin:.2f} margin — "
                           "keeping the default plan")
            return choice
        choice.winner = best_variant
        choice.decided = True
        choice.rule = (f"{best_variant.label} beats the default "
                       f"({best_value:.3f} vs {default_value:.3f})")
        return choice


# ---------------------------------------------------------------------------
# variant generation (bounded: only plans the planner already produces)
# ---------------------------------------------------------------------------

# preference orderings that produce genuinely different backward chains. They
# are PREFERENCES, not authority: every cap still passes its own gates.
_IDENTITY_FIELD_PREFS: Tuple[str, ...] = (
    "email_candidates", "email_verify", "breach_correlate", "osint_identity",
)


def build_variants(planner: Any, wm: Any, goal: str,
                   prefs: Optional[Sequence[str]] = None,
                   ledger: Any = None,
                   goal_facts: Sequence[str] = (),
                   primary: Any = None,
                   dead: Optional[frozenset] = None) -> List[PlanVariant]:
    """Build the plan variants to arbitrate over.

    `primary` is the plan the run already computed (kept as-is so the default
    is exactly what the run would have done). The extra variants re-run the
    same strategic planner with a different preference ordering — never with
    different gates — so a variant can only reorder already-allowed moves.

    `dead` is the run's dead-capability set (failed/novelty-dead). It MUST be
    threaded through to every variant: a variant is a reordering of the SAME
    allowed moves, and a move the run deliberately killed is not allowed, so
    re-planning without it could resurrect a capability the default plan
    correctly refused (that is how a variant wins and then executes a move
    the run had already ruled out).

    Bounded: at most three plans, each planner call wrapped so a failure
    simply drops that variant.
    """
    variants: List[PlanVariant] = []

    def _add(vid: str, label: str, plan: Any) -> None:
        if plan is None:
            return
        try:
            graph = PlanGraph.from_plan(plan, goal_facts=goal_facts)
        except Exception:
            return
        variants.append(PlanVariant(variant_id=vid, label=label, plan=plan,
                                    graph=graph,
                                    goal_facts=tuple(goal_facts or ())))

    primary = primary if primary is not None else planner.plan_strategic(
        wm, goal=goal, preference=list(prefs or []), ledger=ledger,
        dead=dead)
    _add("primary", "planner default", primary)

    base = list(prefs or [])
    ident = [c for c in _IDENTITY_FIELD_PREFS if c not in base] + base
    try:
        _add("identity_field", "identity field first",
             planner.plan_strategic(wm, goal=goal, preference=ident,
                                    ledger=ledger, dead=dead))
    except Exception:
        pass

    try:
        _add("generic", "no preference (generic chain)",
             planner.plan_strategic(wm, goal=goal, preference=[],
                                    ledger=ledger, dead=dead))
    except Exception:
        pass

    return variants
