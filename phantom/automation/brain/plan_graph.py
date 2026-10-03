"""plan_graph.py — the run's PLAN as an explicit DAG (buco 3).

The planner produced an ORDERED LIST of steps and the run arbitrated ONE MOVE
at a time from it. That model can say "do this next"; it cannot say "this move
is on the critical path to the goal, that one is a side branch", which is what
the operator asked for when they chose the DAG as the run's MENTAL MODEL.

This module makes that model explicit:

    PlanNode   — one planned capability: its category, the fact kinds it
                 produces, its kill-chain RANK (the layering axis).
    PlanGraph  — the nodes plus the dependency edges, a synthetic GOAL node
                 every terminal capability points at, the topological LAYERS,
                 and the CRITICAL PATH (the longest chain from the entry
                 layer to the goal).

Edges only ever go from a lower rank to a higher one, so the structure is a
DAG by CONSTRUCTION — the graph cannot silently contain a cycle, and a plan
whose ordering violates the kill-chain ladder shows up as an empty edge set
rather than as a crash. The beacon is just a node; the goal is the sink.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Sequence, Tuple

# kill-chain rank of a category — the layering axis. Unknown categories sit
# in the middle so a new one degrades visibly instead of crashing.
_RANK: Dict[str, int] = {
    "identity": 0, "osint": 0, "social": 0,
    "recon": 1, "scan": 1, "service": 1, "mobile": 1,
    "web": 2, "hunt": 2,
    "exploit": 3, "brute": 3, "creds": 3,
    "payload": 4, "beacon": 4,
    "post": 5, "ad": 5, "cloud": 5,
    "report": 6,
}

# the synthetic sink every terminal capability points at
GOAL_NODE = "__goal__"


@dataclass(frozen=True)
class PlanNode:
    node_id: str
    capability: str
    category: str
    rank: int
    effects: Tuple[str, ...] = ()
    contact: str = ""

    def to_dict(self) -> dict:
        return {"node": self.node_id, "capability": self.capability,
                "category": self.category, "rank": self.rank,
                "effects": list(self.effects), "contact": self.contact}


class PlanGraph:
    """The plan as a DAG: nodes, dependency edges, layers, critical path."""

    def __init__(self, nodes: Sequence[PlanNode],
                 edges: Iterable[Tuple[str, str]] = (),
                 goal_facts: Sequence[str] = ()) -> None:
        self.nodes: List[PlanNode] = list(nodes)
        self.edges: Tuple[Tuple[str, str], ...] = tuple(sorted(set(
            (str(a), str(b)) for a, b in edges)))
        self.goal_facts: Tuple[str, ...] = tuple(goal_facts or ())

    # ── construction ───────────────────────────────────────────────────
    @classmethod
    def from_plan(cls, plan: Any,
                  goal_facts: Sequence[str] = ()) -> "PlanGraph":
        steps = list(getattr(plan, "steps", []) or [])
        nodes: List[PlanNode] = []
        for i, st in enumerate(steps):
            cap = getattr(st, "capability", st)
            cat = str(getattr(cap, "category", "") or "")
            cid = str(getattr(cap, "id", "") or "")
            nodes.append(PlanNode(
                node_id=cid or f"n{i}", capability=cid, category=cat,
                rank=_RANK.get(cat, 3),
                effects=tuple(str(e) for e in
                              (getattr(cap, "effects", ()) or ())),
                contact=str(getattr(cap, "contact", "") or "")))
        layers = cls._by_rank(nodes)
        ranks = sorted(layers)
        edges: set = set()
        # complete bipartite between CONSECUTIVE non-empty layers: a move in
        # a later layer depends on the layer that feeds it
        for a, b in zip(ranks, ranks[1:]):
            for u in layers[a]:
                for v in layers[b]:
                    edges.add((u.node_id, v.node_id))
        if ranks:
            for u in layers[ranks[-1]]:
                edges.add((u.node_id, GOAL_NODE))
        return cls(nodes=nodes, edges=edges, goal_facts=goal_facts)

    @staticmethod
    def _by_rank(nodes: Sequence[PlanNode]) -> Dict[int, List[PlanNode]]:
        out: Dict[int, List[PlanNode]] = {}
        for n in nodes:
            out.setdefault(n.rank, []).append(n)
        return out

    # ── structure ──────────────────────────────────────────────────────
    def layers(self) -> List[List[str]]:
        by_rank = self._by_rank(self.nodes)
        return [[n.node_id for n in sorted(by_rank[r], key=lambda x: x.node_id)]
                for r in sorted(by_rank)]

    def is_dag(self) -> bool:
        """True always by construction — kept as an executable invariant."""
        return all(self._rank_of(a) < self._rank_of(b)
                   for a, b in self.edges if b != GOAL_NODE)

    def critical_path(self) -> List[str]:
        """The longest chain from the entry layer to the GOAL.

        Deterministic: one node per non-empty layer, the lowest node id in
        each, then the goal sink. Because edges are rank-increasing, the
        longest path visits every layer exactly once.
        """
        path: List[str] = []
        for layer in self.layers():
            path.append(layer[0])
        if path:
            path.append(GOAL_NODE)
        return path

    def critical_ids(self) -> set:
        return {n for n in self.critical_path() if n != GOAL_NODE}

    def _rank_of(self, node_id: str) -> int:
        for n in self.nodes:
            if n.node_id == node_id:
                return n.rank
        return _RANK.get("report", 6)

    def to_dict(self) -> dict:
        return {"nodes": [n.to_dict() for n in self.nodes],
                "edges": [list(e) for e in self.edges],
                "layers": self.layers(),
                "critical_path": self.critical_path(),
                "critical": sorted(self.critical_ids()),
                "goal_facts": list(self.goal_facts),
                "dag": self.is_dag()}
