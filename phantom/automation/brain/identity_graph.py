"""
phantom.automation.brain.identity_graph — the identity FIELD graph (I4).

I1 reasons over a thin identity field: it turns a handle / a masked reset
email / a leaked address into CANDIDATE fields. I2 executes the non-contact
primitives that turn a candidate into a fact. This module answers the
operator's NEXT question, the one neither of those modules could:

    "of all the fields I could widen, which ONE do I widen first?"

A senior operator does not probe blindly. They hold a small graph in their
head: this handle implies these local-parts, this masked reset reveals this
domain, this domain buys these candidates, a candidate that verifies opens
the services where the address is an account, and exposure widens the same
person elsewhere. The order they widen is not arbitrary — they walk the
SPINE that leads to "the person is mapped", and they prefer the field that
unlocks the most (bounded by how uncertain the situation is).

The module makes that graph explicit:

    FieldNode    — one identity field: its kind, whether it is KNOWN (a
                   finding already in the WorldModel) or still a CANDIDATE,
                   the capability+contact class that would widen it, and its
                   cost.
    Deduction    — a kind-level edge: `email_masked -> domain_candidate`,
                   `email_candidate -> email_verified`, `email_verified ->
                   service_account`, ... Every edge points from a lower
                   field-kind rank to a higher one, so the structure is a DAG
                   BY CONSTRUCTION (the same trick brain/plan_graph.py uses
                   for the plan).
    FRONTIER     — the candidate fields reachable from what we already know:
                   the only fields it is legitimate to widen right now.
    CRITICAL PATH— the longest spine from an entry kind to a TERMINAL kind
                   (verified / breach / service account / widened identity):
                   reaching one of those means the person is MAPPED.
    INFO-GAIN    — how many still-unknown fields a widening unlocks. It is a
                   BOUNDED multiplier (R3: "solo a ipotesi incerte"), so it
                   can only reorder near-ties — a cheap, high-confidence,
                   non-contact field still wins outright.

`next_fields()` is the operator answer: the frontier ordered by
  * on the critical path (the spine to mapping), then
  * cost/confidence, discounted by contact class, modulated by a bounded
    info-gain bonus.
Nothing here gates a capability or touches the network: the graph only
ORDERS moves that are already allowed, exactly like the reasoning engine.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from phantom.automation.brain.identity import (
    KIND_ACCOUNT_LINK,
    KIND_BREACH_EXPOSURE,
    KIND_CREDS,
    KIND_DOMAIN_CANDIDATE,
    KIND_EMAIL_CANDIDATE,
    KIND_EMAIL_MASKED,
    KIND_EMAIL_VERIFIED,
    KIND_IDENTITY,
    KIND_IDENTITY_WIDENED,
    KIND_PROFILE,
    KIND_SERVICE_ACCOUNT,
    Derivation,
)
from phantom.automation.brain.lenses import INFO_GAIN_CEIL, INFO_GAIN_MAX

# field kinds that can be a node in the graph
FIELD_KINDS: frozenset = frozenset({
    KIND_IDENTITY, KIND_PROFILE, KIND_ACCOUNT_LINK, KIND_EMAIL_MASKED,
    KIND_DOMAIN_CANDIDATE, KIND_EMAIL_CANDIDATE, KIND_EMAIL_VERIFIED,
    KIND_SERVICE_ACCOUNT, KIND_BREACH_EXPOSURE, KIND_IDENTITY_WIDENED,
    KIND_CREDS,
})

# reaching one of these means the person is MAPPED
TERMINAL_KINDS: frozenset = frozenset({
    KIND_EMAIL_VERIFIED, KIND_BREACH_EXPOSURE, KIND_SERVICE_ACCOUNT,
    KIND_IDENTITY_WIDENED,
})

# layering axis: every deduction points from a lower rank to a higher one, so
# the graph cannot contain a cycle by construction.
_KIND_RANK: Dict[str, int] = {
    KIND_IDENTITY: 0, KIND_PROFILE: 0, KIND_ACCOUNT_LINK: 0,
    KIND_EMAIL_MASKED: 0, KIND_CREDS: 0,
    KIND_DOMAIN_CANDIDATE: 1,
    KIND_EMAIL_CANDIDATE: 2,
    KIND_EMAIL_VERIFIED: 3,
    KIND_BREACH_EXPOSURE: 4,
    KIND_SERVICE_ACCOUNT: 5,
    KIND_IDENTITY_WIDENED: 5,
}

# the deduction schema: kind A can yield kind B. All edges rank-increasing.
_DEDUCTION_SCHEMA: Tuple[Tuple[str, str], ...] = (
    (KIND_IDENTITY, KIND_DOMAIN_CANDIDATE),
    (KIND_IDENTITY, KIND_EMAIL_CANDIDATE),
    (KIND_PROFILE, KIND_DOMAIN_CANDIDATE),
    (KIND_PROFILE, KIND_EMAIL_CANDIDATE),
    (KIND_PROFILE, KIND_ACCOUNT_LINK),
    (KIND_EMAIL_MASKED, KIND_DOMAIN_CANDIDATE),
    (KIND_EMAIL_MASKED, KIND_EMAIL_CANDIDATE),
    (KIND_DOMAIN_CANDIDATE, KIND_EMAIL_CANDIDATE),
    (KIND_EMAIL_CANDIDATE, KIND_EMAIL_VERIFIED),
    (KIND_CREDS, KIND_SERVICE_ACCOUNT),
    (KIND_EMAIL_VERIFIED, KIND_BREACH_EXPOSURE),
    (KIND_EMAIL_VERIFIED, KIND_SERVICE_ACCOUNT),
    (KIND_EMAIL_VERIFIED, KIND_IDENTITY_WIDENED),
    (KIND_BREACH_EXPOSURE, KIND_IDENTITY_WIDENED),
    (KIND_BREACH_EXPOSURE, KIND_SERVICE_ACCOUNT),
)

# contact class -> integer penalty rank (non-contact first, the whole point)
_CONTACT_RANK: Dict[str, int] = {
    "": 0, "none": 0, "passive": 0, "active": 1, "contact": 2,
}


def _is_known(wm: Any, kind: str, key: str) -> bool:
    try:
        return any(f.key == key for f in wm.find(kind))
    except Exception:
        return False


@dataclass(frozen=True)
class FieldNode:
    """One identity field: known finding or a candidate to widen."""
    node_id: str
    kind: str
    known: bool = False
    confidence: float = 0.0
    capability: str = ""
    contact: str = ""
    cost: float = 1.0
    reason: str = ""
    evidence: str = ""

    @property
    def rank(self) -> int:
        return _KIND_RANK.get(self.kind, 3)

    @property
    def terminal(self) -> bool:
        return self.kind in TERMINAL_KINDS

    def to_dict(self) -> dict:
        return {"node": self.node_id, "kind": self.kind, "known": self.known,
                "confidence": round(self.confidence, 3),
                "capability": self.capability, "contact": self.contact,
                "cost": self.cost, "rank": self.rank, "terminal": self.terminal}


@dataclass(frozen=True)
class FieldPriority:
    """A frontier field + WHY it ranks where it does."""
    node_id: str
    kind: str
    capability: str
    contact: str
    cost: float
    confidence: float
    info_gain: int
    score: float
    on_critical_path: bool = False
    reason: str = ""

    def to_dict(self) -> dict:
        return {"node": self.node_id, "kind": self.kind,
                "capability": self.capability, "contact": self.contact,
                "cost": self.cost, "confidence": round(self.confidence, 3),
                "info_gain": self.info_gain, "score": round(self.score, 4),
                "critical": self.on_critical_path, "reason": self.reason}


class IdentityFieldGraph:
    """The identity field graph: nodes, deduction edges, frontier, spine."""

    def __init__(self, nodes: Sequence[FieldNode],
                 edges: Iterable[Tuple[str, str]] = ()) -> None:
        self.nodes: List[FieldNode] = list(nodes)
        self._by_id: Dict[str, FieldNode] = {n.node_id: n for n in self.nodes}
        self.edges: Tuple[Tuple[str, str], ...] = tuple(sorted(set(
            (str(a), str(b)) for a, b in edges)))
        self._adj: Dict[str, Set[str]] = {}
        self._rev: Dict[str, Set[str]] = {}
        for a, b in self.edges:
            self._adj.setdefault(a, set()).add(b)
            self._rev.setdefault(b, set()).add(a)

    # ── construction ───────────────────────────────────────────────────
    @classmethod
    def from_reasoner(cls, derivations: Sequence[Derivation],
                      wm: Any) -> "IdentityFieldGraph":
        """Build the graph from the reasoner's derivations + the WorldModel.

        Known findings seed the root nodes; every derivation contributes a
        (candidate) node and, when its hypothesis names a capability, the
        move that would widen it.
        """
        nodes: Dict[str, FieldNode] = {}
        # 1) known findings in the field kinds are the roots
        for kind in FIELD_KINDS:
            for f in wm.find(kind):
                nid = str(f.key)
                nodes.setdefault(nid, FieldNode(
                    node_id=nid, kind=kind, known=True,
                    confidence=float(getattr(f, "confidence", 0.0) or 0.0),
                    evidence=str(getattr(f, "evidence", "") or "")))
        # 2) derivations overlay candidate nodes (and attach the move)
        for d in derivations:
            if d.kind not in FIELD_KINDS:
                continue
            nid = d.key
            hyp = d.hypothesis or {}
            prev = nodes.get(nid)
            known = _is_known(wm, d.kind, nid) or (prev.known if prev else False)
            cand = FieldNode(
                node_id=nid, kind=d.kind, known=known,
                confidence=max(float(d.confidence or 0.0),
                               prev.confidence if prev else 0.0),
                capability=str(hyp.get("capability_id", "") or ""),
                contact=str(hyp.get("contact", "") or ""),
                cost=float(hyp.get("cost", 1.0) or 1.0),
                reason=str(hyp.get("reason", "") or ""),
                evidence=str(d.evidence or ""))
            if prev and prev.known and not cand.capability:
                # keep the richer known node
                nodes[nid] = FieldNode(
                    node_id=nid, kind=prev.kind, known=True,
                    confidence=prev.confidence, evidence=prev.evidence)
                continue
            nodes[nid] = cand
        # 3) edges from the kind-level deduction schema
        by_kind: Dict[str, List[str]] = {}
        for n in nodes.values():
            by_kind.setdefault(n.kind, []).append(n.node_id)
        edges: Set[Tuple[str, str]] = set()
        for a_kind, b_kind in _DEDUCTION_SCHEMA:
            for a in by_kind.get(a_kind, ()):
                for b in by_kind.get(b_kind, ()):
                    if a != b:
                        edges.add((a, b))
        return cls(list(nodes.values()), edges)

    @classmethod
    def from_world(cls, wm: Any, active_consent: bool = False,
                   contact_consent: bool = False) -> "IdentityFieldGraph":
        """Convenience: run the I1 reasoner, then build the graph."""
        from phantom.automation.brain.identity import IdentityReasoner
        reasoner = IdentityReasoner(active_consent=active_consent,
                                    contact_consent=contact_consent)
        return cls.from_reasoner(reasoner.reason(wm), wm)

    # ── structure ──────────────────────────────────────────────────────
    def is_dag(self) -> bool:
        """True by construction — kept as an executable invariant."""
        return all(_KIND_RANK.get(self._by_id[a].kind, 3)
                   < _KIND_RANK.get(self._by_id[b].kind, 3)
                   for a, b in self.edges)

    def _ancestors(self, node_id: str) -> Set[str]:
        seen: Set[str] = set()
        stack = list(self._rev.get(node_id, ()))
        while stack:
            x = stack.pop()
            if x in seen or x not in self._by_id:
                continue
            seen.add(x)
            stack.extend(self._rev.get(x, ()))
        return seen

    def _descendants(self, node_id: str) -> Set[str]:
        seen: Set[str] = set()
        stack = list(self._adj.get(node_id, ()))
        while stack:
            x = stack.pop()
            if x in seen or x not in self._by_id:
                continue
            seen.add(x)
            stack.extend(self._adj.get(x, ()))
        return seen

    def frontier(self) -> List[FieldNode]:
        """Candidate fields reachable from what is already known."""
        out: List[FieldNode] = []
        for n in self.nodes:
            if n.known:
                continue
            ancestors = self._ancestors(n.node_id)
            if not ancestors or any(self._by_id[a].known for a in ancestors):
                out.append(n)
        return out

    def unknown_info_gain(self, node_id: str) -> int:
        """How many still-unknown fields widening this one unlocks."""
        return sum(1 for d in self._descendants(node_id)
                   if d in self._by_id and not self._by_id[d].known)

    def terminal_nodes(self) -> List[FieldNode]:
        return [n for n in self.nodes if n.terminal]

    # ── critical path (the spine to "mapped") ──────────────────────────
    def critical_path(self) -> List[str]:
        """The longest spine from an entry to a TERMINAL node.

        Deterministic: ties are broken by node id, so the same world maps to
        the same spine. When no terminal node exists the longest chain in the
        graph is returned (the spine to whatever the field can reach).
        """
        memo: Dict[str, List[str]] = {}

        def _longest_to(nid: str) -> List[str]:
            if nid in memo:
                return memo[nid]
            parents = sorted(p for p in self._rev.get(nid, ())
                             if p in self._by_id)
            best: List[str] = []
            for p in parents:
                path = _longest_to(p)
                if len(path) > len(best) or (len(path) == len(best)
                                             and best and path < best):
                    best = path
            memo[nid] = best + [nid]
            return memo[nid]

        ends = [n.node_id for n in self.terminal_nodes()] or \
            [n.node_id for n in self.nodes]
        best: List[str] = []
        for e in sorted(ends):
            path = _longest_to(e)
            if len(path) > len(best) or (len(path) == len(best)
                                         and best and path < best):
                best = path
        return best

    def critical_ids(self) -> Set[str]:
        return set(self.critical_path())

    # ── the operator answer ────────────────────────────────────────────
    def next_fields(self, top: Optional[int] = None,
                    info_bias: float = 1.0,
                    allow_active: bool = True,
                    allow_contact: bool = False) -> List[FieldPriority]:
        """The frontier ranked: which field to widen first.

        score = confidence / cost, discounted by contact class, modulated by
        a BOUNDED info-gain bonus, nudged when the field sits on the spine to
        mapping. The info-gain band is the same one the arbiter uses (R3), so
        a decisive low-cost non-contact field still wins outright.

        Consent mirrors I3's demotion (never removal): a probe the operator
        has not authorised (`active` without active consent, `contact`
        without contact consent) is pushed DOWN the order, not dropped — the
        graph still names it, so the move stays reachable if the operator
        grants consent.
        """
        frontier = self.frontier()
        if not frontier:
            return []
        gains = {n.node_id: self.unknown_info_gain(n.node_id)
                 for n in frontier}
        max_gain = max(gains.values()) if gains else 0
        critical = self.critical_ids()
        band = min(INFO_GAIN_CEIL, INFO_GAIN_MAX * max(0.0, info_bias))
        out: List[FieldPriority] = []
        for n in frontier:
            base = max(0.05, n.confidence) / max(0.1, n.cost)
            base /= (1.0 + _CONTACT_RANK.get(n.contact or "none", 0))
            if max_gain > 0:
                base *= (1.0 + band * (gains[n.node_id] / max_gain))
            on_cp = n.node_id in critical
            if on_cp:
                base *= 1.15
            if not allow_active and (n.contact or "") == "active":
                base *= 0.35
            if not allow_contact and (n.contact or "") == "contact":
                base *= 0.20
            out.append(FieldPriority(
                node_id=n.node_id, kind=n.kind, capability=n.capability,
                contact=n.contact, cost=n.cost, confidence=n.confidence,
                info_gain=gains[n.node_id], score=base,
                on_critical_path=on_cp, reason=n.reason))
        out.sort(key=lambda p: (-p.score, p.node_id))
        return out[:top] if top is not None else out

    def to_dict(self) -> dict:
        return {"nodes": [n.to_dict() for n in self.nodes],
                "edges": [list(e) for e in self.edges],
                "frontier": sorted(n.node_id for n in self.frontier()),
                "critical_path": self.critical_path(),
                "next_fields": [p.to_dict() for p in self.next_fields()],
                "dag": self.is_dag()}
