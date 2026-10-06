"""
belief.py — the agent's World Model.

The agent does NOT reason over raw command output. Perception turns output
into typed Findings; the planner reasons over Findings only. This module
owns the belief store (WorldModel) and the identity graph (IdentityGraph)
used for OSINT/social pivoting.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Findings (beliefs)
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single typed belief with confidence and provenance."""
    kind: str                       # e.g. "service", "os", "creds", "web_app", "identity"
    key: str                        # stable key within kind (e.g. "tcp/445")
    value: Any                      # structured payload
    confidence: float = 0.5         # 0..1
    source: str = "perception"      # capability id or probe that produced it
    evidence: str = ""              # raw snippet proving the belief
    target: str = ""                # entity this belief refers to
    ts: float = field(default_factory=time.time)
    # Provenance / quality — a raw provider result and a locally verified
    # probe must not be weighed the same even at equal `confidence`. These
    # are additive (defaulted) so positional construction stays compatible.
    source_reliability: float = 0.5  # how trustworthy the SOURCE is (0..1)
    evidence_quality: float = 0.5    # how strongly the evidence proves it (0..1)
    observed_at: float = field(default_factory=time.time)
    ttl: float = 0.0                 # seconds until stale (0 = no expiry)
    # Corroboration: how many INDEPENDENT sources observed the SAME value.
    # 0/1 = a single observation; a second, independent source raises the
    # belief via ``independence_bonus`` instead of merely rewriting it.
    # ``sources`` is the deduplicated set that ``independent_sources`` counts.
    independent_sources: int = 0
    sources: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def freshness(self, now: Optional[float] = None) -> float:
        """1.0 when just observed, decaying linearly to 0.0 at ``ttl``.

        A finding with no ttl (0.0) never goes stale -> always 1.0.
        """
        if self.ttl <= 0:
            return 1.0
        now = time.time() if now is None else now
        age = max(0.0, now - self.observed_at)
        return max(0.0, 1.0 - age / self.ttl)

    def expired(self, now: Optional[float] = None) -> bool:
        return self.ttl > 0 and self.freshness(now) <= 0.0

    def independence_bonus(self) -> float:
        """A bounded reward for corroboration (brief §8.2).

        One observation is neutral (1.0); each ADDITIONAL independent source
        adds 10%, capped at 1.3, so corroboration tilts an ordering without
        letting one much-copied fact dominate a genuinely stronger source.
        """
        extra = max(0, int(self.independent_sources) - 1)
        return min(1.3, 1.0 + 0.1 * extra)

    def belief_score(self, now: Optional[float] = None) -> float:
        """confidence x source_reliability x evidence_quality x freshness
        x independence_bonus.

        An ordering signal that keeps the raw fields intact; NOT a
        replacement for them. With no corroboration the bonus is 1.0, so a
        single-source finding scores exactly as before.
        """
        return (self.confidence * self.source_reliability
                * self.evidence_quality * self.freshness(now)
                * self.independence_bonus())


@dataclass
class Hypothesis:
    """An untested candidate: a possibility the agent will verify cheaply."""
    capability_id: str
    reason: str
    cost: float = 0.0               # opsec cost of verification
    priority: float = 0.5           # heuristic: expected value
    status: str = "pending"         # pending | confirmed | refuted | abandoned
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# belief-revision actions (WorldModel.add_finding)
REVISED_SUPERSEDED = "superseded"   # stronger evidence replaced the belief
REVISED_REJECTED = "rejected"       # weaker evidence could not replace it


@dataclass
class Revision:
    """One belief revision: what changed (or was refused) and why.

    Revision is PER FACT, never a rebuild of a target model: the key
    ``(kind, key)`` is the unit, so a contradiction on one port's version
    cannot invalidate an unrelated credential. Everything that changed is
    kept here for the report and the checkpoint; the belief itself lives
    on in ``WorldModel._findings``.
    """

    kind: str
    key: str
    action: str                 # superseded | rejected
    old_value: Any
    new_value: Any
    old_confidence: float
    new_confidence: float
    source: str = ""
    reason: str = ""
    ts: float = field(default_factory=time.time)

    @property
    def superseded(self) -> bool:
        return self.action == REVISED_SUPERSEDED

    @property
    def stronger(self) -> bool:
        """The challenger carried strictly more confidence than the belief."""
        return self.new_confidence > self.old_confidence

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MergeResult:
    """The evidence-aware merge of every belief about one (kind, key).

    Instead of first-writer-wins (§9), the merge keeps ALL contributions and
    names the best current belief by ``belief_score``, while retaining the
    corroborating observations and the CONTradicting ones (the rejected
    evidence), so nothing is silently overwritten (§9.3).
    """

    kind: str
    key: str
    current: Optional[Finding] = None
    alternatives: List[Finding] = field(default_factory=list)
    rejected: List[Finding] = field(default_factory=list)
    corroborating: List[Finding] = field(default_factory=list)
    reason: str = ""

    @property
    def independent_sources(self) -> int:
        """Distinct sources that observed the CURRENT value (1 + corroborators)."""
        if self.current is None:
            return 0
        return 1 + len({f.source for f in self.corroborating if f.source})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind, "key": self.key,
            "current": self.current.to_dict() if self.current else None,
            "alternatives": [f.to_dict() for f in self.alternatives],
            "rejected": [f.to_dict() for f in self.rejected],
            "corroborating": [f.to_dict() for f in self.corroborating],
            "independent_sources": self.independent_sources,
            "reason": self.reason,
        }


def merge_findings(kind: str, key: str, candidates: List[Finding],
                   now: Optional[float] = None) -> MergeResult:
    """Reconcile several beliefs about one fact by evidence, not order.

    Deterministic: candidates are ranked by ``belief_score`` (then
    confidence, then source id), so two runs over the same set resolve the
    SAME way regardless of arrival order. Contradicting candidates are
    RETAINED in ``rejected`` rather than dropped — the operator can see what
    was overruled and why.
    """
    cands = [c for c in (candidates or []) if c is not None]
    if not cands:
        return MergeResult(kind=kind, key=key, reason="no candidates")
    scored = sorted(cands, key=lambda f: (-f.belief_score(now),
                                          -f.confidence, f.source or ""))
    current = scored[0]
    alternatives: List[Finding] = []
    rejected: List[Finding] = []
    corroborating: List[Finding] = []
    for f in scored[1:]:
        if f.value == current.value:
            if f.source and f.source != current.source:
                corroborating.append(f)
            else:
                alternatives.append(f)      # same value/source: a repeat
        else:
            rejected.append(f)
    reason = (f"best belief score {current.belief_score(now):.3f} via "
              f"{current.source or '?'}; {len(rejected)} contradicting "
              f"candidate(s) retained")
    sources = {f.source for f in corroborating if f.source}
    if sources:
        reason += f"; corroborated by {len(sources)} independent source(s)"
    return MergeResult(kind=kind, key=key, current=current,
                       alternatives=alternatives, rejected=rejected,
                       corroborating=corroborating, reason=reason)


class WorldModel:
    """Belief store + hypothesis queue + opsec ledger."""

    def __init__(self, target: str = "", target_type: str = "ip"):
        self.target = target
        self.target_type = target_type
        self._findings: Dict[tuple, Finding] = {}
        self.hypotheses: List[Hypothesis] = []
        self.opsec_spent = 0.0
        self.actions_taken: List[Dict[str, Any]] = []   # audit trail
        self.failures: List[Dict[str, Any]] = []
        self.errors: List[str] = []
        self.identity = IdentityGraph()
        # noise circuit breaker: cumulative detection-risk accounting
        self.noise_score: float = 0.0
        self.noise_events: List[Dict[str, Any]] = []
        # belief revision: the audit trail of every belief that changed or
        # refused to change, plus the fingerprint-contradiction signal the
        # stall classifier reads (a stronger observation that flipped the
        # OS/fingerprint belief IS "the world contradicts the model").
        self.revisions: List[Revision] = []
        self.last_revision: Optional[Revision] = None
        self.fingerprint_mismatch: bool = False

    # ------------------------------------------------------------- findings

    def add_finding(self, kind: str, key: str, value: Any,
                    confidence: float = 0.5, source: str = "perception",
                    evidence: str = "", target: str = "") -> Finding:
        """Store a belief, REVISING the one it contradicts (per fact).

        The unit of revision is the fact key ``(kind, key)``: a new belief
        that contradicts a stored one either SUPERSEDES it (evidence at
        least as strong) or is REJECTED (strictly weaker — a weaker
        restatement never overwrites a stronger belief), and either way
        the previous value, the challenger and the reason land in
        ``revisions``. Without that record a re-probe could silently flip a
        belief with nothing to show it happened — the plan would then act
        on a world nobody measured.

        Returns the belief that is NOW stored: the new one when it won,
        the retained one when it lost, so a caller compares ``.value`` with
        the value it passed to know which happened.
        """
        f = Finding(kind=kind, key=key, value=value, confidence=confidence,
                    source=source, evidence=evidence, target=target or self.target)
        prev = self._findings.get((kind, key))
        if prev is not None and prev.value != f.value:
            if f.confidence >= prev.confidence:
                action = REVISED_SUPERSEDED
                reason = (f"new evidence ({f.confidence:.2f}) >= stored "
                          f"({prev.confidence:.2f})")
                self._findings[(kind, key)] = f
                stored = f
            else:
                action = REVISED_REJECTED
                reason = (f"new evidence ({f.confidence:.2f}) < stored "
                          f"({prev.confidence:.2f}): the stronger belief "
                          f"stands")
                stored = prev
            self._record_revision(Revision(
                kind=kind, key=key, action=action, old_value=prev.value,
                new_value=f.value, old_confidence=prev.confidence,
                new_confidence=f.confidence, source=source, reason=reason))
            return stored
        if prev is not None:
            # the same value again: CORROBORATION. A weaker restatement
            # never weakens a belief (the evidence that raised it is still
            # on record), so the stored confidence is the maximum ever seen.
            f.confidence = max(prev.confidence, f.confidence)
            if not f.evidence:
                f.evidence = prev.evidence
            # an INDEPENDENT source (different id) seeing the same value is
            # corroboration: fold it into the deduplicated source SET (a
            # repeat from a known source never inflates the count) and keep
            # the stronger evidence quality.
            seen = set(prev.sources or ())
            if prev.source:
                seen.add(prev.source)
            if f.source:
                seen.add(f.source)
            seen.discard("")
            f.sources = tuple(sorted(seen))
            f.independent_sources = len(seen)
            f.evidence_quality = max(f.evidence_quality, prev.evidence_quality)
        elif f.source and not f.sources:
            f.sources = (f.source,)
            f.independent_sources = 1
        self._findings[(kind, key)] = f
        return f

    def _record_revision(self, rev: Revision) -> None:
        self.revisions.append(rev)
        self.last_revision = rev
        # bounded history (the beliefs themselves are what the plan reads)
        if len(self.revisions) > 200:
            del self.revisions[:-100]
        # a STRONGER observation on the OS/fingerprint belief is the
        # "wrong model" signal the stall classifier consumes: keep
        # re-probing, do not repeat the move.
        if rev.superseded and rev.stronger and rev.kind in ("os", "fingerprint"):
            self.fingerprint_mismatch = True

    def contradictions(self, kind: Optional[str] = None) -> List[Revision]:
        """Revisions where the STORED belief won: a challenger was refused.

        These are the ones with no other operator-visible trace (an
        accepted revision shows up as a normal ``found``), so they are
        what a caller surfaces and what the report counts.
        """
        return [r for r in self.revisions
                if r.action == REVISED_REJECTED
                and (not kind or r.kind == kind)]

    def revisions_of(self, kind: str) -> List[Revision]:
        """Every recorded change (accepted or refused) on one fact kind."""
        return [r for r in self.revisions if r.kind == kind]

    def get(self, kind: str, key: str) -> Optional[Finding]:
        return self._findings.get((kind, key))

    def has(self, kind: str, key: str) -> bool:
        return (kind, key) in self._findings

    def has_any(self, kind: str) -> bool:
        """True if at least one finding of `kind` exists (any key)."""
        return any(k == kind for (k, _) in self._findings)

    def find(self, kind: str, **attrs) -> List[Finding]:
        """Return findings of `kind` optionally filtered by value attrs."""
        out = []
        for (k, _), f in self._findings.items():
            if k != kind:
                continue
            if attrs:
                v = f.value if isinstance(f.value, dict) else {}
                if not all(v.get(a) == b for a, b in attrs.items()):
                    continue
            out.append(f)
        return out

    def all_findings(self) -> List[Finding]:
        return list(self._findings.values())

    def trust(self, kind: str, key: str) -> bool:
        f = self.get(kind, key)
        return f is not None and f.confidence >= 0.7

    # ----------------------------------------------------------- hypotheses

    def add_hypothesis(self, capability_id: str, reason: str, cost: float = 0.0,
                       priority: float = 0.5) -> Hypothesis:
        h = Hypothesis(capability_id=capability_id, reason=reason,
                       cost=cost, priority=priority)
        self.hypotheses.append(h)
        return h

    def pending_hypotheses(self) -> List[Hypothesis]:
        return [h for h in self.hypotheses if h.status == "pending"]

    # -------------------------------------------------------------- opsec

    def spend_opsec(self, amount: float) -> bool:
        """Audit-only ledger: records the OPSEC cost of an action.

        There is NO budget to exhaust: termination is governed by never
        repeating failed moves (unless new facts make them viable again),
        and stealth reasoning prevents hammering (e.g. a stealthy operator
        tries one login pair, never 200). The ledger exists for reporting."""
        self.opsec_spent += amount
        return True

    # ------------------------------------------------------------- audit

    def record_action(self, capability_id: str, slots: Dict[str, Any],
                      command: str, ok: bool, note: str = "", opsec: float = 0.0):
        self.actions_taken.append({
            "capability": capability_id,
            "slots": slots,
            "command": command,
            "ok": ok,
            "note": note,
            "opsec": opsec,
            "ts": time.time(),
        })

    def record_failure(self, capability_id: str, reason: str, evidence: str = ""):
        self.failures.append({
            "capability": capability_id, "reason": reason,
            "evidence": evidence, "ts": time.time(),
        })

    # ------------------------------------------------- noise circuit breaker

    NOISE_LIMIT = 12.0        # cumulative detection-risk budget per run
    NOISE_EVENT_WEIGHTS = {
        "brute_online": 2.0,     # online brute force attempts
        "loud_scan": 1.5,        # full-range / aggressive scanning
        "exploit": 1.0,          # exploit attempts against services
        "ad_attack": 2.5,        # kerberoast / AS-REP / DCSync
        "repeated_fail": 1.0,    # re-arming after the same failure
    }

    def record_noise(self, event: str, weight: Optional[float] = None) -> None:
        """Feed the noise circuit breaker (detection-risk accounting).

        The score is cumulative for the run and persisted in checkpoints,
        so a resumed engagement remembers how loud it was. When the score
        crosses NOISE_LIMIT the agent should drop to passive moves — the
        agent consults `noise_breaker_tripped()` before choosing between
        a loud and a quiet capability.
        """
        w = self.NOISE_EVENT_WEIGHTS.get(event, weight if weight is not None else 0.5)
        self.noise_score += float(w)
        self.noise_events.append({"event": event, "weight": w,
                                  "score": round(self.noise_score, 2),
                                  "ts": time.time()})
        # bounded history (the score itself is what matters)
        if len(self.noise_events) > 200:
            del self.noise_events[:-100]

    def noise_breaker_tripped(self) -> bool:
        return self.noise_score >= self.NOISE_LIMIT

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "target_type": self.target_type,
            "findings": [f.to_dict() for f in self.all_findings()],
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "opsec_spent": self.opsec_spent,
            "actions": self.actions_taken,
            "failures": self.failures,
            "identity": self.identity.to_dict(),
            "noise_score": self.noise_score,
            "noise_events": self.noise_events,
            "revisions": [r.to_dict() for r in self.revisions],
            "fingerprint_mismatch": self.fingerprint_mismatch,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WorldModel":
        """Rebuild a WorldModel from a previously serialized state
        (campaign resume after a restart)."""
        wm = cls(target=data.get("target", ""),
                 target_type=data.get("target_type", "ip"))
        for fd in data.get("findings", []):
            f = Finding(
                kind=fd.get("kind", ""),
                key=fd.get("key", ""),
                value=fd.get("value"),
                confidence=fd.get("confidence", 0.5),
                source=fd.get("source", "perception"),
                evidence=fd.get("evidence", ""),
                target=fd.get("target", ""),
                ts=fd.get("ts", time.time()),
                source_reliability=fd.get("source_reliability", 0.5),
                evidence_quality=fd.get("evidence_quality", 0.5),
                observed_at=fd.get("observed_at", fd.get("ts", time.time())),
                ttl=fd.get("ttl", 0.0),
                independent_sources=fd.get("independent_sources", 0),
                sources=tuple(fd.get("sources") or ()),
            )
            wm._findings[(f.kind, f.key)] = f
        for hd in data.get("hypotheses", []):
            wm.hypotheses.append(Hypothesis(
                capability_id=hd.get("capability_id", ""),
                reason=hd.get("reason", ""),
                cost=hd.get("cost", 0.0),
                priority=hd.get("priority", 0.5),
                status=hd.get("status", "pending"),
                evidence=hd.get("evidence", ""),
            ))
        wm.opsec_spent = data.get("opsec_spent", 0.0)
        wm.actions_taken = list(data.get("actions", []))
        wm.failures = list(data.get("failures", []))
        wm.identity = IdentityGraph.from_dict(data.get("identity", {}))
        # circuit-breaker memory (persisted so resumes keep the discipline)
        wm.noise_score = float(data.get("noise_score", 0.0))
        wm.noise_events = list(data.get("noise_events", []))
        # belief revision survives a resume: a checkpointed run remembers
        # which beliefs were contested (and that its model was wrong)
        for rd in data.get("revisions", []):
            wm.revisions.append(Revision(
                kind=rd.get("kind", ""), key=rd.get("key", ""),
                action=rd.get("action", REVISED_SUPERSEDED),
                old_value=rd.get("old_value"), new_value=rd.get("new_value"),
                old_confidence=float(rd.get("old_confidence", 0.0)),
                new_confidence=float(rd.get("new_confidence", 0.0)),
                source=rd.get("source", ""), reason=rd.get("reason", ""),
                ts=rd.get("ts", time.time())))
        if wm.revisions:
            wm.last_revision = wm.revisions[-1]
        wm.fingerprint_mismatch = bool(data.get("fingerprint_mismatch", False))
        return wm


# ---------------------------------------------------------------------------
# Identity graph (persona pivot: username / email / phone → person)
# ---------------------------------------------------------------------------

@dataclass
class IdentityNode:
    """An entity (person, account, email, phone, platform) in the graph."""
    node_type: str                  # person | username | email | phone | platform | company
    value: str
    attributes: Dict[str, Any] = field(default_factory=dict)
    found_on: str = "manual"        # probe/capability that discovered it
    confidence: float = 0.5
    public: Optional[bool] = None   # account visibility if applicable


class IdentityGraph:
    """Bipartite-ish graph linking identity entities (OSINT pivoting)."""

    def __init__(self) -> None:
        self.nodes: Dict[str, IdentityNode] = {}        # key "type:value"
        self.edges: Set[tuple] = set()                  # (node_key_a, node_key_b)

    def _key(self, node_type: str, value: str) -> str:
        return f"{node_type}:{value.lower()}"

    def add_node(self, node_type: str, value: str, **attrs) -> IdentityNode:
        k = self._key(node_type, value)
        if k in self.nodes:
            node = self.nodes[k]
            node.attributes.update(attrs)
            return node
        node = IdentityNode(node_type=node_type, value=value, attributes=attrs)
        self.nodes[k] = node
        return node

    def link(self, a_type: str, a_value: str, b_type: str, b_value: str):
        self.add_node(a_type, a_value)
        self.add_node(b_type, b_value)
        self.edges.add((self._key(a_type, a_value), self._key(b_type, b_value)))

    def get(self, node_type: str, value: str) -> Optional[IdentityNode]:
        return self.nodes.get(self._key(node_type, value))

    def neighbors(self, node_type: str, value: str) -> List[IdentityNode]:
        """Return nodes directly connected to the given node."""
        k = self._key(node_type, value)
        out = []
        for a, b in self.edges:
            if a == k:
                out.append(self.nodes[b])
            elif b == k:
                out.append(self.nodes[a])
        return out

    def person_nodes(self) -> List[IdentityNode]:
        return [n for n in self.nodes.values() if n.node_type in ("person", "username", "email", "phone")]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [{"type": n.node_type, "value": n.value, "attrs": n.attributes,
                       "public": n.public, "confidence": n.confidence}
                      for n in self.nodes.values()],
            "edges": [list(e) for e in self.edges],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IdentityGraph":
        g = cls()
        for n in data.get("nodes", []):
            node = g.add_node(n.get("type", ""), n.get("value", ""),
                              **(n.get("attrs") or {}))
            node.confidence = n.get("confidence", 0.5)
            node.public = n.get("public")
        for a, b in data.get("edges", []):
            g.edges.add((a, b))
        return g
