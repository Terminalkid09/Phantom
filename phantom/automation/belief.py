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
from typing import Any, Dict, List, Optional, Set


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

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


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

    # ------------------------------------------------------------- findings

    def add_finding(self, kind: str, key: str, value: Any,
                    confidence: float = 0.5, source: str = "perception",
                    evidence: str = "", target: str = "") -> Finding:
        f = Finding(kind=kind, key=key, value=value, confidence=confidence,
                    source=source, evidence=evidence, target=target or self.target)
        self._findings[(kind, key)] = f
        return f

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
