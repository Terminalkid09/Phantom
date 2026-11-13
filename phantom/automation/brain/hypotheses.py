"""
phantom.automation.brain.hypotheses — the hypothesis ledger.

A composed chain is a BELIEF, not a fact: "if the upload takes traversal
and the param is injectable, then webshell -> RCE". The ledger turns
beliefs into a disciplined loop:

    propose  -> a Composition becomes a Hypothesis with a confidence
    probe    -> CHEAP discriminating checks run against the target
                (prove the claim before spending exploit budget)
    confirm  -> probes pass  -> the chain graduates into the planner's
                preference list (the agent NOW exploits along it)
    refute   -> probes fail  -> the hypothesis dies WITH A RECORDED
                REASON (priors feed back into future composition costs)

Every state change is emitted as an event so the operator sees the
reasoning live: proposed -> probing -> confirmed/refuted.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from phantom.automation.brain.composition import Composition
from phantom.automation.brain.operators import OperatorRegistry


@dataclass
class ProbeResult:
    probe_id: str
    ok: bool
    detail: str = ""


@dataclass
class Hypothesis:
    """One composed attack-path belief and its verification state."""
    hyp_id: str
    composition: Composition
    status: str = "proposed"       # proposed|probing|confirmed|refuted
    confidence: float = 0.5
    probes: List[ProbeResult] = field(default_factory=list)
    created_ts: float = field(default_factory=time.time)
    settled_ts: float = 0.0
    verdict_reason: str = ""

    def to_dict(self) -> dict:
        return {"id": self.hyp_id, "chain": self.composition.describe(),
                "goal": self.composition.goal, "status": self.status,
                "confidence": round(self.confidence, 2),
                "probes": [{"id": p.probe_id, "ok": p.ok, "detail": p.detail}
                           for p in self.probes],
                "reason": self.verdict_reason}


class HypothesisLedger:
    """Owns the propose -> probe -> settle loop for composed chains."""

    def __init__(self, registry: OperatorRegistry,
                 on_event: Optional[Callable[[str, dict], None]] = None,
                 max_open: int = 8) -> None:
        self.registry = registry
        self.on_event = on_event
        self.max_open = max_open
        self._open: Dict[str, Hypothesis] = {}
        self._settled: List[Hypothesis] = []
        self._seq = 0

    # ── event plumbing ─────────────────────────────────────────────────
    def _emit(self, kind: str, **data) -> None:
        if self.on_event:
            try:
                self.on_event(kind, data)
            except Exception:
                pass

    # ── propose ────────────────────────────────────────────────────────
    def propose(self, composition: Composition) -> Optional[Hypothesis]:
        """Turn a composed chain into a tracked hypothesis. Dedupes by
        chain signature; bounds the open set."""
        if composition.empty:
            return None
        sig = composition.describe()
        for h in list(self._open.values()) + self._settled:
            if h.composition.describe() == sig:
                return None            # already known belief
        if len(self._open) >= self.max_open:
            return None
        self._seq += 1
        hyp = Hypothesis(hyp_id=f"H{self._seq:03d}", composition=composition,
                         confidence=max(0.2, 0.75 - 0.08 * composition.total_cost))
        self._open[hyp.hyp_id] = hyp
        self._emit("hypothesis_proposed", id=hyp.hyp_id,
                   chain=sig, goal=composition.goal,
                   confidence=round(hyp.confidence, 2))
        return hyp

    # ── probe ──────────────────────────────────────────────────────────
    def probe(self, hyp: Hypothesis, wm,
              probe_runner: Optional[Callable[[str, object], ProbeResult]] = None
              ) -> List[ProbeResult]:
        """Run the cheap discriminating probes for every operator in the
        chain. Default runner uses each operator's registered probe fn
        against the WorldModel. A failing probe REFUTES the hypothesis."""
        hyp.status = "probing"
        self._emit("hypothesis_probing", id=hyp.hyp_id,
                   chain=hyp.composition.describe())
        results: List[ProbeResult] = []
        for step in hyp.composition.steps:
            op = self.registry.get(step.op_id)
            if op is None or op.probe is None:
                results.append(ProbeResult(step.op_id, True, "no probe registered"))
                continue
            if probe_runner is not None:
                res = probe_runner(step.op_id, wm)
            else:
                try:
                    ok = bool(op.probe(wm))
                    res = ProbeResult(step.op_id, ok,
                                      "precondition proven on target" if ok
                                      else "precondition NOT proven")
                except Exception as exc:
                    res = ProbeResult(step.op_id, False, f"probe error: {exc}")
            results.append(res)
            if not res.ok:
                hyp.status = "refuted"
                hyp.settled_ts = time.time()
                hyp.verdict_reason = f"{step.op_id}: {res.detail}"
                hyp.confidence = 0.05
                self._open.pop(hyp.hyp_id, None)
                self._settled.append(hyp)
                self._emit("hypothesis_refuted", id=hyp.hyp_id,
                           chain=hyp.composition.describe(),
                           reason=hyp.verdict_reason)
                hyp.probes.extend(results[len(hyp.probes):])
                return hyp.probes
        hyp.probes = results
        return results

    # ── settle ─────────────────────────────────────────────────────────
    def confirm(self, hyp: Hypothesis, reason: str = "all probes passed") -> None:
        hyp.status = "confirmed"
        hyp.settled_ts = time.time()
        hyp.confidence = min(0.95, hyp.confidence + 0.2)
        hyp.verdict_reason = reason
        self._open.pop(hyp.hyp_id, None)
        self._settled.append(hyp)
        self._emit("hypothesis_confirmed", id=hyp.hyp_id,
                   chain=hyp.composition.describe(),
                   confidence=round(hyp.confidence, 2))

    def refute(self, hyp: Hypothesis, reason: str) -> None:
        hyp.status = "refuted"
        hyp.settled_ts = time.time()
        hyp.confidence = 0.05
        hyp.verdict_reason = reason
        self._open.pop(hyp.hyp_id, None)
        self._settled.append(hyp)
        self._emit("hypothesis_refuted", id=hyp.hyp_id,
                   chain=hyp.composition.describe(), reason=reason)

    # ── queries ────────────────────────────────────────────────────────
    def confirmed_goal(self, goal: str) -> Optional[Hypothesis]:
        for h in self._settled:
            if h.status == "confirmed" and h.composition.goal == goal:
                return h
        return None

    def confirmed_chains(self) -> List[Hypothesis]:
        return [h for h in self._settled if h.status == "confirmed"]

    def open(self) -> List[Hypothesis]:
        return list(self._open.values())

    def all(self) -> List[Hypothesis]:
        return self._settled + list(self._open.values())

    def preference_ids(self) -> List[str]:
        """Capability ids to PREFER in planning: the first operator of
        every confirmed chain (the proven entry move)."""
        out: List[str] = []
        for h in self.confirmed_chains():
            if h.composition.steps:
                first = h.composition.steps[0].op_id
                if first not in out:
                    out.append(first)
        return out

    def stats(self) -> dict:
        settled = self._settled
        return {"proposed": len(settled) + len(self._open),
                "confirmed": len(self.confirmed_chains()),
                "refuted": len([h for h in settled if h.status == "refuted"]),
                "open": len(self._open)}
