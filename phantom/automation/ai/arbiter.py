"""arbiter.py — the policy that accepts or REJECTS what a model proposed.

The AI plane used to reach the planner as a list of "preferences": ids the
model liked, front-loaded into the deterministic order. That is not a decision
and it is not auditable — nothing said whether a proposal was accepted, why it
lost, or whether the model was even asked. Measured 2026-11-07 on the lab:
`--ai off` and `--ai integrated` produced the same plan and the report could
not tell "the model agreed" from "the model was never consulted".

This module is the missing middle layer. Every proposal crosses an explicit
policy, and every proposal leaves a verdict with a reason:

  * the id must be one of the moves the planner is ALLOWED to run *right now*
    (eligible: preconditions met, stealth allowed, not dead, not already used);
  * its confidence must clear the authority's floor;
  * it may only move a move as far as the authority allows (``nudge`` = 2
    positions, ``decide`` = 5, ``full`` = anywhere) — measured from the
    deterministic pick, never from whatever order happened to arrive;
  * a loud move is refused while the noise breaker is tripped;
  * ``observe`` (no measurement, nothing earned) refuses every proposal, and
    says so, instead of silently keeping a list of unused preferences.

The arbiter can therefore never ADD a move, never authorise one, never reach
an unready move, and never execute anything: it only chooses among moves the
deterministic engine already permitted. Its whole surface is
``adjudicate() -> Verdict``.

Why the bound is structural and not a tuning knob: an unmeasured model has no
idea how costly a wrong move is, so the size of the effect has to come from
evidence (``trust.Trust.bound``/``max_steps``) or from the operator's announced
``--ai-authority`` override — not from the model's own confidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence

#: Authority level -> (max positions a proposal may move, minimum confidence).
#: ``observe`` refuses everything (floor above 1.0), which is what "the model
#: has measured nothing, so it decides nothing" has to mean in code.
BOUNDS: Dict[str, tuple] = {
    "observe": (0, 1.01),
    "nudge": (2, 0.55),
    "decide": (5, 0.40),
    "full": (99, 0.00),
}

#: Categories and stealth levels that count as "loud" for the noise breaker.
LOUD_CATEGORIES = frozenset({"brute", "ad"})
LOUD_STEALTH = frozenset({"aggressive"})


@dataclass
class Proposal:
    """One model suggestion: a move id, a confidence, and a reason."""

    capability_id: str
    confidence: float = 0.0
    reason: str = ""

    def normalized(self) -> "Proposal":
        try:
            conf = float(self.confidence)
        except (TypeError, ValueError):
            conf = 0.0
        if conf != conf:            # NaN
            conf = 0.0
        return Proposal(str(self.capability_id or "").strip(),
                        max(0.0, min(1.0, conf)), str(self.reason or "")[:200])


@dataclass
class Decision:
    """What happened to one proposal (or to the deterministic pick)."""

    capability_id: str
    verdict: str                 # accepted | rejected | agreement | abstained
    reason: str
    confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {"capability_id": self.capability_id, "verdict": self.verdict,
                "reason": self.reason, "confidence": round(self.confidence, 2)}


@dataclass
class Verdict:
    """The outcome of one adjudication (one fact, one candidate set)."""

    fact: str = ""
    chosen: Any = None
    changed: bool = False
    authority: str = "observe"
    decisions: List[Decision] = field(default_factory=list)
    source: str = ""
    reason: str = ""

    @property
    def accepted(self) -> List[Decision]:
        return [d for d in self.decisions
                if d.verdict in ("accepted", "agreement")]

    @property
    def rejected(self) -> List[Decision]:
        return [d for d in self.decisions if d.verdict == "rejected"]

    def to_dict(self) -> Dict[str, Any]:
        return {"fact": self.fact,
                "chosen": str(getattr(self.chosen, "id", self.chosen) or ""),
                "changed": bool(self.changed), "authority": self.authority,
                "source": self.source, "reason": self.reason,
                "decisions": [d.to_dict() for d in self.decisions]}


def _cap_id(cap: Any) -> str:
    return str(getattr(cap, "id", "") or "")


def _is_loud(cap: Any) -> bool:
    if str(getattr(cap, "category", "") or "").lower() in LOUD_CATEGORIES:
        return True
    if str(getattr(cap, "stealth_level", "") or "").lower() in LOUD_STEALTH:
        return True
    return bool(getattr(cap, "forceful", False))


class Arbiter:
    """The accept/reject policy. One instance per engagement.

    ``proposer`` is a callable ``(fact, capabilities) -> Sequence[Proposal]``.
    It is called at most once per (fact, candidate-set) per cycle and its
    budget is bounded, so a slow or absent model can never stall planning.
    """

    def __init__(self, *, authority: str = "observe",
                 proposer: Optional[Callable] = None,
                 floor: Optional[float] = None,
                 budget: int = 6,
                 audit: bool = True) -> None:
        level = str(authority or "observe").strip().lower()
        self.authority = level if level in BOUNDS else "observe"
        self.max_shift, bound_floor = BOUNDS[self.authority]
        # A caller may raise the floor, never lower it: the authority's floor
        # is the safety property, the parameter is only extra caution.
        self.floor = max(bound_floor, float(floor)) if floor is not None \
            else bound_floor
        self.proposer = proposer
        self.budget = max(0, int(budget))
        self.audit = bool(audit)
        self._cache: Dict[str, List[Proposal]] = {}
        # counters for the end-of-run report: "the AI was never asked" and
        # "the AI was asked and refused" are different facts and must not
        # collapse into the same silence.
        self.stats: Dict[str, int] = {"asked": 0, "proposals": 0,
                                      "accepted": 0, "rejected": 0,
                                      "changed": 0, "abstained": 0, "supplied": 0,
                                      "unavailable": 0}
        self.journal: List[Dict[str, Any]] = []

    # ------------------------------------------------------------- asking
    def _ask(self, fact: str, capabilities: Sequence[Any]) -> List[Proposal]:
        if self.proposer is None or self.budget <= 0:
            self.stats["unavailable"] += 1
            return []
        key = fact + "|" + ",".join(_cap_id(c) for c in capabilities)
        if key in self._cache:
            return self._cache[key]
        self.budget -= 1
        self.stats["asked"] += 1
        try:
            raw = self.proposer(fact, capabilities) or []
        except Exception:
            raw = []
        out: List[Proposal] = []
        for item in raw:
            if isinstance(item, Proposal):
                proposal = item.normalized()
            elif isinstance(item, dict):
                proposal = Proposal(
                    str(item.get("capability_id") or item.get("id") or ""),
                    item.get("confidence", 0.0),
                    str(item.get("reason", ""))).normalized()
            else:
                proposal = Proposal(str(item)).normalized()
            if proposal.capability_id:
                out.append(proposal)
        self._cache[key] = out
        self.stats["proposals"] += len(out)
        return out

    # -------------------------------------------------------- adjudication
    def adjudicate(self, fact: str, capabilities: Sequence[Any],
                   deterministic: Any, *,
                   proposals: Optional[Sequence[Any]] = None,
                   noise_breaker: bool = False,
                   source: str = "") -> Verdict:
        """Pick one of ``capabilities`` given the model's proposals.

        ``capabilities`` MUST already be the eligible set for this fact: the
        arbiter is allowed to choose, not to grant permission.
        """
        eligible = list(capabilities or [])
        index = {_cap_id(c): i for i, c in enumerate(eligible)}
        det_id = _cap_id(deterministic)
        verdict = Verdict(fact=str(fact or ""), chosen=deterministic,
                          authority=self.authority, source=source)
        if not eligible or det_id not in index:
            verdict.reason = "no eligible candidate to adjudicate"
            verdict.decisions.append(
                Decision(det_id, "abstained", verdict.reason))
            self.stats["abstained"] += 1
            return verdict

        if proposals is not None:
            self.stats["supplied"] += 1
        raw = proposals if proposals is not None else self._ask(fact, eligible)
        items = []
        for item in raw or []:
            if isinstance(item, Proposal):
                items.append(item.normalized())
            elif isinstance(item, dict):
                items.append(Proposal(
                    str(item.get("capability_id") or item.get("id") or ""),
                    item.get("confidence", 0.0),
                    str(item.get("reason", ""))).normalized())
            else:
                items.append(Proposal(str(item)).normalized())
        items = [p for p in items if p.capability_id]

        if not items:
            verdict.reason = ("the model proposed nothing for this decision "
                              f"(authority {self.authority}, source "
                              f"{source or 'deterministic'})")
            verdict.decisions.append(
                Decision(det_id, "abstained", verdict.reason))
            self.stats["abstained"] += 1
            self._record(verdict)
            return verdict

        det_pos = index[det_id]
        accepted: List[tuple] = []
        for proposal in items:
            cid = proposal.capability_id
            if cid not in index:
                reason = ("not one of the moves the planner may run for this "
                          "fact right now")
            elif self.authority == "observe":
                reason = ("authority 'observe': no measured advantage, so no "
                          "proposal may steer the plan")
            elif proposal.confidence < self.floor:
                reason = (f"confidence {proposal.confidence:.2f} below the "
                          f"'{self.authority}' floor {self.floor:.2f}")
            elif abs(det_pos - index[cid]) > self.max_shift:
                reason = (f"would move the pick "
                          f"{abs(det_pos - index[cid])} position(s), "
                          f"'{self.authority}' allows {self.max_shift}")
            elif noise_breaker and _is_loud(eligible[index[cid]]):
                reason = ("loud move while the noise breaker is tripped "
                          "(de-escalation wins over a model suggestion)")
            else:
                reason = ""
            if reason:
                verdict.decisions.append(
                    Decision(cid, "rejected", reason, proposal.confidence))
                self.stats["rejected"] += 1
                continue
            accepted.append((index[cid], -proposal.confidence, proposal))
            verdict.decisions.append(
                Decision(cid, "accepted",
                         proposal.reason or "eligible, within authority",
                         proposal.confidence))
            self.stats["accepted"] += 1

        if not accepted:
            verdict.reason = "every proposal was refused; deterministic order"
            verdict.decisions.append(
                Decision(det_id, "agreement",
                         "deterministic pick retained", 0.0))
            self._record(verdict)
            return verdict

        # Highest confidence wins; ties keep the deterministic (earliest)
        # position, so an ambiguous model answer cannot shuffle the plan.
        accepted.sort(key=lambda row: (row[1], row[0]))
        best_index, _, best = accepted[0]
        chosen = eligible[best_index]
        if _cap_id(chosen) == det_id:
            verdict.reason = "the model agreed with the deterministic pick"
            verdict.decisions.append(
                Decision(det_id, "agreement", verdict.reason, best.confidence))
        else:
            verdict.changed = True
            verdict.reason = (f"accepted {_cap_id(chosen)} over {det_id} "
                              f"within '{self.authority}' authority")
            self.stats["changed"] += 1
        verdict.chosen = chosen
        self._record(verdict)
        return verdict

    # ------------------------------------------------------------- audit
    def _record(self, verdict: Verdict) -> None:
        entry = verdict.to_dict()
        self.journal.append(entry)
        if len(self.journal) > 200:
            del self.journal[:100]
        if not self.audit:
            return
        try:
            from phantom.automation.decision_audit import (
                KIND_CHOSEN, KIND_REJECTED, decision_audit)
            decision_audit.record(KIND_CHOSEN, fact=verdict.fact,
                                  chosen=entry["chosen"],
                                  changed=entry["changed"],
                                  authority=verdict.authority,
                                  reason=verdict.reason)
            for decision in verdict.decisions:
                if decision.verdict != "rejected":
                    continue
                decision_audit.record(KIND_REJECTED, fact=verdict.fact,
                                      capability=decision.capability_id,
                                      reason=decision.reason,
                                      authority=verdict.authority)
        except Exception:
            pass

    def summary(self) -> Dict[str, Any]:
        """What the arbiter did this run (for the report and the benchmark)."""
        changed = [row for row in self.journal if row.get("changed")]
        return {
            "authority": self.authority,
            "max_shift": self.max_shift,
            "floor": round(self.floor, 2),
            "asked": self.stats["asked"],
            "proposals": self.stats["proposals"],
            "accepted": self.stats["accepted"],
            "rejected": self.stats["rejected"],
            "changed": self.stats["changed"],
            "abstained": self.stats["abstained"],
            "unavailable": self.stats["unavailable"],
            "changed_decisions": changed[:10],
            "note": self._note(),
        }

    def _note(self) -> str:
        if self.authority == "observe":
            return ("no measured advantage for this phase: every proposal is "
                    "refused and the deterministic order stands")
        if self.stats["asked"] == 0 and self.stats.get("supplied", 0) == 0:
            return ("the model was never asked (no proposer configured): this "
                    "run is deterministic, not 'AI-assisted'")
        if self.stats["proposals"] == 0:
            return ("the model was asked and returned no usable proposal: the "
                    "deterministic order stands, and it is recorded as an "
                    "abstention rather than as agreement")
        if self.stats["changed"] == 0:
            return (f"{self.stats['accepted']} proposal(s) accepted, none "
                    f"changed a pick: the model agreed with the plan")
        return (f"{self.stats['changed']} pick(s) changed by an accepted "
                f"proposal within '{self.authority}' authority")
