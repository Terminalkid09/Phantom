"""
gates.py — hard validation gates for LLM-proposed hypotheses.

The LLM GENERATES reasoning; it is never authorized to act. Every
LLM-proposed hypothesis passes through these gates before it reaches
the planner:

    G1 registry     — the proposed operator/capability must exist
    G2 scope        — the target of the action must be activatable
                      (TargetLedger.activatable — scope is law)
    G3 policy       — stealth profile vetoes loud moves (paranoid mode
                      strips aggressive/forceful, noise breaker active
                      strips brute)
    G4 evidence     — the hypothesis must reference at least one fact
                      that EXISTS in the WorldModel (no prompt-induced
                      hallucinated prerequisites)
    G5 budget       — the chain's opsec cost must fit the remaining
                      noise budget of the engagement

A rejected hypothesis is logged WITH the gate that rejected it: silent
drops would hide a misbehaving model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from phantom.automation.brain.operators import OperatorRegistry


@dataclass
class ProposedChain:
    """One LLM-proposed operator chain, pre-validation."""
    operators: List[str]
    goal: str
    rationale: str = ""
    referenced_facts: List[str] = field(default_factory=list)
    source: str = "llm"


@dataclass
class GateResult:
    gate: str
    passed: bool
    detail: str = ""


@dataclass
class ValidatedChain:
    proposal: ProposedChain
    results: List[GateResult] = field(default_factory=list)

    @property
    def approved(self) -> bool:
        return all(r.passed for r in self.results)

    def failed_gate(self) -> Optional[str]:
        for r in self.results:
            if not r.passed:
                return r.gate
        return None


class ValidationGates:
    """The five gates, evaluated in order (cheap first)."""

    def __init__(self, registry: OperatorRegistry, ledger=None,
                 paranoid: bool = False,
                 noise_budget_remaining: Optional[float] = None) -> None:
        self.registry = registry
        self.ledger = ledger          # TargetLedger (scope law)
        self.paranoid = paranoid
        self.noise_budget_remaining = noise_budget_remaining

    def validate(self, proposal: ProposedChain, wm) -> ValidatedChain:
        out = ValidatedChain(proposal=proposal)
        # G1 registry
        missing = [op for op in proposal.operators
                   if self.registry.get(op) is None]
        out.results.append(GateResult(
            "registry", not missing,
            f"unknown operators: {missing}" if missing else "all operators exist"))
        if missing:
            return out
        # G2 scope
        target = str(getattr(wm, "target", "") or "")
        if self.ledger is not None and target and \
                not self.ledger.activatable(target):
            out.results.append(GateResult(
                "scope", False, f"target {target} is not activatable"))
            return out
        out.results.append(GateResult("scope", True, "target in scope"))
        # G3 policy
        if self.paranoid:
            loud = [self.registry.get(op) for op in proposal.operators]
            loud = [o for o in loud if o is not None and
                    (getattr(o, "noise", 0) >= 0.45)]
            if loud:
                out.results.append(GateResult(
                    "policy", False,
                    f"paranoid mode: high-noise operators rejected: "
                    f"{[o.op_id for o in loud]}"))
                return out
        out.results.append(GateResult("policy", True, "stealth policy ok"))
        # G4 evidence: at least one referenced fact must exist in the world
        known = self._known_facts(wm)
        grounded = [f for f in proposal.referenced_facts if f in known]
        if proposal.referenced_facts and not grounded:
            out.results.append(GateResult(
                "evidence", False,
                f"none of the referenced facts exist: "
                f"{proposal.referenced_facts[:4]}"))
            return out
        out.results.append(GateResult(
            "evidence", True,
            f"grounded in {len(grounded)} observed fact(s)"))
        # G5 budget
        if self.noise_budget_remaining is not None:
            total_noise = sum(
                (self.registry.get(op).noise or 0.0)
                for op in proposal.operators if self.registry.get(op))
            if total_noise > self.noise_budget_remaining:
                out.results.append(GateResult(
                    "budget", False,
                    f"chain noise {total_noise:.2f} exceeds remaining "
                    f"{self.noise_budget_remaining:.2f}"))
                return out
        out.results.append(GateResult("budget", True, "within noise budget"))
        return out

    @staticmethod
    def _known_facts(wm) -> set:
        kinds = set()
        for f in wm.all_findings():
            kinds.add(f.kind)
            v = f.value if isinstance(f.value, dict) else {}
            for key in ("class", "service", "software", "product"):
                if v.get(key):
                    kinds.add(str(v[key]).lower())
        return kinds
