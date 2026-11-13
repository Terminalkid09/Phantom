"""
engine.py — the fuzz driver.

Loop: baseline per parameter -> grammar seeds -> send -> oracle verdicts
-> keep interesting mutations -> evolve them -> repeat (bounded rounds,
bounded requests). Verdicts with family hints feed back into the brain's
composition space (a time-based sqli signal maps to web.param facts).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from phantom.automation.brain.fuzz.grammar import Grammar, Mutation
from phantom.automation.brain.fuzz.oracles import DifferentialOracle, Response, Verdict


@dataclass
class FuzzFinding:
    """A mutation the oracles flagged as interesting."""
    mutation: Mutation
    verdict: Verdict
    baseline_status: int = 0
    mutated_status: int = 0

    def to_dict(self) -> dict:
        return {**self.mutation.to_dict(), "oracle": self.verdict.to_dict(),
                "baseline_status": self.baseline_status,
                "mutated_status": self.mutated_status}


class FuzzEngine:
    """Bounded generative fuzzing against one target's parameters."""

    def __init__(self,
                 sender: Callable[[str, str], Response],
                 families: Optional[List[str]] = None,
                 rounds: int = 2,
                 max_requests: int = 60,
                 seed: Optional[int] = None) -> None:
        """`sender(param, payload) -> Response` performs ONE request."""
        self.sender = sender
        self.grammar = Grammar(families=families, seed=seed)
        self.oracle = DifferentialOracle()
        self.rounds = rounds
        self.max_requests = max_requests
        self.requests_sent = 0

    # ── driver ─────────────────────────────────────────────────────────
    def run(self, params: List[str]) -> List[FuzzFinding]:
        findings: List[FuzzFinding] = []
        # baselines (one request per param)
        baselines: Dict[str, Response] = {}
        for param in params:
            if self.requests_sent >= self.max_requests:
                break
            resp = self._send(param, "phantom-baseline-0")
            if resp is not None:
                baselines[param] = resp
        # rounds
        current = self.grammar.seed_payloads(list(baselines))
        for rnd in range(self.rounds):
            interesting: List[Mutation] = []
            for m in current:
                if self.requests_sent >= self.max_requests:
                    break
                base = baselines.get(m.param)
                if base is None:
                    continue
                resp = self._send(m.param, m.payload)
                if resp is None:
                    continue
                verdict = self.oracle.evaluate(base, resp)
                if verdict.interesting:
                    findings.append(FuzzFinding(
                        m, verdict, base.status, resp.status))
                    interesting.append(m)
            if not interesting or rnd == self.rounds - 1:
                break
            current = self.grammar.evolve(interesting)
        return findings

    # ── plumbing ───────────────────────────────────────────────────────
    def _send(self, param: str, payload: str) -> Optional[Response]:
        self.requests_sent += 1
        try:
            t0 = time.time()
            resp = self.sender(param, payload)
            if resp is None:
                return None
            if not isinstance(resp, Response):
                resp = Response(status=getattr(resp, "status", 0),
                                body=getattr(resp, "body", "") or "",
                                elapsed=time.time() - t0)
            return resp
        except Exception:
            return None

    # ── projection into the brain's fact space ─────────────────────────
    @staticmethod
    def to_composition_facts(findings: List[FuzzFinding]) -> List[Tuple[str, dict]]:
        """Fuzz findings -> (fact-token, finding-dict) pairs the
        composition engine understands (feeds web.param / web.ssrf)."""
        out: List[Tuple[str, dict]] = []
        seen_families = {f.mutation.family for f in findings
                         if f.verdict.family_hint in ("sqli", "ssti", "fuzz")}
        if seen_families:
            out.append(("web.param", {"class": "fuzz",
                                      "families": sorted(seen_families)}))
        for f in findings:
            if f.mutation.family == "path":
                out.append(("web.param", {"class": "path_traversal",
                                          "param": f.mutation.param}))
        return out
