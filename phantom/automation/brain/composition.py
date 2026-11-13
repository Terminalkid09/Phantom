"""
phantom.automation.brain.composition — state-space search over operators.

Given the WorldModel's current facts and a goal fact, the composition
engine searches for CHAINS of primitives that reach the goal — chains
the capability registry never contained. This is the mechanism that
lets the agent DO something it was never explicitly programmed to do
on this target: the senior move.

Search: iterative-deepening BFS over operator applications (optimal in
cost-ish terms, bounded, no exponential blowup on the small registry).
Cost model: sum of operator costs + noise penalty; the cheapest chain
wins. Cycles are pruned by the fact-set signature of each state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Set, Tuple

from phantom.automation.brain.operators import Operator, OperatorRegistry


@dataclass
class CompositionStep:
    op_id: str
    facts_produced: Tuple[str, ...]
    cost: float
    noise: float


@dataclass
class Composition:
    """A discovered attack path: operator chain + costs + reasoning."""
    steps: List[CompositionStep] = field(default_factory=list)
    goal: str = ""
    total_cost: float = 0.0
    total_noise: float = 0.0

    @property
    def empty(self) -> bool:
        return not self.steps

    def describe(self) -> str:
        return " -> ".join(s.op_id for s in self.steps)

    def to_dict(self) -> dict:
        return {"chain": self.describe(), "goal": self.goal,
                "cost": round(self.total_cost, 2),
                "noise": round(self.total_noise, 2)}


class CompositionEngine:
    """Searches operator compositions from current facts to a goal fact."""

    def __init__(self, registry: OperatorRegistry,
                 max_depth: int = 5) -> None:
        self.registry = registry
        self.max_depth = max_depth

    # ── public API ─────────────────────────────────────────────────────
    def facts_from_worldmodel(self, wm) -> Set[str]:
        """Project the WorldModel's findings into the composition fact
        space. The mapping is deliberately conservative: only findings
        that PROVE the fact's claim map in."""
        from phantom.automation.brain.operators import (
            BEACON_LIVE, CREDS_ANY, OS_KNOWN, PERSIST_INSTALLED, PRIV_SYSTEM,
            INTERNAL_HOST, INTERNAL_SERVICE,
            SERVICE_DB, SERVICE_SMB, SERVICE_SSH,
            WEB_APP, WEB_PARAM,
        )
        facts: Set[str] = set()
        if wm.find("web_app") or wm.find("web_header"):
            facts.add(WEB_APP.token)
        if wm.find("hunt_anomaly"):
            facts.add(WEB_PARAM.token)
            for f in wm.find("hunt_anomaly"):
                v = f.value if isinstance(f.value, dict) else {}
                cls = str(v.get("class", "")).lower()
                if cls in ("ssrf", "url_fetch"):
                    facts.add("web.ssrf")
                if "upload" in str(v.get("endpoint", v.get("path", ""))).lower():
                    facts.add("web.upload")
        if wm.find("creds", valid=True):
            facts.add(CREDS_ANY.token)
        if wm.find("environment"):
            v = wm.find("environment")[0].value
            if isinstance(v, dict) and v.get("cloud"):
                facts.add("cloud.metadata")
        kinds = {"ssh": SERVICE_SSH, "smb": SERVICE_SMB}
        # nmap service names for the same fact: microsoft-ds/samba/netbios
        # are all SMB; the projection must speak the scanner's dialect.
        # Port 445 is SMB even when the service string is unparseable.
        smb_aliases = ("smb", "microsoft-ds", "samba", "netbios")
        for f in wm.find("service"):
            v = f.value if isinstance(f.value, dict) else {}
            svc = str(v.get("service", "")).lower()
            port = v.get("port")
            if svc.startswith("ssh"):
                facts.add(SERVICE_SSH.token)
            elif svc.startswith("smb") or svc in smb_aliases or port == 445:
                facts.add(SERVICE_SMB.token)
            if svc in ("mysql", "mssql", "postgresql", "postgres", "redis"):
                facts.add(SERVICE_DB.token)
        if wm.find("os"):
            facts.add(OS_KNOWN.token)
        # post-exploitation state: a live beacon and confirmed SYSTEM/root
        # projection into the composition space so the engine can plan
        # escalation/persistence/lateral chains for the manual core too.
        if wm.find("beacon"):
            facts.add(BEACON_LIVE.token)
        if wm.find("system_privilege"):
            facts.add(PRIV_SYSTEM.token)
        if wm.find("persistence"):
            facts.add(PERSIST_INSTALLED.token)
        # internal expansion state: the beacon's internal snapshot/probe
        # results satisfy the internal recon goals so the core neither
        # re-plans nor re-runs them, and the pivot goals can then chain on
        # the discovered peers.
        if wm.find("internal_host"):
            facts.add(INTERNAL_HOST.token)
        if wm.find("internal_service"):
            facts.add(INTERNAL_SERVICE.token)
        return facts

    def search(self, have: Set[str], goal: str,
               noise_budget: Optional[float] = None) -> Optional[Composition]:
        """Cheapest operator chain from `have` to `goal`, or None."""
        result = self._search(tuple(sorted(have)), goal, noise_budget)
        return result

    def search_from_worldmodel(self, wm, goal: str,
                               noise_budget: Optional[float] = None
                               ) -> Optional[Composition]:
        return self.search(self.facts_from_worldmodel(wm), goal, noise_budget)

    # ── search core ────────────────────────────────────────────────────
    def _search(self, start: Tuple[str, ...], goal: str,
                noise_budget: Optional[float]) -> Optional[Composition]:
        # iterative deepening: depth 0 = already satisfied
        if goal in start:
            return Composition(goal=goal)
        for depth in range(1, self.max_depth + 1):
            found = self._dfs(set(start), goal, depth, [], noise_budget)
            if found is not None:
                return found
        return None

    def _dfs(self, have: Set[str], goal: str, depth: int,
             path: List[CompositionStep],
             noise_budget: Optional[float]) -> Optional[Composition]:
        if goal in have:
            comp = Composition(goal=goal)
            comp.steps = list(path)
            comp.total_cost = sum(s.cost for s in path)
            comp.total_noise = sum(s.noise for s in path)
            return comp
        if depth <= 0:
            return None
        # candidate operators: viable now, not already in the path
        best: Optional[Composition] = None
        for op in sorted(self.registry.all(), key=lambda o: o.cost):
            if not op.viable(have):
                continue
            if any(op.op_id == s.op_id for s in path):
                continue   # no operator twice in one chain
            new_facts = [f for f in op.produces if f not in have]
            if not new_facts:
                continue
            nxt = CompositionStep(op_id=op.op_id,
                                  facts_produced=tuple(new_facts),
                                  cost=op.cost, noise=op.noise)
            if noise_budget is not None:
                spent = (sum(s.noise for s in path) + op.noise)
                if spent > noise_budget:
                    continue
            have.update(new_facts)
            path.append(nxt)
            found = self._dfs(have, goal, depth - 1, path, noise_budget)
            path.pop()
            for f in new_facts:
                have.discard(f)
            if found is not None:
                # keep the CHEAPEST found at this depth
                if best is None or found.total_cost < best.total_cost:
                    best = found
        return best
