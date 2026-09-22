"""SwarmTask: the fact-driven work unit.

A task is a goal on a set of targets, released when its ``needs`` facts
are committed on the board, publishing ``provides`` facts. The kill-chain
DAG is never hardcoded: ``exploit(needs={service})`` waits for the recon
task's commit because the FACT is missing, not because a chain says so.
Three recon tasks on three targets release three exploit tasks in
parallel for free.

Contact classes (and default acting caps) are reused from the cell
roster (``brain/cells.py``) — one vocabulary for "how a role touches
the world".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List

from phantom.automation.brain.cells import (
    ACTING_CAP,
    ACTING_CAP_AGGRESSIVE,
    CONTACT_EXPLOIT,
    CONTACT_NONE,
    CONTACT_RECON,
)

MAX_AGENTS_DEFAULT = 10   # per-operation cap (operator may raise to ceiling)
MAX_AGENTS_CEILING = 15   # hard ceiling: orchestrator or red-teamer decision

STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_DONE = "done"
STATUS_FAILED = "failed"


@dataclass
class SwarmTask:
    """One unit of swarm work."""
    id: str
    goal: str                       # agent goal run by the worker
    targets: List[str]              # static targets (or resolved, see below)
    needs: FrozenSet[str] = frozenset()
    provides: FrozenSet[str] = frozenset()
    contact: str = CONTACT_RECON
    max_agents: int = 1             # Fase 3: one worker per task
    budget: int = 10                # worker max_iterations
    seed: int = 0
    # --- reasoning diversity (Fase 4): two workers on the same task must
    # be able to reason DIFFERENTLY, or parallelism only spends budget ---
    profile: str = ""               # reason profile ("" = orchestrator picks)
    avoid_caps: FrozenSet[str] = frozenset()   # capability ids a sibling
                                    # already tried: seeded as dead so the
                                    # planner falls to the NEXT source
                                    # (novelty via existing machinery)
    banned_categories: FrozenSet[str] = frozenset()  # capability
                                    # categories this worker may not plan
                                    # with (subset registry)
    target_source: str = ""         # "" = static; else a fact kind whose
                                    # committed values become EXTRA targets
                                    # (e.g. "victim_ip" from osint)
    status: str = STATUS_QUEUED
    attempts: int = 0
    failure_kind: str = ""          # "" | "task" | "agent" (Fase 5 classifies)
    note: str = ""
    # --- fan-out runtime (Fase 7): tried caps per target feed the
    # stall-helper's avoid set; helper_used bounds second opinions ---
    tried: Dict[str, List[str]] = field(default_factory=dict)
    helper_used: bool = False
    # --- per-target completion (M3): one orchestrator+pool per target,
    # so a task spanning N targets is done only when every static
    # target delivered its provides (dynamic extras ride along).
    done_targets: set = field(default_factory=set)
    def ready(self, board) -> bool:
        """Releasable when every needs-fact is committed for every STATIC
        target. Dynamically resolved targets (victim IPs...) are the task's
        OUTPUT, not its precondition — requiring needs on boards that do
        not exist yet would deadlock the DAG."""
        for target in self.targets:
            for fact in self.needs:
                if not board.has(target, fact):
                    return False
        return True

    def target_ready(self, board, target: str) -> bool:
        """Per-target release (M3 pools): the needs on THIS target only."""
        for fact in self.needs:
            if not board.has(target, fact):
                return False
        return True

    def targets_for(self, board, origin: str) -> List[str]:
        """The action scope for one per-target worker: its origin target
        plus extras dynamically resolved FROM it (victim IPs...)."""
        out = [origin]
        if self.target_source:
            for extra in board.target_values(origin, self.target_source):
                if extra not in out:
                    out.append(extra)
        return out

    def target_satisfied(self, board, target: str) -> bool:
        """Provides delivered on THIS target (empty provides = vacuously
        true so pure-side-effect tasks still complete)."""
        if not self.provides:
            return True
        return all(board.has(target, f) for f in self.provides)

    def effective_targets(self, board) -> List[str]:
        """Static targets plus dynamically resolved ones (victim IPs...)."""
        out = list(self.targets)
        if self.target_source:
            for target in self.targets:
                for extra in board.target_values(target, self.target_source):
                    if extra not in out:
                        out.append(extra)
        base = list(self.targets)
        return base + [t for t in out if t not in base] if self.target_source \
            else out

    def satisfied(self, board) -> bool:
        """Task done when every provides-fact is committed (any target)."""
        if not self.provides:
            return True
        targets = self.effective_targets(board)
        if not targets:
            return False
        return any(all(board.has(t, f) for f in self.provides)
                   for t in targets)


# chain -> ordered task specs. Order sets scheduling priority only; the
# FACTS set the actual release (a task never runs before its needs).
# Contact classes set the fan-out width (none=up to 5 upfront, recon and
# exploit=1 lead + stall helper).
_CHAINS: Dict[str, List[dict]] = {
    "footprint": [
        {"goal": "footprint", "contact": CONTACT_RECON,
         "needs": frozenset(), "provides": frozenset({"service"})},
    ],
    "identity": [
        {"goal": "identity", "contact": CONTACT_NONE,
         "needs": frozenset(), "provides": frozenset({"identity", "victim_ip"})},
        {"goal": "footprint", "contact": CONTACT_RECON,
         "needs": frozenset({"victim_ip"}),
         "provides": frozenset({"service"}),
         "target_source": "victim_ip"},
    ],
    "creds": [
        {"goal": "footprint", "contact": CONTACT_RECON,
         "needs": frozenset(), "provides": frozenset({"service"})},
        {"goal": "creds", "contact": CONTACT_EXPLOIT,
         "needs": frozenset({"service"}), "provides": frozenset({"creds"})},
    ],
    "web": [
        {"goal": "footprint", "contact": CONTACT_RECON,
         "needs": frozenset(), "provides": frozenset({"service"})},
        {"goal": "web", "contact": CONTACT_EXPLOIT,
         "needs": frozenset({"service"}),
         "provides": frozenset({"hunt_anomaly", "rce_foothold"})},
    ],
    "full": [
        {"goal": "footprint", "contact": CONTACT_RECON,
         "needs": frozenset(), "provides": frozenset({"service"})},
        {"goal": "complete_kill_chain", "contact": CONTACT_EXPLOIT,
         "needs": frozenset({"service"}),
         "provides": frozenset({"beacon"})},
        {"goal": "creds", "contact": CONTACT_EXPLOIT,
         "needs": frozenset({"service"}), "provides": frozenset({"creds"})},
        {"goal": "post_exploit", "contact": CONTACT_EXPLOIT,
         "needs": frozenset({"beacon"}),
         "provides": frozenset({"persistence", "system_privilege"})},
    ],
    "deep": [
        {"goal": "footprint", "contact": CONTACT_RECON,
         "needs": frozenset(), "provides": frozenset({"service"})},
        {"goal": "complete_kill_chain", "contact": CONTACT_EXPLOIT,
         "needs": frozenset({"service"}),
         "provides": frozenset({"beacon"})},
        {"goal": "creds", "contact": CONTACT_EXPLOIT,
         "needs": frozenset({"service"}), "provides": frozenset({"creds"})},
        {"goal": "post_exploit", "contact": CONTACT_EXPLOIT,
         "needs": frozenset({"beacon"}),
         "provides": frozenset({"persistence", "system_privilege"})},
        {"goal": "ad", "contact": CONTACT_EXPLOIT,
         "needs": frozenset({"beacon"}),
         "provides": frozenset({"ad_domain", "ad_creds"})},
        {"goal": "crack", "contact": CONTACT_NONE,
         "needs": frozenset({"ad_creds"}),
         "provides": frozenset({"cracked"})},
        {"goal": "lateral", "contact": CONTACT_EXPLOIT,
         "needs": frozenset({"beacon", "creds"}),
         "provides": frozenset({"pivot"})},
    ],
}
CHAIN_TEMPLATES = tuple(_CHAINS.keys())


def build_tasks(chain: str, targets: List[str], seed: int = 0,
                budget: int = 10, aggressive: bool = False) -> List[SwarmTask]:
    """Expand a chain template into tasks (deterministic ids)."""
    if chain not in _CHAINS:
        raise ValueError(f"unknown chain: {chain} (want one of {CHAIN_TEMPLATES})")
    caps = ACTING_CAP_AGGRESSIVE if aggressive else ACTING_CAP
    tasks = []
    for i, spec in enumerate(_CHAINS[chain]):
        contact = spec["contact"]
        tasks.append(SwarmTask(
            id=f"{spec['goal']}-{i}",
            goal=spec["goal"],
            targets=list(targets),
            needs=spec["needs"],
            provides=spec["provides"],
            contact=contact,
            max_agents=caps.get(contact, 1),
            budget=budget,
            seed=(seed or 0) + i * 7919,
            target_source=spec.get("target_source", ""),
        ))
    return tasks
