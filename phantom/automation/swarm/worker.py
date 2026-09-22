"""WorkerAgent: one task, one target, one private WorldModel.

The worker mirrors the construction the legacy single-agent path uses
(same agent class, same runner contract), with exactly three differences:

1. it runs on a board SNAPSHOT, never the shared model;
2. its budget is the task budget (planner iterations);
3. it returns staged findings (dicts) instead of writing anywhere.

The orchestrator commits. Single-worker runs are therefore comparable
finding-for-finding with the legacy path (the Fase 3 acceptance test).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class TaskResult:
    task_id: str
    target: str
    ok: bool                       # provides satisfied after this run
    staged: List[dict] = field(default_factory=list)
    actions_taken: int = 0
    iterations: int = 0
    failures: int = 0              # recorded capability failures in-run
    stall: str = ""                # stall class if the run stalled
    crashed: bool = False          # the worker itself blew up (not the plan)
    note: str = ""


def run_swarm_task(task, target: str, board, runner=None,
                   profile: str = "enterprise", aggressive: bool = False,
                   on_event: Optional[Callable[[str, dict], None]] = None,
                   llm: bool = False, worker_profile: Optional[str] = None,
                   worker_avoid=None, worker_seed: Optional[int] = None,
                   scope_list=None) -> TaskResult:
    """Run one task on one target; return staged findings (no board writes).

    ``llm`` enables the worker's internal non-gating advisor (the
    --llm semantics: suggestions only, validated, never executed). The
    orchestrator sets it only when the operator approved LLM use for
    this operation (session approval). One-shot consults on failure go
    through swarm/llm.consult instead.

    ``worker_profile`` / ``worker_avoid`` / ``worker_seed`` override the
    task fields for THIS worker only (thread-safe fan-out: siblings
    share the task object but never its overrides).
    """
    from phantom.automation.agent import AutonomousAgent
    from phantom.automation.runtime.stealth_runtime import (
        StealthRuntime, TimingGovernor)
    from phantom.automation.runtime.toolchain import ToolRegistry

    snapshot = board.snapshot(target)
    before = {(f.get("kind", ""), f.get("key", ""))
              for f in snapshot.to_dict().get("findings", [])}

    registry = None
    if getattr(task, "banned_categories", None):
        # subset registry: banned categories are unplannable for THIS
        # worker (a second worker with a different ban reasons over a
        # different move set from the same truth)
        from phantom.automation.guidance.commands import (
            Registry, make_registry)
        banned = set(task.banned_categories)
        registry = Registry()
        for cap in make_registry().all():
            if cap.category not in banned:
                registry.register(cap)

    agent = AutonomousAgent(
        target=target, shared_wm=snapshot,
        toolchain=ToolRegistry(installed={"nmap", "curl", "nc"}),
        command_seed=task.seed if worker_seed is None else worker_seed,
        on_event=on_event,
        hunt_runner=_quiet_hunt_runner if runner is None else None,
        registry=registry,
        reason_profile=(task.profile if worker_profile is None
                        else worker_profile),
        llm=bool(llm),
        scope_list=list(scope_list or []) if scope_list else None,
    )
    # novelty seeding: capabilities a sibling already tried stay DEAD for
    # the whole run (via _novelty_dead, distinct from failures so the
    # retry machinery never re-arms them), forcing this worker's planner
    # down the next source for the same facts.
    try:
        avoid = task.avoid_caps if worker_avoid is None else worker_avoid
        agent._novelty_dead = set(avoid or ())
    except Exception:
        pass
    # zero-delay governor + injected runner: deterministic, offline-safe
    agent.runtime = StealthRuntime(
        agent.stealth_engine,
        runner=runner or _null_runner(),
        cost_per_action=0.5,
        governor=TimingGovernor(base_delay=0.0, jitter=0.0))
    if runner is not None and getattr(agent, "hunt_runner", None) is None:
        agent.hunt_runner = _quiet_hunt_runner

    budget = max(1, int(task.budget or 1))
    result = agent.run(goal=task.goal, max_iterations=budget)
    try:
        run_failures = len(agent.wm.failures or [])
    except Exception:
        run_failures = 0
    run_stall = str(getattr(agent, "_last_stall", "") or "")
    staged: List[dict] = []
    try:
        findings = agent.wm.to_dict().get("findings", [])
    except Exception:
        findings = []
    for f in findings:
        key = (f.get("kind", ""), f.get("key", ""))
        if key in before or not key[0] or not key[1]:
            continue
        staged.append({
            "kind": key[0], "key": key[1],
            "value": f.get("value", {}),
            "confidence": f.get("confidence", 0.5),
            "source": f.get("source") or task.id,
        })
    ok = _provides_satisfied(task, target, board, staged)
    actions = 0
    try:
        actions = int(result.get("actions_taken", 0))
    except Exception:
        actions = 0
    return TaskResult(task_id=task.id, target=target, ok=ok,
                      staged=staged, actions_taken=actions,
                      iterations=budget, failures=run_failures,
                      stall=run_stall,
                      note="" if ok else "provides not satisfied")


def _provides_satisfied(task, target: str, board, staged: List[dict]) -> bool:
    if not task.provides:
        return True
    staged_kinds = {s.get("kind", "") for s in staged}
    committed_kinds = set(board.kinds(target))
    return all(p in (staged_kinds | committed_kinds) for p in task.provides)


def _null_runner():
    """Offline-safe command runner: every tool is 'missing' (empty miss)."""
    class _Res:
        ok = False
        stdout = ""
        stderr = ""
    def run(cmd, timeout=None):
        return _Res()
    return run


def _quiet_hunt_runner(method, url, body="", timeout=8.0):
    from phantom.automation.exploit.anomaly import ProbeResult
    return ProbeResult()
