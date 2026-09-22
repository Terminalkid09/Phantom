"""Swarm scheduler: release tasks by facts, commit results, summarize.

Two modes (one code path, flag-controlled):

* single-pool (grouped=False): every action shares the passed
  orchestrator — kept for unit tests and simple callers;
* per-target pools (grouped=True, the auto-mode path): every STATIC
  target owns its Orchestrator + worker pool; a shared semaphore caps
  TOTAL concurrent workers operation-wide (default ceiling 15).
  Dynamically resolved targets (victim IPs...) get a lazy pool of
  their own. The board stays shared: cross-target facts are a feature,
  not a leak (writes are still mediated commits).

Fan-out policy (the operator's spec):

* CONTACT_NONE tasks (osint...) fan out UPFRONT to task.max_agents
  workers — no target contact, parallelism is free. Slot 0 runs the
  picked profile; further slots rotate profiles + offset seeds, so
  five agents on one target reason five different ways over the same
  committed truth (scratch isolation keeps them divergent).
* CONTACT_RECON/EXPLOIT tasks run ONE lead per target. On an
  agent-kind failure WITH a stall class, ONE helper is submitted
  (adversarial profile, the lead's tried caps as avoid, xored seed —
  the cells.escalate semantics): a second opinion, not a second
  assault.
* task-kind failures requeue once with a rotated profile (replan-lite).

Failed tasks are ATTRIBUTED (swarm/failures.py), not just logged:
agent-kind failures are packaged as Triage FailureCases for the
evolution loop (human PR gate unchanged) and persisted as JSONL when a
failure log path is configured.
"""
from __future__ import annotations

import threading as _threading
from typing import Dict, List

_MAX_WAVES = 3  # initial + requeue/helpers + final helpers
_MAX_HELPERS_PER_TASK = 1  # one second opinion max (escalation, not fan-out)
_UPFRONT_FANOUT_CAP = 5  # CONTACT_NONE slots submitted together


def schedule(orch, board, tasks, drain_timeout=120.0, priors=None,
             registry=None, sink=None, grouped=False, orch_factory=None,
             ceiling=15, max_agents=10) -> Dict:
    """Submit + drain (up to 3 waves); operation summary."""
    if grouped:
        if orch_factory is None:
            raise ValueError("grouped scheduling needs orch_factory")
        return _schedule_grouped(
            board, tasks, orch_factory,
            drain_timeout=drain_timeout, priors=priors, registry=registry,
            sink=sink, ceiling=ceiling, max_agents=max_agents)
    return _schedule_single(
        orch, board, tasks, drain_timeout=drain_timeout, priors=priors,
        registry=registry, sink=sink)


def _pool_orchs(static_targets, orch_factory, ceiling, max_agents):
    import threading
    sem = threading.BoundedSemaphore(max(1, int(ceiling or 1)))
    orchs = {}
    for target in static_targets:
        orchs[target] = orch_factory(sem, max_agents)
    return orchs, sem


def _drain_all(orchs, drain_timeout) -> None:
    import threading
    threads = []
    for orch in orchs.values():
        t = threading.Thread(target=orch.run,
                             kwargs={"drain_timeout": drain_timeout},
                             daemon=True)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()


def _schedule_grouped(board, tasks, orch_factory, drain_timeout=120.0,
                      priors=None, registry=None, sink=None,
                      ceiling=15, max_agents=10) -> Dict:
    from .profiles import pick_profile  # noqa: F401 (re-export surface)
    from .worker import TaskResult  # noqa: F401  (re-export surface)
    sink = sink if sink is not None else {"failures": [], "cases": []}
    sink.setdefault("tried", {})
    sink.setdefault("lock", _threading.Lock())
    static_targets = sorted({t for task in tasks for t in task.targets})
    orchs, _sem = _pool_orchs(static_targets, orch_factory, ceiling,
                              max_agents)

    def _new_pool():
        # a dynamically resolved origin (victim IP...) gets its own pool on
        # first use; bind the shared semaphore + per-pool width here so the
        # lazy-creation path stays a zero-arg callable
        return orch_factory(_sem, max_agents)

    order = {t.id: i for i, t in enumerate(tasks)}
    helpers: list = []  # (task, origin, profile, avoid, seed)
    for _wave in range(_MAX_WAVES):
        did = False
        for task in [t for t in tasks if t.status == "queued"]:
            _ensure_profile(task, board, priors)
            for origin in _origins_for(task, board):
                _submit_origin_slots(orchs, _new_pool, board, task,
                                     order[task.id], origin)
                did = True
        for task, origin, profile, avoid, seed in helpers:
            _submit_helper(orchs, _new_pool, board, task,
                           order[task.id], origin, profile, avoid, seed)
            did = True
        helpers = []
        if not did:
            break
        _drain_all(orchs, drain_timeout)
        _requeue_failed(tasks)
        helpers = _prepare_helpers(tasks, sink)
    return _summarize(tasks, board, orchs, sink)


def _schedule_single(orch, board, tasks, drain_timeout=120.0, priors=None,
                     registry=None, sink=None) -> Dict:
    """Legacy single-pool path (unit tests, simple callers)."""
    from .profiles import pick_profile  # noqa: F401  (re-export surface)
    from .worker import TaskResult  # noqa: F401  (re-export surface)
    sink = sink if sink is not None else {"failures": [], "cases": []}
    sink.setdefault("tried", {})
    sink.setdefault("lock", _threading.Lock())
    order = {t.id: i for i, t in enumerate(tasks)}
    helpers: list = []
    for _wave in range(_MAX_WAVES):
        submitted = False
        for task in [t for t in tasks if t.status == "queued"]:
            _ensure_profile(task, board, priors)
            if task.contact == "none" and task.max_agents > 1:
                for slot in range(min(task.max_agents,
                                      _UPFRONT_FANOUT_CAP)):
                    _submit_slot(orch, board, task, order[task.id], slot,
                                 task.targets[0] if task.targets else "")
            else:
                _submit_slot(orch, board, task, order[task.id], 0,
                             task.targets[0] if task.targets else "")
            submitted = True
        for task, origin, profile, avoid, seed in helpers:
            _submit_helper(orch, None, board, task, order[task.id], origin,
                           profile, avoid, seed)
            submitted = True
        helpers = []
        if not submitted:
            break
        orch.run(drain_timeout=drain_timeout)
        _requeue_failed(tasks)
        helpers = _prepare_helpers(tasks, sink)
    return _summarize(tasks, board, {"": orch}, sink)


def _summarize(tasks, board, orchs, sink) -> Dict:
    out = []
    for task in tasks:
        if task.status == "queued":
            # never released: a need that no committed fact can satisfy
            # (producer failed or chain mismatch) — say so explicitly
            # instead of leaving a silent "queued".
            task.status = "failed"
            task.note = f"never released (needs={sorted(task.needs)})"
        out.append({"id": task.id, "goal": task.goal,
                    "status": task.status, "attempts": task.attempts,
                    "profile": task.profile or "balanced",
                    "failure_kind": task.failure_kind, "note": task.note,
                    "targets_done": sorted(task.done_targets)})
    trail = []
    for orch in orchs.values():
        trail.extend(list(orch.campaign))
    return {"tasks": out, "board": board.summary(),
            "added": board.added, "skipped": board.skipped,
            "actions_taken": int(sink.get("actions", 0)),
            "trail": trail,
            "failures": list(sink["failures"]),
            "evolution_cases": list(sink["cases"])}


def _origins_for(task, board) -> List[str]:
    """Static origins still owed work, plus newly resolved dynamic
    extras. Completed origins (done_targets) never resubmit — the
    commit, not a submit-once set, guards repeats, so requeues after
    failure still run."""
    origins = [t for t in task.targets if t not in task.done_targets]
    if task.target_source:
        for origin in task.targets:
            for extra in board.target_values(origin, task.target_source):
                if extra not in origins and extra not in task.done_targets:
                    origins.append(extra)
    return origins


def _ensure_profile(task, board, priors) -> None:
    if task.profile or priors is None:
        return
    try:
        from phantom.automation.brain.priors import fingerprint_class
        from .profiles import pick_profile
        fp = fingerprint_class(board.worldmodel(task.targets[0])) \
            if task.targets else "generic"
        task.profile = pick_profile(task.goal, fp, priors,
                                    seed=task.seed,
                                    round_idx=task.attempts)
    except Exception:
        task.profile = ""


def _submit_origin_slots(orchs, factory, board, task, priority_idx: int,
                          origin: str):
    """One lead (slot 0), plus upfront fan-out slots on CONTACT_NONE.
    Pools are lazy: a dynamic extra gets its own orchestrator on first
    use (own pool per target, always)."""
    try:
        board.ensure(origin)
    except Exception:
        pass
    orch = orchs.get(origin) if isinstance(orchs, dict) else orchs
    if orch is None:
        if factory is None:
            return
        orch = orchs[origin] = factory()
    slots = 1
    if task.contact == "none" and task.max_agents > 1:
        slots = min(task.max_agents, _UPFRONT_FANOUT_CAP)
    for slot in range(slots):
        _submit_slot(orch, board, task, priority_idx, slot, origin or "")


def _submit_slot(orch, board, task, priority_idx: int, slot: int,
                 origin: str):
    """One worker slot: slot 0 runs the task profile; further slots
    rotate profiles and offset seeds (deterministic divergence). An
    empty origin means whole-task scope (legacy single-pool path)."""
    from .profiles import PROFILES, rotate
    if slot == 0:
        profile, avoid, seed = None, None, None  # task fields as-is
    else:
        base = task.profile or PROFILES[0]
        profile = rotate(base) if slot == 1 else PROFILES[
            slot % len(PROFILES)]
        avoid, seed = None, task.seed + slot * 131
    action = orch.submit(
        capability_id=f"swarm:{task.id}#w{slot}#{origin or 'all'}",
        entity=f"task:{task.id}#w{slot}#{origin or 'all'}",
        priority=100 - priority_idx,
        task_id=task.id,
        gate=_target_gate(task, board, origin) if origin
        else _gate_for(task, board),
    )
    action.task = task  # the dispatcher runs THIS task object
    action.targets = [origin] if origin else None
    action.task_origin = origin
    action.worker_profile = profile
    action.worker_avoid = avoid
    action.worker_seed = seed
    action.is_helper = False
    return action


def _submit_helper(orchs, factory, board, task, priority_idx: int,
                   origin: str, profile: str, avoid, seed: int):
    """One second opinion on a stalled task (still needs its facts)."""
    try:
        board.ensure(origin)
    except Exception:
        pass
    if isinstance(orchs, dict):
        orch = orchs.get(origin)
        if orch is None:
            if factory is None:
                return None
            orch = orchs[origin] = factory()
    else:
        orch = orchs  # single-pool path passes the orchestrator itself
    action = orch.submit(
        capability_id=f"swarm:{task.id}#help#{origin}",
        entity=f"task:{task.id}#help#{origin}",
        priority=100 - priority_idx,
        task_id=task.id,
        gate=_target_gate(task, board, origin),
    )
    action.task = task
    action.targets = [origin]
    action.task_origin = origin
    action.worker_profile = profile
    action.worker_avoid = avoid
    action.worker_seed = seed
    action.is_helper = True
    task.helper_used = True
    return action


def _requeue_failed(tasks) -> bool:
    """Reset task-kind failures for one more wave with a rotated profile.
    Agent-kind failures are learning material, not retries."""
    from .profiles import rotate
    retried = False
    for task in tasks:
        if task.status == "failed" and task.failure_kind == "task" \
                and task.attempts < 2:
            task.status = "queued"
            task.profile = rotate(task.profile or "")
            task.note = (task.note + " | requeue profile=" + task.profile) \
                if task.note else "requeue profile=" + task.profile
            retried = True
    return retried


def _prepare_helpers(tasks, sink) -> list:
    """One helper per stalled agent-kind failure (bounded). Pools are
    created lazily at submit time, so preparation stays pool-free."""
    from .profiles import PROFILES
    try:
        from phantom.automation.brain.lenses import ADVERSARIAL_PAIR
    except Exception:
        ADVERSARIAL_PAIR = {}
    helpers = []
    tried = sink.get("tried", {})
    records = [f for f in sink.get("failures", [])
               if f.get("kind") == "agent" and f.get("stall")]
    for task in tasks:
        if task.status != "failed" or task.failure_kind != "agent":
            continue
        if task.helper_used or task.attempts >= 3:
            continue
        recs = [r for r in records if r.get("task") == task.id]
        if not recs:
            continue  # no stall class: nothing for a peer to second-guess
        origin = recs[0].get("target") or (task.targets[0]
                                           if task.targets else "")
        if not origin:
            continue
        avoid: set = set()
        for (tid, tgt), caps in tried.items():
            if tid == task.id:
                avoid |= set(caps)
        base = task.profile or PROFILES[0]
        helpers.append((task, origin,
                        ADVERSARIAL_PAIR.get(base, "evidence_first"),
                        frozenset(avoid), task.seed ^ 0x5F3759DF))
        if len(helpers) >= _MAX_HELPERS_PER_TASK * max(1, len(tasks)):
            break
    return helpers


def _target_gate(task, board, origin: str):
    """Release gate on ONE origin's needs (dynamic extras resolve from
    an origin whose needs already hold, so they inherit openness)."""
    def _ready() -> bool:
        try:
            return task.target_ready(board, origin)
        except Exception:
            return False
    return _ready


def _gate_for(task, board):
    """Whole-task gate (legacy single-pool path)."""
    def _ready() -> bool:
        try:
            return task.ready(board)
        except Exception:
            return False
    return _ready


def commit_result(board, task, target: str, result, priors=None,
                  registry=None, sink=None):
    """Commit one worker's staged findings; advance the task state; feed
    the outcome back into the profile priors AND the failure ledger.
    Per-target completion: a task spanning N targets is done only when
    every static target delivered. Returns the failure record, or None
    when this target is done."""
    from .failures import AGENT, classify, package_case
    task.attempts += 1
    added, skipped = board.commit(task.id, target, result.staged)
    if result.ok or task.target_satisfied(board, target):
        task.done_targets.add(target)
    if task.done_targets >= set(task.targets) or \
            (not task.targets and task.satisfied(board)):
        task.status = "done"
        task.failure_kind = ""
        task.note = f"+{added} ~{skipped}"
        done_here = True
    else:
        task.status = "failed"
        task.note = result.note or "provides not satisfied"
        task.failure_kind = classify(task, result)
        done_here = False
    if priors is not None:
        try:
            from phantom.automation.brain.priors import fingerprint_class
            from .profiles import record_outcome
            wm = board.worldmodel(target)
            fp = fingerprint_class(wm) if wm is not None else "generic"
            record_outcome(priors, task.goal, task.profile or "balanced",
                           fp, done_here)
        except Exception:
            pass
    if sink is None or done_here:
        return None
    record = {"task": task.id, "goal": task.goal,
              "profile": task.profile or "balanced", "target": target,
              "kind": task.failure_kind or "task",
              "stall": getattr(result, "stall", ""),
              "failures": getattr(result, "failures", 0),
              "actions": getattr(result, "actions_taken", 0),
              "note": task.note,
              "llm_requested": False, "llm_suggestions": []}
    sink["failures"].append(record)
    if task.failure_kind == AGENT:
        case = package_case(task, target, result, board=board,
                            registry=registry)
        if case is not None:
            try:
                sink["cases"].append(case.to_dict())
            except Exception:
                pass
    return record
