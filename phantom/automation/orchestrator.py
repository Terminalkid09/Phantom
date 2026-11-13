"""
orchestrator.py — elastic agent pool + prioritized work queue.

The orchestrator behaves like a red-team lead: it keeps a queue of
Actions ordered by expected value (probability x cost), dispatches them
to a pool of 1..N agents (threads) that share the WorldModel, enforces
per-entity locks so two agents never touch the same target, and collects
the campaign trail for the reports.
"""

from __future__ import annotations

import heapq
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Dict, List, Optional

from phantom.automation.belief import WorldModel
from phantom.automation.guidance.stealth import StealthEngine


class ActionStatus(Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"


def _gate_open(gate) -> bool:
    """A gate that raises is a closed gate (never break the pool)."""
    try:
        return bool(gate())
    except Exception:
        return False


@dataclass
class PrioritizedAction:
    priority: float = field(compare=False)  # expected value: probability x cost
    seq: int = field(compare=False)
    # payload ---------------------------------------------------------
    capability_id: str = field(compare=False)
    entity: str = field(compare=False)      # locked resource (target/host)
    slot_values: Dict[str, str] = field(compare=False, default_factory=dict)
    status: ActionStatus = field(compare=False, default=ActionStatus.QUEUED)
    detail: str = field(compare=False, default="")
    # swarm scheduling: optional release gate + owning task id. A gated
    # action whose gate() is False stays QUEUED while others drain — this
    # is how fact-driven DAGs (exploit waits for service) reuse the pool
    # without the pool knowing about facts.
    gate: Optional[Callable[[], bool]] = field(default=None, compare=False)
    task_id: str = field(default="", compare=False)

    def __lt__(self, other):
        return (-self.priority, self.seq) < (-other.priority, other.seq)


class Orchestrator:
    """Dispatches prioritized actions to an elastic pool of agent threads."""

    def __init__(self, wm: WorldModel, stealth: StealthEngine,
                  worker: Callable, max_agents: int = 10,
                  min_agents: int = 1,
                  global_slot=None) -> None:
        """
        worker(action: PrioritizedAction, ctx: dict) -> bool
        ctx carries the shared WorldModel, registry, planner, etc.
        global_slot: optional threading.BoundedSemaphore shared across
        pool instances (swarm multi-target: every target owns its
        orchestrator + pool, the semaphore caps TOTAL concurrent
        workers operation-wide).
        """
        self.wm = wm
        self.stealth = stealth
        self.worker = worker
        self.max_agents = max_agents
        self.min_agents = min_agents
        self.global_slot = global_slot
        self._queue: List[PrioritizedAction] = []
        self._seq = 0
        self._locks: Dict[str, threading.Lock] = {}
        self._lock_guard = threading.Lock()
        self._agents: List[threading.Thread] = []
        self._agents_guard = threading.Lock()
        self._pause = threading.Event()
        self._stop = threading.Event()
        self._done_count = 0
        self._finished_count = 0
        self._running = False
        self._paused_requested = False
        self.campaign: List[dict] = []  # decision trail for reports
        self._trail_guard = threading.Lock()

    # ------------------------------------------------------------------ queue

    def submit(self, capability_id: str, entity: str, priority: float,
                slot_values: Optional[Dict[str, str]] = None,
                gate: Optional[Callable[[], bool]] = None,
                task_id: str = "") -> PrioritizedAction:
        action = PrioritizedAction(
            priority=priority, seq=self._seq, capability_id=capability_id,
            entity=entity, slot_values=slot_values or {},
            gate=gate, task_id=task_id,
        )
        self._seq += 1
        heapq.heappush(self._queue, action)
        return action

    def pending(self) -> List[PrioritizedAction]:
        return list(self._queue)

    def _pop(self) -> Optional[PrioritizedAction]:
        action = None
        with self._lock_guard:
            if not self._queue:
                return None
            # scan for the highest-priority action that is runnable: queued,
            # gate-open and entity-free. The rest goes back on the heap, so
            # a gated head never blocks a ready tail.
            deferred = []
            while self._queue:
                a = heapq.heappop(self._queue)
                if a.status != ActionStatus.QUEUED:
                    continue
                if a.gate is not None and not _gate_open(a.gate):
                    deferred.append(a)
                    continue
                if not self._entity_free(a.entity):
                    deferred.append(a)
                    continue
                action = a
                break
            for d in deferred:
                heapq.heappush(self._queue, d)
            if action is not None:
                action.status = ActionStatus.RUNNING
        if action is not None:
            self._lock_entity(action.entity)
        return action

    def _entity_free(self, entity: str) -> bool:
        return entity not in self._locks or not self._locks[entity].locked()

    def _lock_entity(self, entity: str) -> None:
        with self._lock_guard:
            lock = self._locks.setdefault(entity, threading.Lock())
        if not lock.locked():
            lock.acquire()

    def _unlock_entity(self, entity: str) -> None:
        with self._lock_guard:
            lock = self._locks.get(entity)
        if lock is not None and lock.locked():
            lock.release()

    def _record_trail(self, action: PrioritizedAction, ok: bool, detail: str) -> None:
        with self._trail_guard:
            self.campaign.append({
                "time": time.strftime("%H:%M:%S"),
                "capability": action.capability_id,
                "entity": action.entity,
                "ok": ok,
                "detail": detail,
            })

    # ------------------------------------------------------------------- run

    def run(self, drain_timeout: float = 120.0) -> None:
        """Drain the queue with an elastic agent pool until empty.

        A bounded drain_timeout (default 120s) prevents an agent thread
        that is stuck inside its capability from keeping the orchestrator
        alive forever (which would hang the test session / CLI exit). The
        timeout only applies while an agent is still RUNNING (the queue may
        be empty or hold actions its commit will release).

        When NO agent is running, the loop stops at once: nothing local can
        open a gate or free an entity, so the only remaining actions are
        ones a sibling pool could release — the scheduler's wave loop
        re-submits those after its drains, instead of this loop idling for
        the full drain_timeout. Actions already runnable are always
        dispatched first.
        """
        if not self._paused_requested:
            self._pause.set()
        self._stop.clear()
        self._running = True
        idle_since: Optional[float] = None
        try:
            while not self._stop.is_set():
                self._pause.wait()
                action = self._pop()
                if action is None:
                    if self._agents_active() == 0:
                        # No worker is running, so nothing local can commit
                        # a fact or release a lock. Either the queue is empty
                        # (drained) or every remaining action is parked on a
                        # gate only a SIBLING pool could satisfy — parking
                        # here for the whole drain_timeout would stall the
                        # operation for minutes doing nothing. Stop and let
                        # the caller re-submit (the scheduler runs waves, so
                        # a fact committed elsewhere is picked up next wave).
                        break
                    # an agent is still running: bounded wait for a stuck
                    # capability (one that never returns).
                    if idle_since is None:
                        idle_since = time.time()
                    elif time.time() - idle_since > drain_timeout:
                        break
                    time.sleep(0.1)
                    continue
                idle_since = None
                # bounded pool: never spawn past max_agents. A saturated pool
                # returns the action to the queue (status back to QUEUED,
                # entity lock released) and waits for a free slot — this is
                # what keeps a campaign from spawning a thread per action.
                if self._agents_active() >= self.max_agents:
                    action.status = ActionStatus.QUEUED
                    with self._lock_guard:
                        heapq.heappush(self._queue, action)
                    self._unlock_entity(action.entity)
                    time.sleep(0.1)
                    continue
                t = threading.Thread(target=self._run_one, args=(action,), daemon=True)
                with self._agents_guard:
                    self._agents.append(t)
                t.start()
        finally:
            self._running = False

    def stop(self) -> None:
        """Signal the run-loop to stop draining (does not kill agents).
        Sets BOTH the stop flag and the pause event: the run loop blocks on
        `self._pause.wait()` while draining, so a stop during an idle wait
        must wake it or the loop never exits (the previous double-definition
        of stop() only set _stop and could hang a paused run)."""
        self._stop.set()
        self._pause.set()

    def _run_one(self, action: PrioritizedAction) -> None:
        slot = False
        if self.global_slot is not None:
            # cross-pool ceiling: wait for a global worker slot, but
            # never past a stop request (otherwise a saturated operation
            # parks threads here while the drains already gave up).
            while not self._stop.is_set():
                if self.global_slot.acquire(blocking=False):
                    slot = True
                    break
                time.sleep(0.05)
            if not slot:
                action.status = ActionStatus.FAILED
                action.detail = "stopped waiting for a global worker slot"
                self._unlock_entity(action.entity)
                with self._lock_guard:
                    self._done_count += 1
                self._record_trail(action, False, action.detail)
                return
        try:
            ok = bool(self.worker(action, self._ctx()))
            action.status = ActionStatus.DONE if ok else ActionStatus.FAILED
        except Exception as e:
            action.status = ActionStatus.FAILED
            action.detail = str(e)[:200]
            ok = False
        finally:
            if slot:
                try:
                    self.global_slot.release()
                except Exception:
                    pass
            self._unlock_entity(action.entity)
            with self._lock_guard:
                self._done_count += 1
            self._record_trail(action, ok, action.detail)

    def _ctx(self) -> dict:
        return {"wm": self.wm, "stealth": self.stealth, "orchestrator": self}

    def _agents_active(self) -> int:
        with self._agents_guard:
            return sum(1 for t in self._agents if t.is_alive())

    # -------------------------------------------------------------- controls

    def pause(self) -> None:
        self._paused_requested = True
        self._pause.clear()

    def resume(self) -> None:
        self._paused_requested = False
        self._pause.set()

    def wait(self) -> None:
        """Block until the queue is empty and all agents finished."""
        if not self._running:
            self.run()
            return
        while self._queue or self._agents_active():
            if not self._pause.is_set():
                self.resume()
            time.sleep(0.1)
        self._stop.set()

    def stats(self) -> dict:
        with self._lock_guard:
            return {"queued": len(self._queue), "done": self._done_count,
                    "agents": self._agents_active(),
                    "campaign_entries": len(self.campaign)}
