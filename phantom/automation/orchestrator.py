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

    def __lt__(self, other):
        return (-self.priority, self.seq) < (-other.priority, other.seq)


class Orchestrator:
    """Dispatches prioritized actions to an elastic pool of agent threads."""

    def __init__(self, wm: WorldModel, stealth: StealthEngine,
                 worker: Callable, max_agents: int = 10,
                 min_agents: int = 1) -> None:
        """
        worker(action: PrioritizedAction, ctx: dict) -> bool
        ctx carries the shared WorldModel, registry, planner, etc.
        """
        self.wm = wm
        self.stealth = stealth
        self.worker = worker
        self.max_agents = max_agents
        self.min_agents = min_agents
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
               slot_values: Optional[Dict[str, str]] = None) -> PrioritizedAction:
        action = PrioritizedAction(
            priority=priority, seq=self._seq, capability_id=capability_id,
            entity=entity, slot_values=slot_values or {},
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
            while self._queue:
                a = heapq.heappop(self._queue)
                if a.status == ActionStatus.QUEUED and self._entity_free(a.entity):
                    action = a
                    break
                if a.status != ActionStatus.QUEUED:
                    continue
                heapq.heappush(self._queue, a)
                break
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
        timeout only applies when the queue is empty but an agent is still
        running; actions already queued are always dispatched first.
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
                    if self._agents_active() == 0 and not self._queue:
                        break
                    # queue empty but an agent is still running: bounded wait
                    if idle_since is None:
                        idle_since = time.time()
                    elif time.time() - idle_since > drain_timeout:
                        # an agent is stuck (e.g. a capability that never
                        # returns). Stop waiting and let the caller proceed.
                        break
                    time.sleep(0.1)
                    continue
                idle_since = None
                t = threading.Thread(target=self._run_one, args=(action,), daemon=True)
                with self._agents_guard:
                    self._agents.append(t)
                t.start()
        finally:
            self._running = False

    def stop(self) -> None:
        """Signal the run-loop to stop draining (does not kill agents)."""
        self._stop.set()
        self._pause.set()

    def _run_one(self, action: PrioritizedAction) -> None:
        try:
            ok = bool(self.worker(action, self._ctx()))
            action.status = ActionStatus.DONE if ok else ActionStatus.FAILED
        except Exception as e:
            action.status = ActionStatus.FAILED
            action.detail = str(e)[:200]
            ok = False
        finally:
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

    def stop(self) -> None:
        self._stop.set()

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
