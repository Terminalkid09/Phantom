"""Auto-mode job registry and event translation.

Extracted from ``phantom.api.server`` so the HTTP composition root is not also
the owner of the run lifecycle.  The names are re-exported by the server for
backwards compatibility with the API contract tests and with callers that
import ``AutoJob`` from there.
"""

from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime
from typing import Optional

# ── Auto-Mode (job manager: per-run state, cooperative stop) ──────────────
# The old module globals (_auto_stream/_auto_current_step/_auto_done) made
# every run share ONE buffer: a second run reset the first one's stream
# mid-flight and "stop" only flipped a bool the agent never read. Each run
# is now a job with its OWN stream buffer and a stop Event the agent checks
# between planner iterations (cooperative: a scan already in flight
# finishes, the loop exits at the next boundary).

_auto_lock = threading.Lock()   # guards every job's stream buffer

# F-27: the run lifecycle the BACKEND can actually assert. A state is listed
# here only when something in Phantom distinguishes it — a label the engine
# cannot tell apart would be the UI presenting a guess as a fact, which is the
# exact failure this set exists to remove (`run_state` was the panel's own
# optimistic label and nothing ever corrected it).
#
#   planning  : the job exists, its thread has not reported an action yet
#   running   : the engine reported real work (an action went out)
#   stopping  : a cooperative stop was requested and not yet honoured
#   cancelled : the loop exited BECAUSE of the stop request
#   completed : the loop exited on its own
#   failed    : the loop raised
#
# Deliberately absent, because nothing in the backend produces them:
#   `paused`      — there is no pause control on a run (only stop);
#   `timed_out`   — a run has no wall-clock deadline (the swarm budget bounds
#                   STEPS, not time; a slow target is not a failed run);
#   `partial`     — the engine does not report per-target outcomes separately
#                   from a normal completion, and inventing the split here
#                   would be the same lie in a new place.
AUTOMODE_STATES = ("planning", "running", "stopping", "cancelled",
                   "completed", "failed")

# The answer for "no job": a SEPARATE token (never a job state), so a finished
# job answering `completed` is never confused with an absent one.
AUTOMODE_IDLE = "idle"

AUTOMODE_TRANSITIONS = {
    "planning": frozenset({"running", "stopping", "cancelled", "completed",
                           "failed"}),
    "running": frozenset({"stopping", "cancelled", "completed", "failed"}),
    "stopping": frozenset({"cancelled", "completed", "failed"}),
    "cancelled": frozenset(),
    "completed": frozenset(),
    "failed": frozenset(),
}

# The event kinds that mean "the engine is executing". Both engines have one:
# the agent emits `run` right before a capability goes out, the swarm emits
# `task_target` when a worker starts a (task, target) slice. Everything else
# (note, blocked, found, failed...) is commentary ABOUT a run, so a buffered
# event cannot promote a planning job into running on its own.
_EXECUTION_KINDS = frozenset({"run", "task_target"})

# Bounded tail of transitions. The history is operator-facing evidence
# ("why does it say cancelled?"), not a log: a long run must not grow the
# job's memory without limit.
_STATE_HISTORY_LIMIT = 40


class AutoJob:
    """One auto-mode run: dedicated stream, stop signal, lifecycle."""

    def __init__(self, job_id: str, targets: list, mode: str,
                 profile: str, goal: str) -> None:
        self.id = job_id
        self.verbose = False
        # P0: the SECOND axis. `state` is the job lifecycle; `outcome` is
        # whether the ENGAGEMENT reached anything. They are independent on
        # purpose: a cancelled job can have a partial outcome, a completed
        # job can have reached nothing.
        self.outcome = "not_started"
        self.outcome_label = "not started"
        self.targets_outcome: dict = {}
        self.targets = list(targets)
        self.mode = mode
        self.profile = profile
        self.goal = goal
        self.stream: list[dict] = []
        self.current_step = -1
        self.done = False
        # F-27: the lifecycle. `planning` is the honest state at THIS point
        # (the thread exists, nothing has executed), and every later move goes
        # through `set_state`, which refuses an illegal transition instead of
        # writing a state the run never reached.
        self.state = "planning"
        self.state_history: list[dict] = [
            {"state": "planning", "at": time.time(),
             "detail": "job accepted"},
        ]
        self.end_reason = ""
        self._state_lock = threading.Lock()
        # A handoff is a DECISION the operator makes, not a notification
        # (see CHANGELOG.md, automode handoff): `ready` until accepted or
        # dismissed.
        self.handoff_state = "none"
        # Beacons THIS RUN established. The stream flattens events into log
        # lines and drops the event kind, so the UI had no way to tell "this
        # run produced a beacon" from "a beacon was already registered" — it
        # could only diff the whole beacon list and guess. Recorded here, at
        # the one place that knows, and served alongside the stream.
        self.handoffs: list[dict] = []
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.started_at = time.time()
        self.error: Optional[str] = None
        # dynamic extra steps (deep goals): label -> index, allocated
        # from 8 up in first-appearance order (the UI appends them).
        self.extra_steps: dict = {}
        # LLM on-demand approval (Fase 6): denied by default; the operator
        # pre-approves with the run's llm flag or flips it live via
        # POST /api/automode/llm (Electron checkbox). The legacy agent
        # path only honors session pre-approval; mid-run flips take full
        # effect on the swarm path (Fase 7 migration target).
        from phantom.automation.swarm.llm import LLMApproval
        self.llm_approval = LLMApproval()

    def callback(self, kind: str, data: dict) -> None:
        with _auto_lock:
            self.stream.append({"kind": kind, "data": data})
            if kind == "handoff":
                beacon_id = str((data or {}).get("beacon_id") or "").strip()
                if beacon_id and not any(
                        h.get("beacon_id") == beacon_id for h in self.handoffs):
                    self.handoffs.append({
                        "beacon_id": beacon_id,
                        "kind": "beacon_established",
                        "target": str((data or {}).get("target")
                                       or (self.targets[0] if self.targets else "")
                                       or ""),
                        "created_at": time.time(),
                        "status": "ready",
                    })
                    # A new beacon re-opens a handoff the operator dismissed
                    # earlier: it is new information, not the old card.
                    self.handoff_state = "ready"
        # Outside `_auto_lock`: state has its own lock, and taking both in one
        # order here is what keeps a callback from deadlocking the run thread.
        if kind in _EXECUTION_KINDS:
            self.set_state("running", f"{kind} event")

    def set_outcome(self, envelope: dict) -> bool:
        """Record the engagement outcome a run produced.

        Refuses an unknown token or an empty envelope rather than storing
        something the UI cannot render: the whole point of this field is
        that it never claims more than the run proved. The label is derived
        here so every producer (CLI orchestrator, API thread, a future
        caller) reports the same words for the same token.
        """
        if not isinstance(envelope, dict):
            return False
        token = str(envelope.get("outcome") or "").strip()
        if not token:
            return False
        try:
            from phantom.automation.engagement_outcome import (
                OUTCOMES, outcome_label)
            if token not in OUTCOMES:
                return False
            label = outcome_label(token)
        except Exception:
            label = token
        with self._state_lock:
            self.outcome = token
            self.outcome_label = label
            tgt = envelope.get("targets")
            self.targets_outcome = dict(tgt) if isinstance(tgt, dict) else {}
        return True

    def handoff_records(self) -> list[dict]:
        """Handoffs so far, oldest first. A snapshot, so a UI poll cannot
        mutate the job's state by iterating it."""
        with _auto_lock:
            return [dict(h) for h in self.handoffs]

    def drain(self) -> list[dict]:
        with _auto_lock:
            events = self.stream[:]
            self.stream.clear()
        return events

    # ── lifecycle (F-27) ────────────────────────────────────────────────

    def set_state(self, state: str, detail: str = "") -> bool:
        """Move to `state` when that transition is legal. Never raises.

        This runs on the RUN's own thread (inside the engine callback), where
        an exception would kill the run it is only describing — and a state
        machine is not worth a lost engagement. An illegal or repeated
        transition is dropped silently-but-visibly: the history keeps what
        really happened.
        """
        if state not in AUTOMODE_STATES:
            return False
        with self._state_lock:
            if state == self.state or state not in AUTOMODE_TRANSITIONS[self.state]:
                return False
            self.state = state
            self.state_history.append({
                "state": state, "at": time.time(),
                "detail": str(detail or "")[:160],
            })
            while len(self.state_history) > _STATE_HISTORY_LIMIT:
                self.state_history.pop(0)
            return True

    def request_stop(self) -> bool:
        """Request a cooperative stop and record that we asked.

        `stopping` is the window the operator needs to see: the request has
        been made and the engine has not halted yet (a scan already in flight
        finishes first). Returns True when this call is what asked.
        """
        asked = self.stop_event.is_set()
        self.stop_event.set()
        if not self.done:
            self.set_state("stopping", "stop requested by operator")
        return not asked

    def finish(self, reason: str = "") -> str:
        """Terminal transition. The CAUSE decides the terminal state, so a
        cancelled run can never be read as a completed one (or the reverse)."""
        self.done = True
        self.end_reason = str(reason or "")
        if self.error:
            final = "failed"
        elif self.stop_event.is_set():
            final = "cancelled"
        else:
            final = "completed"
        self.set_state(final, self.end_reason or "run ended")
        return final

    def resolve_handoff(self, beacon_id: str, decision: str) -> bool:
        """Accept or dismiss ONE handoff. False when it is not this job's.

        Refusing an unknown beacon is the point: the renderer must not be able
        to talk the backend into "accepted" for a beacon the run never
        produced (a button that reports success for nothing).
        """
        if decision not in ("accept", "dismiss"):
            return False
        status = "accepted" if decision == "accept" else "dismissed"
        with _auto_lock:
            matched = [h for h in self.handoffs
                       if h.get("beacon_id") == beacon_id]
            if not matched:
                return False
            for h in matched:
                h["status"] = status
                h["resolved_at"] = time.time()
            self.handoff_state = status
        return True

    def snapshot(self) -> dict:
        """The job as the operator (and the renderer) needs to see it.

        ONE shape for every state, idle included (see `_IDLE_STATUS`), so the
        renderer narrows a single payload instead of a union of "job" and
        "no job" answers.
        """
        approval = getattr(self, "llm_approval", None)
        with _auto_lock:
            handoffs = [dict(h) for h in self.handoffs]
        with self._state_lock:
            history = [dict(h) for h in self.state_history]
            state = self.state
        return {
            "job_id": self.id,
            "state": state,
            "state_history": history,
            "running": not self.done,
            "done": self.done,
            "end_reason": self.end_reason,
            "error": self.error or "",
            # P0 engagement outcome (what the run ACHIEVED), alongside the
            # lifecycle state (what the process is DOING).
            "outcome": self.outcome,
            "outcome_label": self.outcome_label,
            "targets_outcome": dict(self.targets_outcome),
            "current_step": self.current_step,
            "started_at": self.started_at,
            "elapsed": max(0.0, time.time() - self.started_at),
            "targets": list(self.targets),
            "mode": self.mode,
            "profile": self.profile,
            "goal": self.goal,
            "llm": approval.state if approval is not None else "denied",
            "llm_pending": len(approval.pending_requests())
            if approval is not None else 0,
            "handoffs": handoffs,
            "handoff_state": self.handoff_state,
        }


class AutoJobManager:
    """Registry of auto-mode runs. One ACTIVE run at a time (a new run
    replaces it), finished runs are kept briefly for status queries and
    pruned after an hour so the process never accumulates state."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[str, AutoJob] = {}
        self._active_id: Optional[str] = None

    def create(self, targets: list, mode: str, profile: str,
               goal: str, verbose: bool = False) -> AutoJob:
        with self._lock:
            job = AutoJob(f"job_{uuid.uuid4().hex[:8]}", targets, mode,
                          profile, goal)
            job.verbose = verbose
            self._jobs[job.id] = job
            self._active_id = job.id
            self._prune_locked()
            return job

    def active(self) -> Optional[AutoJob]:
        with self._lock:
            if self._active_id:
                return self._jobs.get(self._active_id)
            return None

    def get(self, job_id: str) -> Optional[AutoJob]:
        """One job by id (F-25 `getJob`): the ACTIVE one by default, a
        finished one by id while it is still retained."""
        with self._lock:
            return self._jobs.get(job_id) if job_id else None

    def stop_active(self) -> Optional[AutoJob]:
        """Request a cooperative stop: set the Event (the agent's drive loop
        observes it at the next iteration boundary and halts) and move the job
        to `stopping` so the UI can show the request without pretending the
        run is already over."""
        with self._lock:
            job = self._jobs.get(self._active_id) if self._active_id else None
            if job and not job.done:
                job.request_stop()
                return job
            return None

    def _prune_locked(self) -> None:
        now = time.time()
        for jid in [j for j, jb in self._jobs.items()
                    if jb.done and now - jb.started_at > 3600]:
            self._jobs.pop(jid, None)


auto_jobs = AutoJobManager()


# capability substring -> fixed step index (the 8 steps the UI shows).
_BASE_STEP_MAP = {
    "scan": 0, "osint": 1, "os_detect": 2,
    "web_recon": 3, "web_probe": 3, "http_probe": 3,
    "cve_correlate": 4, "service_exploit": 4, "exploit": 4,
    "creds": 5, "ssh_login": 5, "web_creds": 5, "breach_check": 5,
    "beacon_deploy": 6, "beacon_via_rce": 6, "inject_beacon": 6,
    "persist": 7, "persistence_install": 7,
}

# capability substring -> dynamic step label (deep goals: lateral, AD,
# crack, hunt, social...). Allocated from index 8 up in first-appearance
# order; the UI appends them instead of freezing on PERSIST.
_EXTRA_STEP_LABELS = {
    "lateral": "LATERAL", "pivot": "LATERAL",
    "crack": "CRACK", "hash_crack": "CRACK",
    "ad_enum": "AD", "kerberoast": "AD", "as_rep": "AD",
    "dc_sync": "AD", "dcsync": "AD",
    "hunt": "HUNT", "differential": "HUNT", "idor": "HUNT",
    "cleanup": "CLEANUP", "ransom_sim": "IMPACT",
    "social": "SOCIAL", "phish": "SOCIAL", "persona": "SOCIAL",
    "trojan": "DELIVERY", "cloud": "CLOUD", "mobile": "MOBILE",
}


def _match_step(cap: str, job) -> tuple:
    """(index, name-or-None) for a capability: fixed map first, then the
    dynamic labels (allocated per job). (None, None) when unknown."""
    for key, idx in _BASE_STEP_MAP.items():
        if key in cap:
            return idx, None
    for key, label in _EXTRA_STEP_LABELS.items():
        if key in cap:
            extra = getattr(job, "extra_steps", None)
            if extra is None:
                extra = job.extra_steps = {}
            if label not in extra:
                extra[label] = 8 + len(extra)
            return extra[label], label
    return None, None


def _step_update(idx: int, status: str, detail: str,
                 name=None) -> dict:
    upd = {"step": idx, "status": status, "detail": detail}
    if name:
        upd["name"] = name
    return upd


def _automode_log_entries(job, events) -> tuple:
    """Translate drained auto-mode events into UI entries.

    Pure on purpose (no request, no web types) so the translation — the
    exact layer that used to drop half the engine's signal — is testable
    without an HTTP round trip.

    Returns ``(step_updates, logs)``. Wording and level come from the
    shared contract (phantom.core.stream_contract), the same one the CLI
    prints, so the two surfaces cannot disagree. Events are REDACTED
    before rendering: the UI stream must never carry a raw credential.
    """
    from phantom.core.stream_contract import render_event
    from phantom.utils.redact import redact, redact_text

    step_updates = []
    logs = []

    for ev in events:
        kind = ev.get("kind", "")
        # REDACT BEFORE RENDERING: the UI stream, the persisted session
        # mirror and the audit trail must never carry a raw password/OTP/
        # token. The WorldModel keeps the real values for the kill chain;
        # redacting here also covers the free-text reason (a planner reason
        # can quote the command, and the command can carry `sshpass -p …`).
        data = redact(ev.get("data") or {})
        cap = (data.get("capability") or "").lower()

        # the UI checklist is a SEPARATE, kind-specific contract: it maps an
        # event onto a step, independent of the wording
        if kind in ("run", "found", "failed"):
            idx, name = _match_step(cap, job)
            if idx is not None:
                if kind == "run":
                    status, detail = "running", cap[:40]
                elif kind == "found":
                    status = "done"
                    detail = ", ".join((data.get("findings") or [])[:3])
                else:
                    status = "failed"
                    detail = str(data.get("reason") or data.get("output")
                                 or "execution failed")[:60]
                step_updates.append(_step_update(idx, status, detail, name))
                if kind != "failed":
                    job.current_step = idx
        elif kind == "beacon_up":
            step_updates.append({"step": 6, "status": "done",
                                 "detail": data.get("beacon_id", "")})
            job.current_step = 6

        # ONE renderer, shared with the CLI: this translation used to know
        # 17 of the ~40 kinds and silently dropped the rest (stall, error,
        # success, gate, shared, llm …), which is why the UI showed findings
        # but no reasoning.
        rendered = render_event(kind, data, verbose=bool(
            getattr(job, "verbose", False)))
        if rendered is None:
            continue
        fields = dict(rendered.fields)
        for key in ("command", "reason"):
            if fields.get(key):
                fields[key] = redact_text(fields[key])
        logs.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "text": rendered.head,
            "level": rendered.level,
            **fields,
        })

    return step_updates, logs


def _preapprove_llm(job, llm: bool) -> None:
    """Pre-approve LLM use for the session when the run asked for it:
    same meaning as CLI --llm (the advisor may consult from the start,
    with committed context instead of hallucinating from zero)."""
    if llm and getattr(job, "llm_approval", None) is not None:
        job.llm_approval.approve_session()
