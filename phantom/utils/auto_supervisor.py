"""
auto_supervisor.py — mid-run crash supervision for an auto-mode engagement.

``--resume-latest`` covers ONE case: a process that is STARTED again (by the
operator, by a service manager, by a reboot) resumes the newest engagement.
It does not cover the case this module exists for — a run that is killed at
hour three of a multi-day operation while nobody is watching. Without a
supervisor that engagement stays dead until a human relaunches it, which is
exactly the interruption the checkpoint was written for.

The split of responsibility is deliberate and strict:

* this module decides WHEN to relaunch (a crash, and only a crash);
* :mod:`phantom.utils.auto_resume` decides WHETHER a relaunch is allowed
  (the persisted restart budget and the checkpoint schema gate).

No accounting is duplicated here: the budget, its JSON counter and the
schema refusal all come from ``auto_resume.plan_resume``, so an engagement
cannot gain extra restarts by being supervised.

Contract
--------
* ``run`` is INJECTED — ``run(checkpoint_path)`` returns normally, raises, or
  exits through ``SystemExit``. This module owns no CLI and no engine.
* a **normal return means "the run finished"**: the loop stops. It never
  interprets a completed-but-unsuccessful engagement as a crash (the caller
  reads the summary and the report), so a run that legitimately halts cannot
  be relaunched forever.
* a **crash** is an exception or a non-zero ``SystemExit``. Only that
  relaunches, and only up to the persisted budget.
* ``KeyboardInterrupt`` is an operator STOP: it propagates out undeclared and
  no relaunch happens.
* nothing here calls ``input()`` or needs a TTY, and a policy refusal is
  reported as a ``reason``, never as an exception.
"""

from __future__ import annotations

import os
import time
from typing import Any, Callable, Dict, Optional

from phantom.utils.auto_resume import (
    DEFAULT_MAX_RESTARTS,
    counter_path_for,
    note_success,
    plan_resume,
)

__all__ = ["supervise", "resolve_checkpoint"]


# ── checkpoint discovery (for a run that was never given one) ──────────────

def resolve_checkpoint(since: float = 0.0) -> str:
    """The newest auto-mode checkpoint written at/after ``since``, or "".

    A first launch may not know where the agent will write its checkpoint
    (the engine picks ``data/sessions/auto_*/checkpoint.json``). When that
    run then crashes, the supervisor has to find it — but it must NOT adopt
    an older engagement's checkpoint, or it would resume somebody else's
    operation with this one's scope. Hence the mtime floor: only a file
    touched while THIS run was alive counts.

    Best effort by construction: a missing ``session_bundle`` or an
    unreadable directory degrades to "", which the policy then refuses with
    its own reason.
    """
    try:
        from phantom.utils.session_bundle import latest_checkpoint
        path = latest_checkpoint() or ""
    except Exception:
        return ""
    if not path or not os.path.isfile(path):
        return ""
    try:
        # one second of tolerance: a coarse-timestamp filesystem must not
        # make a checkpoint this very run wrote look like an older one.
        if since and os.path.getmtime(path) < since - 1.0:
            return ""
    except OSError:
        return ""
    return path


# ── the supervisor ─────────────────────────────────────────────────────────

def _emit(on_event: Optional[Callable[[str, dict], None]],
          kind: str, payload: Dict[str, Any]) -> None:
    """Report one lifecycle event. A broken callback never breaks the loop."""
    if on_event is None:
        return
    try:
        on_event(kind, payload)
    except Exception:
        pass


def _run_once(run: Callable[[str], Any], checkpoint: str):
    """``(crashed, error)`` for ONE attempt.

    ``KeyboardInterrupt`` is re-raised first, so an operator stop can never be
    turned into a relaunch by the crash handling below.
    """
    try:
        run(checkpoint)
    except KeyboardInterrupt:
        raise
    except SystemExit as exc:                      # BaseException, not Exception
        code = getattr(exc, "code", None)
        if code in (None, 0):
            return False, ""
        return True, f"SystemExit({code!r})"
    except Exception as exc:                       # a real crash
        return True, f"{exc.__class__.__name__}: {exc}"
    return False, ""


def supervise(run: Callable[[str], Any], *, resume: str = "",
              max_restarts: int = DEFAULT_MAX_RESTARTS,
              counter_path: str = "",
              on_event: Optional[Callable[[str, dict], None]] = None) -> dict:
    """Run ``run`` and relaunch it from its checkpoint after a CRASH.

    ``run(checkpoint_path)`` is the injected launch callable: it receives
    ``resume`` on the first attempt (``""`` = a fresh engagement) and the
    resolved checkpoint path afterwards. Returns
    ``{"attempts", "stopped_reason", "last_error"}``.

    ``attempts`` counts LAUNCHES, so a run that crashed once and then
    finished reports ``2``. ``stopped_reason`` is ``"completed"`` for a
    normal finish, or the policy's own operator-readable reason when a
    relaunch was refused (budget spent, checkpoint unreadable, schema
    mismatch, no checkpoint at all).
    """
    try:
        limit = max(0, int(max_restarts))
    except (TypeError, ValueError):
        limit = DEFAULT_MAX_RESTARTS

    checkpoint = (resume or "").strip()
    counter = (counter_path or "").strip()
    attempts = 0
    last_error = ""
    stopped_reason = "completed"

    while True:
        attempts += 1
        started = time.time()
        _emit(on_event, "launch", {"attempt": attempts,
                                   "checkpoint": checkpoint})
        crashed, error = _run_once(run, checkpoint)

        if not crashed:
            # finished (however successfully): the caller owns the verdict,
            # and the crash budget resets for the NEXT engagement.
            note_success(counter or (counter_path_for(checkpoint)
                                     if checkpoint else ""))
            break

        last_error = error
        # where to relaunch from: the checkpoint we were given, else the one
        # THIS attempt wrote (never an older engagement's).
        target = checkpoint or resolve_checkpoint(since=started)
        if not counter:
            counter = counter_path_for(target) if target else ""
        decision = plan_resume(target, max_restarts=limit,
                               counter_path=counter)
        if not decision.ok:
            stopped_reason = decision.reason or "resume refused"
            _emit(on_event, "stopped", {"reason": stopped_reason,
                                        "attempts": attempts,
                                        "error": last_error})
            break

        _emit(on_event, "relaunch", {"attempt": attempts + 1,
                                     "reason": decision.reason,
                                     "checkpoint": decision.checkpoint})
        checkpoint = decision.checkpoint

    return {"attempts": attempts, "stopped_reason": stopped_reason,
            "last_error": last_error}
