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
* a **crash** is an exception or a non-zero ``SystemExit``. Only that
  relaunches, and only up to the persisted budget.
* a **normal return** normally ends the loop — but when the caller passes
  ``outcome_of`` (a reader of the run's own result) AND that outcome is a
  terminal NOT-reached token, the run ended cleanly *without getting
  anywhere*: that is the ``completed`` ≠ goal-reached gap, and it is just as
  unattended as a crash (the process is gone and nobody is watching). It
  relaunches from the same checkpoint, through the SAME policy and budget,
  and for the same reason: an engagement that stopped talking must come
  back. The budget is NOT reset on such a relaunch, so this cannot loop
  forever. A reached goal, an `awaiting_operator`/`cancelled` outcome, an
  unknown token and a missing ``outcome_of`` all end the loop exactly as
  before.
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
    """``(crashed, error, result)`` for ONE attempt.

    ``KeyboardInterrupt`` is re-raised first, so an operator stop can never be
    turned into a relaunch by the crash handling below. ``result`` is what
    ``run`` returned (``None`` after a crash or a ``SystemExit``): the caller's
    ``outcome_of`` reads the engagement outcome from it.
    """
    try:
        result = run(checkpoint)
    except KeyboardInterrupt:
        raise
    except SystemExit as exc:                      # BaseException, not Exception
        code = getattr(exc, "code", None)
        if code in (None, 0):
            return False, "", None
        return True, f"SystemExit({code!r})", None
    except Exception as exc:                       # a real crash
        return True, f"{exc.__class__.__name__}: {exc}", None
    return False, "", result


#: Terminal tokens that mean "the run stopped and did NOT reach the goal".
#: Kept as a local frozenset (not an import) because this module must stay
#: usable when `phantom.automation` cannot be imported at all — the reader is
#: injected, and an unknown token simply ends the loop.
_UNREACHED_OUTCOMES = frozenset({
    "blocked_preflight", "partial", "completed_without_goal",
    "failed_infrastructure", "failed_policy", "failed_capability",
})

#: Tokens that deliberately END the loop: the operator is the next actor.
_OPERATOR_OUTCOMES = frozenset({"awaiting_operator", "cancelled"})


def _outcome_of(result: Any) -> str:
    """The engagement outcome a run reported, or ``""`` when unknown.

    Total by construction: this reads a dict a different layer produced, and
    an unexpected shape must end the loop, not raise inside it.
    """
    try:
        if isinstance(result, dict):
            return str(result.get("outcome") or "").strip()
    except Exception:
        return ""
    return ""


def supervise(run: Callable[[str], Any], *, resume: str = "",
              max_restarts: int = DEFAULT_MAX_RESTARTS,
              counter_path: str = "",
              on_event: Optional[Callable[[str, dict], None]] = None,
              outcome_of: Optional[Callable[[Any], str]] = None) -> dict:
    """Run ``run`` and relaunch it from its checkpoint after a CRASH — or
    after a CLEAN run that never reached its goal.

    ``run(checkpoint_path)`` is the injected launch callable: it receives
    ``resume`` on the first attempt (``""`` = a fresh engagement) and the
    resolved checkpoint path afterwards. Its return value is handed to
    ``outcome_of`` when that is supplied. Returns
    ``{"attempts", "stopped_reason", "last_error", "outcome"}``.

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
    outcome = ""
    stopped_reason = "completed"

    def _read_outcome(value: Any) -> str:
        """The outcome the caller can read from a run's return value.

        A broken/unexpected reader ends the loop (it must not raise inside
        it), and so does an outcome we do not recognise: relaunching on a
        token nobody defined is how a supervisor becomes a loop.
        """
        if outcome_of is None:
            return ""
        try:
            token = str(outcome_of(value) or "").strip()
        except Exception:
            return ""
        return token if token in (_UNREACHED_OUTCOMES | _OPERATOR_OUTCOMES
                                  | {"completed_goal"}) else ""

    while True:
        attempts += 1
        started = time.time()
        _emit(on_event, "launch", {"attempt": attempts,
                                   "checkpoint": checkpoint})
        crashed, error, result = _run_once(run, checkpoint)

        unfinished = False
        if not crashed:
            outcome = _read_outcome(result)
            unfinished = outcome in _UNREACHED_OUTCOMES
            if not unfinished:
                # finished (goal reached, operator stop, or the caller gave
                # us nothing to judge with): the caller owns the verdict, and
                # the crash budget resets for the NEXT engagement.
                note_success(counter or (counter_path_for(checkpoint)
                                         if checkpoint else ""))
                break
            # A clean run that reached NOTHING is unattended work in exactly
            # the same way a crash is: the process is gone, the engagement is
            # not finished, and nobody is watching. Fall through to the same
            # policy decision — which is what keeps it bounded.
        else:
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
            if unfinished:
                stopped_reason = f"unfinished ({outcome}): {stopped_reason}"
            _emit(on_event, "stopped", {"reason": stopped_reason,
                                        "attempts": attempts,
                                        "outcome": outcome,
                                        "error": last_error})
            break

        _emit(on_event, "relaunch", {"attempt": attempts + 1,
                                     "reason": (f"unfinished: {outcome}"
                                                if unfinished
                                                else decision.reason),
                                     "outcome": outcome,
                                     "checkpoint": decision.checkpoint})
        checkpoint = decision.checkpoint

    return {"attempts": attempts, "stopped_reason": stopped_reason,
            "last_error": last_error, "outcome": outcome}
