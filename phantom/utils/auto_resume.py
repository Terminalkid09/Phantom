"""
auto_resume.py — unattended resume policy for an auto-mode run.

``auto_session.offer_resume`` asks the OPERATOR and silently skips whenever
there is no TTY, so an overnight engagement that dies stays dead until a
person relaunches it by hand. This module is the policy for the opposite
case: nobody is watching.

It answers exactly ONE question, deterministically and without ever
blocking:

    "may this process relaunch the engagement from its checkpoint?"

and it answers it so that a broken run cannot loop forever: the restart
count is PERSISTED next to the checkpoint, so the fourth crash of a run
that keeps dying is a refusal WITH A REASON instead of a silent, endless
relaunch.

Contract
--------
* never calls ``input()``, never needs a TTY, never raises — a refusal is a
  :class:`ResumeDecision` carrying an operator-readable ``reason``;
* the restart budget lives in a small JSON file (``auto_restarts.json`` by
  default) beside the checkpoint, keyed by the checkpoint's directory, so a
  fresh engagement starts from a clean budget and
  :func:`note_success` clears the current one after a clean finish;
* the schema gate reuses
  ``phantom.automation.agent.CHECKPOINT_SCHEMA``. This is deliberately
  STRICTER than ``AutonomousAgent.from_state``, which warns and resumes
  best-effort: a warning needs an operator to read it, and here there is
  none. A mismatch is refused, and the refusal says to relaunch by hand.

The caller resolves a portable ``.pm`` bundle to its checkpoint (see
``session_bundle.import_session``, which returns ``resume_path``); passing a
bundle straight in also works — the embedded checkpoint is read for the
schema gate — but the resumed path must be a real file the run can open.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

#: name of the persisted crash counter, written next to the checkpoint
_COUNTER_NAME = "auto_restarts.json"

#: default automatic relaunches before the policy refuses
DEFAULT_MAX_RESTARTS = 3


@dataclass
class ResumeDecision:
    """The verdict of :func:`plan_resume`.

    ``ok`` is the only field a caller must branch on; ``reason`` is written
    for the operator (it is shown as-is in the CLI/Electron log), and
    ``attempt`` is the restart number this decision AUTHORIZES (0 when the
    decision refuses).
    """

    ok: bool
    checkpoint: str = ""
    attempt: int = 0
    reason: str = ""


# ── counter (persisted crash budget) ───────────────────────────────────────

def counter_path_for(checkpoint: str, state_path: str = "") -> str:
    """Where the crash counter for ``checkpoint`` lives.

    Kept beside the checkpoint (or beside ``state_path`` when the caller
    knows where this run writes its own state) so two engagements in two
    report directories never share a budget.
    """
    base = state_path or checkpoint
    directory = os.path.dirname(os.path.abspath(base)) if base else ""
    return os.path.join(directory or ".", _COUNTER_NAME)


def _read_counter(path: str) -> int:
    """Restarts used so far. Never raises: an unreadable counter is 0."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return 0
    try:
        return max(0, int((data or {}).get("restarts", 0)))
    except (TypeError, ValueError, AttributeError):
        return 0


def _write_counter(path: str, value: int) -> None:
    """Persist the counter. Best effort: a read-only disk must not kill the
    run, it only loses the loop guard for the next process."""
    try:
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"restarts": max(0, int(value))}, fh, indent=2)
    except (OSError, ValueError, TypeError):
        pass


def note_success(counter_path: str) -> None:
    """A run finished cleanly: clear its crash budget for the next one."""
    if not counter_path:
        return
    _write_counter(counter_path, 0)


# ── checkpoint reading + schema gate ───────────────────────────────────────

def _expected_schema() -> Tuple[int, str]:
    """``(schema, why_not)`` — the agent's checkpoint schema, or -1 when the
    constant cannot be imported (the gate then degrades to a noted
    best-effort instead of blocking a legitimate resume)."""
    try:
        from phantom.automation.agent import CHECKPOINT_SCHEMA
        return int(CHECKPOINT_SCHEMA), ""
    except Exception as exc:                      # pragma: no cover - defensive
        return -1, f"schema gate unavailable ({exc.__class__.__name__})"


def _read_from_bundle(path: str, first_exc: Exception
                      ) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    """Fall back to the checkpoint embedded in a portable ``.pm`` bundle."""
    try:
        from phantom.utils.session_bundle import read_bundle
        data = read_bundle(path)
    except Exception:
        return (False, None,
                f"checkpoint unreadable: {path} "
                f"({first_exc.__class__.__name__})")
    embedded = data.get("checkpoint") if isinstance(data, dict) else None
    if not isinstance(embedded, dict) or not embedded:
        return False, None, f"bundle carries no resumable checkpoint: {path}"
    return True, embedded, ""


def _read_checkpoint(path: str) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    """``(ok, checkpoint_dict, reason)`` — a plain JSON checkpoint, or the
    checkpoint embedded in a ``.pm`` bundle. Never raises."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        return _read_from_bundle(path, exc)
    if not isinstance(data, dict):
        return False, None, f"checkpoint is not a JSON object: {path}"
    return True, data, ""


# ── the policy ─────────────────────────────────────────────────────────────

def plan_resume(latest_checkpoint: str,
                state_path: str = "",
                max_restarts: int = DEFAULT_MAX_RESTARTS,
                counter_path: str = "") -> ResumeDecision:
    """Decide whether an unattended process may resume from a checkpoint.

    Refuses — always with a reason, never with an exception — when:

    * no checkpoint was named, or the file does not exist;
    * the checkpoint cannot be read (not JSON, not a ``.pm`` bundle, or a
      bundle with no embedded checkpoint);
    * the checkpoint's ``schema`` does not match the running build;
    * the persisted restart budget is already spent.

    ``max_restarts`` is the number of AUTOMATIC relaunches allowed for this
    checkpoint's directory; ``0`` refuses every automatic resume (the
    operator keeps ``--resume``, which bypasses this policy on purpose).
    """
    checkpoint = (latest_checkpoint or "").strip()
    if not checkpoint:
        return ResumeDecision(False, "", 0, "no checkpoint to resume from")
    if not os.path.isfile(checkpoint):
        return ResumeDecision(False, checkpoint, 0,
                              f"checkpoint not found: {checkpoint}")

    ok, data, reason = _read_checkpoint(checkpoint)
    if not ok:
        return ResumeDecision(False, checkpoint, 0, reason)

    expected, why_not = _expected_schema()
    actual = (data or {}).get("schema")
    if expected >= 0 and actual != expected:
        return ResumeDecision(
            False, checkpoint, 0,
            f"checkpoint schema {actual!r} != {expected}: refusing an "
            f"unattended resume — relaunch by hand to accept it")
    note = f" ({why_not}: resumed best-effort)" if expected < 0 else ""

    try:
        limit = max(0, int(max_restarts))
    except (TypeError, ValueError):
        limit = DEFAULT_MAX_RESTARTS

    counter_file = (counter_path
                    or counter_path_for(checkpoint, state_path))
    used = _read_counter(counter_file)
    if used >= limit:
        return ResumeDecision(
            False, checkpoint, used,
            f"restart budget exhausted: {used}/{limit} automatic resumes "
            f"already used for this engagement — relaunch by hand")

    attempt = used + 1
    _write_counter(counter_file, attempt)
    return ResumeDecision(True, checkpoint, attempt,
                          f"automatic resume {attempt}/{limit}{note}")
