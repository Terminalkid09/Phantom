"""checkpoint.py — the swarm checkpoint: surviving a process boundary.

The agent path has written a checkpoint after every wave for a long time
(``automode`` -> ``--resume``). The SWARM path had nothing: ``run_swarm``
built a fresh Board + tasks on every call, and ``--resume`` was ignored on
that path. For an operation meant to span days that is fatal — a machine
that reboots at 03:00 spends the next morning rediscovering facts the board
already held.

This module closes that: :func:`save_swarm_checkpoint` serializes the board
and the DAG STATE (not just the facts), :func:`load_swarm_checkpoint` brings
them back, and a checkpoint written by another schema is REFUSED LOUDLY with
:class:`CheckpointSchemaError` — never interpreted — mirroring the discipline
the agent path already applies to its own state file.

What is restored, and what deliberately is not
----------------------------------------------
Restored:

* the blackboard — every committed ``WorldModel`` (findings *and* the belief
  revisions and hypotheses that survive ``WorldModel.from_dict``);
* the per-target budget ledger (limits + what was already spent), so a
  resumed target keeps exactly the allowance it had left;
* the idempotency registry's COMPLETED keys, so a ``(task, target)`` unit
  that already succeeded is never re-run and never re-spends budget;
* the DAG state of every task — ``status``, ``attempts``, ``profile``,
  ``done_targets``, ``helper_used``, ``failure_kind``, ``note`` — plus the
  sink's ``tried`` map (which capability a sibling already burned) and the
  failure/case records the report consumes.

NOT restored, on purpose:

* LIVE LEASES. A lease is ownership of an IN-FLIGHT run and its TTL is
  measured on ``time.monotonic()``, which is per-process (per boot). A lease
  serialized by a previous process can therefore never be trusted to be
  either live or expired: restoring one could wedge a task behind a dead
  owner, or silently reclaim a slot. Nothing is in flight after a crash, so
  the resumed board starts with a free table; the counters stay for the audit.
* the ``sink`` thread lock and the live task object list (execution-only).
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Dict, Optional

# Bump when a field changes MEANING (not when one is added): a checkpoint
# from a different meaning is refused instead of misread.
SWARM_CHECKPOINT_SCHEMA = 1

# One writer at a time: several worker threads can commit concurrently and
# each one attempts a checkpoint (see swarm/__init__._checkpoint).
_WRITE_LOCK = threading.Lock()

# Key separator for the sink's `tried` map, whose keys are (task, target)
# TUPLES and would otherwise not survive JSON.
_KEY_SEP = "\x1f"


class CheckpointSchemaError(Exception):
    """A checkpoint written by another schema: refused, never interpreted."""


def _pack_key(key: Any) -> str:
    """JSON-safe form of a sink/tried key (a 2-tuple becomes 'a\\x1fb')."""
    if isinstance(key, (tuple, list)) and len(key) == 2:
        return f"{key[0]}{_KEY_SEP}{key[1]}"
    return str(key)


def _unpack_key(key: Any):
    """The reverse of :func:`_pack_key` (back to a 2-tuple when it was one)."""
    parts = str(key).split(_KEY_SEP)
    return tuple(parts) if len(parts) == 2 else str(key)


def safe_sink(sink: Optional[dict]) -> Dict[str, Any]:
    """The JSON-safe, RESUMABLE subset of the dispatch sink.

    The sink also carries execution-only state (a ``threading.Lock``, the
    live task list) which must not be serialized. ``tried`` IS kept rather
    than dropped: it is real budget evidence, and losing it on resume would
    let the next wave re-spend a capability a sibling already burned.
    """
    out: Dict[str, Any] = {"failures": [], "cases": [], "actions": 0,
                           "tried": {}}
    if not isinstance(sink, dict):
        return out
    try:
        out["actions"] = int(sink.get("actions", 0) or 0)
    except Exception:
        out["actions"] = 0
    for key in ("failures", "cases"):
        try:
            out[key] = json.loads(
                json.dumps(list(sink.get(key) or []), default=str))
        except Exception:
            out[key] = []
    try:
        for key, caps in (sink.get("tried") or {}).items():
            out["tried"][_pack_key(key)] = sorted(str(c) for c in (caps or ()))
    except Exception:
        out["tried"] = {}
    return out


def _sink_from(data: Optional[dict]) -> Dict[str, Any]:
    """Rebuild a LIVE sink: fresh lock, ``tried`` keys back as tuples."""
    sink: Dict[str, Any] = {
        "failures": list((data or {}).get("failures") or []),
        "cases": list((data or {}).get("cases") or []),
        "actions": int((data or {}).get("actions") or 0),
        "tried": {},
        "lock": threading.Lock(),
    }
    for key, caps in ((data or {}).get("tried") or {}).items():
        sink["tried"][_unpack_key(key)] = set(caps or ())
    return sink


def restore_budget_ledger(snapshot: Optional[dict]):
    """Rebuild a ``BudgetLedger`` from ``snapshot()`` without a restorer.

    ``budget.py`` exposes ``snapshot()`` but no inverse, so the state is
    REPLAYED through the public API: limits first, then exactly the amounts
    already spent. ``spend`` refuses only when a charge would CROSS a limit
    (strict ``>``), so charging the recorded amount reproduces the row and a
    resumed target keeps precisely the allowance it had left. A zero limit
    means UNLIMITED and stays zero, i.e. absent policy is not zero policy.
    """
    from phantom.automation.budget import BudgetLedger
    ledger = BudgetLedger()
    rows = (snapshot or {}).get("targets") or {}
    for target, row in rows.items():
        try:
            ledger.set_limit(target, max_actions=row.get("max_actions"),
                             max_noise=row.get("max_noise"),
                             max_requests=row.get("max_requests"))
            ledger.spend(target, actions=int(row.get("actions") or 0),
                         noise=float(row.get("noise") or 0.0),
                         requests=int(row.get("requests") or 0))
        except Exception:
            continue
    return ledger


def save_swarm_checkpoint(path, board, tasks, sink=None, idempotency=None) -> str:
    """Atomically write board + DAG state + sink + idempotency to ``path``.

    Returns the path written. Atomic (tmp + ``os.replace``) so a crash
    mid-write cannot leave a half-parsed checkpoint behind, and serialized
    under a module lock so two worker threads committing at the same time
    cannot interleave into one file.
    """
    path = os.fspath(path)
    if not path:
        return ""
    payload: Dict[str, Any] = {
        "schema": SWARM_CHECKPOINT_SCHEMA,
        "saved_at": time.time(),
        "board": board.to_dict(),
        "tasks": [t.to_dict() for t in (tasks or [])],
        "sink": safe_sink(sink),
        "idempotency": (idempotency.snapshot()
                        if idempotency is not None else {}),
    }
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = f"{path}.tmp"
    with _WRITE_LOCK:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    return path


def load_swarm_checkpoint(path) -> Dict[str, Any]:
    """Load a checkpoint: ``{schema, saved_at, board, tasks, sink, idempotency}``.

    Raises :class:`CheckpointSchemaError` when the file was written by a
    different schema, so the caller fails before any worker thread exists
    rather than reasoning over a state it does not understand.
    """
    path = os.fspath(path)
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    schema = data.get("schema")
    if schema != SWARM_CHECKPOINT_SCHEMA:
        raise CheckpointSchemaError(
            f"swarm checkpoint schema {schema!r} != {SWARM_CHECKPOINT_SCHEMA!r} "
            f"({path}): written by another build. Refusing to interpret it — "
            "start a fresh run, or migrate the file explicitly.")
    from .board import Board
    from .idempotency import IdempotencyRegistry
    from .tasks import SwarmTask
    board = Board.from_dict(data.get("board") or {})
    tasks = [SwarmTask.from_dict(t) for t in (data.get("tasks") or [])]
    idempotency = IdempotencyRegistry()
    try:
        idempotency.restore(data.get("idempotency") or {})
    except Exception:
        pass
    return {
        "schema": schema,
        "saved_at": float(data.get("saved_at") or 0.0),
        "board": board,
        "tasks": tasks,
        "sink": _sink_from(data.get("sink") or {}),
        "idempotency": idempotency,
    }
