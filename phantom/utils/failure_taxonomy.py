"""failure_taxonomy.py — every caught error gets a NAME.

An orchestrator that turns ``except Exception`` into "no finding" is lying by
omission: the operator reads a clean result and has no way to tell

  * the target genuinely had nothing (``target_negative``), from
  * the tool was never installed (``tool_missing``), from
  * the scope refused the move (``out_of_scope``), from
  * our own code raised (``internal_bug``).

All four used to look identical from the outside. This module is the one
place that decides which of them an error IS, records it somewhere
observable (the decision audit + the log), and hands the category back so a
caller can act on it.

It is deliberately tiny and dependency-free at import time: it is called from
`except` blocks, so it must never be the thing that raises. `record()` is
total — every failure inside it is swallowed, and the category is still
returned.
"""
from __future__ import annotations

import socket
import threading
import time
from collections import Counter
from typing import Any, Dict, List, Optional

#: The vocabulary. A category is a CLAIM about WHY something failed, so the
#: list is closed: adding one is a deliberate act, and callers that cannot
#: justify a specific token fall back to ``internal_bug`` (which is a
#: confession, not a shrug).
#:
#: ``contract_violation`` was added by the driver-contract work: a manifest
#: that pins its binary and then runs a DIFFERENT one is not "out of scope",
#: not "unsupported" and certainly not an internal bug — it is the declared
#: contract being broken, and it must stay countable on its own.
CATEGORIES = (
    "unsupported",         # the capability/feature does not exist here
    "tool_missing",        # the external binary/toolchain is not installed
    "out_of_scope",        # refused by the scope / a guardrail
    "network_timeout",     # the network did not answer in time (or at all)
    "auth_failed",         # credentials / keys were rejected
    "parse_failed",        # the output could not be read
    "target_negative",     # the target answered "no" — NOT a bug
    "internal_bug",        # OUR fault: the default, never a silent one
    "operator_cancelled",  # a human stopped it
    "io_error",            # filesystem / device
    "config_error",        # configuration is unusable
    "contract_violation",  # what ran did not honour its declared contract
)

CATEGORY_LABELS: Dict[str, str] = {
    "unsupported": "not supported here",
    "tool_missing": "tool not installed",
    "out_of_scope": "refused by scope/guardrail",
    "network_timeout": "network timeout/unreachable",
    "auth_failed": "authentication failed",
    "parse_failed": "output could not be parsed",
    "target_negative": "target answered negative",
    "internal_bug": "internal bug",
    "operator_cancelled": "cancelled by operator",
    "io_error": "filesystem/device error",
    "config_error": "configuration error",
    "contract_violation": "driver breached its declared contract",
}

#: Bounded ring of what was recorded, so a test (or a future `doctor`) can
#: see the taxonomy in action without depending on the log file.
_RECENT_LIMIT = 200
_LOCK = threading.Lock()
_RECENT: List[Dict[str, Any]] = []

# Exceptions that name their category unambiguously. Anything not listed is
# ``internal_bug``: guessing "parse_failed" from a bare ValueError would make
# the vocabulary decorative.
_TYPE_MAP = (
    (KeyboardInterrupt, "operator_cancelled"),
    (SystemExit, "operator_cancelled"),
    (TimeoutError, "network_timeout"),
    (socket.timeout, "network_timeout"),
    (socket.gaierror, "network_timeout"),
    (ConnectionError, "network_timeout"),
    (PermissionError, "io_error"),
    (FileNotFoundError, "io_error"),
    (IsADirectoryError, "io_error"),
    (OSError, "io_error"),
    (ModuleNotFoundError, "unsupported"),
)


def is_category(token: str) -> bool:
    return str(token or "") in CATEGORIES


def category_label(token: str) -> str:
    return CATEGORY_LABELS.get(str(token or ""), str(token or ""))


def classify(exc: Optional[BaseException] = None) -> str:
    """The category a raw exception maps to.

    Deliberately conservative: only exception types that cannot mean anything
    else are mapped. A caller that KNOWS better (it looked for a binary and
    did not find it, it parsed a banner and failed) passes ``category=``
    explicitly — which is the point: the specific token has to be justified
    by the call site, never inferred from a type name.
    """
    if exc is None:
        return "internal_bug"
    try:
        import json as _json
        if isinstance(exc, _json.JSONDecodeError):
            return "parse_failed"
    except Exception:                                     # pragma: no cover
        pass
    if isinstance(exc, UnicodeDecodeError):
        return "parse_failed"
    for kind, token in _TYPE_MAP:
        try:
            if isinstance(exc, kind):
                return token
        except TypeError:                                 # pragma: no cover
            continue
    return "internal_bug"


def record(where: str, exc: Optional[BaseException] = None,
           category: str = "", detail: str = "",
           best_effort: bool = False,
           extra: Optional[Dict[str, Any]] = None) -> str:
    """Record one caught failure and return its category.

    * ``where``      — a stable dotted site name ("broker._scope_ok"): the
                       site, not the message, is what an operator greps.
    * ``category``   — pass it when the call site KNOWS the reason; otherwise
                       it is derived from ``exc``.
    * ``best_effort``— the failure is expected and non-operational (a tab
                       completion, an optional hint): recorded at info level
                       so it is visible without crying wolf.

    Never raises. Returns the category actually recorded.
    """
    token = str(category or "").strip()
    if not is_category(token):
        token = classify(exc)
    entry: Dict[str, Any] = {
        "category": token,
        "where": str(where or "?"),
        "detail": str(detail or "")[:300]
        or (f"{type(exc).__name__}: {exc}"[:300] if exc is not None else ""),
        "exception": type(exc).__name__ if exc is not None else "",
        "at": time.time(),
    }
    if extra:
        try:
            entry.update({k: v for k, v in dict(extra).items()
                          if k not in entry})
        except Exception:                                 # pragma: no cover
            pass
    try:
        with _LOCK:
            _RECENT.append(dict(entry))
            while len(_RECENT) > _RECENT_LIMIT:
                _RECENT.pop(0)
    except Exception:                                     # pragma: no cover
        pass
    # Observable OUTSIDE this process: the engagement audit is the record an
    # operator reads after the fact.
    try:
        from phantom.automation import decision_audit
        decision_audit.record("failure", **entry)
    except Exception:                                     # pragma: no cover
        pass
    try:
        from phantom.utils.notifier import notifier
        line = (f"{entry['where']}: {category_label(token)}"
                + (f" — {entry['detail']}" if entry["detail"] else ""))
        if best_effort:
            notifier.info(line)
        else:
            notifier.warn(line)
    except Exception:                                     # pragma: no cover
        pass
    return token


def recent() -> List[Dict[str, Any]]:
    """A snapshot of what was recorded (oldest first)."""
    with _LOCK:
        return [dict(e) for e in _RECENT]


def summary() -> Dict[str, Any]:
    """Counts by category — the shape a `doctor`/report line wants."""
    counts: Counter = Counter()
    for entry in recent():
        counts[entry.get("category", "internal_bug")] += 1
    return {"total": sum(counts.values()),
            "by_category": dict(sorted(counts.items()))}


def reset() -> None:
    """Clear the ring (tests, and a fresh engagement)."""
    with _LOCK:
        _RECENT.clear()
