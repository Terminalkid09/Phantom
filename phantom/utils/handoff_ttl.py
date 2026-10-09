"""handoff_ttl.py — how long an AutoMode → C2 handoff stays OFFERABLE.

`Handoff` has carried an ``expired`` state since the record was introduced
(``electron/src/store/index.ts``) and NOTHING ever set it: a beacon handed
over yesterday is still ``ready`` today, and ``handoff`` in the AutoShell
keeps offering it. The C2 context it points at may not even exist any more.

Two conditions make a handoff stale, and both are knowable at the call site,
so they live here as one policy instead of being guessed per surface:

* **AGE** — a handoff is a pointer to a beacon that JUST called back. After
  ``DEFAULT_TTL_MINUTES`` it is a decision made on stale state: the run's
  output is no longer the freshest thing the operator has, and a beacon that
  has been idle for an hour is one the C2 has already given up on.
* **LIVENESS** — if the beacon is no longer in the beacon list, the context
  the handoff points at is gone. That check needs the list, so it only runs
  when the caller HAS one (``beacons=``): without it, only the age applies.

Not a "cleanup": nothing is deleted here. The record stays in the store and
keeps its ``expired`` status; what changes is that ``handoff``/the UI stop
OFFERING it, and can say why.

The window is overridable per engagement from the environment
(``PHANTOM_HANDOFF_TTL_MINUTES``), because "an hour" is a default and an
engagement may legitimately run longer.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

ENV_VAR = "PHANTOM_HANDOFF_TTL_MINUTES"

# 60 minutes: a handoff that is older than this is no longer the run's output,
# it is a stale pointer. Short on purpose — the cost of getting it wrong in
# this direction is one re-run; in the other direction it is an operator
# interacting with the wrong beacon.
DEFAULT_TTL_MINUTES = 60

# the keys a record may carry for its creation time, in order of preference:
# the API job uses `created_at` (server.py), the shell's own events use `at`.
_TIME_KEYS = ("created_at", "at", "createdAt", "timestamp")


def ttl_minutes(env: Optional[Dict[str, str]] = None) -> float:
    """The configured window, or the default when unset/unparsable."""
    environ = os.environ if env is None else env
    raw = (environ.get(ENV_VAR) or "").strip()
    if not raw:
        return float(DEFAULT_TTL_MINUTES)
    try:
        value = float(raw)
    except ValueError:
        return float(DEFAULT_TTL_MINUTES)
    return value if value > 0 else float(DEFAULT_TTL_MINUTES)


def ttl_seconds(env: Optional[Dict[str, str]] = None) -> float:
    return ttl_minutes(env) * 60.0


def beacon_id(record: Any) -> str:
    """The beacon a record points at, whatever shape the caller has."""
    if isinstance(record, dict):
        for key in ("beacon_id", "beaconId", "id"):
            value = record.get(key)
            if value:
                return str(value)
        return ""
    return str(record or "")


def parse_time(value: Any) -> Optional[float]:
    """Epoch seconds from a number, an epoch string or an ISO string.

    ``None`` when the value cannot be dated. Milliseconds are understood
    because the UI stores JS timestamps (``Date.now()``).
    """
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value) / 1000.0 if value > 1e11 else float(value)
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _timestamp(record: Any) -> Optional[float]:
    """Epoch seconds from a record, or ``None`` when unreadable."""
    if not isinstance(record, dict):
        return None
    for key in _TIME_KEYS:
        if key in record:
            stamp = parse_time(record.get(key))
            if stamp is not None:
                return stamp
    return None


def _live_state(beacons: Optional[Iterable[Any]]
                ) -> Optional[Dict[str, Optional[float]]]:
    """``{beacon_id: last_seen_or_None}``, or ``None`` when not given.

    The C2 keeps an offline beacon in its list on purpose ("offline in place,
    history preserved"), so membership alone is not liveness: when a
    ``last_seen`` is available it is what decides, and when it is not the
    beacon counts as alive.
    """
    if beacons is None:
        return None
    state: Dict[str, Optional[float]] = {}
    for beacon in beacons:
        bid = beacon_id(beacon)
        if not bid:
            continue
        seen = None
        if isinstance(beacon, dict):
            for key in ("last_seen", "lastSeen"):
                if key in beacon:
                    seen = parse_time(beacon.get(key))
                    break
        state[bid] = seen
    return state


def expiry_reason(record: Any, *, beacons: Optional[Iterable[Any]] = None,
                  now: Optional[float] = None,
                  ttl_s: Optional[float] = None,
                  env: Optional[Dict[str, str]] = None) -> Optional[str]:
    """WHY this handoff is no longer offerable, or ``None`` when it still is.

    Fails CLOSED on a record whose timestamp cannot be read: the same policy
    `TypedTask.is_expired` already applies to a deadline it cannot parse, and
    offering a handoff the operator cannot date is worse than not offering it.
    """
    window = ttl_seconds(env) if ttl_s is None else float(ttl_s)
    stamp = _timestamp(record)
    live = _live_state(beacons)
    bid = beacon_id(record)
    if live is not None:
        if bid and bid not in live:
            return (f"beacon {bid} is no longer known to the C2: the context "
                    f"this handoff points at does not exist any more")
        seen = live.get(bid)
        if seen is not None:
            silent = (now if now is not None
                      else datetime.now().timestamp()) - seen
            if silent > window:
                return (f"beacon {bid} has not checked in for "
                        f"{int(round(silent / 60.0))} minute(s): the handoff "
                        f"points at a silent beacon")
    if stamp is None:
        return ("the handoff has no readable timestamp: cannot tell whether "
                "it is still the run's output")
    age = (now if now is not None else datetime.now().timestamp()) - stamp
    if age > window:
        minutes = int(round(age / 60.0))
        return (f"handoff is {minutes} minute(s) old (limit "
                f"{int(round(window / 60.0))})")
    return None


def is_expired(record: Any, **kwargs) -> bool:
    return expiry_reason(record, **kwargs) is not None


def partition(records: Sequence[Any], **kwargs
              ) -> Tuple[List[Any], List[Tuple[Any, str]]]:
    """``(still_offerable, [(record, reason)])`` — the whole policy in one call.

    Every surface that offers a handoff should iterate the FIRST list: the
    second exists so the operator can be told what was dropped and why
    (a silently missing handoff is the same bug one layer up).
    """
    offerable: List[Any] = []
    expired: List[Tuple[Any, str]] = []
    for record in records or ():
        reason = expiry_reason(record, **kwargs)
        if reason is None:
            offerable.append(record)
        else:
            expired.append((record, reason))
    return offerable, expired


def describe(reason: str) -> str:
    """One line for the operator: the reason plus what to do about it."""
    return (f"{reason} — drop it, or run a fresh `launch`/`resume` and take "
            f"the handoff from THAT run")
