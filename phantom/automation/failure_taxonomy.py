"""failure_taxonomy.py — typed failure classification for the agent/swarm.

A generic ``returncode != 0`` (or a bare ``False``) is not enough for an
autonomous planner: "the tool is not installed" and "the network is down"
and "you are out of scope" call for different next moves, and only one of
them is retryable. This module turns the signals the executor / swarm
already produce (``error`` text, ``timed_out``, ``returncode``, a stall
class) into ONE typed kind, so failure handling, learning and the case file
can branch on the cause instead of the symptom.

It is deliberately additive: callers that only want the coarse task/agent
routing (``swarm/failures.classify``) keep it; the typed kind rides along
as provenance.
"""
from __future__ import annotations

import re
from typing import Any, Optional

# Terminal kinds. Kept as plain strings so they serialize into the case
# file / learning records without an enum import on the reader side.
TOOL_MISSING = "tool_missing"
TOOL_CRASHED = "tool_crashed"
TIMEOUT = "timeout"
NETWORK_UNREACHABLE = "network_unreachable"
AUTH_FAILED = "auth_failed"
SCOPE_DENIED = "scope_denied"
POLICY_DENIED = "policy_denied"
PARSE_FAILED = "parse_failed"
PARTIAL_RESULT = "partial_result"
STALE_RESULT = "stale_result"
CONTRADICTORY_RESULT = "contradictory_result"
OPERATOR_CANCELLED = "operator_cancelled"
UNKNOWN = "unknown"

ALL_KINDS = (
    TOOL_MISSING, TOOL_CRASHED, TIMEOUT, NETWORK_UNREACHABLE, AUTH_FAILED,
    SCOPE_DENIED, POLICY_DENIED, PARSE_FAILED, PARTIAL_RESULT, STALE_RESULT,
    CONTRADICTORY_RESULT, OPERATOR_CANCELLED, UNKNOWN,
)

# Ordered (pattern -> kind): the FIRST match wins, so the more specific
# signals must precede the generic ones.
_RULES = (
    (re.compile(r"out of scope|unsafe target|no engagement scope", re.I),
     SCOPE_DENIED),
    (re.compile(r"not installed|command not found|no such file", re.I),
     TOOL_MISSING),
    (re.compile(r"refused:|unsafe command|policy", re.I), POLICY_DENIED),
    (re.compile(r"401|403|unauthor|forbidden|auth", re.I), AUTH_FAILED),
    (re.compile(r"timed?\s*out|timeout", re.I), TIMEOUT),
    (re.compile(r"unreachable|connection refused|connection reset|"
                r"name or service not known|no route|network", re.I),
     NETWORK_UNREACHABLE),
    (re.compile(r"parse|decode|json|malformed", re.I), PARSE_FAILED),
    (re.compile(r"partial|incomplete", re.I), PARTIAL_RESULT),
    (re.compile(r"stale|expired", re.I), STALE_RESULT),
    (re.compile(r"contradict|cannot rely", re.I), CONTRADICTORY_RESULT),
    (re.compile(r"cancel", re.I), OPERATOR_CANCELLED),
)


def classify_failure(result: Any = None, error: str = "",
                     timed_out: Optional[bool] = None,
                     returncode: Optional[int] = None) -> str:
    """Return ONE typed failure kind for a failed result.

    Accepts a ``QuietResult`` (``error`` / ``timed_out`` / ``returncode``) or
    any object exposing the same attributes, plus explicit overrides. Never
    raises.
    """
    try:
        if result is not None:
            if not error:
                error = str(getattr(result, "error", "") or "")
            if timed_out is None:
                timed_out = getattr(result, "timed_out", None)
            if returncode is None:
                returncode = getattr(result, "returncode", None)

        if timed_out:
            return TIMEOUT

        text = str(error or "")
        # a stall/cancel note carries the strongest signal when present
        for pattern, kind in _RULES:
            if pattern.search(text):
                return kind

        # nothing specific: a non-zero exit is a crash, an outright error
        # with no code is still a crash, otherwise the cause is unknown.
        if returncode is not None and returncode not in (0, None):
            return TOOL_CRASHED
        if text:
            return TOOL_CRASHED
        return UNKNOWN
    except Exception:
        return UNKNOWN
