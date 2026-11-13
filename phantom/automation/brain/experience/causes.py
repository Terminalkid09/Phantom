"""
experience.causes — WHY did the move fail.

This is the module that decides whether the learning engine learns anything
useful at all. "The technique failed" is not a fact — a timeout, a WAF
rejection, a missing local tool and a wrong credential all produce the same
`ok=False` in the audit trail, and averaging them together is noise.

So every failure is classified into a small, closed taxonomy. The
classification is deterministic (regex/keyword rules over the reason,
evidence and command) so it works offline, is reproducible across runs and
never depends on a model being reachable.

The taxonomy also decides what is LEARNABLE. If a capability failed because
the operator's box lacks `nmap`, or because the host was out of scope, that
says nothing about the technique — teaching the engine "this technique is
bad" from such an event would be actively harmful. Those causes are
`ENVIRONMENTAL` and are excluded from everything that adjusts behaviour.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

# ── the closed taxonomy ─────────────────────────────────────────────────────
UNREACHABLE = "unreachable"
TIMEOUT = "timeout"
WAF_BLOCKED = "waf_blocked"
RATE_LIMITED = "rate_limited"
AUTH_REQUIRED = "auth_required"
NOT_FOUND = "not_found"
UNSUPPORTED = "unsupported"
PRIVILEGE = "privilege"
DEPENDENCY_MISSING = "dependency_missing"
SCOPE_DENIED = "scope_denied"
GATED = "gated"
NO_SIGNAL = "no_signal"
PARSE_ERROR = "parse_error"
OTHER = "other"

CAUSES: Tuple[str, ...] = (
    UNREACHABLE, TIMEOUT, WAF_BLOCKED, RATE_LIMITED, AUTH_REQUIRED,
    NOT_FOUND, UNSUPPORTED, PRIVILEGE, DEPENDENCY_MISSING, SCOPE_DENIED,
    GATED, NO_SIGNAL, PARSE_ERROR, OTHER,
)

CAUSE_LABEL: Dict[str, str] = {
    UNREACHABLE: "host/service unreachable",
    TIMEOUT: "timed out",
    WAF_BLOCKED: "blocked by a WAF/filter",
    RATE_LIMITED: "rate limited",
    AUTH_REQUIRED: "authentication required/refused",
    NOT_FOUND: "endpoint/service not found",
    UNSUPPORTED: "unsupported on this target",
    PRIVILEGE: "insufficient privilege",
    DEPENDENCY_MISSING: "local tool/dependency missing",
    SCOPE_DENIED: "out of authorised scope",
    GATED: "disabled by policy/flag or unconfigured",
    NO_SIGNAL: "ran but produced nothing new",
    PARSE_ERROR: "output could not be parsed",
    OTHER: "other",
}

# A cause that is NEVER the technique's fault: excludes the episode from
# everything that reorders moves, and from promotion into the priors.
ENVIRONMENTAL: frozenset = frozenset({
    DEPENDENCY_MISSING, SCOPE_DENIED, GATED,
})

# A cause where retrying the SAME move is pointless until something
# external changes (the target's posture, not our approach).
PERSISTENT: frozenset = frozenset({
    WAF_BLOCKED, UNSUPPORTED, NOT_FOUND, PRIVILEGE,
})


def is_learnable(cause: str) -> bool:
    """True when this failure may inform future planning."""
    return cause not in ENVIRONMENTAL


# Cold-start repair hints: when the cause is known and we have NO data yet,
# these capability-id fragments are the classic ways around it. Data (real
# episodes) always outranks this table — it exists only so the very first
# engagement is not blind.
REPAIR_HINTS: Dict[str, Tuple[str, ...]] = {
    WAF_BLOCKED: ("http_get", "curl", "proxy", "encode", "web_page",
                  "passive"),
    RATE_LIMITED: ("passive", "get", "banner", "osint"),
    AUTH_REQUIRED: ("cred", "login", "breach", "osint", "spray", "default"),
    NOT_FOUND: ("fingerprint", "scan", "discover", "endpoint", "url",
                "profile"),
    UNSUPPORTED: ("version", "fingerprint", "alternative", "osint"),
    TIMEOUT: ("service", "banner", "probe", "http"),
    UNREACHABLE: ("scan", "host", "discovery", "pivot"),
    PRIVILEGE: ("privesc", "sudo", "service_perms", "escalat"),
    NO_SIGNAL: ("osint", "persona", "social", "phish", "breach", "dossier",
                "profile"),
    PARSE_ERROR: ("detail", "verbose", "fingerprint"),
    OTHER: (),
}


# ── rules, most specific first ──────────────────────────────────────────────
# Each rule: (compiled regex, cause). First match wins.
_RULES: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"out of scope|not in scope|scope (?:denied|violation)",
                re.I), SCOPE_DENIED),
    (re.compile(r"requires? --aggressive|requires? config|not configured|"
                r"disabled|unconfigured|flag required|needs? (?:the )?transport",
                re.I), GATED),
    (re.compile(r"not installed|command not found|no such file or directory|"
                r"tool unavailable|missing tool|module not found|"
                r"llama-cpp|import(?:ed)? error", re.I), DEPENDENCY_MISSING),
    (re.compile(r"\bwaf\b|web application firewall|blocked by|cloudflare|"
                r"captcha|challenge|forbidden|\b403\b|access denied|"
                r"mod_security|modsecurity|akamai|imperva|request rejected",
                re.I), WAF_BLOCKED),
    (re.compile(r"\b429\b|rate.?limit|too many requests|slow down|"
                r"throttl", re.I), RATE_LIMITED),
    (re.compile(r"timed? ?out|timeout|deadline exceeded|killed after",
                re.I), TIMEOUT),
    (re.compile(r"connection refused|connection reset|no route to host|"
                r"network unreachable|unreachable|host down|"
                r"connect(?:ion)? failed|nxd?omain|name or service not known|"
                r"temporary failure in name resolution", re.I), UNREACHABLE),
    (re.compile(r"\b401\b|unauthori[sz]ed|authentication (?:failed|required)|"
                r"invalid credential|login failed|auth(?:entication)? refused|"
                r"access denied \(auth", re.I), AUTH_REQUIRED),
    (re.compile(r"permission denied|operation not permitted|"
                r"insufficient privilege|must be root|require(?:s)? "
                r"administrator|privilege", re.I), PRIVILEGE),
    (re.compile(r"\b404\b|not found|no such (?:endpoint|path|service)|"
                r"does not exist|no (?:open|matching)", re.I), NOT_FOUND),
    (re.compile(r"unsupported|not supported|version mismatch|"
                r"requires version|incompatible|not applicable", re.I),
     UNSUPPORTED),
    (re.compile(r"no output|no new facts|no findings|no candidates|"
                r"empty (?:output|response)|no beacon check-?in|"
                r"produced nothing|learned nothing", re.I), NO_SIGNAL),
    (re.compile(r"parse|decode|json|xml|unexpected (?:token|value)|"
                r"malformed|traceback", re.I), PARSE_ERROR),
    (re.compile(r"execution failed|failed|error", re.I), OTHER),
]


def classify(capability: str = "", reason: str = "",
             evidence: str = "", command: str = "",
             cause: Optional[str] = None) -> str:
    """Map a failure to one of `CAUSES`.

    An explicit `cause` (already classified, e.g. by the LLM fallback) is
    trusted when it is a known member of the taxonomy. Otherwise the rules
    run over reason, evidence, capability id and the command, in that
    order of signal quality.
    """
    if cause and cause in CAUSES:
        return cause
    text = " \n".join(str(x) for x in (reason, evidence, capability, command)
                      if x)
    if not text.strip():
        return OTHER
    # the reason is the highest-signal field: try it alone first so a
    # generic word in the command cannot mask a specific failure
    for field_text in (str(reason or ""), str(evidence or "")):
        if not field_text.strip():
            continue
        for rx, ca in _RULES:
            if rx.search(field_text):
                return ca
    for rx, ca in _RULES:
        if rx.search(text):
            return ca
    return OTHER


def repair_hints(cause: str) -> Tuple[str, ...]:
    """Cold-start capability-id fragments that classically bypass a cause."""
    return REPAIR_HINTS.get(cause, ())


def describe(cause: str) -> str:
    return CAUSE_LABEL.get(cause, cause or OTHER)
