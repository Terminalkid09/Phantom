"""
capability.py — the fuzz engine as a PLANNABLE capability.

``grammar.py`` / ``oracles.py`` / ``engine.py`` already implement generative
differential fuzzing, but no capability ever invoked them: the capability set
is code, so the fuzzing the project owns never reached the chain. This module
is the missing adapter, and it stays a THIN seam on purpose — the engine, the
grammar and the oracles are untouched.

Why this matters for discovery: template probes (the hunt engine's fixed
payloads) are one signature a WAF fingerprints in a single request. Generative
fuzzing mutates primitives and compares DIFFERENTIALS instead, so a parameter
that only reacts to an unusual encoding is still found. The mutation space is
derived from the parameters the target ACTUALLY has, not from a fixed list.

Marker format is the same ``k=v`` line style the kit adapters use, and the
emitted finding carries the SAME value shape as ``_hunt_web_interp``'s
``hunt_anomaly`` findings, so the report, the timeline, the attack graph and
the reasoning rules consume it with no changes:

    FUZZ: cls=sqli param=q name=sqli-g0 endpoint=/search port=8080
          signals=error_based score=2.60 confirmed=true severity=high
          requests=14 evidence=error_based:mysql_error_surfaced

HONESTY RULE (mirrors ``exploit/anomaly.py``): an oracle verdict is a
CANDIDATE, never a verdict of vulnerability. ``confirmed`` is True only when a
bounded REPRODUCTION repeated the same oracle on the same parameter — one
extra baseline + one extra probe, charged against the same request budget.
Without the repeat the finding is reported as an unconfirmed candidate.

Nothing here punches a hole in the execution policy: with no injectable/web
surface the adapter returns a ``# comment`` line (the kit convention for
"nothing to do"), and with no injected sender ``run_fuzz`` returns the same
comment instead of touching the network. The registered ENGINE
(``fuzz_engine``) prefers the transport the RUN injects
(``AutonomousAgent.fuzz_sender``) and only falls back to the shared curl
primitive when the run has none — and that fallback is capped in SECONDS as
well as in requests, so this capability can never hold the orchestrator's
drain window open.

Ownership note: registration (``_mk("fuzz_params", ...)`` in
``guidance/kit.py``) and the planner entry in ``_FACT_SOURCES["hunt_anomaly"]``
belong to the coordinator, not to this module.
"""

from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

from phantom.automation.belief import Finding
from phantom.automation.brain.fuzz.engine import FuzzEngine, FuzzFinding
from phantom.automation.brain.fuzz.oracles import Response

# ── capability descriptor (consumed by the coordinator's registration) ─────
CAPABILITY_ID = "fuzz_params"
CATEGORY = "hunt"
EFFECTS = ["hunt_anomaly"]
REQUIRES = ["service"]
SLOTS: Sequence[Dict[str, Any]] = (
    {"name": "port", "type": "port", "required": False,
     "description": "web port (default: the discovered web service)"},
    {"name": "params", "type": "str", "required": False,
     "description": "explicit parameter list (comma/space separated)"},
    {"name": "rounds", "type": "int", "required": False,
     "description": "mutation rounds (default 2)"},
    {"name": "max_requests", "type": "int", "required": False,
     "description": "hard request budget for the whole run (default 60)"},
    {"name": "seed", "type": "int", "required": False,
     "description": "grammar seed; fixed seed = reproducible mutations"},
)

MARKER = "FUZZ:"
NO_OP = ("# fuzz_params: no injectable web surface (needs a web service/app "
         "fact, a port, or an explicit param list)")

DEFAULT_ROUNDS = 2
DEFAULT_MAX_REQUESTS = 60
MAX_PARAMS = 8               # bounded parameter surface per run
REPRODUCTION_LIMIT = 4       # candidates we are willing to re-probe
_EVIDENCE_CHARS = 160

# Wall-clock ceiling for the WHOLE pass, independent of the request count.
# A count is not a bound when the transport is a live one: 60 requests at
# curl's 8s ceiling is eight minutes inside a run that has a schedule to
# keep, and a capability that eats the orchestrator's drain window stalls
# the chain just as surely as a crash. Whichever limit is reached first
# (requests or seconds) ends the pass, and the markers say what came back.
DEFAULT_DEADLINE = 45.0

# web-ish ports when the whole toolchain (kit) cannot be imported
_WEB_PORTS_FALLBACK = ("80", "443", "3000", "5000", "8000", "8080", "8443",
                       "8888", "9000", "9443")

# how strongly an oracle verdict reads as a real signal (drives score/severity)
_ORACLE_SCORE = {
    "error_based": 2.6,      # a server error the baseline did not have
    "content_probe": 2.8,    # a sensitive file's content came back
    "time_based": 1.4,       # the response took meaningfully longer
    "status_differential": 1.6,
    "length_differential": 1.0,
    "differential": 0.5,
}

# a mapped WAF rule is boundary intel, NOT a bug class: emitting it as
# `hunt_anomaly` would inflate the candidate count (and the attack-chain
# predicates key off `cls`), so it is dropped on purpose.
_NON_BUG_HINTS = frozenset({"waf"})

_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.I)
_QUERY_RE = re.compile(r"[?&]([A-Za-z0-9_.\[\]%-]{1,40})=")


# ── WorldModel helpers (never raise: this code runs mid-planning) ──────────

def _find(wm, kind: str) -> List[Any]:
    try:
        return list(wm.find(kind) or [])
    except Exception:
        return []


def _value(finding) -> Dict[str, Any]:
    v = getattr(finding, "value", None)
    return v if isinstance(v, dict) else {}


def _host_of(target: str) -> str:
    """Bare host of a target, tolerating scheme/path/port and IPv6."""
    t = (target or "").strip()
    t = _SCHEME_RE.sub("", t)
    t = t.split("/", 1)[0].split("?", 1)[0]
    if t.count(":") == 1:
        host, _, port = t.partition(":")
        if port.isdigit():
            return host
    return t


def _web_ports() -> Tuple[str, ...]:
    try:
        from phantom.automation.guidance.kit import _WEB_PORTS
        return tuple(str(p) for p in _WEB_PORTS)
    except Exception:
        return _WEB_PORTS_FALLBACK


def _c2_port_for(host: str) -> str:
    """Our own listener port, but ONLY when the target IS this box.

    Probing/fuzzing our own C2 is absurd, so the rule exists — but applying
    it to a REMOTE target made the chosen web port depend on the operator's
    machine: a remote app on 8080 was skipped because the local C2 happened
    to listen on 8080. Delegates to the kit's single implementation.
    """
    try:
        from phantom.automation.guidance.kit import _c2_port_blocks
        return _c2_port_blocks(host)
    except Exception:
        return ""


def _web_target(wm, slots: Optional[Dict[str, Any]] = None) -> Tuple[str, str]:
    """(host, port) of the web surface to fuzz.

    Prefers a fingerprinted web app port, then any web port EXCLUDING the
    operator's own C2 listener (fuzzing our own listener would be absurd),
    then the port given in the slots, then 80 — same policy the kit's
    ``_web_service_target`` uses, so ``web_rce`` and this capability always
    agree on which app they are talking about.
    """
    host = _host_of(getattr(wm, "target", "") or "")
    slots = slots or {}
    explicit = str(slots.get("port", "") or "").strip()
    app_ports = {str(_value(f).get("port", "")) for f in _find(wm, "web_app")}
    app_ports.discard("")
    services = [f for f in _find(wm, "service") if _value(f).get("port")]
    for f in services:
        port = str(_value(f).get("port", ""))
        if port in app_ports:
            return host, port
    web_ports = _web_ports()
    c2_port = _c2_port_for(host)
    for f in services:
        port = str(_value(f).get("port", ""))
        if port in web_ports and port != c2_port:
            return host, port
    if explicit:
        return host, explicit
    return host, "80"


def _has_web_surface(wm, slots: Optional[Dict[str, Any]] = None) -> bool:
    """True when there is something we are entitled to fuzz right now."""
    if (slots or {}).get("params") or (slots or {}).get("port"):
        return True
    if _find(wm, "web_app"):
        return True
    if getattr(wm, "target_type", "") == "url":
        return True
    web_ports = _web_ports()
    for f in _find(wm, "service"):
        if str(_value(f).get("port", "")) in web_ports:
            return True
    return False


def _discovered_params(wm, slots: Optional[Dict[str, Any]] = None,
                       limit: int = MAX_PARAMS) -> List[str]:
    """The parameters to fuzz, derived from what the target ACTUALLY has.

    Order of precedence, deduped and bounded:

    1. an explicit ``params`` slot (operator/planner decision);
    2. parameters named by an existing ``hunt_anomaly`` finding;
    3. parameters recovered from a discovered endpoint's query string
       (``hunt_anomaly.endpoint`` and the P0 ``web_path`` fact);
    4. a small common-parameter fallback, so a web target is never left
       un-fuzzed just because discovery found no endpoint yet.
    """
    slots = slots or {}
    out: List[str] = []

    def _add(param: Any) -> None:
        p = str(param or "").strip()
        if not p or len(p) > 40 or "\n" in p:
            return
        if p not in out:
            out.append(p)

    raw = slots.get("params")
    if isinstance(raw, (list, tuple)):
        for p in raw:
            _add(p)
    elif isinstance(raw, str):
        for p in re.split(r"[,\s]+", raw):
            _add(p)

    for kind in ("hunt_anomaly", "web_path"):
        for f in _find(wm, kind):
            v = _value(f)
            for key in ("param", "params"):
                item = v.get(key)
                if isinstance(item, (list, tuple)):
                    for p in item:
                        _add(p)
                elif isinstance(item, str):
                    for p in re.split(r"[,\s]+", item):
                        _add(p)
            endpoint = v.get("endpoint") or v.get("path")
            if isinstance(endpoint, str):
                for p in _QUERY_RE.findall(endpoint):
                    _add(p)

    if len(out) < limit:
        for p in ("id", "q", "file", "url", "cmd", "path", "page", "name"):
            if len(out) >= limit:
                break
            _add(p)
    return out[:limit]


def _port_of(wm, slots: Optional[Dict[str, Any]] = None) -> str:
    return _web_target(wm, slots)[1]


def _endpoint_for(wm, param: str) -> str:
    """The endpoint that carries this parameter, when discovery knows one."""
    for kind in ("hunt_anomaly", "web_path"):
        for f in _find(wm, kind):
            v = _value(f)
            endpoint = v.get("endpoint") or v.get("path")
            if not isinstance(endpoint, str) or not endpoint:
                continue
            if (v.get("param") == param) or (f"{param}=" in endpoint):
                return endpoint.split("?", 1)[0] or "/"
    return "/"


# ── the capability's adapter / interpreter ────────────────────────────────

def fuzz_adapter(wm, slots) -> str:
    """Marker stub, exactly like ``_hunt_web_adapter``: the fuzz engine runs
    in-process (``exec_class="in_process_engine"``), never through the shell,
    so this adapter exists only to keep the 'the adapter is the single command
    source' invariant. Returns the kit's ``# comment`` convention when the
    target has no web surface to fuzz."""
    try:
        if not _has_web_surface(wm, slots):
            return NO_OP
    except Exception:
        return NO_OP
    return "fuzz://params (generative fuzz engine, in-process)"


def run_fuzz(wm, sender=None, params: Optional[Sequence[str]] = None,
             rounds: int = DEFAULT_ROUNDS,
             max_requests: int = DEFAULT_MAX_REQUESTS,
             seed: Optional[int] = None,
             deadline: Optional[float] = None) -> List[str]:
    """Drive the fuzz engine and return its MARKER LINES.

    ``sender(param, payload) -> Response`` is INJECTED (the agent passes its
    stealth-governed HTTP sender; tests pass a fake). With no sender, or no
    parameter to fuzz, nothing is executed and the ``# comment`` line comes
    back — the engine never invents a network call on its own.

    The stated ``max_requests`` is a TRUE total: the reproduction probes are
    carved OUT of it, so the capability cannot exceed the budget it declares.
    """
    try:
        targets = list(params) if params is not None else \
            _discovered_params(wm, slots=None)
    except Exception:
        targets = []
    if sender is None or not targets:
        return [NO_OP]
    try:
        rounds = max(1, int(rounds))
    except Exception:
        rounds = DEFAULT_ROUNDS
    try:
        max_requests = max(3, int(max_requests))
    except Exception:
        max_requests = DEFAULT_MAX_REQUESTS
    if deadline is None:
        deadline = time.time() + DEFAULT_DEADLINE

    # the WALL-CLOCK stop: one place, applied to the engine AND to the
    # reproduction probes, so no path can outlive the budget it declared.
    def bounded(param: str, payload: str):
        if time.time() > deadline:
            return None
        return sender(param, payload)

    repro_limit = min(REPRODUCTION_LIMIT, max(0, (max_requests - 1) // 3))
    engine_cap = max(1, max_requests - 2 * repro_limit)

    engine = FuzzEngine(sender=bounded, rounds=rounds,
                        max_requests=engine_cap, seed=seed)
    try:
        candidate_findings: List[FuzzFinding] = engine.run(targets)
    except Exception:
        return [NO_OP]

    confirmed: set = set()   # (family, param, oracle) triples that reproduced
    charged = engine_cap
    for finding in candidate_findings[:repro_limit]:
        if charged + 2 > max_requests or time.time() > deadline:
            break
        try:
            if _reproduces(engine, bounded, finding):
                confirmed.add(_identity(finding))
        except Exception:
            pass
        charged += 2

    lines: List[str] = []
    for finding in candidate_findings:
        hint = getattr(finding.verdict, "family_hint", "") or ""
        if hint in _NON_BUG_HINTS:
            continue                      # boundary intel, not a bug class
        lines.append(_marker(
            wm, finding,
            is_confirmed=_identity(finding) in confirmed,
            requests=charged))
    return lines or [NO_OP]


def _scheme_for(wm, port: str) -> str:
    """http/https for the fuzz base URL — one source with the kit."""
    try:
        from phantom.automation.guidance.kit import _web_scheme
        return _web_scheme(wm, port)
    except Exception:
        return "https" if str(port) in ("443", "8443") else "http"


def _live_sender(wm, slots: Optional[Dict[str, Any]] = None,
                 deadline: Optional[float] = None):
    """The ONE place this capability may open a socket.

    Wraps the project's existing curl runner (the same HTTP primitive the
    anomaly hunt uses), so fuzzing inherits its timeouts and bounded reads
    instead of introducing a second, ungoverned network path. Returns None
    when the runner or the web surface is unavailable, and ``run_fuzz``
    then returns the ``# comment`` line without sending anything.

    Each request's timeout is capped to the time LEFT in the pass, so the
    last probe of a slow target cannot outlive the deadline by a full curl
    timeout on top of it.
    """
    try:
        from phantom.automation.exploit.anomaly import curl_runner
    except Exception:
        return None
    host, port = _web_target(wm, slots)
    scheme = _scheme_for(wm, port)
    base = f"{scheme}://{host}:{port}"

    def sender(param: str, payload: str):
        from urllib.parse import quote
        path = _endpoint_for(wm, param) or "/"
        url = f"{base}{path}?{quote(str(param))}={quote(str(payload))}"
        timeout = 8.0
        if deadline is not None:
            timeout = max(1.0, min(timeout, deadline - time.time()))
        return _as_response(curl_runner("GET", url, timeout=timeout))
    return sender


def fuzz_engine(wm, slots: Optional[Dict[str, Any]] = None,
                sender=None) -> str:
    """The capability's in-process engine (``run_engine`` calls this).

    ``sender`` is the CALLER's transport: the run injects its own
    stealth-governed one (``AutonomousAgent.fuzz_sender``), exactly as it
    does for the anomaly hunt's ``hunt_runner``. Only with NO injected
    sender does this fall back to the shared curl transport, and even then
    the pass is bounded in wall-clock time as well as in requests.
    """
    try:
        params = _discovered_params(wm, slots)
    except Exception:
        params = []
    if not params:
        return NO_OP
    deadline = time.time() + DEFAULT_DEADLINE
    if sender is None:
        try:
            sender = _live_sender(wm, slots, deadline)
        except Exception:
            sender = None
    if sender is None:
        return NO_OP
    # The declared slots ARE the caller's budget: this capability advertises
    # `rounds`, `max_requests` and `seed` (see SLOTS), so they have to reach
    # the engine. They were accepted and then dropped, which made the only
    # bound a caller could set a fiction — and left the pass running on
    # Phantom's defaults while the plan said otherwise.
    return "\n".join(run_fuzz(wm, sender=sender, params=params,
                              rounds=_slot_int(slots, "rounds",
                                               DEFAULT_ROUNDS),
                              max_requests=_slot_int(slots, "max_requests",
                                                     DEFAULT_MAX_REQUESTS),
                              seed=_slot_optional_int(slots, "seed"),
                              deadline=deadline))


def _slot_int(slots: Optional[Dict[str, Any]], name: str, default: int) -> int:
    """A declared int slot as an int, or ``default`` when absent/garbage."""
    try:
        raw = (slots or {}).get(name)
        if raw in (None, ""):
            return int(default)
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return int(default)


def _slot_optional_int(slots: Optional[Dict[str, Any]],
                       name: str) -> Optional[int]:
    """A declared int slot as an int, or None (the engine's "not fixed")."""
    try:
        raw = (slots or {}).get(name)
        if raw in (None, ""):
            return None
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return None


def _identity(finding: FuzzFinding) -> Tuple[str, str, str]:
    return (finding.mutation.family, finding.mutation.param,
            finding.verdict.oracle)


def _as_response(obj) -> Response:
    if isinstance(obj, Response):
        return obj
    return Response(status=getattr(obj, "status", 0) or 0,
                    body=getattr(obj, "body", "") or "",
                    elapsed=getattr(obj, "elapsed", 0.0) or 0.0)


def _reproduces(engine: FuzzEngine, sender, finding: FuzzFinding) -> bool:
    """One bounded reproduction: re-baseline + re-probe, same oracle.

    A single differential can be jitter (the anomaly engine's own validation
    pass exists for exactly this reason); only a repeat earns ``confirmed``.
    """
    mutation = finding.mutation
    baseline = _as_response(sender(mutation.param, "phantom-baseline-0"))
    again = _as_response(sender(mutation.param, mutation.payload))
    verdict = engine.oracle.evaluate(baseline, again)
    return bool(verdict.interesting
                and verdict.oracle == finding.verdict.oracle)


def _score(finding: FuzzFinding) -> float:
    return float(_ORACLE_SCORE.get(finding.verdict.oracle, 0.5))


def _severity(score: float, is_confirmed: bool) -> str:
    if is_confirmed:
        return "critical" if score >= 2.5 else "high"
    return "high" if score >= 2.5 else "medium"


def _clean(text: Any, limit: int = _EVIDENCE_CHARS) -> str:
    """Marker fields are space-separated, so values must not contain spaces."""
    return " ".join(str(text or "").split())[:limit].replace(" ", "_")


def _marker(wm, finding: FuzzFinding, *, is_confirmed: bool,
            requests: int) -> str:
    mutation = finding.mutation
    verdict = finding.verdict
    score = _score(finding)
    cls = verdict.family_hint or mutation.family or "fuzz"
    name = f"{mutation.family}-g{mutation.generation}"
    evidence = f"{verdict.oracle}:{verdict.detail}"
    return (
        f"{MARKER} cls={_clean(cls, 20)} param={_clean(mutation.param, 40)} "
        f"name={_clean(name, 40)} endpoint={_clean(_endpoint_for(wm, mutation.param))} "
        f"port={_clean(_port_of(wm))} signals={_clean(verdict.oracle, 40)} "
        f"score={score:.2f} confirmed={'true' if is_confirmed else 'false'} "
        f"severity={_severity(score, is_confirmed)} requests={int(requests)} "
        f"evidence={_clean(evidence)}")


def fuzz_interp(output: str, wm, slots) -> List[Finding]:
    """Parse ``FUZZ:`` markers into ``hunt_anomaly`` findings.

    The value shape matches ``_hunt_web_interp`` exactly (plus ``param``), so
    every downstream consumer of the anomaly fact keeps working. Never raises:
    a truncated or garbage line is skipped, not fatal.
    """
    findings: List[Finding] = []
    try:
        lines = str(output or "").splitlines()
    except Exception:
        return findings
    for line in lines:
        try:
            if not line.startswith(MARKER):
                continue
            kv: Dict[str, str] = {}
            for chunk in line[len(MARKER):].split():
                if "=" in chunk:
                    key, value = chunk.split("=", 1)
                    kv[key.strip()] = value.strip()
            cls = kv.get("cls")
            param = kv.get("param") or ""
            if not cls or not param:
                continue
            score = _safe_float(kv.get("score"))
            is_confirmed = kv.get("confirmed", "") == "true"
            key = f"{cls}:{kv.get('port', '?')}:{param}"
            findings.append(Finding(
                kind="hunt_anomaly", key=key,
                value={"cls": cls, "name": kv.get("name", ""),
                       "param": param,
                       "endpoint": kv.get("endpoint", ""),
                       "signals": kv.get("signals", ""),
                       "score": kv.get("score", ""),
                       "confirmed": is_confirmed,
                       "severity": kv.get("severity", "medium"),
                       "port": kv.get("port", ""),
                       "evidence": kv.get("evidence", "")[:300]},
                confidence=min(0.9, 0.5 + score * 0.15),
                source=CAPABILITY_ID,
                evidence=kv.get("evidence", "")[:300],
                target=getattr(wm, "target", "") or ""))
        except Exception:
            continue
    return findings


def _safe_float(raw: Any) -> float:
    try:
        return float(raw)
    except Exception:
        return 0.5
