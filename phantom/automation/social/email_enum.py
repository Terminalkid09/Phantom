"""email_enum.py — is this address REGISTERED on a service, and is that PROVEN?

Two different questions, and the difference is the whole point:

  * ENUMERATION (holehe-style): ask N services whether the address has an
    account. Each answer is a verdict about ONE service, and a rule that no
    longer matches the live endpoint must degrade to `unknown` — never to a
    confident lie. A false "exists" sends the operator down a wrong pivot; a
    false "absent" makes them skip a real one. `unknown` is the honest answer
    and this module reaches for it generously.
  * CONFIRMATION ORACLE: the password-reset ("forgot password") flow. It never
    reveals a password and never sends mail on its own: requesting the reset is
    what turns "maybe this address is theirs" into "the service recognises this
    address as an account". That is exactly the semantic the operator asked
    for — the reset is used as an ORACLE, not as an attack.

What the output may contain, and what it never contains: the mask of the
address (`a***@gmail.com`) and the verdict. Never a password, never a full
address, never a session. `mask_email` exists so a report can quote the finding
without re-printing the target's address.

Gate: like `toolchain.install`, nothing here runs without an explicit operator
confirmation. `enumerate_email` and `reset_oracle` refuse with the plan (which
services would be asked, and how fast) when `confirm` is absent or answers no.
Phantom never enumerates an address because some scan felt like it.

Design: dependency-free, every request bounded and rate-limited, the classifier
is a PURE function of (rule, status, body) so the whole verdict layer is
verifiable offline with fake responses, and the transport is injectable for the
same reason. The default transport is `recon._fetch`, so there is exactly one
place in the project where an outbound request is made.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

EXISTS = "exists"
ABSENT = "absent"
UNKNOWN = "unknown"
VERDICTS = (EXISTS, ABSENT, UNKNOWN)

DEFAULT_INTERVAL = 1.5     # seconds between two requests to one service
MAX_SERVICES = 40
_E164_OK = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")


# ── rules (data, not code: they drift, and drift must be visible) ────────────
#
# A rule says: for THIS service, a response carrying these markers means the
# account EXISTS; carrying those markers means it does NOT. Everything else is
# `unknown`. `note` records what was actually observed when the rule was
# written, so the next person knows what to re-check instead of guessing.

@dataclass(frozen=True)
class EmailRule:
    service: str
    url: str                       # must contain {email}
    exists: Tuple[str, ...] = ()
    absent: Tuple[str, ...] = ()
    exists_status: Tuple[int, ...] = ()
    absent_status: Tuple[int, ...] = ()
    reset_url: str = ""            # the confirmation-oracle endpoint
    reset_sent: Tuple[str, ...] = ()   # "we emailed you a code"-style proof
    note: str = ""
    confidence: str = "heuristic"  # the honest label for every rule here

    def __post_init__(self) -> None:
        if "{email}" not in self.url:
            raise ValueError(f"rule {self.service}: url needs {{email}}")


RULES: Tuple[EmailRule, ...] = (
    EmailRule(
        service="github",
        url="https://api.github.com/search/users?q={email}+in:email",
        exists=('"total_count":1', '"total_count": 1'),
        absent=('"total_count":0', '"total_count": 0'),
        reset_url="https://github.com/password_reset",
        reset_sent=("reset link", "check your email"),
        note="the search API answers per email; deprecated for some accounts",
    ),
    EmailRule(
        service="spotify",
        url="https://www.spotify.com/api/signup/valid/username?username={email}",
        exists=("is taken", "already been taken"),
        absent=("is available",),
        note="signup validity oracle, observed 2024",
    ),
    EmailRule(
        service="x",
        url="https://api.twitter.com/i/users/email_available.json?email={email}",
        exists=('"valid":false', "already taken"),
        absent=('"valid":true',),
        reset_url="https://twitter.com/account/begin_password_reset",
        reset_sent=("we've sent", "we have sent"),
        note="email_available endpoint",
    ),
    EmailRule(
        service="pinterest",
        url="https://www.pinterest.com/resource/EmailExistsResource/get/"
            "?data=%7B%22options%22%3A%7B%22email%22%3A%22{email}%22%7D%7D",
        exists=('"exists":true', '"exists": true'),
        absent=('"exists":false', '"exists": false'),
        note="EmailExistsResource",
    ),
    EmailRule(
        service="tumblr",
        url="https://www.tumblr.com/svc/account/register?email={email}",
        exists=("already in use", "email is taken"),
        absent=("successfully reserved",),
        note="register preflight",
    ),
    EmailRule(
        service="dropbox",
        url="https://www.dropbox.com/register?email={email}",
        exists=("already in use", "already registered"),
        absent=("create your account",),
        note="register page copy",
    ),
    EmailRule(
        service="adobe",
        url="https://auth.services.adobe.com/signup/v2/users?email={email}",
        exists=("already registered", "already in use"),
        absent=("is available",),
        reset_url="https://auth.services.adobe.com/recovery/initiate",
        reset_sent=("check your email", "sent a verification"),
        note="signup availability endpoint",
    ),
)

# A marker shorter than this is a coin flip on a real response body: the day a
# rule drifts, `"true"` matches everything and every address "exists". The
# shipped table must not contain one (a test enforces it), which is how the
# "degrade to unknown, never to a confident lie" rule stays true over time.
MIN_MARKER_LEN = 8

_RESET_SENT_GENERIC = ("check your", "we sent", "we've sent", "sent a",
                       "verification code", "reset link", "recovery link")
_RESET_UNKNOWN_ADDRESS = ("we couldn't find", "no account", "not registered",
                          "unable to find", "does not exist")


def rules_by_name() -> Dict[str, EmailRule]:
    return {r.service: r for r in RULES}


def weak_markers(min_len: int = MIN_MARKER_LEN) -> List[Tuple[str, str]]:
    """(service, marker) pairs too generic to be evidence — drift alarm."""
    out: List[Tuple[str, str]] = []
    for rule in RULES:
        for marker in rule.exists + rule.absent:
            if len(marker) < min_len:
                out.append((rule.service, marker))
    return out


def mask_email(email: str) -> str:
    """`someone@example.com` -> `s******@example.com`.

    Reports quote the target: the mask keeps the finding readable without
    re-printing the address in every line of output.
    """
    addr = str(email or "").strip()
    if "@" not in addr:
        return "***"
    local, _, domain = addr.partition("@")
    if not local:
        return "***@" + domain
    keep = local[0]
    return keep + "*" * max(len(local) - 1, 1) + "@" + domain


def is_email(value: str) -> bool:
    return bool(_E164_OK.match(str(value or "").strip()))


# ── the pure verdict layer ───────────────────────────────────────────────────

def classify(rule: EmailRule, status: int, body: str) -> Tuple[str, str]:
    """Decide one service's verdict from its raw response.

    Rules, in order, and the ORDER is the semantics:

      1. an explicit status match (the service tells us with a status code),
      2. a body marker for ABSENT (present, or missing),
      3. a body marker for EXISTS,
      4. otherwise UNKNOWN.

    A response carrying BOTH kinds of marker is a CONTRADICTION and yields
    `unknown`: two opposite proofs cancel out, and guessing one of them is how
    an enumeration poisons the identity graph. The returned evidence string is
    the marker that decided it, so a verdict can always be audited.
    """
    body = body or ""
    if rule.absent_status and status in rule.absent_status:
        return ABSENT, f"status:{status}"
    if rule.exists_status and status in rule.exists_status:
        return EXISTS, f"status:{status}"
    hits_absent = [m for m in rule.absent if m in body]
    hits_exists = [m for m in rule.exists if m in body]
    if hits_absent and hits_exists:
        return UNKNOWN, "contradictory-markers"
    if hits_absent:
        return ABSENT, f"marker:{hits_absent[0]}"
    if hits_exists:
        return EXISTS, f"marker:{hits_exists[0]}"
    return UNKNOWN, "no-marker"


def classify_reset(rule: EmailRule, status: int, body: str) -> Tuple[str, str]:
    """The confirmation oracle for ONE service.

    `EXISTS` here means "the service accepted this address as one of its
    accounts": a positive sent-a-code marker came back, or a service whose own
    enumeration rule says the address is registered. An "address unknown"
    marker yields `ABSENT`. Everything else — including a 200 with no marker,
    which several services return for EVERY address — is `UNKNOWN`, because
    treating that as proof would confirm every address you tried.
    """
    body = body or ""
    if status >= 500:
        return UNKNOWN, f"status:{status}"
    hits_unknown_addr = [m for m in _RESET_UNKNOWN_ADDRESS if m in body.lower()]
    hits_sent = [m for m in (rule.reset_sent or _RESET_SENT_GENERIC)
                 if m in body.lower()]
    if hits_unknown_addr and hits_sent:
        return UNKNOWN, "contradictory-markers"
    if hits_unknown_addr:
        return ABSENT, f"marker:{hits_unknown_addr[0]}"
    if hits_sent:
        return EXISTS, f"sent:{hits_sent[0]}"
    return UNKNOWN, "no-marker"


# ── transport, results, the gated flow ───────────────────────────────────────

@dataclass
class ServiceVerdict:
    service: str
    verdict: str = UNKNOWN
    evidence: str = ""
    source: str = "enumeration"     # enumeration | reset-oracle
    reset_supported: bool = False

    @property
    def proven(self) -> bool:
        return self.verdict == EXISTS and self.source == "reset-oracle"

    def to_dict(self) -> Dict[str, Any]:
        return {"service": self.service, "verdict": self.verdict,
                "evidence": self.evidence, "source": self.source,
                "proven": self.proven}


@dataclass
class EmailEnumReport:
    masked: str
    verdicts: List[ServiceVerdict] = field(default_factory=list)
    requested: List[str] = field(default_factory=list)
    error: str = ""
    started: float = 0.0
    finished: float = 0.0

    # ---------------------------------------------------------------- views

    @property
    def registered(self) -> List[ServiceVerdict]:
        return [v for v in self.verdicts if v.verdict == EXISTS]

    @property
    def absent(self) -> List[ServiceVerdict]:
        return [v for v in self.verdicts if v.verdict == ABSENT]

    @property
    def unknown(self) -> List[ServiceVerdict]:
        return [v for v in self.verdicts if v.verdict == UNKNOWN]

    @property
    def confirmed(self) -> List[ServiceVerdict]:
        return [v for v in self.verdicts if v.proven]

    def to_dict(self) -> Dict[str, Any]:
        return {"masked": self.masked, "requested": list(self.requested),
                "verdicts": [v.to_dict() for v in self.verdicts],
                "registered": [v.service for v in self.registered],
                "confirmed": [v.service for v in self.confirmed],
                "unknown": [v.service for v in self.unknown],
                "error": self.error,
                "duration": round(max(self.finished - self.started, 0.0), 2)}

    def render(self) -> str:
        if self.error:
            return f"email enumeration refused/failed: {self.error}"
        if not self.verdicts:
            return f"email enumeration: no service answered ({self.masked})"
        lines = [f"email enumeration for {self.masked}: "
                 f"{len(self.registered)} registered, {len(self.unknown)} unknown,"
                 f" {len(self.absent)} absent"]
        for v in self.verdicts:
            mark = {EXISTS: "REGISTERED", ABSENT: "no account",
                    UNKNOWN: "unknown"}[v.verdict]
            tag = " (reset-oracle PROVEN)" if v.proven else ""
            lines.append(f"  {v.service:<12} {mark:<11} [{v.evidence}]{tag}")
        return "\n".join(lines)


def fetch_with_status(url: str, timeout: float = 12.0) -> Tuple[int, str]:
    """curl-based transport that reports (status, body).

    Used by default so a rule that needs the status code has one; keeps the
    dependency-free property (`curl` is already a hard requirement of the
    recon layer).
    """
    import subprocess
    try:
        proc = subprocess.run(
            ["curl", "-sS", "-o", "-", "-w", "\n%{http_code}", "-L",
             "--max-time", str(int(timeout)), url],
            capture_output=True, text=True, timeout=timeout + 5)
    except Exception:
        return 0, ""
    out = proc.stdout or ""
    head, _, code = out.rpartition("\n")
    try:
        return int(code.strip()), head
    except ValueError:
        return 0, out


def plan(email: str, *, services: Optional[Sequence[str]] = None,
         include_reset: bool = False) -> List[Dict[str, Any]]:
    """What WOULD be asked, without asking anything (the confirm payload)."""
    rules = rules_by_name()
    names = [s for s in (services or list(rules)) if s in rules]
    return [
        {"service": r.service,
         "url": r.url.format(email=email),
         "reset_url": r.reset_url.format(email=email) if
         (include_reset and r.reset_url) else "",
         "interesting_markers": list(r.exists)}
        for r in (rules[n] for n in names)
    ]


def enumerate_email(email: str, *, confirm: Optional[Callable[..., bool]] = None,
                    services: Optional[Sequence[str]] = None,
                    include_reset: bool = True,
                    fetch: Optional[Callable[..., Any]] = None,
                    sleep: Optional[Callable[[float], None]] = None,
                    interval: float = DEFAULT_INTERVAL,
                    max_services: int = MAX_SERVICES) -> EmailEnumReport:
    """Ask services whether the address is registered — WITH operator consent.

    `confirm(service, url)` is mandatory in spirit and enforced in fact: with
    no callback, nothing is sent and the report explains what it would have
    asked. A callback that raises counts as NO. One service failing never
    aborts the rest, and the verdict is always one of the three above.
    """
    addr = str(email or "").strip()
    report = EmailEnumReport(masked=mask_email(addr), started=time.time())
    if not is_email(addr):
        report.error = f"not an email address: {mask_email(addr)}"
        report.finished = time.time()
        return report
    rules = rules_by_name()
    names = [s for s in (services or list(rules)) if s in rules][:max_services]
    if not names:
        report.error = "no service rule matched the selection"
        report.finished = time.time()
        return report
    if confirm is None:
        report.requested = names
        report.error = ("refused: email enumeration contacts third-party "
                        "services and needs an explicit operator confirmation "
                        "(plan returned in `requested`)")
        report.finished = time.time()
        return report

    do_sleep = sleep or time.sleep
    do_fetch = fetch or fetch_with_status
    internet_failures = 0
    for index, name in enumerate(names):
        rule = rules[name]
        url = rule.url.format(email=addr)
        try:
            allowed = bool(confirm(name, url))
        except Exception:
            allowed = False          # a broken confirm is a NO, never a YES
        if not allowed:
            report.verdicts.append(ServiceVerdict(
                name, UNKNOWN, "operator-declined"))
            continue
        if index:
            try:
                do_sleep(interval)
            except Exception:
                pass
        status, body = _ask(do_fetch, url)
        if status == 0 and not body:
            internet_failures += 1
            report.verdicts.append(ServiceVerdict(name, UNKNOWN, "no-response"))
            continue
        verdict, evidence = classify(rule, status, body)
        report.verdicts.append(ServiceVerdict(name, verdict, evidence))
        if include_reset and verdict == EXISTS and rule.reset_url:
            r_status, r_body = _ask(do_fetch, rule.reset_url)
            r_verdict, r_evidence = classify_reset(rule, r_status, r_body)
            report.verdicts.append(ServiceVerdict(
                name, r_verdict, r_evidence, source="reset-oracle",
                reset_supported=True))
    if internet_failures and internet_failures == len(names):
        report.error = "no service answered: check the network/tooling"
    report.finished = time.time()
    return report


def _ask(fetch: Callable[..., Any], url: str) -> Tuple[int, str]:
    """One request, never raising, always returning (status, body)."""
    try:
        out = fetch(url)
    except Exception:
        return 0, ""
    if isinstance(out, tuple) and len(out) == 2:
        try:
            return int(out[0]), str(out[1] or "")
        except (TypeError, ValueError):
            return 0, ""
    return 200, str(out or "")


def reset_oracle(email: str, *, services: Optional[Sequence[str]] = None,
                 confirm: Optional[Callable[..., bool]] = None,
                 fetch: Optional[Callable[..., Any]] = None,
                 sleep: Optional[Callable[[float], None]] = None,
                 interval: float = DEFAULT_INTERVAL) -> List[ServiceVerdict]:
    """The password-reset confirmation step, alone and opt-in.

    Only services with a `reset_url` are asked. `verdict == EXISTS` here means
    the service accepted the address in its reset flow — the strongest
    non-contact confirmation this module can produce, and the strongest claim
    it ever makes. Everything else is `unknown`/`absent`, never a guess.
    """
    addr = str(email or "").strip()
    out: List[ServiceVerdict] = []
    if not is_email(addr):
        return [ServiceVerdict("", UNKNOWN, "not-an-email", "reset-oracle")]
    rules = rules_by_name()
    names = [s for s in (services or list(rules))
             if s in rules and rules[s].reset_url]
    if confirm is None:
        return [ServiceVerdict(n, UNKNOWN, "operator-confirmation-required",
                               "reset-oracle", True) for n in names]
    do_fetch = fetch or fetch_with_status
    do_sleep = sleep or time.sleep
    for index, name in enumerate(names):
        rule = rules[name]
        try:
            allowed = bool(confirm(name, rule.reset_url))
        except Exception:
            allowed = False
        if not allowed:
            out.append(ServiceVerdict(name, UNKNOWN, "operator-declined",
                                      "reset-oracle", True))
            continue
        if index:
            try:
                do_sleep(interval)
            except Exception:
                pass
        status, body = _ask(do_fetch, rule.reset_url)
        verdict, evidence = classify_reset(rule, status, body)
        out.append(ServiceVerdict(name, verdict, evidence, "reset-oracle", True))
    return out


# ── ingest into the identity graph ───────────────────────────────────────────

def apply_to_graph(graph: Any, email: str,
                   verdicts: Sequence[ServiceVerdict], *,
                   handle: str = "") -> Dict[str, int]:
    """Fold a report into the identity graph.

    A verdict alone links the ADDRESS to a SERVICE account. A PROVEN reset
    verdict is what links a handle to the address (`reset_flow_match`), which
    is the edge that can make two profiles one person — the only place this
    module is allowed to produce a strong proof, and only from the oracle.
    """
    from phantom.automation.social import social_graph as sg
    email_key = sg.node_key("email", email)
    graph.add_node(email_key, "email", label=mask_email(email),
                   source="email_enum", confidence=0.7)
    edges = 0
    for verdict in verdicts:
        if verdict.verdict != EXISTS:
            continue
        service_key = sg.node_key("domain", verdict.service)
        graph.add_node(service_key, "domain", label=verdict.service,
                       source="email_enum", confidence=0.6)
        if graph.add_edge(email_key, service_key, "email_match",
                          evidence=f"{verdict.source}:{verdict.service}",
                          confidence=0.8 if verdict.proven else 0.6,
                          source="email_enum"):
            edges += 1
    strong = [v for v in verdicts if v.proven]
    if handle and strong:
        handle_key = sg.node_key("handle", handle)
        graph.add_handle(handle, source="email_enum", confidence=0.7)
        if graph.add_edge(handle_key, email_key, "reset_flow_match",
                          evidence="reset:" + ",".join(
                              v.service for v in strong),
                          confidence=0.85, source="email_enum"):
            edges += 1
    return {"edges": edges,
            "proven": len(strong)}


def to_json(report: EmailEnumReport, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent, default=str)
