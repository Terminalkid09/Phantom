"""domain_readiness.py — the domain is the campaign's weakest link.

A perfect pretext from a domain with no SPF, no DKIM and `p=none` lands in
Spam no matter how good the copy is. This module scores the sending domain
from records the operator (or a DNS probe) already fetched — it never makes
a request itself, so it is usable before any infrastructure exists and it
is fully testable offline.

What it checks, in order of impact at Gmail/Microsoft 365:

    SPF     present, exactly one, and it does not end in +all/?all
    DKIM    at least one selector known (a message with no DKIM signature
            loses alignment even when SPF passes)
    DMARC   present, with a policy stricter than none and a reporting URI
    MX      present (a domain that cannot receive bounces is a reputation
            red flag; for cold outreach it is also a deliverability one)

The report explains the fix for every issue, because "score 40" alone is
not actionable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional

_SEV = ("critical", "high", "medium", "low")
_PENALTY = {"critical": 40, "high": 20, "medium": 8, "low": 3}
_DOMAIN = re.compile(r"^(?=.{3,253}$)([a-z0-9-]+\.)+[a-z]{2,}$", re.I)


@dataclass
class Issue:
    severity: str
    code: str
    detail: str
    fix: str = ""

    def line(self) -> str:
        return f"[{self.severity}] {self.code}: {self.detail}"


@dataclass
class DomainReport:
    domain: str = ""
    score: int = 100
    issues: List[Issue] = field(default_factory=list)

    @property
    def grade(self) -> str:
        v = self.score
        if v >= 90:
            return "A"
        if v >= 75:
            return "B"
        if v >= 60:
            return "C"
        if v >= 40:
            return "D"
        return "F"

    @property
    def blocking(self) -> bool:
        return any(i.severity == "critical" for i in self.issues)

    @property
    def ready(self) -> bool:
        return not self.blocking and self.score >= 60

    def codes(self, severity: Optional[str] = None) -> List[str]:
        return [i.code for i in self.issues
                if severity is None or i.severity == severity]

    def top_fix(self) -> str:
        for sev in _SEV:
            for i in self.issues:
                if i.severity == sev and i.fix:
                    return f"{i.code}: {i.fix}"
        return ""

    def marker(self) -> str:
        return (f"DOMAIN_READINESS: domain={self.domain} score={self.score} "
                f"grade={self.grade} ready={int(self.ready)} "
                f"issues={','.join(self.codes()) or 'none'}")

    def report(self) -> List[str]:
        out = [self.marker()]
        for i in sorted(self.issues, key=lambda x: _SEV.index(x.severity)):
            out.append("  " + i.line() + (f" -> {i.fix}" if i.fix else ""))
        return out


def _spf_records(spf: str) -> List[str]:
    return [part.strip() for part in str(spf or "").split(";")
            if part.strip().lower().startswith("v=spf1")]


def check_domain(domain: str, *, spf: str = "", dmarc: str = "",
                 dkim: Iterable[str] = (), mx: Iterable[str] = ()
                 ) -> DomainReport:
    """Score a sending domain from records already fetched. Pure function."""
    rep = DomainReport(domain=str(domain or "").strip().lower())
    issues = rep.issues

    def add(severity: str, code: str, detail: str, fix: str = "") -> None:
        issues.append(Issue(severity, code, detail, fix))

    dom = rep.domain
    if not dom:
        add("critical", "no_domain", "no sending domain",
            "a campaign needs a domain you control")
        rep.score = 0
        return rep
    if not _DOMAIN.match(dom):
        add("high", "odd_domain", f"{dom!r} does not look like a FQDN",
            "use a normal registrable domain")

    spf_parts = _spf_records(spf)
    if not spf_parts:
        add("critical", "no_spf",
            "no SPF record for the sending domain",
            "publish v=spf1 with only the relays you use, ending -all")
    elif len(spf_parts) > 1:
        add("high", "multiple_spf",
            "more than one SPF record — receivers treat the result as "
            "permerror", "merge them into ONE v=spf1 record")
    else:
        record = spf_parts[0].lower()
        if "+all" in record or "?all" in record:
            add("critical", "permissive_spf",
                "SPF ends in +all/?all: anyone may send as this domain",
                "end with -all and list only your relays")
        elif "~all" in record:
            add("medium", "softfail_spf",
                "SPF ends in ~all (softfail)", "move to -all once the relays "
                "are right")
        if "include:" not in record and "ip4:" not in record and \
                "ip6:" not in record:
            add("medium", "empty_spf",
                "SPF lists no authorised sender at all",
                "add the relay/IP that actually sends")

    dmarc_low = str(dmarc or "").strip().lower()
    if not dmarc_low:
        add("high", "no_dmarc",
            "no DMARC record: alignment failures are not even reported",
            "publish v=DMARC1 with p=none first, then quarantine/reject")
    else:
        policy = re.search(r"\bp\s*=\s*(none|quarantine|reject)", dmarc_low)
        if not policy:
            add("high", "dmarc_no_policy",
                "DMARC record has no p= policy", "add p=quarantine or p=reject")
        elif policy.group(1) == "none":
            add("medium", "dmarc_none",
                "DMARC policy is p=none: failures are monitored, not blocked",
                "raise to quarantine/reject after the reports are clean")
        if "rua=" not in dmarc_low:
            add("low", "dmarc_no_rua",
                "DMARC has no aggregate-report address",
                "add rua=mailto:dmarc@yourdomain")

    selectors = [s for s in (dkim or ()) if str(s).strip()]
    if not selectors:
        add("high", "no_dkim",
            "no DKIM selector known — messages lose alignment even when SPF "
            "passes", "sign with a selector and keep the key 2048-bit")
    elif any(len(str(s).strip()) < 2 for s in selectors):
        add("low", "odd_dkim_selector", "a DKIM selector looks malformed",
            "use the selector name your MTA publishes")

    if not list(mx or ()):
        add("medium", "no_mx",
            "no MX record: bounces cannot come back and the domain looks "
            "disposable", "add MX (even a null MX is a statement)")

    rep.score = max(0, min(100, 100 - sum(_PENALTY[i.severity]
                                          for i in issues)))
    return rep


def combined_ready(text_report, domain_report: DomainReport) -> bool:
    """A send is defensible only when BOTH the domain and the pretext pass."""
    text_ok = bool(getattr(text_report, "ready", False))
    return text_ok and domain_report.ready
