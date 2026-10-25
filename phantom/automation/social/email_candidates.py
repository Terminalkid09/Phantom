"""email_candidates.py — from a person to the addresses worth TESTING.

The reset oracle in ``email_enum`` answers "does this service know this
address" — it is a yes/no, not a way to unmask ``c***@gmail.com``. Reading
the mask gives a pattern (first letter, domain, length), never the address.
So the missing half is generation: turn the identity facts an engagement
already holds (name, handle, employer domain, breach corpus) into a short,
ranked list of plausible addresses, then spend the oracle on the top few.

Design rules:

* **Generation is offline.** No request is made here; the module is pure
  and testable. Verification is a separate, consent-gated call.
* **Ranking is explicit.** Common corporate patterns beat exotic ones, a
  known employer domain beats a guessed one, a breach hit is real evidence
  and a handle match is a strong personal-account signal.
* **Outputs are masked.** ``Candidate.markers()`` never prints a full
  address; the raw value is only available to the caller that verifies it.
  That keeps a report safe to quote.
* **The oracle confirms, it does not explode.** A `verified` candidate is
  one the service accepted in its reset flow; absence/unknown stay honest.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from phantom.automation.social.email_enum import (
    EXISTS,
    UNKNOWN,
    mask_email,
    reset_oracle,
)

# How common each local-part pattern is in the wild (corporate + personal).
PATTERN_WEIGHTS: Dict[str, float] = {
    "first.last": 0.95,
    "firstlast": 0.90,
    "f.last": 0.82,
    "first.l": 0.78,
    "first_last": 0.70,
    "first": 0.62,
    "last.first": 0.58,
    "handle": 0.72,
    "handle.last": 0.60,
}

# A corporate domain is worth more than a guessed free-mail one.
DOMAIN_WEIGHTS: Dict[str, float] = {
    "corporate": 1.0,
    "breach": 0.95,
    "explicit": 0.9,
    "free": 0.75,
    "guessed": 0.6,
}

def _fold(text: str) -> str:
    """Lowercase, strip accents/punctuation that mail providers drop."""
    text = unicodedata.normalize("NFKD", str(text or ""))
    text = "".join(c for c in text if not unicodedata.combining(c))
    return re.sub(r"[^a-z0-9]+", "", text.lower())


def normalize_person(first: str = "", last: str = "") -> Tuple[str, str]:
    return _fold(first), _fold(last)


def normalize_handle(handle: str = "") -> str:
    """Handles keep dots/underscores (they are part of the address)."""
    text = unicodedata.normalize("NFKD", str(handle or ""))
    text = "".join(c for c in text if not unicodedata.combining(c))
    text = text.lower().lstrip("@")
    return re.sub(r"[^a-z0-9._-]+", "", text).strip("._-")


@dataclass
class Candidate:
    """One plausible address, with why it was proposed."""

    email: str
    pattern: str
    domain_kind: str = "guessed"
    score: float = 0.0
    reasons: Tuple[str, ...] = field(default_factory=tuple)

    @property
    def masked(self) -> str:
        return mask_email(self.email)

    def markers(self) -> str:
        return (f"EMAIL_CANDIDATE: masked={self.masked} "
                f"pattern={self.pattern} domain={self.domain_kind} "
                f"score={self.score:.2f}")

    def to_dict(self) -> Dict[str, object]:
        return {"masked": self.masked, "pattern": self.pattern,
                "domain_kind": self.domain_kind,
                "score": round(self.score, 2), "reasons": list(self.reasons)}


def _local_parts(first: str, last: str, handle: str) -> List[Tuple[str, str]]:
    f, l = normalize_person(first, last)
    h = normalize_handle(handle)
    out: List[Tuple[str, str]] = []
    if f and l:
        out += [(f"{f}.{l}", "first.last"), (f"{f}{l}", "firstlast"),
                (f"{f[0]}.{l}", "f.last"), (f"{f}.{l[0]}", "first.l"),
                (f"{f}_{l}", "first_last"), (f"{l}.{f}", "last.first")]
    if f:
        out.append((f, "first"))
    if h:
        out.append((h, "handle"))
        if l:
            out.append((f"{h}.{l}", "handle.last"))
    seen = set()
    uniq: List[Tuple[str, str]] = []
    for local, pattern in out:
        if local and local not in seen:
            seen.add(local)
            uniq.append((local, pattern))
    return uniq


def _domains(domain: str, extra: Iterable[str],
             breach_emails: Iterable[str]) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    seen = set()

    def add(value: str, kind: str) -> None:
        dom = str(value or "").strip().lower().lstrip("@")
        if not dom or "." not in dom or dom in seen:
            return
        seen.add(dom)
        out.append((dom, kind))

    for raw in breach_emails:
        addr = str(raw or "").strip().lower()
        if "@" in addr:
            add(addr.rsplit("@", 1)[-1], "breach")
    add(domain, "corporate")
    for dom in extra:
        add(dom, "explicit")
    for dom in ("gmail.com", "outlook.com", "libero.it"):
        add(dom, "free")
    return out


def generate(first: str = "", last: str = "", handle: str = "",
             domain: str = "", *, extra_domains: Iterable[str] = (),
             breaches: Sequence[str] = ()) -> List[Candidate]:
    """Ranked plausible addresses from identity facts. Pure, offline."""
    locals_ = _local_parts(first, last, handle)
    domains = _domains(domain, extra_domains, breaches)
    breach_locals: Dict[str, str] = {}
    for raw in breaches:
        addr = str(raw or "").strip().lower()
        if "@" in addr:
            local, dom = addr.rsplit("@", 1)
            breach_locals[f"{local}@{dom}"] = local

    scored: List[Candidate] = []
    for local, pattern in locals_:
        for dom, kind in domains:
            email = f"{local}@{dom}"
            base = PATTERN_WEIGHTS.get(pattern, 0.5)
            score = base * DOMAIN_WEIGHTS.get(kind, 0.6)
            reasons = [f"pattern:{pattern}", f"domain:{kind}"]
            if email in breach_locals:
                score += 0.35
                reasons.append("breach_hit")
            scored.append(Candidate(email=email, pattern=pattern,
                                    domain_kind=kind,
                                    score=round(min(1.0, score), 3),
                                    reasons=tuple(reasons)))
    # The same local part on N domains: keep the best, but keep the rest
    # ranked below it (the oracle may confirm a secondary one).
    scored.sort(key=lambda c: (-c.score, c.email))
    return scored


def top(candidates: Sequence[Candidate], limit: int = 5) -> List[Candidate]:
    return list(candidates)[:max(0, int(limit))]


@dataclass
class Verified:
    candidate: Candidate
    verdict: str = UNKNOWN
    evidence: str = ""

    def marker(self) -> str:
        return (f"EMAIL_VERIFIED: masked={self.candidate.masked} "
                f"verdict={self.verdict} evidence={_one(self.evidence)}")


def verify(candidates: Sequence[Candidate], *,
           confirm: Optional[Callable[..., bool]] = None,
           oracle: Optional[Callable[..., list]] = None,
           max_candidates: int = 3,
           services: Optional[Sequence[str]] = None,
           fetch=None, sleep=None) -> List[Verified]:
    """Spend the reset oracle on the top candidates, in rank order.

    ``confirm`` is mandatory in spirit: with no callback the oracle refuses
    and every result stays `unknown` with that reason — nothing is sent.
    ``oracle`` is injectable for tests (and for a caller with its own
    transport); the default is :func:`email_enum.reset_oracle`.
    """
    ask = oracle or reset_oracle
    out: List[Verified] = []
    for cand in top(candidates, max_candidates):
        try:
            verdicts = ask(cand.email, services=services, confirm=confirm,
                           fetch=fetch, sleep=sleep) or []
        except Exception as exc:                     # a broken oracle is "no"
            out.append(Verified(cand, UNKNOWN, f"oracle-error:{exc}"[:160]))
            continue
        verdict = UNKNOWN
        evidence = ""
        for v in verdicts:
            # reset-oracle verdicts are the only ones that count here; the
            # generic "service knows the address" ones are supporting.
            if getattr(v, "verdict", "") == EXISTS:
                verdict = EXISTS
                evidence = getattr(v, "evidence", "") or "reset accepted"
                break
            if not evidence:
                evidence = getattr(v, "evidence", "") or ""
        out.append(Verified(cand, verdict, evidence))
    return out


def _one(text: str) -> str:
    return " ".join(str(text or "").split())[:120]
