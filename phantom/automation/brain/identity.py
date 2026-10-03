"""
phantom.automation.brain.identity — reasoning over a THIN identity field.

The operator's manual loop, generalized: from a single narrow field
(an Instagram handle, a masked reset email, a leaked address) a senior
operator DEDUCES the next field, verifies it cheaply, and only then
spends exposure. This module is that reasoning step, made explicit,
bounded and auditable:

    handle        -> local-part + candidate domains   (where else does it live)
    masked email  -> confirmed local-part/domain      (the reset leak)
    name + domain -> email CANDIDATES                 (the "crunch" step)
    verified email-> service accounts + handle variants (where it is an account)
    breach        -> widened identity + reused creds   (same person, elsewhere)

Design rules (non-negotiable, they mirror the operator's decisions):

* every output is a CANDIDATE (``*_candidate`` / ``identity_widened`` /
  ``service_account``). None of these kinds gates any capability, so an
  inference can GUIDE a move but never AUTHORIZE it — the same rule the
  machine-side reasoning engine follows.
* NO GUESSING OF DOMAINS. A candidate domain must be OBSERVED (an email
  already in hand, a domain surfaced in a profile link). The engine never
  invents "gmail.com" out of nothing; that is the difference between
  reasoning and noise.
* the ladder is NON-CONTACT FIRST. The hypotheses this module proposes
  order passive discovery before active verification, and active
  verification before any contact capability. Phishing is only proposed
  when the passive+active ladder is exhausted AND contact consent exists.
* bounded: candidate generation is capped and deduplicated, so a thin
  field cannot explode into an unbounded probe list.

The module is pure (no I/O, no registry required). The reasoning engine
(``reasoning.py``) owns the rule wiring and the registry filter; the
identity phase capabilities (``guidance/kit.py``) own execution.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

# ── finding kinds (all NON-gating) ─────────────────────────────────────────

KIND_IDENTITY = "identity"
KIND_PROFILE = "profile"
KIND_ACCOUNT_LINK = "account_link"
KIND_EMAIL_MASKED = "email_masked"          # the reset-leak mask
KIND_DOMAIN_CANDIDATE = "domain_candidate"  # an observed domain
KIND_EMAIL_CANDIDATE = "email_candidate"    # a generated address
KIND_EMAIL_VERIFIED = "email_verified"      # existence confirmed
KIND_SERVICE_ACCOUNT = "service_account"    # where an address is an account
KIND_BREACH_EXPOSURE = "breach_exposure"
KIND_IDENTITY_WIDENED = "identity_widened"
KIND_CREDS = "creds"

# candidate-generation bounds
MAX_CANDIDATES = 200
MAX_DOMAINS = 8

# separators used when composing name parts into a local-part
_SEPARATORS = (".", "_", "-", "")

# the local-part of an address, up to (not including) the domain
_LOCAL_RE = re.compile(r"^[^@\s<>()]+@")
_MASK_RE = re.compile(r"^([A-Za-z0-9._%+\-*]*[*●•]{1,}[A-Za-z0-9._%+\-*]*)@")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_DOMAIN_RE = re.compile(r"\b([A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
                        r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+)\b")

# domains that are never a person's mailbox provider we should probe
_NOISE_DOMAINS = frozenset({
    "instagram.com", "tiktok.com", "twitter.com", "x.com", "github.com",
    "reddit.com", "telegram.org", "t.me", "facebook.com", "youtube.com",
    "google.com", "gstatic.com", "fbcdn.net", "cdninstagram.com",
    "schema.org", "w3.org", "example.com",
})

# name particles that are not a usable local-part token
_NAME_NOISE = frozenset({"di", "de", "del", "della", "da", "van", "von",
                         "der", "la", "le", "el", "bin", "ibn"})


@dataclass(frozen=True)
class Derivation:
    """One deduced identity field + the move that would verify it."""
    kind: str
    key: str
    value: Dict[str, Any]
    confidence: float
    evidence: str
    source: str = "identity_reasoning"
    # capability hypothesis that would turn this candidate into a fact
    hypothesis: Optional[Dict[str, Any]] = None

    def to_dict(self) -> dict:
        return {"kind": self.kind, "key": self.key, "value": self.value,
                "confidence": round(self.confidence, 2),
                "evidence": self.evidence,
                "hypothesis": self.hypothesis}


# ── parsing helpers ────────────────────────────────────────────────────────

def local_part(address: str) -> str:
    """The local-part of an address (mask preserved), or ''."""
    a = (address or "").strip()
    if "@" not in a:
        return ""
    return a.rsplit("@", 1)[0].strip().lower()


def domain_of(address: str) -> str:
    """The domain of an address, or ''."""
    a = (address or "").strip().lower()
    if "@" not in a:
        return ""
    dom = a.rsplit("@", 1)[1].strip()
    return dom if "." in dom else ""


def mask_shape(masked: str) -> Dict[str, Any]:
    """Describe a masked address: visible prefix/suffix + domain.

    ``m***o@gmail.com`` -> {prefix:'m', suffix:'o', domain:'gmail.com',
    length:5}. The shape is what lets a candidate list be RANKED: an
    address whose local-part starts with 'm' and ends with 'o' is a far
    better fit than one that does not.
    """
    m = _MASK_RE.match((masked or "").strip())
    if not m:
        return {}
    body = m.group(1)
    dom = domain_of(masked)
    stars = sum(1 for c in body if c in "*●•")
    prefix = body.split("*")[0].split("●")[0].split("•")[0]
    suffix = ""
    for ch in ("*", "●", "•"):
        if ch in body:
            suffix = body.rsplit(ch, 1)[1]
            break
    return {"prefix": prefix, "suffix": suffix, "domain": dom,
            "length": len(body), "masked": masked, "stars": stars}


def name_parts(name: str) -> List[str]:
    """Usable local-part tokens from a real name ('Mario Rossi' -> [mario, rossi])."""
    out: List[str] = []
    for token in re.split(r"[^A-Za-z0-9]+", (name or "")):
        t = token.strip().lower()
        if len(t) < 2 or t in _NAME_NOISE or t in out:
            continue
        out.append(t)
    return out


def _dedupe(seq: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for item in seq:
        k = (item or "").strip().lower()
        if not k or k in seen:
            continue
        seen.add(k)
        out.append(k)
    return out


# ── the reasoner ───────────────────────────────────────────────────────────

class IdentityReasoner:
    """Deduce identity fields from what is already known.

    ``active_consent`` mirrors the dedicated consent flag (I2): without it
    the reasoner never proposes an ACTIVE probe (SMTP RCPT / reset-enum),
    only passive discovery. Contact (phish/dm) is proposed only when
    ``contact_consent`` is given AND the ladder is exhausted.
    """

    def __init__(self, *, active_consent: bool = False,
                 contact_consent: bool = False,
                 max_candidates: int = MAX_CANDIDATES) -> None:
        self.active_consent = bool(active_consent)
        self.contact_consent = bool(contact_consent)
        self.max_candidates = max(1, int(max_candidates))

    # ── collected inputs ───────────────────────────────────────────────

    @staticmethod
    def _known_handles(wm) -> List[str]:
        out: List[str] = []
        for kind in (KIND_PROFILE, KIND_IDENTITY, KIND_ACCOUNT_LINK,
                     KIND_IDENTITY_WIDENED):
            for f in wm.find(kind):
                v = f.value if isinstance(f.value, dict) else {}
                for k in ("username", "handle", "user"):
                    if v.get(k):
                        out.append(str(v[k]).lstrip("@"))
        # the engagement target itself, when it is a handle
        tt = (getattr(wm, "target_type", "") or "").lower()
        if tt in ("username", "handle") and wm.target:
            out.append(str(wm.target).lstrip("@"))
        return _dedupe(out)

    @staticmethod
    def _known_names(wm) -> List[str]:
        out: List[str] = []
        for kind in (KIND_PROFILE, KIND_IDENTITY, "dossier"):
            for f in wm.find(kind):
                v = f.value if isinstance(f.value, dict) else {}
                for k in ("full_name", "name", "real_name"):
                    if v.get(k):
                        out.append(str(v[k]))
        return out

    @staticmethod
    def _known_addresses(wm) -> List[Tuple[str, str]]:
        """(address, source_kind) for every email already observed."""
        out: List[Tuple[str, str]] = []
        for kind in (KIND_IDENTITY, KIND_PROFILE, KIND_BREACH_EXPOSURE,
                     KIND_EMAIL_VERIFIED, KIND_EMAIL_CANDIDATE):
            for f in wm.find(kind):
                v = f.value if isinstance(f.value, dict) else {}
                addr = str(v.get("email") or v.get("address") or "").strip()
                if addr and "@" in addr:
                    out.append((addr, kind))
        return out

    def _known_domains(self, wm) -> List[str]:
        """OBSERVED domains only — from emails, explicit domain facts and
        domains surfaced inside profile links. Never invented."""
        doms: List[str] = []
        for addr, _src in self._known_addresses(wm):
            d = domain_of(addr)
            if d:
                doms.append(d)
        for f in wm.find(KIND_DOMAIN_CANDIDATE):
            v = f.value if isinstance(f.value, dict) else {}
            d = str(v.get("domain") or f.key or "").strip().lower()
            if d:
                doms.append(d)
        for f in wm.find(KIND_PROFILE):
            v = f.value if isinstance(f.value, dict) else {}
            for k in ("link", "website", "url"):
                raw = str(v.get(k) or "")
                for m in _DOMAIN_RE.finditer(raw):
                    doms.append(m.group(1).lower())
        clean: List[str] = []
        for d in _dedupe(doms):
            if d in _NOISE_DOMAINS or "." not in d:
                continue
            clean.append(d)
        return clean[:MAX_DOMAINS]

    # ── rules ──────────────────────────────────────────────────────────

    def _rule_local_parts(self, wm) -> List[Derivation]:
        """handle / masked email -> the local-part it implies + the domain."""
        out: List[Derivation] = []
        for handle in self._known_handles(wm):
            if len(handle) < 2:
                continue
            out.append(Derivation(
                kind=KIND_EMAIL_CANDIDATE, key=f"email_candidate:handle:{handle}",
                value={"local_part": handle, "handle": handle, "domain": "",
                       "why": "handle as local-part"},
                confidence=0.35,
                evidence=f"handle '{handle}' can be the local-part of an address",
                hypothesis=self._verify_hyp("handle implies a local-part")))
        for f in wm.find(KIND_EMAIL_MASKED):
            v = f.value if isinstance(f.value, dict) else {}
            masked = str(v.get("masked") or v.get("email") or "")
            shape = mask_shape(masked)
            if not shape:
                continue
            out.append(Derivation(
                kind=KIND_DOMAIN_CANDIDATE, key=f"domain_candidate:{shape['domain']}",
                value={"domain": shape["domain"], "observed": True,
                       "from": "reset leak"},
                confidence=0.8,
                evidence=f"masked reset email reveals domain {shape['domain']}",
                hypothesis=None))
            out.append(Derivation(
                kind=KIND_EMAIL_MASKED, key=f"email_masked:{masked}",
                value=shape, confidence=0.8,
                evidence=f"masked address shape from {masked}",
                hypothesis=self._verify_hyp(
                    "masked reset email narrows the local-part")))
        return out

    def _rule_email_candidates(self, wm) -> List[Derivation]:
        """name + handle + observed domains -> candidate addresses (the
        'crunch' step, but identity-aware and bounded)."""
        domains = self._known_domains(wm)
        if not domains:
            return []          # no observed domain: do NOT guess one
        handles = self._known_handles(wm)
        tokens: List[str] = []
        for name in self._known_names(wm):
            parts = name_parts(name)
            tokens.extend(parts)
            if len(parts) >= 2:
                first, last = parts[0], parts[-1]
                for sep in _SEPARATORS:
                    tokens.append(f"{first}{sep}{last}")
                tokens.append(f"{first[0]}{last}")
                tokens.append(f"{first}{last[0]}")
                tokens.append(f"{last}{sep}{first}" if sep else f"{last}{first}")
        tokens.extend(handles)
        tokens = [t for t in _dedupe(tokens) if 2 <= len(t) <= 40]

        out: List[Derivation] = []
        count = 0
        for dom in domains:
            for tok in tokens:
                if count >= self.max_candidates:
                    break
                addr = f"{tok}@{dom}"
                out.append(Derivation(
                    kind=KIND_EMAIL_CANDIDATE, key=f"email_candidate:{addr}",
                    value={"email": addr, "local_part": tok, "domain": dom,
                           "why": "name/handle x observed domain"},
                    confidence=0.3,
                    evidence=f"candidate from tokens x observed domain {dom}",
                    hypothesis=self._verify_hyp(
                        f"verify candidate {addr}")))
                count += 1
        return out

    def _rule_expand_from_email(self, wm) -> List[Derivation]:
        """A VERIFIED address is an account somewhere: derive the handle
        variants (same person elsewhere) and the services to look at."""
        verified = [f for f in wm.find(KIND_EMAIL_VERIFIED)]
        out: List[Derivation] = []
        for f in verified:
            v = f.value if isinstance(f.value, dict) else {}
            addr = str(v.get("email") or "")
            if not addr:
                continue
            lp = local_part(addr)
            dom = domain_of(addr)
            if dom and dom not in _NOISE_DOMAINS:
                out.append(Derivation(
                    kind=KIND_DOMAIN_CANDIDATE, key=f"domain_candidate:{dom}",
                    value={"domain": dom, "observed": True,
                           "from": "verified email"},
                    confidence=0.9,
                    evidence=f"verified address confirms domain {dom}"))
            for variant in _handle_variants(lp):
                out.append(Derivation(
                    kind=KIND_IDENTITY_WIDENED, key=f"identity_widened:{variant}",
                    value={"handle": variant, "platform": "",
                           "from_email": addr, "why": "local-part variant"},
                    confidence=0.45,
                    evidence=f"handle variant '{variant}' of {addr}",
                    hypothesis=self._passive_hyp(
                        "resolve the handle variants on other platforms")))
            out.append(Derivation(
                kind=KIND_SERVICE_ACCOUNT, key=f"service_account:{addr}",
                value={"email": addr, "services": [], "known": False},
                confidence=0.4,
                evidence=f"{addr} is a live mailbox: find where it is an account",
                hypothesis=self._passive_hyp(
                    "map the services where this address is an account")))
        return out

    def _rule_breach_correlation(self, wm) -> List[Derivation]:
        """Breach exposure widens the identity and hands over reusable
        credentials — the same-person correlation the operator does."""
        out: List[Derivation] = []
        for f in wm.find(KIND_BREACH_EXPOSURE):
            v = f.value if isinstance(f.value, dict) else {}
            addr = str(v.get("email") or "")
            if not addr:
                continue
            lp = local_part(addr)
            out.append(Derivation(
                kind=KIND_IDENTITY_WIDENED, key=f"identity_widened:{lp}",
                value={"handle": lp, "platform": "", "from_email": addr,
                       "why": "breach local-part"},
                confidence=0.5,
                evidence=f"breach on {addr} links handle '{lp}'",
                hypothesis=self._passive_hyp(
                    "correlate the breached identity across platforms")))
        for f in wm.find(KIND_CREDS):
            v = f.value if isinstance(f.value, dict) else {}
            if v.get("source") == "breach" or v.get("service") == "leak":
                out.append(Derivation(
                    kind=KIND_SERVICE_ACCOUNT, key="service_account:leaked",
                    value={"email": str(v.get("username") or ""),
                           "services": ["leak"], "known": True,
                           "reused": False},
                    confidence=0.5,
                    evidence="leaked credential: test reuse elsewhere (no lockout)",
                    hypothesis=self._active_hyp(
                        "test credential reuse on discovered services")))
        return out

    def _rule_ladder(self, wm) -> List[Derivation]:
        """The NON-CONTACT-FIRST ladder: propose the moves that widen the
        field passively, then actively, and only as a LAST RESORT contact."""
        out: List[Derivation] = []
        has_identity = bool(wm.find(KIND_IDENTITY) or wm.find(KIND_PROFILE))
        has_masked = bool(wm.find(KIND_EMAIL_MASKED))
        has_candidates = bool(wm.find(KIND_EMAIL_CANDIDATE))
        has_verified = bool(wm.find(KIND_EMAIL_VERIFIED))
        has_breach = bool(wm.find(KIND_BREACH_EXPOSURE))

        if not has_identity:
            out.append(Derivation(
                kind=KIND_IDENTITY, key="identity:discovery",
                value={"stage": "discovery"}, confidence=0.0,
                evidence="no identity resolved yet",
                hypothesis=self._passive_hyp(
                    "resolve the handle before anything else")))
        if has_masked and not has_candidates:
            out.append(Derivation(
                kind=KIND_EMAIL_CANDIDATE, key="email_candidate:pending",
                value={"stage": "candidates"}, confidence=0.0,
                evidence="a masked address was leaked: enumerate candidates",
                hypothesis=self._passive_hyp(
                    "generate candidate addresses from the leak shape")))
        if has_candidates and not has_verified:
            # active verification is CONSENT-GATED
            hyp = (self._active_hyp("verify the candidate addresses")
                   if self.active_consent else None)
            out.append(Derivation(
                kind=KIND_EMAIL_VERIFIED, key="email_verified:pending",
                value={"stage": "verify", "consent_required": True,
                       "consent": self.active_consent},
                confidence=0.0,
                evidence=("active verification allowed" if self.active_consent
                          else "candidates exist: verification needs the "
                               "identity-active consent flag"),
                hypothesis=hyp))
        if has_verified and not has_breach:
            out.append(Derivation(
                kind=KIND_BREACH_EXPOSURE, key="breach_exposure:pending",
                value={"stage": "breach"}, confidence=0.0,
                evidence="address confirmed: check breach exposure",
                hypothesis=self._passive_hyp(
                    "check breach exposure for the confirmed address")))
        # CONTACT is the last resort: only when the passive+active ladder
        # produced nothing actionable AND contact was explicitly allowed.
        ladder_exhausted = (has_identity and has_verified and has_breach
                            and not wm.find(KIND_SERVICE_ACCOUNT))
        if ladder_exhausted and self.contact_consent:
            out.append(Derivation(
                kind=KIND_IDENTITY, key="identity:contact-last-resort",
                value={"stage": "contact", "last_resort": True},
                confidence=0.0,
                evidence="field mapped, nothing reachable without contact",
                hypothesis=self._contact_hyp(
                    "contact the subject as a LAST resort")))
        return out

    # ── hypothesis helpers (contact ordering is encoded here) ──────────

    @staticmethod
    def _passive_hyp(reason: str) -> Dict[str, Any]:
        return {"capability_id": "osint_identity", "reason": reason,
                "cost": 0.4, "priority": 0.7, "contact": "none"}

    @staticmethod
    def _verify_hyp(reason: str) -> Dict[str, Any]:
        return {"capability_id": "email_verify", "reason": reason,
                "cost": 0.5, "priority": 0.75, "contact": "active"}

    @staticmethod
    def _active_hyp(reason: str) -> Dict[str, Any]:
        return {"capability_id": "email_verify", "reason": reason,
                "cost": 0.6, "priority": 0.8, "contact": "active"}

    @staticmethod
    def _contact_hyp(reason: str) -> Dict[str, Any]:
        return {"capability_id": "phish_identity", "reason": reason,
                "cost": 1.8, "priority": 0.2, "contact": "contact"}

    # ── public ─────────────────────────────────────────────────────────

    def reason(self, wm) -> List[Derivation]:
        out: List[Derivation] = []
        for rule in (self._rule_local_parts, self._rule_email_candidates,
                     self._rule_expand_from_email,
                     self._rule_breach_correlation, self._rule_ladder):
            out.extend(rule(wm))
        return out


def _handle_variants(local: str) -> List[str]:
    """Local-part variants that are plausibly the SAME handle elsewhere."""
    lp = (local or "").strip().lower()
    if len(lp) < 3:
        return []
    out = [lp]
    for sep in (".", "_", "-"):
        if sep in lp:
            out.append(lp.replace(sep, ""))
        else:
            # insert the separator between the first and second token
            for cut in range(2, len(lp) - 1):
                out.append(lp[:cut] + sep + lp[cut:])
    return _dedupe(out)[:12]


def handle_variants(local: str) -> List[str]:
    """Public alias (used by tests and the phase adapters)."""
    return _handle_variants(local)
