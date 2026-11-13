"""
dossier.py — strategic-phishing target analysis.

Strategic phishing is ONE well-crafted lure per target, not a spray-and-pray
blast. The dossier is the intelligence file that makes that lure credible:

  * everything the engagement actually discovered (name, emails, phones,
    platform, company) is merged into one profile
  * breach facts are CORRELATED across channels: when the same breach name
    shows up for the victim's email AND their phone, that is a strong,
    verifiable hook the target will recognize ("how do you know my number?")
  * a deterministic scorer ranks the pretext library against the dossier so
    the campaign starts with the story most likely to convert (delivery
    notification when we only have a phone, security alert when we have a
    platform + a real breach, recruiter when we have a public profile ...)

Everything here is pure data + scoring: no network, no side effects, fully
unit-testable. The optional LLM advisor can refine the pick afterwards, but
the deterministic scorer is what guarantees a sensible default offline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class BreachFact:
    """A breach the target's identity was exposed in, across channels."""

    name: str
    date: str = ""
    channels: List[str] = field(default_factory=list)  # email | phone | username

    @property
    def cross_channel(self) -> bool:
        """True when the same breach hit more than one channel (e.g. email
        AND phone) — the strongest recognition hook a lure can use."""
        return len(set(self.channels)) > 1


@dataclass
class TargetDossier:
    """One target, everything known, plus derived strategic signals."""

    name: str = ""
    emails: List[str] = field(default_factory=list)
    phones: List[str] = field(default_factory=list)
    platform: str = ""
    company: str = ""
    breaches: List[BreachFact] = field(default_factory=list)
    profile: Dict[str, Any] = field(default_factory=dict)  # profile_recon
    hook: str = ""                       # one-line recognition hook
    recommended: str = "security_alert"  # best pretext for this target
    recommendation_score: float = 0.0
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "emails": list(self.emails),
            "phones": list(self.phones),
            "platform": self.platform,
            "company": self.company,
            "breaches": [
                {"name": b.name, "date": b.date, "channels": list(b.channels),
                 "cross_channel": b.cross_channel} for b in self.breaches],
            "profile": dict(self.profile),
            "hook": self.hook,
            "recommended_pretext": self.recommended,
            "recommendation_score": round(self.recommendation_score, 2),
            "reasons": list(self.reasons),
        }


# ---------------------------------------------------------------------------
# building the dossier from discovery memory
# ---------------------------------------------------------------------------

def _breaches_from(discovered: Dict[str, Any]) -> List[BreachFact]:
    """Merge breach names with the channels they were seen on.

    `discovered` carries `breaches` (list of names) and `breach_channels`
    (dict name -> list of channels: "email", "phone", "username"). Names
    without a channel entry default to ["email"] for backward compatibility.
    """
    names = list(discovered.get("breaches") or [])
    channels = discovered.get("breach_channels") or {}
    merged: Dict[str, BreachFact] = {}
    for n in names:
        n = str(n).strip()
        if not n:
            continue
        ch = channels.get(n) or ["email"]
        if n in merged:
            for c in ch:
                if c not in merged[n].channels:
                    merged[n].channels.append(c)
        else:
            merged[n] = BreachFact(name=n, channels=list(ch))
    facts = list(merged.values())
    # strongest first: cross-channel breaches on top, then by channel count
    facts.sort(key=lambda b: (b.cross_channel, len(b.channels)), reverse=True)
    return facts


def _best_hook(dossier: TargetDossier) -> str:
    """One recognition line for the lure body, from the strongest fact."""
    for b in dossier.breaches:
        if b.cross_channel:
            return ("Your email and phone were both exposed in the "
                    f"{b.name} breach - that's why we're reaching out "
                    "directly.")
        if "phone" in b.channels and dossier.phones:
            return (f"Your number was exposed in the {b.name} breach - "
                    "we're notifying every affected user personally.")
        if dossier.emails:
            return (f"Your address appeared in the {b.name} breach - "
                    "please confirm your recent activity.")
    if dossier.phones:
        tail = dossier.phones[0][-4:]
        return f"Sent to the number on file ending in {tail}."
    return ""


def build_dossier(discovered: Dict[str, Any]) -> TargetDossier:
    """Assemble the target dossier from the engine's discovery memory."""
    emails = list(discovered.get("emails") or [])
    phones = list(discovered.get("phones") or [])
    breaches = _breaches_from(discovered)
    name = (discovered.get("name") or "").strip()
    if not name and emails:
        local = emails[0].split("@")[0]
        parts = [p for p in local.replace(".", " ").replace("_", " ")
                 .split() if p]
        if parts:
            name = " ".join(p.capitalize() for p in parts[:2])
    platform = (discovered.get("platform") or "").strip()
    profile = dict(discovered.get("profile") or {})
    if not platform and profile.get("platform"):
        platform = str(profile["platform"]).strip()
    company = (discovered.get("company") or "").strip()
    if not company and emails:
        domain = emails[0].split("@")[-1]
        company = domain.split(".")[0].capitalize() if domain else ""
    d = TargetDossier(name=name, emails=emails, phones=phones,
                      platform=platform, company=company, breaches=breaches,
                      profile=profile)
    d.hook = _best_hook(d)
    d.recommended, d.recommendation_score, d.reasons = recommend_pretext(d)
    return d


# ---------------------------------------------------------------------------
# pretext scoring (deterministic)
# ---------------------------------------------------------------------------

def recommend_pretext(dossier: TargetDossier) -> Tuple[str, float, List[str]]:
    """Score every pretext against what we know about the target."""
    has_platform = bool(dossier.platform)
    has_breach = bool(dossier.breaches)
    has_cross = any(b.cross_channel for b in dossier.breaches)
    has_phone = bool(dossier.phones)
    has_email = bool(dossier.emails)
    has_company = bool(dossier.company)
    has_name = bool(dossier.name)
    has_private = bool(dossier.profile.get("private"))
    has_link = bool(dossier.profile.get("link"))

    scores: List[Tuple[str, float, List[str]]] = [
        ("security_alert",
         (1.0 if has_cross else 0.0) + (0.55 if has_breach else 0.0)
         + (0.45 if has_platform else 0.0) + (0.15 if has_email else 0.0)
         + (0.15 if has_private else 0.0),
         [r for r, ok in [
             ("cross-channel breach gives a real hook", has_cross),
             ("known breach to reference", has_breach),
             ("platform known -> account alert fits", has_platform),
             ("private profile -> alert looks pre-informed", has_private),
         ] if ok]),
        ("package_delivery",
         (0.8 if has_phone else 0.0) + (0.3 if has_email else 0.0)
         + (0.1 if has_private else 0.0),
         [r for r, ok in [
             ("phone known -> delivery notice is natural", has_phone),
         ] if ok]),
        ("password_reset",
         (0.7 if has_platform else 0.0) + (0.3 if has_email else 0.0),
         [r for r, ok in [
             ("platform known -> reset flow fits", has_platform),
         ] if ok]),
        ("it_helpdesk",
         (0.6 if has_company else 0.0) + (0.4 if has_email else 0.0),
         [r for r, ok in [
             ("company known -> IT mail looks internal", has_company),
         ] if ok]),
        ("hr_benefits",
         (0.5 if has_company else 0.0) + (0.3 if has_email else 0.0),
         [r for r, ok in [
             ("company known -> HR statement fits", has_company),
         ] if ok]),
        ("recruiter",
         (0.6 if has_platform else 0.0) + (0.4 if has_name else 0.0),
         [r for r, ok in [
             ("public profile -> recruiter is natural", has_platform),
             ("real name known -> personalize the intro", has_name),
         ] if ok]),
        ("doc_share",
         (0.45 if has_company else 0.0) + (0.25 if has_email else 0.0),
         [r for r, ok in [
             ("company known -> shared doc is plausible", has_company),
         ] if ok]),
    ]
    scores.sort(key=lambda s: s[1], reverse=True)
    best, best_score, best_reasons = scores[0]
    return best, best_score, best_reasons


# ---------------------------------------------------------------------------
# summary (markers / API)
# ---------------------------------------------------------------------------

def dossier_summary(dossier: TargetDossier) -> Dict[str, Any]:
    d = dossier.to_dict()
    d["breach_count"] = len(dossier.breaches)
    d["cross_channel_breach"] = any(b.cross_channel for b in dossier.breaches)
    return d
