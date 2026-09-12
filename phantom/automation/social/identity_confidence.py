"""identity_confidence.py — is this handle REALLY the same person?

The dangerous failure mode the operator flagged: a username found on
TikTok is NOT automatically the same person on Instagram — usernames
collide across platforms. Acting (DM/follow/phish) on the wrong person
harms an innocent third party AND burns the engagement.

The fix is a confidence tier system over the correlation signals:

  CONFIRMED  — same-person proof that username collision cannot fake:
               avatar_hash equality, bio similarity >= 0.75, cross-link
               (profile A links profile B), email/handle in bio of both
  PROBABLE   — two or more weak signals agreeing (name in bio + interests)
  UNRELATED  — single weak signal only (same handle = NOT proof)

Policy (wired into the agent):
  * CONFIRMED leads are activatable pivots (register + act);
  * PROBABLE leads are registered but gated: the chain may RECON them
    (read-only) but never CONTACT (dm/follow/phish) without --aggressive;
  * UNRELATED leads are recorded as noise, never pivots.

Every lead keeps its evidence trail so the operator can audit WHY.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ── tiers ────────────────────────────────────────────────────────────────

CONFIRMED = "confirmed"
PROBABLE = "probable"
UNRELATED = "unrelated"

# single signals and their standalone strength (0..1). Username equality
# across platforms is deliberately WEAK — that is the exact trap.
SIGNAL_STRENGTH = {
    "avatar_match": 0.85,       # identical avatar bytes
    "cross_link": 0.90,         # profile A links to profile B (both ways ok)
    "bio_sim": 0.0,             # scaled: 0.75+ bio jaccard -> strong
    "name_in_bio": 0.45,        # real name from primary platform in bio
    "same_handle": 0.20,        # username equality alone — weak on purpose
    "interest_match": 0.35,     # shared niche interests (dossier vs bio)
    "email_in_bio": 0.80,       # same email visible in both bios
    "phone_in_bio": 0.80,       # same phone visible in both bios
    "contact_overlap": 0.0,     # scaled: commenter/tag graph overlap
}

CONFIRMED_THRESHOLD = 0.80
PROBABLE_THRESHOLD = 0.55
# weak-signal sums stop here: probable is the BEST they can become
PROBABLE_CEILING = 0.75

CONTACT_CAPABILITIES = {"dm_launch", "dm_stage2", "dm_follow",
                        "wait_follow", "campaign_launch", "phish_identity"}


@dataclass
class IdentityLead:
    """A candidate same-person claim with its evidence."""
    handle: str
    platform: str
    signals: List[Tuple[str, float]] = field(default_factory=list)  # (kind, weight)
    evidence: str = ""

    @property
    def score(self) -> float:
        """Combined confidence.

        A single strong signal (>= CONFIRMED_THRESHOLD) passes as-is.
        Weak signals may ACCUMULATE into PROBABLE but their sum is capped
        just below CONFIRMED: adding up coincidences can never fake one
        piece of same-person proof (that is the username-collision trap
        this module exists to close)."""
        if not self.signals:
            return 0.0
        strongest = max(w for _, w in self.signals)
        if strongest >= CONFIRMED_THRESHOLD:
            return strongest
        weak_sum = sum(w for _, w in self.signals if w < CONFIRMED_THRESHOLD)
        return min(PROBABLE_CEILING, max(strongest, weak_sum))

    @property
    def tier(self) -> str:
        s = self.score
        if s >= CONFIRMED_THRESHOLD:
            return CONFIRMED
        if s >= PROBABLE_THRESHOLD:
            return PROBABLE
        return UNRELATED


# ── scoring ──────────────────────────────────────────────────────────────

def _bio_similarity(a: str, b: str) -> float:
    ta = {w.lower().strip(".,#@") for w in (a or "").split() if len(w) > 2}
    tb = {w.lower().strip(".,#@") for w in (b or "").split() if len(w) > 2}
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def score_lead(primary_platform: str, primary: Dict, candidate: Dict
               ) -> IdentityLead:
    """Score a cross-platform candidate against the primary identity.

    `primary` / `candidate` dicts: {username, bio, avatar_hash, link,
    full_name, emails, interests}. Missing fields simply skip signals.
    """
    lead = IdentityLead(handle=str(candidate.get("username", "")),
                        platform=str(candidate.get("platform", "")))

    # 1. avatar hash equality — cannot be faked by username coincidence
    ph, ch = primary.get("avatar_hash"), candidate.get("avatar_hash")
    if ph and ch and ph == ch:
        lead.signals.append(("avatar_match", SIGNAL_STRENGTH["avatar_match"]))
        lead.evidence += f"avatar identical to {primary_platform}; "

    # 2. cross-linking: candidate bio/links back to the primary profile
    #    (the link field AND the raw bio text — links usually live in bio)
    link = str(candidate.get("link", "")).lower()
    cbio = str(candidate.get("bio", "")).lower()
    pu = str(primary.get("username", "")).lower()
    if pu and (pu in link or pu in cbio):
        lead.signals.append(("cross_link", SIGNAL_STRENGTH["cross_link"]))
        lead.evidence += f"bio references @{pu}; "

    # 3. same contact info (structured fields AND visible in bio text)
    p_emails = {e.lower() for e in (primary.get("emails") or [])}
    c_emails = {e.lower() for e in (candidate.get("emails") or [])}
    shared_email = p_emails & c_emails
    if not shared_email and p_emails:
        shared_email = {e for e in p_emails if e in cbio}
    if shared_email:
        lead.signals.append(("email_in_bio", SIGNAL_STRENGTH["email_in_bio"]))
        lead.evidence += "same email visible; "
    pp = primary.get("phone")
    if pp and str(pp) == str(candidate.get("phone", "")):
        lead.signals.append(("phone_in_bio", SIGNAL_STRENGTH["phone_in_bio"]))
        lead.evidence += "same phone in bios; "

    # 4. bio similarity — strong only when high
    sim = _bio_similarity(str(primary.get("bio", "")),
                          str(candidate.get("bio", "")))
    if sim >= 0.75:
        lead.signals.append(("bio_sim", min(0.85, sim)))
        lead.evidence += f"bio similarity {sim:.2f}; "
    elif sim >= 0.5:
        lead.signals.append(("bio_sim", 0.35))
        lead.evidence += f"bio overlap {sim:.2f}; "

    # 5. real name from primary appears in candidate bio
    name = str(primary.get("full_name", "")).strip().lower()
    if name and len(name.split()) >= 2 and name in str(
            candidate.get("bio", "")).lower():
        lead.signals.append(("name_in_bio", SIGNAL_STRENGTH["name_in_bio"]))
        lead.evidence += f"'{name}' in bio; "

    # 6. shared niche interests
    pi = {i.lower() for i in (primary.get("interests") or [])}
    ci = {i.lower() for i in (candidate.get("interests") or [])}
    if pi and ci and len(pi & ci) >= 2:
        lead.signals.append(("interest_match",
                             SIGNAL_STRENGTH["interest_match"]))
        lead.evidence += f"interests {sorted(pi & ci)}; "

    # 7. same handle — always recorded, deliberately weak
    if pu and str(candidate.get("username", "")).lower() == pu:
        lead.signals.append(("same_handle", SIGNAL_STRENGTH["same_handle"]))
        lead.evidence += "same handle (weak alone); "

    # 8. CONTACT-GRAPH OVERLAP — the same strangers comment on / are
    #    tagged by BOTH accounts. Two random people rarely share a
    #    meaningful slice of their social graph; a shared social circle
    #    on two platforms is real same-person evidence. Scaled by the
    #    overlap size (bounded, so a single shared friend cannot cheat).
    pg = {x.lower() for x in (primary.get("graph") or [])}
    cg = {x.lower() for x in (candidate.get("graph") or [])}
    if pg and cg:
        shared = pg & cg
        if len(shared) >= 3:
            w = min(0.70, 0.30 + 0.08 * len(shared))
            lead.signals.append(("contact_overlap", w))
            lead.evidence += f"graph overlap {len(shared)}: {sorted(shared)[:3]}; "

    return lead


def tier_of(lead: IdentityLead) -> str:
    return lead.tier


# ── the pivot gate ───────────────────────────────────────────────────────

def may_act(lead: IdentityLead, capability: str,
            aggressive: bool = False) -> Tuple[bool, str]:
    """The single gate the auto-mode consults before acting on a
    cross-platform identity candidate.

    * CONFIRMED            -> any capability in the identity chain
    * PROBABLE             -> read-only recon ALWAYS; contact only
                              with --aggressive (operator accepted the
                              wrong-person risk explicitly)
    * UNRELATED            -> nothing (noise; the chain just records it)
    """
    tier = lead.tier
    if tier == CONFIRMED:
        return True, f"identity CONFIRMED ({lead.evidence.strip()})"
    if tier == PROBABLE:
        if capability in CONTACT_CAPABILITIES and not aggressive:
            return False, (
                f"identity only PROBABLE ({lead.evidence.strip()}) — "
                f"'{capability}' needs --aggressive or better evidence "
                "(avoid acting on the wrong person)")
        return True, f"identity probable, read-only ok ({lead.evidence.strip()})"
    return False, f"identity UNRELATED — noise, not a pivot " \
                  f"({lead.evidence.strip()})"
