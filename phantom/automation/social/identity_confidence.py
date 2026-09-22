"""identity_confidence.py — is this handle REALLY the same person?

The dangerous failure mode the operator flagged: a username found on
TikTok is NOT automatically the same person on Instagram — usernames
collide across platforms. Acting (DM/follow/phish) on the wrong person
harms an innocent third party AND burns the engagement.

Design rules from the operator (not tunable without reason):

* the AVATAR alone proves nothing — same person with different avatars,
  different people with the same avatar (memes, defaults, stolen pics).
  It is a supporting signal only, never decisive;
* what actually decides: MUTUALS/common people, shared EMAIL/PHONE,
  similar-tag bios, and above all the OTHER account IN BIO (both ways:
  A links B and B links A is near-certain — a quick friend-vs-self
  look then settles it, and that check is fast);
* same-platform self-tags (insta bio points at own tiktok and back)
  count on every platform, not just cross-platform pairs.

The fix is a confidence tier system over the correlation signals:

   CONFIRMED  — same-person proof coincidence cannot fake: bidirectional
                cross-link, shared email/phone, (single strong anchor);
   PROBABLE   — two or more agreeing signals (mutuals + bio tags,
                self-tag + handle, similar names + interests);
   UNRELATED  — single weak signal only (same handle/ lone avatar).

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

# single signals and their standalone strength (0..1). NOTHING reaches
# CONFIRMED_THRESHOLD alone except a same-person anchor (shared contact
# data, bidirectional link): username equality, lone avatar and loose
# bio overlap are supporting signals by operator rule.
SIGNAL_STRENGTH = {
    "cross_link_bidi": 0.95,  # A bio links B AND B bio links A — near-certain
    "email_match": 0.85,      # same email on both sides
    "phone_match": 0.85,      # same phone on both sides
    "cross_link": 0.70,       # one direction only (could be a fan mention)
    "self_tag": 0.75,         # primary handle inside candidate's own
                              # tags/comments (self-reference pattern)
    "bio_sim": 0.0,           # scaled: high jaccard -> strong, capped below
    "avatar_match": 0.40,     # identical avatar bytes — supporting only
    "avatar_similar": 0.35,   # perceptual hash close (re-encoded same pic)
    "name_in_bio": 0.45,      # real name from primary platform in bio
    "same_handle": 0.20,      # username equality alone — weak on purpose
    "interest_match": 0.35,   # shared niche interests (dossier vs bio)
    "contact_overlap": 0.0,   # scaled: mutuals/graph overlap
}

# penalty: both sides name DIFFERENT real names -> probably a friend or a
# namesake, not self. A penalty, never a veto (nicknames/married names).
NAME_MISMATCH_PENALTY = 0.30

CONFIRMED_THRESHOLD = 0.80
PROBABLE_THRESHOLD = 0.55
# weak-signal sums stop here: probable is the BEST they can become
PROBABLE_CEILING = 0.75
# bio jaccard at/above this counts as strong (still capped, never alone)
BIO_SIM_STRONG = 0.75
BIO_SIM_CAP = 0.70
# perceptual-hash hamming distance at/below this counts as "same picture"
DHASH_MAX_DISTANCE = 10

CONTACT_CAPABILITIES = {"dm_launch", "dm_stage2", "dm_follow",
                        "wait_follow", "campaign_launch", "phish_identity"}


@dataclass
class IdentityLead:
    """A candidate same-person claim with its evidence."""
    handle: str
    platform: str
    signals: List[Tuple[str, float]] = field(default_factory=list)  # (kind, weight)
    penalties: List[Tuple[str, float]] = field(default_factory=list)  # (kind, amount)
    evidence: str = ""

    @property
    def score(self) -> float:
        """Combined confidence.

        A single ANCHOR signal (>= CONFIRMED_THRESHOLD: shared email/
        phone, bidirectional link) passes as-is. Everything else may
        ACCUMULATE into PROBABLE but the sum is capped just below
        CONFIRMED: adding up coincidences can never fake one piece of
        same-person proof (that is the username-collision trap this
        module exists to close). Name-mismatch penalties subtract
        afterwards (a friend with your handle is not you)."""
        if not self.signals:
            return 0.0
        strongest = max(w for _, w in self.signals)
        if strongest >= CONFIRMED_THRESHOLD:
            base = strongest
        else:
            weak_sum = sum(w for _, w in self.signals
                           if w < CONFIRMED_THRESHOLD)
            base = min(PROBABLE_CEILING, max(strongest, weak_sum))
        penalty = sum(a for _, a in self.penalties)
        return max(0.0, base - penalty)

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


def _name_tokens(name: str) -> set:
    return {w for w in (name or "").lower().replace(".", " ").replace(
        "_", " ").split() if len(w) > 1}


def dhash_distance(a: str, b: str) -> Optional[int]:
    """Hamming distance between two hex perceptual hashes (None when
    either side is missing/unparseable)."""
    try:
        if not a or not b:
            return None
        return bin(int(str(a), 16) ^ int(str(b), 16)).count("1")
    except (ValueError, TypeError):
        return None


def compute_dhash(raw: bytes) -> str:
    """Perceptual hash (8x8 dHash, hex) of image bytes. Survives the
    re-encoding platforms apply to the same avatar (JPEG quality, resize)
    where exact md5 structurally fails. Pillow missing/unreadable bytes
    -> "" (signal skipped, never an error)."""
    try:
        if not raw:
            return ""
        from PIL import Image
        import io
        img = Image.open(io.BytesIO(bytes(raw[:300000])))
        img = img.convert("L").resize((9, 8))
        px = list(img.getdata())
        bits = "".join(
            "1" if px[r * 9 + c] > px[r * 9 + c + 1] else "0"
            for r in range(8) for c in range(8))
        return "%016x" % int(bits, 2)
    except Exception:
        return ""


def score_lead(primary_platform: str, primary: Dict, candidate: Dict
               ) -> IdentityLead:
    """Score a cross-platform candidate against the primary identity.

    `primary` / `candidate` dicts: {username, bio, avatar_hash,
    avatar_dhash, link, outbound[] (handles the primary page points
    at), full_name, emails, phone, interests, graph[]}. Missing fields
    simply skip signals — a private profile with almost nothing
    visible scores low instead of erroring, which is the honest answer.
    """
    lead = IdentityLead(handle=str(candidate.get("username", "")),
                        platform=str(candidate.get("platform", "")))
    pu = str(primary.get("username", "")).lower()
    cu = str(candidate.get("username", "")).lower()
    cbio = str(candidate.get("bio", "")).lower()

    # 1. avatar: supporting ONLY (operator rule — same avatar proves
    #    nothing alone, different avatars disprove nothing). Exact bytes
    #    and perceptual closeness both count, neither decides.
    ph, ch = primary.get("avatar_hash"), candidate.get("avatar_hash")
    if ph and ch and ph == ch:
        lead.signals.append(("avatar_match", SIGNAL_STRENGTH["avatar_match"]))
        lead.evidence += f"avatar identical to {primary_platform}; "
    else:
        dist = dhash_distance(str(primary.get("avatar_dhash") or ""),
                              str(candidate.get("avatar_dhash") or ""))
        if dist is not None and dist <= DHASH_MAX_DISTANCE:
            lead.signals.append(("avatar_similar",
                                 SIGNAL_STRENGTH["avatar_similar"]))
            lead.evidence += f"avatar perceptually close (d={dist}); "

    # 2. cross-linking, BIDIRECTIONAL first: the candidate points at the
    #    primary AND the primary points back at the candidate. People put
    #    their OWN other account in bio; almost nobody does it both ways
    #    for someone else. Near-certain, then a quick friend-check.
    link = str(candidate.get("link", "")).lower()
    p_outbound = {str(h).lower().lstrip("@")
                  for h in (primary.get("outbound") or []) if h}
    to_primary = bool(pu and (pu in link or pu in cbio))
    from_primary = bool(cu and cu in p_outbound)
    if to_primary and from_primary:
        lead.signals.append(("cross_link_bidi",
                             SIGNAL_STRENGTH["cross_link_bidi"]))
        lead.evidence += f"bios link each other (@{pu} <-> @{cu}); "
    elif to_primary:
        lead.signals.append(("cross_link", SIGNAL_STRENGTH["cross_link"]))
        lead.evidence += f"bio references @{pu}; "

    # 3. self-tag: the primary handle inside the candidate's OWN tags /
    #    commenters graph (people tag themselves across their profiles;
    #    strangers rarely end up in YOUR tagged set repeatedly).
    c_graph = {str(x).lower().lstrip("@")
               for x in (candidate.get("graph") or []) if x}
    if pu and pu in c_graph:
        lead.signals.append(("self_tag", SIGNAL_STRENGTH["self_tag"]))
        lead.evidence += "self-tagged by primary circle; "

    # 4. same contact info (structured fields AND visible in bio text)
    p_emails = {e.lower() for e in (primary.get("emails") or [])}
    c_emails = {e.lower() for e in (candidate.get("emails") or [])}
    shared_email = p_emails & c_emails
    if not shared_email and p_emails:
        shared_email = {e for e in p_emails if e in cbio}
    if shared_email:
        lead.signals.append(("email_match", SIGNAL_STRENGTH["email_match"]))
        lead.evidence += "same email visible; "
    pp = primary.get("phone")
    if pp and str(pp) == str(candidate.get("phone", "")):
        lead.signals.append(("phone_match", SIGNAL_STRENGTH["phone_match"]))
        lead.evidence += "same phone in bios; "

    # 5. bio similarity — strong only when high, capped so similar bios
    #    alone (common templates, fan pages) never confirm by themselves.
    sim = _bio_similarity(str(primary.get("bio", "")),
                          str(candidate.get("bio", "")))
    if sim >= BIO_SIM_STRONG:
        lead.signals.append(("bio_sim", BIO_SIM_CAP))
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
    if pu and cu == pu:
        lead.signals.append(("same_handle", SIGNAL_STRENGTH["same_handle"]))
        lead.evidence += "same handle (weak alone); "

    # 8. CONTACT-GRAPH OVERLAP (mutuals) — the same strangers interact
    #    with BOTH accounts. Two random people rarely share a meaningful
    #    slice of their social graph; a shared circle is real same-person
    #    evidence. Scaled by overlap size (bounded). The two handles
    #    themselves are excluded: "A links B" belongs to cross-link,
    #    not to mutuals.
    pg = {x.lower() for x in (primary.get("graph") or [])}
    cg = {x.lower() for x in (candidate.get("graph") or [])}
    if pg and cg:
        shared = (pg & cg) - {pu, cu}
        if len(shared) >= 3:
            w = min(0.70, 0.30 + 0.08 * len(shared))
            lead.signals.append(("contact_overlap", w))
            lead.evidence += f"graph overlap {len(shared)}: {sorted(shared)[:3]}; "

    # 9. friend-vs-self: BOTH sides name DIFFERENT real names -> almost
    #    certainly a friend/namesake with a colliding handle, not self.
    #    A penalty (fast to check), never a veto.
    pf, cf = _name_tokens(str(primary.get("full_name", ""))), \
        _name_tokens(str(candidate.get("full_name", "")))
    if len(pf) >= 2 and len(cf) >= 2 and not (pf & cf):
        lead.penalties.append(("name_mismatch", NAME_MISMATCH_PENALTY))
        lead.evidence += "names differ (friend/namesake?); "

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
