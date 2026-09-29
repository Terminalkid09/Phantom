"""Profile policy: the ENVIRONMENT profile decides HOW an operation starts.

The operator picks an environment profile (``smb`` / ``enterprise`` /
``cloud`` / ``financial`` / ``government`` / ``mobile``). Before this
module that choice was an *label*: it was forwarded to the threat model
and the OPSEC engine but it never changed the PLAN. Every profile ran the
same fixed chain with the same vocabulary.

The user-visible symptom: ``--profile mobile`` still opened with a direct
web chain, which is the one thing that never works on a sandboxed phone.

This module is the single place where a profile maps to a starting
posture:

* ``chain``       — the chain template used when the operator did NOT
                    pick one explicitly (``--chain`` still wins);
* ``difficulty``  — prior (0..1) that a single pass on this surface
                    yields: low for hardened/sandboxed classes, which
                    routes budget toward depth, not breadth;
* ``thin_surface``— what to do when enumeration finds little, WITHOUT
                    falling back to active OSINT/phishing by default;
* ``reason_hint``  — the reasoning objective that fits the class when the
                    operator gave none.

Deterministic and data-only: the same profile always yields the same
posture (the suite requires determinism), and no profile invents a chain
that does not exist in ``swarm.tasks.CHAIN_TEMPLATES``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple

# reason objectives the swarm understands (swarm.profiles.PROFILES)
_REASONS = ("balanced", "evidence_first", "stealth_first", "force_first")

# thin-surface behaviours (consumed by the agent's strategic layer):
#   deepen_one     — go DEEPER on the one service that is open
#   identity       — identity/MDM/social surface before anything active
#   control_plane  — cloud identity/config (OIDC, IAM, tokens), not ports
THIN_DEEPEN_ONE = "deepen_one"
THIN_IDENTITY = "identity"
THIN_CONTROL_PLANE = "control_plane"


@dataclass(frozen=True)
class ProfilePolicy:
    """Starting posture for one environment class."""

    profile: str
    chain: str
    difficulty: float
    thin_surface: str
    reason_hint: str

    def __post_init__(self) -> None:  # pragma: no cover - defensive
        if not 0.0 <= self.difficulty <= 1.0:
            raise ValueError(f"difficulty out of range: {self.difficulty}")
        if self.reason_hint not in _REASONS:
            raise ValueError(f"unknown reason: {self.reason_hint}")


# The table is the policy: it is deliberately explicit and reviewable.
# `difficulty` is the prior that ONE pass yields, not a promise.
POLICY: Dict[str, ProfilePolicy] = {
    # small/medium business: perimeter-focused, few defenses -> creds on
    # the open service is the shortest honest path.
    "smb": ProfilePolicy("smb", "creds", 0.65,
                         THIN_DEEPEN_ONE, "balanced"),
    # corporate: full stack, but the surface is broad and classic.
    "enterprise": ProfilePolicy("enterprise", "full", 0.55,
                                THIN_DEEPEN_ONE, "balanced"),
    # cloud: no "ports" to speak of. Identity / config IS the surface,
    # so the identity chain leads; evidence-first keeps enumeration deep.
    "cloud": ProfilePolicy("cloud", "identity", 0.45,
                           THIN_CONTROL_PLANE, "evidence_first"),
    # financial: heavily monitored and regulated -> creds-led, quiet.
    "financial": ProfilePolicy("financial", "creds", 0.35,
                               THIN_DEEPEN_ONE, "stealth_first"),
    # government: air-gapped segments, strict controls -> thorough + quiet.
    "government": ProfilePolicy("government", "deep", 0.30,
                                THIN_DEEPEN_ONE, "stealth_first"),
    # mobile: the OS sandbox hides the device from port scans. Start with
    # the scan (footprint) but assume the surface is thin and the real
    # angle is identity/MDM, never a direct web assault.
    "mobile": ProfilePolicy("mobile", "footprint", 0.20,
                            THIN_IDENTITY, "evidence_first"),
}

_DEFAULT = POLICY["enterprise"]


def policy_for(profile: str) -> ProfilePolicy:
    """Policy for a profile; unknown/empty falls back to enterprise."""
    return POLICY.get((profile or "").strip().lower(), _DEFAULT)


def chain_for_profile(profile: str, fallback: str = "full") -> str:
    """The chain template a profile starts with.

    ``fallback`` is used only when the profile is unknown AND has no
    policy — it never shadows a known profile.
    """
    key = (profile or "").strip().lower()
    if key in POLICY:
        return POLICY[key].chain
    return fallback


def difficulty_for(profile: str) -> float:
    """Prior (0..1) that one pass on this class yields something."""
    return policy_for(profile).difficulty


def reason_hint_for(profile: str) -> str:
    """Reasoning objective that fits the class (used when none given)."""
    return policy_for(profile).reason_hint


def thin_surface_for(profile: str) -> str:
    """How to proceed when enumeration finds little."""
    return policy_for(profile).thin_surface


# ---------------------------------------------------------------------------
# profile <-> target coherence
# ---------------------------------------------------------------------------
#
# The profile describes the ENVIRONMENT (what the box looks like); the
# target describes the ENTITY the operator handed us. When the two
# contradict, the posture derived from the profile is wrong by
# construction — and it is the PLAN that is misled: `--profile mobile` on
# a PC opens with the mobile posture (scan + identity/MDM, difficulty
# 0.20), which is the one posture that never opens a machine.

# target kinds that mean "a machine on a network"
HOST_TARGET_TYPES = ("ip", "domain", "url")
# target kinds that mean "a sandboxed personal device" (the person's phone)
DEVICE_TARGET_TYPES = ("phone", "mobile")

# profiles whose posture assumes a networked MACHINE
MACHINE_PROFILES = ("smb", "enterprise", "financial", "government")
# the profile whose posture assumes a sandboxed personal DEVICE
DEVICE_PROFILE = "mobile"
# what a machine-class target falls back to when the device posture was asked
MACHINE_FALLBACK = "enterprise"


@dataclass(frozen=True)
class ProfileTargetCheck:
    """Outcome of the profile<->target coherence check.

    ``ok`` False means the requested profile contradicts the target class
    and ``effective`` is the profile the plan should use instead; the
    caller announces ``reason`` (never silently).
    """

    requested: str
    effective: str
    ok: bool
    reason: str
    target_kinds: Tuple[str, ...] = ()

    @property
    def corrected(self) -> bool:
        return self.effective != self.requested


def check_profile_target(profile: str, target_types, *, force: bool = False
                         ) -> ProfileTargetCheck:
    """Detect a profile that contradicts the target's class.

    Two contradictions exist and are detected here (nothing else is
    flagged — a cloud profile on a bare IP is legitimate, identity
    targets are the engagement SUBJECT, not a device):

    * ``--profile mobile`` on a host (ip/domain/url) with no phone in
      sight: the mobile posture assumes a sandboxed device, so the plan
      must not be built on it -> machine fallback.
    * a machine profile (smb/enterprise/financial/government) on a phone
      with no host in sight: a network posture is useless on a device
      that hides from scans -> the device profile.

    ``force=True`` keeps the operator's choice (CLI ``--force-profile``):
    the operator may know the IP *is* the phone, or the box *is* a
    corporate asset reached through an identity. Returns a
    ``ProfileTargetCheck``; callers announce it and use ``effective``.
    """
    requested = (profile or "").strip().lower()
    kinds = tuple(dict.fromkeys(
        (k or "").strip().lower() for k in (target_types or [])))
    if requested not in POLICY:
        # no posture of its own: the default answers for it, exactly like
        # policy_for/chain_for_profile already do — nothing to announce
        return ProfileTargetCheck(requested or MACHINE_FALLBACK,
                                  MACHINE_FALLBACK, True, "", kinds)
    if force:
        return ProfileTargetCheck(requested, requested, True, "", kinds)
    has_host = any(k in HOST_TARGET_TYPES for k in kinds)
    has_device = any(k in DEVICE_TARGET_TYPES for k in kinds)
    if requested == DEVICE_PROFILE and has_host and not has_device:
        return ProfileTargetCheck(
            requested, MACHINE_FALLBACK, False,
            "Profilo 'mobile' ma il target è un host (ip/domain/url): la "
            "postura mobile (sandbox del dispositivo, identità/MDM) non "
            f"apre una macchina — uso '{MACHINE_FALLBACK}'. Rilancia con "
            "--force-profile se il target è davvero un dispositivo mobile.",
            kinds)
    if requested in MACHINE_PROFILES and has_device and not has_host:
        return ProfileTargetCheck(
            requested, DEVICE_PROFILE, False,
            f"Profilo '{requested}' ma il target è un numero di telefono: "
            "una postura da rete è inutile su un dispositivo sandboxed — "
            f"uso '{DEVICE_PROFILE}'. Rilancia con --force-profile per "
            f"mantenere '{requested}'.",
            kinds)
    return ProfileTargetCheck(requested, requested, True, "", kinds)
