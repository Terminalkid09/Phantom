"""
capabilities.py — the osint phase's capabilities.

Identity discovery, breach correlation, reverse-engineering of profiles,
attack-surface mapping, persona building and the social delivery chain.
"""

from __future__ import annotations

from typing import List

OSINT_CAPABILITY_IDS = (
    "osint_identity",
    # passive phone metadata (offline): phone + geolocation facts
    "phone_osint",
    "breach_check",
    "deep_recon",
    # identity-field primitives (I2)
    "email_candidates",
    "reset_enum",
    "email_verify",
    "breach_correlate",
    "surface_map",
    "persona_create",
    "persona_profile",
    "dossier_analyze",
    "profile_recon",
    "phish_identity",
    "campaign_launch",
    "poll_hits",
    "harvest_campaign",
    "dm_launch",
    "dm_stage2",
    "dm_follow",
    "wait_follow",
)


def phase_capabilities(registry) -> List:
    """The osint capabilities from a live registry, phase-contract view."""
    out = []
    for cid in OSINT_CAPABILITY_IDS:
        cap = registry.get(cid)
        if cap is not None:
            out.append(cap)
    return out