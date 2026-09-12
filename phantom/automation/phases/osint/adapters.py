"""
adapters.py — the osint phase's execution adapters.

Re-exported from guidance/kit.py during the migration (same rationale
as the recon facade).
"""

from __future__ import annotations

from phantom.automation.guidance.kit import (  # noqa: F401
    _osint_identity_adapter as osint_identity,
    _breach_check_adapter as breach_check,
    _profile_recon_adapter as profile_recon,
    _persona_create_adapter as persona_create,
    _persona_profile_adapter as persona_profile,
    _dossier_adapter as dossier_analyze,
    _phish_adapter as phish_identity,
    _surface_map_adapter as surface_map,
    _poll_hits_adapter as poll_hits,
    _campaign_adapter as campaign_launch,
    _harvest_adapter as harvest_campaign,
    _dm_adapter as dm_launch,
    _dm_stage2_adapter as dm_stage2,
)