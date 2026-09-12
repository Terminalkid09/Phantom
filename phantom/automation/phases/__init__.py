"""
phantom.automation.phases — the kill-chain phase packages.

Every capability belongs to exactly ONE phase. A phase owns its
capabilities (declared ids), adapters (command synthesis) and
interpreters (output -> findings). Phases never import each other;
they communicate only through the WorldModel facts + the capability
registry.

Phase order follows the kill chain:
    recon -> osint -> exploit -> foothold -> beacon -> post -> report
(recon and osint both run at the front: recon on network targets,
osint on identity targets; the target class doctrine picks.)

The migration re-exports the CURRENT adapters from guidance/kit.py (the
live registry) so the contract is real without a big-bang rewrite.
"""

from __future__ import annotations

from typing import Dict, List, Optional

PHASE_ORDER = (
    "recon",
    "osint",
    "exploit",
    "foothold",
    "beacon",
    "post",
    "report",
)

# capability id -> owning phase. Keep in sync with each phase's
# capabilities.py — this is the planner-facing index.
_CAPABILITY_PHASE: Dict[str, str] = {
    # recon
    "scan_tcp": "recon",
    "version_detect": "recon",
    "os_detect": "recon",
    "ssh_banner": "recon",
    "http_probe": "recon",
    "http_get": "recon",
    "fingerprint_services": "recon",
    "smb_enum": "recon",
    "redis_info": "recon",
    "env_probe": "recon",
    "mobile_probe": "recon",
    "mobile_mdm_fingerprint": "recon",
    # osint
    "osint_identity": "osint",
    "breach_check": "osint",
    "deep_recon": "osint",
    "surface_map": "osint",
    "persona_create": "osint",
    "persona_profile": "osint",
    "dossier_analyze": "osint",
    "profile_recon": "osint",
    "phish_identity": "osint",
    "campaign_launch": "osint",
    "poll_hits": "osint",
    "harvest_campaign": "osint",
    "dm_launch": "osint",
    "dm_stage2": "osint",
    "dm_follow": "osint",
    "wait_follow": "osint",
    # exploit (discovery + weaponization)
    "service_exploit": "exploit",
    "hunt_web": "exploit",
    "differential_analysis": "exploit",
    "rce_foothold": "exploit",
    "beacon_via_rce": "exploit",
    "web_rce": "exploit",
    "idor_scan": "exploit",
    # foothold (ACCESS: creds + shell)
    "brute_ssh": "foothold",
    "cred_spray": "foothold",
    "ssh_login": "foothold",
    "web_creds": "foothold",
    "payload_reverse": "foothold",
    "payload_bind": "foothold",
    # beacon
    "beacon_deploy": "beacon",
    # post
    "env_probe_internal": "post",
    "persistence_install": "post",
    "privesc_system": "post",
    "inject_beacon": "post",
    "privesc_sudo": "post",
    "privesc_service_perms": "post",
    "ad_enum": "post",
    "kerberoast": "post",
    "as_rep_roast": "post",
    "dc_sync": "post",
    "hash_crack": "post",
    "lateral_pivot": "post",
    "smb_pivot": "post",
    "winrm_pivot": "post",
    "cleanup": "post",
    "cookie_stealer": "post",
    "bt_scan": "post",
    "cdp_pivot": "post",
    "socks_proxy": "post",
    "ransom_sim": "post",
    "trojan_deliver": "post",
    "cloud_creds_harvest": "post",
    "cloud_s3_enum": "post",
    "cloud_iam_enum": "post",
    "cloud_assume_role": "post",
    "cloud_cross_account": "post",
    "k8s_escape": "post",
    "internal_recon": "post",
    "internal_probe": "post",
    "edr_disable": "post",
    "loot_triage": "post",
}


def phase_of(capability_id: str) -> Optional[str]:
    """The phase that owns a capability id, or None for unknown ids."""
    return _CAPABILITY_PHASE.get(capability_id)


def capabilities_of(phase: str) -> List[str]:
    """All capability ids owned by a phase."""
    return [cid for cid, owner in _CAPABILITY_PHASE.items() if owner == phase]


def load_phase(phase: str):
    """Import a phase package (safe for unknown names)."""
    if phase not in PHASE_ORDER:
        raise ValueError(f"unknown phase: {phase}")
    import importlib
    return importlib.import_module(f"phantom.automation.phases.{phase}")


def phases() -> List[str]:
    return list(PHASE_ORDER)