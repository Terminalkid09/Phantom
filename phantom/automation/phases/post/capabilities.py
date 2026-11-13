"""
capabilities.py — the post phase's capabilities.

Post-beacon: env, persistence, privesc, AD, lateral, hygiene, harvest,
cloud and container escape.
"""

from __future__ import annotations

from typing import List

POST_CAPABILITY_IDS = (
    "env_probe_internal",
    "persistence_install",
    "privesc_system",
    "inject_beacon",
    "privesc_sudo",
    "privesc_service_perms",
    "ad_enum",
    "kerberoast",
    "as_rep_roast",
    "dc_sync",
    "hash_crack",
    "lateral_pivot",
    "smb_pivot",
    "winrm_pivot",
    "cleanup",
    "cookie_stealer",
    "bt_scan",
    "cdp_pivot",
    "socks_proxy",
    "ransom_sim",
    "trojan_deliver",
    "cloud_creds_harvest",
    "cloud_s3_enum",
    "cloud_iam_enum",
    "cloud_assume_role",
    "cloud_cross_account",
    "k8s_escape",
    # post-exploitation depth: internal recon -> pivot services -> EDR kill
    # -> loot triage (the beacon-expansion chain)
    "internal_recon",
    "internal_probe",
    "edr_disable",
    "loot_triage",
)


def phase_capabilities(registry) -> List:
    """The post capabilities from a live registry, phase-contract view."""
    out = []
    for cid in POST_CAPABILITY_IDS:
        cap = registry.get(cid)
        if cap is not None:
            out.append(cap)
    return out