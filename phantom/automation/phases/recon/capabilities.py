"""
capabilities.py — the recon phase's capabilities.

The migration contract: the planner's live registry is guidance/kit.py
(single source of truth during the move); this module declares WHICH
capabilities belong to the recon phase and re-exports them, so the
phase package is the unit of work while the registry stays stable.
"""

from __future__ import annotations

from typing import List

RECON_CAPABILITY_IDS = (
    "scan_tcp",
    "version_detect",
    "os_detect",
    "ssh_banner",
    "http_probe",
    "http_get",
    "fingerprint_services",
    "smb_enum",
    "redis_info",
    "env_probe",
    "mobile_probe",
    "mobile_mdm_fingerprint",
)


def phase_capabilities(registry) -> List:
    """The recon capabilities from a live registry, phase-contract view."""
    from phantom.automation.guidance.commands import Registry
    out = []
    for cid in RECON_CAPABILITY_IDS:
        cap = registry.get(cid)
        if cap is not None:
            out.append(cap)
    return out
