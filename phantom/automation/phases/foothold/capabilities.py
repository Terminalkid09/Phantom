"""
capabilities.py — the foothold phase's capabilities.

Credential validation and (aggressive-only) bounded brute force.
"""

from __future__ import annotations

from typing import List

FOOTHOLD_CAPABILITY_IDS = (
    "brute_ssh",
    "cred_spray",
    "ssh_login",
    "web_creds",
    "payload_reverse",
    "payload_bind",
)


def phase_capabilities(registry) -> List:
    """The foothold capabilities from a live registry, phase-contract view."""
    out = []
    for cid in FOOTHOLD_CAPABILITY_IDS:
        cap = registry.get(cid)
        if cap is not None:
            out.append(cap)
    return out