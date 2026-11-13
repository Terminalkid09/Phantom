"""
capabilities.py — the beacon phase's capabilities.

The C2-access capability: beacon_deploy.
"""

from __future__ import annotations

from typing import List

BEACON_CAPABILITY_IDS = (
    "beacon_deploy",
)


def phase_capabilities(registry) -> List:
    """The beacon capabilities from a live registry, phase-contract view."""
    out = []
    for cid in BEACON_CAPABILITY_IDS:
        cap = registry.get(cid)
        if cap is not None:
            out.append(cap)
    return out