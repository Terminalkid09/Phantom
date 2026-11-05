"""
capabilities.py — the foothold phase's capabilities.

Credential validation and (aggressive-only) bounded brute force.

DECLARATIVE SURFACE: this module owns the ids and the phase-contract view, not
behaviour. The adapters/interpreters are re-exported from guidance/kit.py
(see adapters.py and interpreters.py in this package), and the executable
phase lives in phantom.automation.agent. `phases.implementation_for("foothold")`
returns that location, so "the phase exists" and "the phase is wired" are not
the same claim.
"""

from __future__ import annotations

from typing import List

FOOTHOLD_CAPABILITY_IDS = (
    "brute_ssh",
    "brute_smb",
    "brute_rdp",
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