"""
phases.recon — the reference phase implementation.

Owns everything about the footprint/recon stage: port scanning
(multi-tool via brain.toolbelt), OS detection, service versioning,
banner grabbing, HTTP probing. The migration re-exports the CURRENT
adapters from guidance/kit.py (the live registry) so the contract is
real without a big-bang rewrite; subsequent passes move the bodies.
"""

from __future__ import annotations
