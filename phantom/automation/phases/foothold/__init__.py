"""
phases.foothold — the credential/access-acquisition phase.

Owns the moves that convert discovered credentials into a verified
access state on a host: single-pair SSH login checks and (in
aggressive mode only) bounded online brute force. Every credential
produced here is the gate the beacon phase waits on.

The migration re-exports the CURRENT adapters from guidance/kit.py (the
live registry) so the contract is real without a big-bang rewrite.
"""

from __future__ import annotations