"""
phases.beacon — the C2-access phase.

Owns the single capability that turns a verified access state into a
live C2 session: beacon_deploy (execute the payload command on target).
Everything after this point (persistence, privesc, lateral, cloud)
belongs to the post phase.
"""

from __future__ import annotations