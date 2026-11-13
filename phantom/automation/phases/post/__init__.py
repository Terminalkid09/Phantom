"""
phases.post — the post-exploitation phase.

Owns everything that happens AFTER the beacon is up: internal
environment probing, persistence, privilege escalation, AD attacks
(enum/kerberoast/as-rep/dcsync/hash-crack), lateral movement (SSH/SMB/
WinRM pivots), operational hygiene, cookie/BT/SOCKS harvesting, cloud
credential harvesting + IAM lateral movement, trojan delivery and the
Kubernetes escape surface.

The migration re-exports the CURRENT adapters from guidance/kit.py (the
live registry) so the contract is real without a big-bang rewrite.
"""

from __future__ import annotations