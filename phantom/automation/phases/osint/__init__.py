"""
phases.osint — the identity/OSINT phase.

Owns everything about the person side of the engagement: identity
discovery (username/email/phone), breach correlation, deep profile
reverse-engineering, attack-surface mapping, persona creation and the
social engineering delivery chain (phish / DM / campaign / harvest).

The migration re-exports the CURRENT adapters from guidance/kit.py (the
live registry) so the contract is real without a big-bang rewrite;
subsequent passes move the bodies here.
"""

from __future__ import annotations