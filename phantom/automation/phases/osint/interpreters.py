"""
interpreters.py — the osint phase's output interpreters.

All identity/social capabilities share the stable-marker interpreter
(IDENTITY:/BREACH:/PROFILE:/DOSSIER:/PHISH_SENT:/VICTIM_IP:...).
"""

from __future__ import annotations

from phantom.automation.guidance.kit import (  # noqa: F401
    _social_interp as parse_social,
)