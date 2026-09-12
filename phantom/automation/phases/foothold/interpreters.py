"""
interpreters.py — the foothold phase's output interpreters.

Brute-force success lines (hydra 'login:/password:', medusa '[SUCCESS]')
into creds findings.
"""

from __future__ import annotations

from phantom.automation.guidance.kit import (  # noqa: F401
    _brute_ssh_interp as parse_brute,
    _web_creds_interp as parse_web_creds,
)