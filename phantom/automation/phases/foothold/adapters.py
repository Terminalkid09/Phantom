"""
adapters.py — the foothold phase's execution adapters.

Re-exported from guidance/kit.py during the migration (same rationale
as the recon facade).
"""

from __future__ import annotations

from phantom.automation.guidance.kit import (  # noqa: F401
    _brute_ssh_adapter as brute_ssh,
    _ssh_login_adapter as ssh_login,
    _web_creds_adapter as web_creds,
)