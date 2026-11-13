"""
adapters.py — the beacon phase's execution adapters.

Re-exported from guidance/kit.py during the migration (same rationale
as the recon facade).
"""

from __future__ import annotations

from phantom.automation.guidance.kit import (  # noqa: F401
    _beacon_adapter as beacon_deploy,
)