"""
capabilities.py — the report phase's capabilities.

Reporting is a post-run deliverable, not a planner capability: the
phase declares no registry capability ids. The contract's adapters /
interpreters expose the builders instead.
"""

from __future__ import annotations

from typing import List

REPORT_CAPABILITY_IDS: tuple = ()


def phase_capabilities(registry) -> List:
    """The report capabilities from a live registry — always empty."""
    return []