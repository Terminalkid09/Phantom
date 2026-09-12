"""
adapters.py — the report phase's "adapters".

Reporting builds documents from an agent's collected state instead of
synthesizing shell commands, so the adapter role is filled by the
report builders themselves: raw (operator) and client (sanitized).
"""

from __future__ import annotations

from typing import Any, Dict


def raw_report(agent: Any) -> "RawReport":
    from phantom.automation.reporting import RawReport
    return RawReport.from_agent(agent)


def client_report(agent: Any, profile: str = "enterprise") -> "ClientReport":
    from phantom.automation.reporting import ClientReport
    return ClientReport.from_agent(agent, profile)


def write_reports(raw, client) -> Dict[str, str]:
    from phantom.automation.reporting import ReportWriter
    return ReportWriter().write(raw, client)