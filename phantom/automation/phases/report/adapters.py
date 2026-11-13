"""
adapters.py — the report phase's "adapters".

Reporting builds documents from an agent's collected state instead of
synthesizing shell commands, so the adapter role is filled by the
report builders themselves: raw (operator) and client (sanitized).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict

if TYPE_CHECKING:  # annotation-only: the builders are still imported per
    # function so importing this phase's adapters never pulls the reporting
    # stack (markdown/PDF deps) into the phase-contract import graph.
    from phantom.automation.reporting import ClientReport, RawReport


def raw_report(agent: Any) -> "RawReport":
    from phantom.automation.reporting import RawReport
    return RawReport.from_agent(agent)


def client_report(agent: Any, profile: str = "enterprise") -> "ClientReport":
    from phantom.automation.reporting import ClientReport
    return ClientReport.from_agent(agent, profile)


def write_reports(raw: "RawReport", client: "ClientReport",
                  out_dir: str) -> Dict[str, str]:
    # `out_dir` is required: ReportWriter() with no directory raises
    # TypeError, so this facade could never have written a document.
    from phantom.automation.reporting import ReportWriter
    return ReportWriter(out_dir).write(raw, client)