"""
phases.report — the reporting phase.

Owns the engagement deliverables: the operator-detail raw report and
the sanitized client report (plus campaign reports). No registry
capabilities — reporting runs once at the end of the run — so the
phase contract exposes the report builders as adapters and the
agent-state extraction as the interpreter side.
"""

from __future__ import annotations