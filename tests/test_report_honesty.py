"""G1/G2/G8/G17 — the report must not lie and must not lose evidence.

G1  The executive summary has THREE states per phase — not executed /
    executed with no findings / executed with N findings — read from
    `session.results`, not inferred from an empty list. Before this the
    summary said "identified no critical vulnerabilities" even when the
    exploit module had never run: a clean assessment and an unfinished one
    read identically to the client.

G8  Two reports generated in the same wall-clock second must not land in
    the same directory and overwrite each other's evidence.

G17 The confidence the modules already compute lives in the WorldModel and
    was dropped by the report, which only reads `session.results`.

G2  When persistence was installed the report must point the client at the
    supported removal path (`unpersist`), not just list IOCs.
"""
import os
from datetime import datetime

import pytest

from phantom.modules import report as rep
from phantom.core.knowledge import reset_wm, session_wm


@pytest.fixture(autouse=True)
def _clean_session():
    """Isolate the process-global session and WorldModel per test."""
    saved = {
        "target": rep.session.target,
        "results": dict(rep.session.results),
        "kb": rep.session.knowledge_base,
        "scope": list(rep.session.scope),
    }
    rep.session.results = {}
    rep.session.knowledge_base = dict(rep.session.knowledge_base)
    for key in ("persistence_set", "status"):
        rep.session.knowledge_base.pop(key, None)
    reset_wm("10.0.0.5")
    yield
    rep.session.target = saved["target"]
    rep.session.results = saved["results"]
    rep.session.knowledge_base = saved["kb"]
    rep.session.scope = saved["scope"]


# ── G1: three explicit states ───────────────────────────────────────────────

def test_vulnerability_phase_never_run_says_not_executed():
    # No `exploit` key at all: the phase did not run. The old text claimed
    # "identified no critical vulnerabilities" — a clean result.
    summary = rep._executive_summary()
    assert "Vulnerability identification was **not executed**" in summary
    assert "Vulnerability identification ran" not in summary


def test_vulnerability_phase_ran_with_no_findings_says_ran():
    rep.session.results["exploit"] = {"ranked": []}
    summary = rep._executive_summary()
    assert "Vulnerability identification ran and found **no**" in summary
    assert "Vulnerability identification was **not executed**" not in summary


def test_vulnerability_phase_with_findings_counts_them():
    rep.session.results["exploit"] = {"ranked": [
        {"score": 90, "cve": {"id": "CVE-2026-0001"}, "service": {}},
        {"score": 10, "cve": {"id": "CVE-2026-0002"}, "service": {}},
    ]}
    summary = rep._executive_summary()
    assert "found **2**" in summary
    assert "**1** HIGH risk" in summary


def test_reconnaissance_not_run_is_distinct_from_ran_empty():
    not_run = rep._executive_summary()
    assert "Reconnaissance was **not executed**" in not_run
    rep.session.results["scan"] = {"x": 1}
    rep.session.results["service_summary"] = []
    ran_empty = rep._executive_summary()
    assert "Reconnaissance ran and found **no**" in ran_empty


def test_credential_testing_state_is_explicit():
    rep.session.results["brute"] = {"ok": True}
    rep.session.knowledge_base["creds_found"] = []
    assert "Credential testing ran and found **no**" in rep._executive_summary()
    rep.session.knowledge_base["creds_found"] = [{"username": "u"}]
    assert "Credential testing found **1**" in rep._executive_summary()


# ── G8: timestamp collision ─────────────────────────────────────────────────

def test_unique_dir_disambiguates_without_overwriting(tmp_path):
    a = rep._unique_dir(str(tmp_path), "engagement_20261008_120000")
    b = rep._unique_dir(str(tmp_path), "engagement_20261008_120000")
    assert a != b
    assert os.path.isdir(a) and os.path.isdir(b)


def test_generate_twice_in_same_second_does_not_overwrite(tmp_path, monkeypatch):
    import phantom.utils.paths as paths
    monkeypatch.setattr(paths, "reports_dir", lambda: str(tmp_path), raising=True)
    rep.session.target = "10.0.0.5"
    first = rep.ReportModule().generate("json")
    second = rep.ReportModule().generate("json")
    assert first["raw_path"] != second["raw_path"]
    assert os.path.dirname(first["raw_path"]) != os.path.dirname(second["raw_path"])


# ── G17: confidence reaches the report ──────────────────────────────────────

def test_confidence_from_worldmodel_reaches_the_report():
    session_wm().add_finding("vuln", "CVE-2026-9999", {"cve": "CVE-2026-9999"},
                             confidence=0.92, source="exploit")
    rep.session.results["exploit"] = {"ranked": [{
        "score": 90, "cve": {"id": "CVE-2026-9999", "description": "d"},
        "service": {"service": "http", "port": 80},
    }]}
    client = rep._build_client_markdown()
    assert "0.92" in client
    operator = rep._build_operator_markdown()
    assert "confidence 0.92" in operator


def test_missing_confidence_says_not_recorded_not_zero():
    rep.session.results["exploit"] = {"ranked": [{
        "score": 90, "cve": {"id": "CVE-UNKNOWN", "description": "d"},
        "service": {"service": "http", "port": 80},
    }]}
    assert "not recorded" in rep._build_client_markdown()


# ── G2: persistence cleanup is part of the report ───────────────────────────

def test_persistence_installed_adds_an_unpersist_cleanup_section():
    rep.session.knowledge_base["persistence_set"] = True
    client = rep._build_client_markdown()
    assert "Persistence & Cleanup" in client
    assert "unpersist" in client
    assert "unpersist" in rep._build_operator_markdown()


def test_no_persistence_no_cleanup_section():
    assert "Persistence & Cleanup" not in rep._build_client_markdown()


# ── bonus: markdown bold must produce balanced markup ───────────────────────

def test_bold_to_html_alternates_open_and_close():
    out = rep._bold_to_html("a **b** c **d** e", "<strong>", "</strong>")
    assert out == "a <strong>b</strong> c <strong>d</strong> e"
    assert out.count("<strong>") == out.count("</strong>")
