"""Tests for the manual-core enterprise upgrade:
- wordlist module registration in the shell
- adaptive `run` (next step from target type + findings)
- professional two-level report (operator raw + sanitized client)
- scan -> knowledge_base population
- exploit enterprise enrichment (threat intel + ATT&CK + risk)
- evidence-based engagement learning at report time
"""

import os
import tempfile
from types import SimpleNamespace

import pytest

from phantom.core.session import session
from phantom.core import shell as shell_mod


@pytest.fixture(autouse=True)
def clean_session():
    session.target = ""
    session.results = {}
    session.notes = []
    session.history = []
    session.knowledge_base = {
        "target": "", "target_type": None, "stealth": True, "aggressive": False,
        "started_at": None, "status": {}, "services": [], "os_info": {},
        "creds_found": [], "rce_vectors": [], "cves": [], "web_endpoints": [],
        "social_profiles": [], "emails_found": [], "subdomains_found": [],
        "breaches_found": [], "beacon_deployed": False, "persistence_set": False,
        "current_step": None, "errors": [], "next_targets": [], "last_output": {},
        "critical_infrastructure": False, "domain_environment": False,
        "network_segmentation": {}, "critical_assets": [], "password_policy": {},
        "waf_detected": False, "domain_enumerated": False, "known_defaults": False,
    }
    yield


# ── shell registration ────────────────────────────────────────────────────

def test_wordlist_registered_in_do_use():
    sh = shell_mod.PhantomShell()
    # _instantiate_module must resolve wordlist
    inst = sh._instantiate_module("wordlist")
    assert inst is not None
    assert inst.module_name == "wordlist"


def test_next_step_for_identity_target_suggests_osint():
    sh = shell_mod.PhantomShell()
    session.target = "mario.rossi@acme.it"
    module, reason = sh._next_step()
    assert module == "osint"
    assert "identity" in reason.lower()


def test_next_step_for_network_target_without_findings_suggests_scan():
    sh = shell_mod.PhantomShell()
    session.target = "10.0.0.5"
    from phantom.core.knowledge import reset_wm
    reset_wm(target="10.0.0.5")
    module, reason = sh._next_step()
    assert module == "scan"


def test_run_without_target_errors():
    sh = shell_mod.PhantomShell()
    session.target = ""
    sh.do_run("")  # must not raise


def test_run_unknown_module_errors():
    sh = shell_mod.PhantomShell()
    session.target = "10.0.0.5"
    sh.do_run("not-a-module")  # must not raise


def test_set_target_accepts_phone_and_username_with_dot():
    sh = shell_mod.PhantomShell()
    from phantom.core.knowledge import reset_wm
    sh.do_set("target +391234567890")
    assert session.target == "+391234567890"
    sh.do_set("target mario.rossi")
    assert session.target == "mario.rossi"
    sh.do_set("target bob@corp.com")
    assert session.target == "bob@corp.com"
    reset_wm(target="")


def test_network_module_warns_on_identity_target(caplog):
    sh = shell_mod.PhantomShell()
    session.target = "bob@corp.com"
    from phantom.core.knowledge import reset_wm
    reset_wm(target="bob@corp.com")
    assert sh._warn_identity_target("scan") is True
    assert sh._warn_identity_target("osint") is False
    sh.do_run("scan")  # must not crash on identity target


# ── professional report ───────────────────────────────────────────────────

def _seed_session():
    session.target = "10.0.0.5"
    session.results["service_summary"] = [
        {"port": 22, "service": "ssh", "version": "OpenSSH 8.2"}]
    session.results["exploit"] = {"ranked": [
        {"cve": {"id": "CVE-2024-1234", "description": "Test vuln"},
         "service": {"port": 22, "service": "ssh"}, "score": 85,
         "has_msf": True, "has_poc": False, "exploited": True}]}
    session.results["scan"] = {"cmd": "nmap -sV 10.0.0.5"}
    session.knowledge_base["creds_found"] = [
        {"service": "ssh", "username": "root", "password": "toor", "valid": True}]
    session.knowledge_base["attack_techniques"] = [
        {"id": "T1110", "name": "Brute Force", "tactic": "Credential Access",
         "phase": "initial-access", "prevalence": 60.0}]
    session.knowledge_base["target_risk"] = 85.0
    session.history = ["[12:00:00] nmap -sV 10.0.0.5"]


def test_operator_report_contains_everything():
    from phantom.modules.report import _build_operator_markdown
    _seed_session()
    md = _build_operator_markdown()
    assert "root" in md              # credentials present for the operator
    assert "nmap -sV" in md          # full command history present
    assert "CVE-2024-1234" in md
    assert "MITRE ATT&CK Mapping" in md
    assert "Target Exposure Risk" in md
    assert "Operator Report" in md


def test_client_report_is_sanitized():
    from phantom.modules.report import _build_client_markdown
    _seed_session()
    md = _build_client_markdown()
    assert "root" not in md          # credentials must never leak
    assert "nmap" not in md          # commands must never leak
    assert "toor" not in md
    assert "Penetration Test Report" in md
    assert "Scope & Methodology" in md
    assert "Recommended Hardening" in md
    assert "MITRE ATT&CK Coverage" in md
    assert "CVE-2024-1234" in md


def test_export_full_set_writes_four_files():
    import phantom.core.calibration as cal
    import phantom.core.history as hist
    tmp = tempfile.mkdtemp()
    orig_cal, orig_hist = cal.calibration_engine, hist.history_analyzer
    try:
        cal.calibration_engine = cal.CalibrationEngine(os.path.join(tmp, "cal.json"))
        hist.history_analyzer = hist.HistoricalAnalyzer(os.path.join(tmp, "hist.json"))

        from phantom.modules.report import ReportModule
        _seed_session()
        ReportModule()._export_full_set()
        from phantom.utils.paths import reports_dir
        rdir = reports_dir()
        candidates = []
        for d in os.listdir(rdir):
            p = os.path.join(rdir, d)
            if os.path.isdir(p) and os.listdir(p):
                candidates.append(p)
        newest = max(candidates, key=os.path.getmtime)
        files = set(os.listdir(newest))
        assert {"raw_report.json", "raw_report.md",
                "client_report.md", "client_report.html"} <= files
    finally:
        # restore the module singletons: other tests read them and a stale
        # temp-file instance silently empties their assertions
        cal.calibration_engine = orig_cal
        hist.history_analyzer = orig_hist


# ── scan -> knowledge_base ────────────────────────────────────────────────

def test_scan_populates_knowledge_base():
    from phantom.modules.scan import ScanModule
    session.target = "10.0.0.5"
    results = {"cmd": "nmap -sV 10.0.0.5\n"
                      "22/tcp open ssh OpenSSH 8.2\n"
                      "445/tcp open microsoft-ds Windows 10\n"
                      "OS details: Windows 10 Pro"}
    ScanModule()._analyze_vulnerabilities(results)
    kb = session.knowledge_base
    assert kb["status"]["scan_done"] is True
    assert kb["services"], "services must be stored in KB"
    assert kb["domain_environment"] is True      # 445 microsoft-ds
    assert kb["os_info"].get("os")               # OS parsed from output
    assert session.get_result("service_summary")


# ── exploit enterprise enrichment ─────────────────────────────────────────

class _FakeIntel:
    def is_recently_exploited(self, cve_id):
        return {"exploited": cve_id == "CVE-2024-1234",
                "confidence": 95.0, "source": "CISA KEV"}


def test_exploit_enrichment_threat_intel_and_attck():
    import phantom.automation.enterprise as ent
    from phantom.modules.exploit import ExploitModule

    orig = ent.EnterpriseBrain
    ent.EnterpriseBrain = lambda profile="enterprise", threat_intel=None: \
        orig(profile, threat_intel=_FakeIntel())
    try:
        svc = SimpleNamespace(port="22", service="ssh",
                              product="OpenSSH", version="8.2")
        ranked = [
            {"service": svc, "cve": {"id": "CVE-2024-1234", "description": "x"},
             "score": 60, "has_msf": False, "has_poc": False},
            {"service": svc, "cve": {"id": "CVE-2023-9999", "description": "y"},
             "score": 80, "has_msf": True, "has_poc": True},
        ]
        session.target = "10.0.0.5"
        ExploitModule()._enterprise_enrich(ranked, [svc])
    finally:
        ent.EnterpriseBrain = orig

    res = session.get_result("exploit")
    assert res["ranked"][0]["exploited"] is True       # KEV CVE first
    assert res["ranked"][0]["score"] >= 75             # boosted +15
    assert res["ranked"][0]["exploit_source"] == "CISA KEV"
    assert res["attack_techniques"]                    # ATT&CK mapped
    assert res["target_risk"] >= 0                     # composite risk
    assert session.knowledge_base["attack_techniques"]
    assert session.knowledge_base["target_risk"] == res["target_risk"]


# ── evidence-based learning ───────────────────────────────────────────────

def test_record_learning_evidence_based():
    import phantom.core.calibration as cal
    import phantom.core.history as hist
    tmp = tempfile.mkdtemp()
    orig_cal, orig_hist = cal.calibration_engine, hist.history_analyzer
    try:
        cal.calibration_engine = cal.CalibrationEngine(os.path.join(tmp, "cal.json"))
        hist.history_analyzer = hist.HistoricalAnalyzer(os.path.join(tmp, "hist.json"))

        from phantom.modules.report import ReportModule
        session.target = "10.0.0.5"
        session.results["scan"] = {"cmd": "nmap"}
        session.results["service_summary"] = [{"port": 22, "service": "ssh"}]
        session.results["brute"] = {"x": "y"}
        session.results["exploit"] = {"ranked": []}
        session.knowledge_base["creds_found"] = [{"service": "ssh", "username": "u"}]
        session.knowledge_base["status"]["rce_attempted"] = True

        n = ReportModule()._record_learning()
        assert n == 4
        obs = cal.calibration_engine.observations
        assert obs["network_service_scanning"] == {"successes": 1, "failures": 0}
        assert obs["brute_force_passwords"] == {"successes": 1, "failures": 0}
        assert obs["exploit_cve_public"] == {"successes": 0, "failures": 1}
        assert obs["beacon_deploy"] == {"successes": 0, "failures": 1}
    finally:
        # restore the module singletons (same pollution guard as above)
        cal.calibration_engine = orig_cal
        hist.history_analyzer = orig_hist
