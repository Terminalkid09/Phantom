"""Generic CVE intake: a new CVE becomes a weapon without a code change."""
from __future__ import annotations

from unittest.mock import patch

from phantom.automation.belief import WorldModel
from phantom.automation.exploit import intake
from phantom.automation.exploit.access import (
    AccessCandidate,
    collect_candidates,
)
from phantom.automation.exploit.execution import (
    ExploitOutcome,
    attempt_cve,
)
from phantom.automation.exploit import execution


def _wm(product="acme", version="1.0", port="80"):
    wm = WorldModel(target="10.0.0.5")
    wm.add_finding("service", f"tcp/{port}",
                   {"port": port, "service": "http", "product": product,
                    "version": version}, confidence=0.9)
    return wm


def _nvd(product="acme", version="1.0", cve="CVE-2099-12345", cvss=9.8):
    def lookup(_product, _version):
        return [{"id": cve, "cvss": cvss, "exact_match": True,
                 "description": f"{product} remote code execution"}]
    return lookup


def test_new_cve_resolves_a_module_from_the_local_exploitdb_mirror():
    with patch.object(intake.module_registry, "get", return_value=None), \
            patch.object(intake, "find_local_poc", return_value=None), \
            patch("phantom.utils.exploitdb.module_paths_for_cve",
                  return_value=["exploit/multi/http/acme_rce"]):
        pack = intake.resolve_weapon("CVE-2099-12345", "acme", "1.0",
                                     allow_msf_search=False)
    assert pack.actionable
    assert pack.msf_module == "exploit/multi/http/acme_rce"
    assert pack.source == "exploitdb"
    assert pack.status == "candidate"


def test_collection_turns_the_new_cve_into_an_actionable_path():
    with patch.object(intake.module_registry, "get", return_value=None), \
            patch.object(intake, "find_local_poc", return_value=None), \
            patch("phantom.utils.exploitdb.module_paths_for_cve",
                  return_value=["exploit/multi/http/acme_rce"]):
        candidates = collect_candidates(wm=_wm(), nvd_fn=_nvd(),
                                        include_nvd=True)
    cand = next(c for c in candidates if c.cve == "CVE-2099-12345")
    assert cand.actionable is True
    assert cand.module is not None
    assert cand.module.msf_module == "exploit/multi/http/acme_rce"


def test_high_severity_cve_without_a_known_weapon_is_a_bounded_intake_candidate():
    with patch.object(intake.module_registry, "get", return_value=None), \
            patch.object(intake, "find_local_poc", return_value=None), \
            patch("phantom.utils.exploitdb.module_paths_for_cve",
                  return_value=[]):
        candidates = collect_candidates(wm=_wm(), nvd_fn=_nvd(),
                                        include_nvd=True)
    cand = next(c for c in candidates if c.cve == "CVE-2099-12345")
    assert cand.actionable is True
    assert cand.metadata.get("intake") is True
    assert cand.module is None and cand.poc is None
    # It must lose to a known weapon and never pretend to be evidence.
    assert cand.success < 0.5


def test_execution_discovers_a_module_and_marks_the_pack_verified():
    pack = intake.ExploitPack(
        cve="CVE-2099-12345", msf_module="exploit/multi/http/acme_rce",
        source="msf_search")
    outcome = ExploitOutcome(
        cve="CVE-2099-12345", target="10.0.0.5", port="80", method="msf",
        attempted=True, vulnerable=True, rce=True, success=True,
        evidence="meterpreter session 1 opened", detail="session 1 opened")
    with patch("phantom.automation.exploit.intake.resolve_weapon",
               return_value=pack), \
            patch("phantom.automation.exploit.execution.msf_available",
                  return_value=True), \
            patch("phantom.automation.exploit.execution.run_msf_module",
                  return_value=outcome) as msf:
        outcomes = attempt_cve("CVE-2099-12345", "10.0.0.5", "80",
                               allow_msf=True, product="acme",
                               version="1.0")
    assert msf.call_count == 1
    assert outcomes[0].rce is True
    stored = intake.get_pack("CVE-2099-12345")
    assert stored is not None
    assert stored.status == "verified"
    assert stored.rce is True


def test_local_poc_lab_run_is_evidence_and_verifies_the_pack(
        tmp_path, monkeypatch):
    poc_dir = tmp_path / "pocs"
    poc_dir.mkdir()
    (poc_dir / "lab_poc.py").write_text(
        'METADATA = {"name": "lab", "cve": "CVE-2099-99999",\n'
        '            "port": "Any", "timeout": 10}\n'
        "def run(target, port, command=\"\"):\n"
        '    print("VULNERABLE (RCE) uid=0(root)")\n'
        '    return "VULNERABLE (RCE) uid=0(root)"\n',
        encoding="utf-8")
    monkeypatch.setattr(execution, "_POC_ROOT", poc_dir)
    intake.reset_cache()
    with patch.object(intake.module_registry, "get", return_value=None), \
            patch("phantom.utils.exploitdb.module_paths_for_cve",
                  return_value=[]):
        outcomes = execution.attempt_cve("CVE-2099-99999", "127.0.0.1", "1")
    out = outcomes[0]
    assert out.method == "poc"
    assert out.attempted is True
    assert out.vulnerable is True
    assert out.rce is True
    stored = intake.get_pack("CVE-2099-99999")
    assert stored is not None and stored.status == "verified"
    assert stored.evidence.startswith("VULNERABLE")


def test_verified_pack_ranks_higher_and_three_failures_retire_it():
    cve = "CVE-2099-77777"
    cand = AccessCandidate(
        id=cve, cve=cve, target="10.0.0.5", port="80", access="exec",
        actionable=True, auto_execute=True)
    plain = cand.score_for("balanced")
    cand.metadata["pack_status"] = "verified"
    cand.metadata["pack_boost"] = 4.0
    assert cand.score_for("balanced") == round(plain + 4.0, 2)

    pack = intake.ExploitPack(cve=cve, msf_module="exploit/multi/http/x")
    for _ in range(3):
        intake.record_outcome(
            cve, ExploitOutcome(cve=cve, attempted=True, vulnerable=False,
                                detail="not vulnerable"), pack=pack)
    stored = intake.get_pack(cve)
    assert stored is not None and stored.status == "deprecated"
    assert intake.rank_boost(cve) == (-10.0, False)


def test_fire_resolves_a_new_cve_through_intake():
    from phantom.core.session import session
    from phantom.modules.exploit import ExploitModule as ShellExploit

    cve = "CVE-2099-12345"
    pack = intake.ExploitPack(
        cve=cve, msf_module="exploit/multi/http/acme_rce",
        source="msf_search")
    outcome = ExploitOutcome(
        cve=cve, target="10.0.0.5", port="80", method="msf",
        attempted=True, vulnerable=True, rce=True, success=True,
        evidence="session 1 opened", detail="session 1 opened")
    shell = object.__new__(ShellExploit)
    shell._port_for_cve = lambda _cve: "80"
    shell._module_for_cve = lambda _cve: None
    seen = {}
    shell._fire_outcomes = lambda cve_id, port, outcomes, module=None: seen.update(
        {"cve": cve_id, "module": module, "outcomes": outcomes})
    previous = session.target
    session.target = "10.0.0.5"
    try:
        with patch("phantom.automation.exploit.execution.find_local_poc",
                   return_value=None), \
                patch("phantom.automation.exploit.intake.resolve_weapon",
                      return_value=pack), \
                patch("phantom.automation.exploit.execution.attempt_cve",
                      return_value=[outcome]) as run:
            shell.do_fire(cve)
    finally:
        session.target = previous
    assert seen["cve"] == cve
    assert seen["module"] is not None
    assert seen["module"].msf_module == "exploit/multi/http/acme_rce"
    assert run.call_args.kwargs["module"].msf_module == (
        "exploit/multi/http/acme_rce")


def test_deprecated_pack_is_not_auto_fired():
    cve = "CVE-2099-88888"
    intake.save_pack(intake.ExploitPack(
        cve=cve, msf_module="exploit/multi/http/x", status="deprecated"))
    with patch("phantom.utils.exploitdb.module_paths_for_cve",
               return_value=["exploit/multi/http/x"]):
        candidates = collect_candidates(wm=_wm(), nvd_fn=_nvd(cve=cve),
                                        include_nvd=True)
    cand = next(c for c in candidates if c.cve == cve)
    assert cand.auto_execute is False
