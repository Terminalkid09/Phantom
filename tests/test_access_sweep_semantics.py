"""Best-path semantics: bounded fallback, exhaustive, no retest, real probes."""
from __future__ import annotations

import socket
import threading
from types import SimpleNamespace
from unittest.mock import patch

from phantom.automation.belief import WorldModel
from phantom.automation.exploit.access import (
    AccessCandidate,
    collect_candidates,
    run_non_cve_candidate,
    select_candidates,
)
from phantom.automation.exploit.execution import ExploitOutcome
from phantom.automation.exploit.modules.registry import ExploitModule
from phantom.automation.exploit.sweep import exploit_worldmodel


def _candidate(cve: str, port: str = "80", auto: bool = True):
    module = ExploitModule(
        cve_id=cve, name=cve, software="example", description="",
        msf_module="exploit/multi/http/example")
    return AccessCandidate(
        id=cve, cve=cve, target="10.0.0.5", port=port, access="exec",
        module=module, actionable=True, auto_execute=auto)


def _negative(cve: str) -> ExploitOutcome:
    return ExploitOutcome(
        cve=cve, target="10.0.0.5", port="80", method="msf",
        attempted=True, vulnerable=False, detail="target not vulnerable")


def _rce(cve: str) -> ExploitOutcome:
    return ExploitOutcome(
        cve=cve, target="10.0.0.5", port="80", method="poc",
        attempted=True, vulnerable=True, rce=True, success=True,
        evidence="uid=0(root)", detail="VULNERABLE (RCE)")


def test_fallback_runs_only_after_the_best_path_fails():
    a, b = _candidate("CVE-2099-0001"), _candidate("CVE-2099-0002")
    wm = WorldModel(target="10.0.0.5")
    with patch("phantom.automation.exploit.sweep.collect_candidates",
               return_value=[a, b]), \
            patch("phantom.automation.exploit.sweep.attempt_cve",
                  side_effect=[[_negative(a.cve)], [_rce(b.cve)]]) as run:
        summary = exploit_worldmodel(wm, mode="balanced")
    assert run.call_count == 2
    assert summary["rce"] == [b.cve]
    assert summary["vulnerable"] == [b.cve]


def test_first_success_stops_the_fallback():
    candidates = [_candidate(f"CVE-2099-000{i}") for i in range(1, 4)]
    wm = WorldModel(target="10.0.0.5")
    with patch("phantom.automation.exploit.sweep.collect_candidates",
               return_value=candidates), \
            patch("phantom.automation.exploit.sweep.attempt_cve",
                  side_effect=[[_rce(candidates[0].cve)]]) as run:
        summary = exploit_worldmodel(wm, mode="balanced")
    assert run.call_count == 1
    assert summary["rce"] == [candidates[0].cve]


def test_exhaustive_is_the_only_mode_that_tries_everything():
    candidates = [_candidate(f"CVE-2099-000{i}") for i in range(1, 4)]
    wm = WorldModel(target="10.0.0.5")
    with patch("phantom.automation.exploit.sweep.collect_candidates",
               return_value=candidates), \
            patch("phantom.automation.exploit.sweep.attempt_cve",
                  side_effect=[[_rce(c.cve)] for c in candidates]) as run:
        summary = exploit_worldmodel(wm, mode="balanced", exhaustive=True)
    assert run.call_count == 3
    assert sorted(summary["rce"]) == sorted(c.cve for c in candidates)


def test_already_tested_candidate_is_not_retested():
    cand = _candidate("CVE-2099-0001")
    wm = WorldModel(target="10.0.0.5")
    wm.add_finding("exploit_result", cand.cve,
                   {"cve": cand.cve, "attempted": True, "vulnerable": False},
                   confidence=0.6)
    with patch("phantom.automation.exploit.sweep.collect_candidates",
               return_value=[cand]), \
            patch("phantom.automation.exploit.sweep.attempt_cve") as run:
        summary = exploit_worldmodel(wm, mode="balanced")
    assert run.call_count == 0
    assert summary["attempted"] == 0


def test_plan_candidate_is_visible_but_never_auto_executed():
    plan = _candidate("CVE-2099-0001", auto=False)
    wm = WorldModel(target="10.0.0.5")
    with patch("phantom.automation.exploit.sweep.collect_candidates",
               return_value=[plan]), \
            patch("phantom.automation.exploit.sweep.attempt_cve") as run:
        summary = exploit_worldmodel(wm, mode="balanced")
    assert run.call_count == 0
    assert summary["selected"] == []
    assert select_candidates([plan], "balanced") == []


def _serve_once(response: bytes) -> int:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def _run():
        try:
            conn, _ = server.accept()
            try:
                conn.recv(4096)
                conn.sendall(response)
            finally:
                conn.close()
        finally:
            server.close()

    threading.Thread(target=_run, daemon=True).start()
    return port


def _service_candidate(service: str, port: int, target: str = "127.0.0.1"):
    wm = WorldModel(target=target)
    wm.add_finding("service", f"tcp/{port}",
                   {"port": str(port), "service": service,
                    "product": "", "version": ""}, confidence=0.9)
    candidates = collect_candidates(wm=wm, include_nvd=False)
    return next(c for c in candidates if c.service == service)


def test_redis_probe_needs_the_marker_and_never_claims_rce():
    port = _serve_once(b"$40\r\n# Server\r\nredis_version:7.0.0\r\n")
    cand = _service_candidate("redis", port)
    out = run_non_cve_candidate(cand, timeout=2)
    assert out.attempted is True
    assert out.vulnerable is True
    assert out.rce is False
    assert cand.access == "control"


def test_redis_probe_without_marker_is_not_vulnerable():
    port = _serve_once(b"ERR unknown command\r\n")
    cand = _service_candidate("redis", port)
    out = run_non_cve_candidate(cand, timeout=2)
    assert out.attempted is True
    assert out.vulnerable is False


def test_memcached_stats_proves_exposure_not_file_read():
    port = _serve_once(b"STAT version 1.6.0\r\nEND\r\n")
    cand = _service_candidate("memcached", port)
    out = run_non_cve_candidate(cand, timeout=2)
    assert out.attempted is True
    assert out.vulnerable is True
    assert out.rce is False
    assert cand.access == "info"


def test_automode_forwards_posture_and_exhaustive():
    from phantom.core import automode

    agent = SimpleNamespace(wm=WorldModel(target="10.0.0.5"), result={})
    summary = {"candidates": 1, "attempted": 0, "rce": [],
               "vulnerable": [], "outcomes": [], "knowledge_only": []}
    with patch("phantom.automation.exploit.sweep.exploit_worldmodel",
               return_value=summary) as sweep:
        automode._exploit_all_after_run(
            agent, "deliver", "", {}, stealth=True, exhaustive=True)
    kwargs = sweep.call_args.kwargs
    assert kwargs["mode"] == "stealth"
    assert kwargs["exhaustive"] is True

    with patch("phantom.automation.exploit.sweep.exploit_worldmodel",
               return_value=summary) as sweep:
        automode._exploit_all_after_run(
            agent, "deliver", "", {}, stealth=True, aggressive=True)
    assert sweep.call_args.kwargs["mode"] == "aggressive"


def _fingerprinting_agent(services):
    """Agent double: the WorldModel, a registry with only version_detect,
    and an executor that emulates nmap -sV storing product+version at the
    SAME confidence as the scan finding (so belief revision supersedes)."""
    wm = WorldModel(target="127.0.0.1")
    for port, value in services:
        wm.add_finding("service", f"tcp/{port}", value, confidence=0.9)

    class _Reg:
        def get(self, cid):
            if cid == "version_detect":
                return SimpleNamespace(id="version_detect", category="recon")
            return None

    agent = SimpleNamespace(wm=wm, result={}, registry=_Reg(), executed=[])

    def _execute_capability(step):
        agent.executed.append(step)
        for port, _value in services:
            agent.wm.add_finding(
                "service", f"tcp/{port}",
                {"port": str(port), "service": "http",
                 "product": "Apache httpd", "version": "2.4.49"},
                confidence=0.9, source="version_detect")
        return True

    agent._execute_capability = _execute_capability
    return agent


def _empty_sweep():
    return {"candidates": 1, "attempted": 0, "rce": [], "vulnerable": [],
            "outcomes": [], "knowledge_only": []}


def test_exploit_all_fingerprints_unversioned_ports_before_the_match():
    """Live docker lab: the scan labelled 8081 `blackice-icecap` with an
    empty product/version, so the CVE registry matched nothing and the
    auto-mode payload chain stayed empty while the manual `fire` on the same
    port confirmed the traversal. The sweep must see a fingerprinted world."""
    from phantom.core import automode

    agent = _fingerprinting_agent([
        (8081, {"port": "8081", "service": "blackice-icecap",
                "product": "", "version": ""})])
    seen = {}
    summary = _empty_sweep()

    def _sweep(wm, **kwargs):
        seen["version"] = wm.find("service")[0].value.get("version")
        return summary

    with patch("phantom.automation.exploit.sweep.exploit_worldmodel",
               side_effect=_sweep):
        out = automode._exploit_all_after_run(agent, "deliver", "", {})

    assert [s.capability.id for s in agent.executed] == ["version_detect"]
    assert "unversioned" in agent.executed[0].reason
    assert seen["version"] == "2.4.49"      # the sweep ran on the new facts
    assert out["fingerprint"]["attempted"] is True
    assert out["fingerprint"]["versioned"] == 1
    assert out["fingerprint"]["still_unversioned_ports"] == []


def test_exploit_all_refingerprints_nothing_when_versions_are_known():
    from phantom.core import automode

    agent = _fingerprinting_agent([
        (80, {"port": "80", "service": "http", "product": "nginx",
              "version": "1.24.0"})])
    with patch("phantom.automation.exploit.sweep.exploit_worldmodel",
               return_value=_empty_sweep()):
        out = automode._exploit_all_after_run(agent, "deliver", "", {})

    assert agent.executed == []
    assert out["fingerprint"]["attempted"] is False
    assert "already" in out["fingerprint"]["reason"]


def test_exploit_all_says_which_ports_stayed_unversioned():
    """A refusal (recon banned for this worker, no nmap, gate veto) must not
    read as "no weapon exists": the receipt names the blind ports."""
    from phantom.core import automode

    agent = _fingerprinting_agent([
        (8081, {"port": "8081", "service": "blackice-icecap",
                "product": "", "version": ""})])
    agent.registry = SimpleNamespace(get=lambda cid: None)
    with patch("phantom.automation.exploit.sweep.exploit_worldmodel",
               return_value=_empty_sweep()):
        out = automode._exploit_all_after_run(agent, "deliver", "", {})

    assert agent.executed == []
    assert out["fingerprint"]["attempted"] is False
    assert "not registered" in out["fingerprint"]["reason"]
    assert out["fingerprint"]["unversioned_ports"] == ["8081"]


# ── a candidate with no weapon is NOT "already tested" ────────────────────

def test_a_recorded_but_unattempted_candidate_is_retried():
    """Audit 2026-10-30: `exploit-all` with no Metasploit wrote
    `attempted: False` for every CVE, and `_already_tested` then excluded them
    for ever. Installing the tool and re-running reported "already attempted"
    on a path that had never been tried once.
    """
    from phantom.automation.exploit.sweep import _already_tested

    wm = WorldModel(target="10.0.0.5")
    cand = AccessCandidate(id="c1", cve="CVE-2021-41773", port="80",
                           service="http", kind="cve", access="rce")
    key = cand.id if hasattr(cand, "id") else "c1"
    from phantom.automation.exploit import sweep as _sweep
    key = _sweep._candidate_key(cand)

    wm.add_finding("exploit_result", key,
                   {"cve": cand.cve, "id": cand.id, "attempted": False,
                    "vulnerable": False, "rce": False, "detail":
                    "no weapon available"},
                   confidence=0.6, source="test")
    assert _already_tested(wm, cand) is False, (
        "nothing was executed, so the path must stay in the retry set")

    wm.add_finding("exploit_result", key,
                   {"cve": cand.cve, "id": cand.id, "attempted": True,
                    "vulnerable": False, "rce": False},
                   confidence=0.6, source="test")
    assert _already_tested(wm, cand) is True
