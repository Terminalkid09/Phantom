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
