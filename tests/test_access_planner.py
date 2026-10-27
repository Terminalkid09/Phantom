"""Access-planner contracts: breadth of candidates, best-path execution."""
from __future__ import annotations

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
from phantom.automation.exploit.sweep import exploit_worldmodel


def _candidate(cid, *, access="exec", success=0.8, complexity=0.4,
               noise=0.5, cve="", action=None, auto=True):
    return AccessCandidate(
        id=cid, cve=cve, target="10.0.0.5", port="80",
        service="http", access=access, success=success,
        complexity=complexity, noise=noise, actionable=True,
        auto_execute=auto, action=action or {"type": "service"})


def test_stealth_prefers_quiet_path_aggressive_prefers_rce():
    loud = _candidate("loud", access="exec", success=0.90,
                      complexity=0.20, noise=0.95)
    quiet = _candidate("quiet", access="file_read", success=0.80,
                       complexity=0.10, noise=0.10)
    stealth = select_candidates([loud, quiet], "stealth", max_attempts=1)
    aggressive = select_candidates([loud, quiet], "aggressive",
                                   max_attempts=1)
    assert stealth and stealth[0].id == "quiet"
    assert aggressive and aggressive[0].id == "loud"


def test_non_cve_service_is_a_candidate_without_version():
    wm = WorldModel(target="10.0.0.5")
    wm.add_finding("service", "tcp/6379",
                   {"port": "6379", "service": "redis", "product": "",
                    "version": ""}, confidence=0.9)
    candidates = collect_candidates(wm=wm, include_nvd=False)
    redis = [c for c in candidates if c.id == "noncve:service:redis:6379"]
    assert redis, [c.id for c in candidates]
    assert redis[0].action["type"] == "service"
    # Unauthenticated Redis means CONFIG SET / MODULE LOAD / replica control,
    # not merely authentication: the old "auth" label understated it.
    assert redis[0].access == "control"


def test_memcached_stats_is_info_not_file_read():
    """`stats` proves exposure, not file read: do not inflate the access."""
    wm = WorldModel(target="10.0.0.5")
    wm.add_finding("service", "tcp/11211",
                   {"port": "11211", "service": "memcached",
                    "product": "", "version": ""}, confidence=0.9)
    candidates = collect_candidates(wm=wm, include_nvd=False)
    mem = [c for c in candidates
           if c.id == "noncve:service:memcached:11211"]
    assert mem
    assert mem[0].access == "info"
    assert mem[0].access_level == 1


def test_redis_info_timeout_setting_is_exposure_not_error():
    """A healthy INFO block carries ``timeout:0``; that is data, not failure.

    Measured on redis:7-alpine (docker lab, 2026-10-26): the old negative
    list matched the bare word ``timeout`` and scored a proven
    unauthenticated Redis as "marker not observed".
    """
    info = ("$131\r\n# Server\r\nredis_version:7.4.11\r\n"
            "redis_mode:standalone\r\n# Clients\r\ntimeout:0\r\n")
    cand = _candidate("noncve:service:redis:6379", access="control",
                      action={"type": "service", "service": "redis",
                              "probe": "redis", "marker": "redis_version",
                              "port": "6379"})
    cand.service = "redis"
    with patch("phantom.automation.exploit.access._tcp_probe",
               return_value=(info, "")):
        out = run_non_cve_candidate(cand)
    assert out.attempted is True
    assert out.vulnerable is True and out.success is True
    assert "redis exposure confirmed" in out.detail


def test_probe_transport_error_stays_negative():
    """A real transport failure must still be reported as no evidence."""
    cand = _candidate("noncve:service:redis:6379", access="control",
                      action={"type": "service", "service": "redis",
                              "probe": "redis", "marker": "redis_version",
                              "port": "6379"})
    cand.service = "redis"
    with patch("phantom.automation.exploit.access._tcp_probe",
               return_value=("", "timed out")):
        out = run_non_cve_candidate(cand)
    assert out.attempted is True
    assert out.vulnerable is False
    assert out.detail == "timed out"


def test_vnc_stays_visible_but_is_not_actionable():
    """A reachable RFB port is a fingerprint, not an access path."""
    wm = WorldModel(target="10.0.0.5")
    wm.add_finding("service", "tcp/5900",
                   {"port": "5900", "service": "vnc", "product": "",
                    "version": ""}, confidence=0.9)
    candidates = collect_candidates(wm=wm, include_nvd=False)
    vnc = [c for c in candidates if c.id == "noncve:service:vnc:5900"]
    assert vnc
    assert vnc[0].actionable is False
    assert vnc[0].auto_execute is False
    assert select_candidates(candidates, "balanced") == []


def test_confirmed_upload_is_file_write_not_exec():
    wm = WorldModel(target="10.0.0.5")
    wm.add_finding("hunt_anomaly", "upload:/upload:8080",
                   {"cls": "upload", "confirmed": True, "port": "8080",
                    "endpoint": "/upload", "evidence": "upload accepted"},
                   confidence=0.9)
    candidates = collect_candidates(wm=wm, include_nvd=False)
    upload = [c for c in candidates if c.id.startswith("noncve:anomaly:upload")]
    assert upload
    assert upload[0].access == "file_write"
    assert upload[0].auto_execute is False


def test_plan_is_visible_but_never_auto_selected():
    plan = AccessCandidate(
        id="CVE-2099-0001", cve="CVE-2099-0001", target="10.0.0.5",
        port="80", source="plan", provider="plan", kind="rce",
        access="exec", success=0.9, actionable=True, auto_execute=False)
    assert select_candidates([plan], "balanced") == []
    assert select_candidates([plan], "balanced", require_auto=False)


def test_exhaustive_is_the_only_way_to_select_everything():
    candidates = [_candidate(f"c{i}") for i in range(5)]
    assert len(select_candidates(candidates, "balanced", max_attempts=2)) == 2
    assert len(select_candidates(candidates, "balanced",
                                 max_attempts=0)) == 5


def test_sweep_executes_best_path_only():
    wm = WorldModel(target="10.0.0.5")
    wm.add_finding("service", "tcp/80",
                   {"port": "80", "service": "http", "product": "apache",
                    "version": "2.4.49"}, confidence=0.9)
    wm.add_finding("service", "tcp/22",
                   {"port": "22", "service": "ssh", "product": "openssh",
                    "version": "7.4"}, confidence=0.9)
    fake = ExploitOutcome(
        cve="CVE-2021-41773", target="10.0.0.5", port="80",
        method="poc", attempted=True, vulnerable=True, rce=True,
        success=True, detail="VULNERABLE (RCE)", evidence="VULNERABLE (RCE)")
    with patch("phantom.automation.exploit.sweep.attempt_cve",
               return_value=[fake]) as run:
        summary = exploit_worldmodel(wm, mode="balanced")
    assert run.call_count == 1
    assert summary["rce"] == ["CVE-2021-41773"]
    assert len(summary["selected"]) >= 1


def test_service_exploit_uses_exploit_lhost_and_lport():
    from phantom.automation.guidance.commands import make_registry
    wm = WorldModel(target="10.0.0.5")
    wm.add_finding("service", "tcp/80",
                   {"port": "80", "service": "http", "product": "apache",
                    "version": "2.4.49"}, confidence=0.9)
    cap = make_registry().get("service_exploit")
    with patch("phantom.automation.exploit.execution._msf_lhost",
               return_value="10.0.0.99"), \
            patch("phantom.automation.exploit.execution._msf_lport",
                  return_value=4444):
        command = cap.make_command(wm, {})
    assert "set LHOST 10.0.0.99" in command
    assert "set LPORT 4444" in command
    assert "set LPORT 8080" not in command


def test_plan_alone_does_not_become_rce_foothold():
    from phantom.automation.guidance.kit import _pick_rce_candidate
    wm = WorldModel(target="10.0.0.5")
    wm.add_finding("exploit_plan", "CVE-2099-0001",
                   {"cve": "CVE-2099-0001", "kind": "rce",
                    "msf_module": "exploit/multi/http/x", "port": "80"},
                   confidence=0.9)
    assert _pick_rce_candidate(wm) is None


def test_confirmed_foothold_can_borrow_plan_module():
    from phantom.automation.guidance.kit import _pick_rce_candidate
    wm = WorldModel(target="10.0.0.5")
    wm.add_finding("exploit_plan", "CVE-2017-7494",
                   {"cve": "CVE-2017-7494", "kind": "rce",
                    "msf_module": "exploit/linux/samba/is_known_pipid",
                    "port": "445"}, confidence=0.9)
    wm.add_finding("rce_foothold", "msf:x",
                   {"channel": "msf"}, confidence=0.9)
    cand = _pick_rce_candidate(wm)
    assert cand is not None
    assert cand["msf_module"] == "exploit/linux/samba/is_known_pipid"


def test_exploitdb_path_key_is_resolved():
    from phantom.utils import exploitdb
    hit = {"Path": "/usr/share/exploitdb/exploits/"
                   "multiple/remote/modules/exploit/multi/http/x.rb",
           "Title": "Metasploit module"}
    with patch.object(exploitdb, "by_cve", return_value=[hit]):
        paths = exploitdb.module_paths_for_cve("CVE-2099-0001")
    assert paths == ["exploit/multi/http/x"]
