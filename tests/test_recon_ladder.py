"""The bounded recon ladder: preflight, chunks, early stop, typed verdict."""
from __future__ import annotations

from phantom.automation import recon_ladder as rl


def test_port_chunks_cover_the_whole_space_without_one_giant_run():
    chunks = rl.port_chunks(8192)
    assert chunks[0] == "1-8192"
    assert chunks[-1].endswith("-65535")
    # every port appears exactly once
    covered = set()
    for spec in chunks:
        start, end = (int(x) for x in spec.split("-"))
        covered.update(range(start, end + 1))
    assert covered == set(range(1, 65536))


def test_chunk_command_is_bounded_and_budgeted():
    cmd = rl.chunk_command("192.168.1.18", "8193-16384")
    assert "-p 8193-16384" in cmd
    assert "--host-timeout" in cmd and "--max-retries 1" in cmd
    assert "--min-rate" in cmd
    assert "1-65535" not in cmd


def test_parse_scan_extracts_open_ports_services_and_filtered_count():
    out = """PORT     STATE    SERVICE
22/tcp   open     ssh
443/tcp  open     https
8080/tcp filtered http-proxy
Not shown: 8190 filtered tcp ports (no-response)
"""
    ports, services, filtered = rl.parse_scan(out)
    assert ports == [22, 443]
    assert services[22] == "ssh"
    assert filtered == 8190


def test_unreachable_host_is_not_scanned_at_all():
    calls = []

    def runner(cmd, timeout):
        calls.append(cmd)
        return True, ""

    result = rl.run_ladder(
        "192.168.1.18", runner=runner,
        ping=lambda _h: False, probe=lambda _h, _p: False)
    assert result.verdict == "unreachable"
    assert result.pivot == "identity"
    assert calls == [], "a host that answers nothing must not be scanned"
    assert "RECON_VERDICT" in result.markers()[-1]


def test_two_consecutive_filtered_chunks_stop_the_tcp_rung():
    calls = []

    def runner(cmd, timeout):
        calls.append(cmd)
        return True, "Not shown: 8192 filtered tcp ports (no-response)"

    result = rl.run_ladder(
        "192.168.1.18", runner=runner, chunk_size=8192,
        ping=lambda _h: True, probe=lambda _h, _p: False)
    tcp_calls = [c for c in calls if "-sT" in c]
    assert len(tcp_calls) == 2, calls
    assert result.verdict == "filtered"
    assert result.pivot == "identity"
    assert "pivot to the identity path" in result.reason


def test_open_ports_make_it_a_network_target_and_keep_the_service():
    def runner(cmd, timeout):
        if "-p 1-8" in cmd:
            return True, ("PORT   STATE SERVICE\n"
                          "22/tcp open  ssh\n"
                          "Not shown: 6 filtered tcp ports")
        return True, "All 8 scanned ports are closed"

    result = rl.run_ladder(
        "10.0.0.5", runner=runner, chunk_size=8, udp=False,
        ping=lambda _h: True, probe=lambda _h, _p: False)
    assert result.verdict == "open"
    assert result.pivot == "network"
    assert 22 in result.open_ports
    assert result.services[22] == "ssh"
    assert any("SERVICE: port=22" in m for m in result.markers())


def test_udp_rung_runs_when_tcp_finds_nothing_and_can_find_the_surface():
    seen = []

    def runner(cmd, timeout):
        seen.append(cmd)
        if "-sU" in cmd:
            return True, ("PORT    STATE SERVICE\n"
                          "161/udp open  snmp\n")
        return True, "Not shown: 8192 filtered tcp ports"

    result = rl.run_ladder(
        "10.0.0.5", runner=runner, chunk_size=8192, udp=True,
        ping=lambda _h: True, probe=lambda _h, _p: False)
    assert any("-sU" in c for c in seen)
    assert result.verdict == "open"
    assert 161 in result.open_ports


def test_exhausted_budget_returns_a_partial_verdict_not_a_hang():
    result = rl.run_ladder(
        "10.0.0.5", runner=lambda cmd, timeout: (True, ""),
        budget_s=0, ping=lambda _h: True, probe=lambda _h, _p: False)
    assert result.verdict == "partial"
    assert result.pivot == "identity"
    assert result.chunks == []


def test_pivot_helper_maps_the_verdict_to_the_next_goal():
    assert rl.pivot_for(rl.LadderResult(target="x", pivot="identity")) == \
        "identity"
    assert rl.pivot_for(rl.LadderResult(target="x", pivot="network")) == \
        "deliver"


def test_the_capability_is_escalation_only_and_never_a_command():
    from phantom.automation.guidance.kit import (
        CAPABILITIES, recon_ladder_capability)
    # Build-on-demand: the planner must not see a full-range sweep as just
    # another recon move (or an e2e test could execute it by accident).
    assert not [c for c in CAPABILITIES if c.id == "recon_ladder"]
    cap = recon_ladder_capability()
    assert cap.id == "recon_ladder"
    assert cap.exec_class == "in_process_engine"
    assert cap.engine is not None and cap.interpreter is not None
    assert set(cap.effects) == {"service", "recon_verdict"}
    # the preview must not fire the engine: make_command is a placeholder
    from phantom.automation.belief import WorldModel
    cmd = cap.make_command(WorldModel(target="10.0.0.5"), {})
    assert cmd.startswith("# in-process engine")


def test_the_interpreter_turns_markers_into_findings():
    from phantom.automation.belief import WorldModel
    from phantom.automation.guidance.kit import _ladder_interp
    out = "\n".join([
        "SERVICE: port=22 proto=tcp state=open service=ssh",
        "SERVICE: port=443 proto=tcp state=open service=https",
        "RECON_VERDICT: surface=open pivot=network open=22,443 "
        "reason=2 open port(s)",
    ])
    wm = WorldModel(target="10.0.0.5")
    findings = _ladder_interp(out, wm, {})
    services = [f for f in findings if f.kind == "service"]
    verdict = [f for f in findings if f.kind == "recon_verdict"][0]
    assert {f.value["port"] for f in services} == {"22", "443"}
    assert verdict.value["pivot"] == "network"
    assert all(f.source == "recon_ladder" for f in findings)
