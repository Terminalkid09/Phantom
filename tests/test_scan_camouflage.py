"""Scan camouflage: profiles, seeded determinism, bounded jitter.

The operator's rule is one acting agent on the scan, so this is traffic
VARIATION from a single source, not distributed scanning. The tests pin the
honest properties: balanced is unchanged, blend is deterministic with a
seed, coverage is identical, jitter never eats the budget, and SYN only
appears with an explicit opt-in.
"""
from __future__ import annotations

import re
from types import SimpleNamespace

import pytest

from phantom.automation import recon_ladder as rl

_SPEC = re.compile(r"-p (\S+)")


def _run(profile, *, seed=None, budget=60, allow_syn=False, sleep=None,
         clock=None, udp=False, stop=99):
    calls = []

    def runner(cmd, timeout):
        calls.append(cmd)
        return True, "Not shown: 8192 filtered tcp ports"

    result = rl.run_ladder(
        "10.0.0.5", runner=runner, chunk_size=8192, udp=udp,
        filtered_chunks_to_stop=stop, profile=profile, seed=seed,
        budget_s=budget, allow_syn=allow_syn,
        # never sleep for real in a unit test; a test that CARES about the
        # delay passes its own recorder (and a clock that advances with it)
        sleep=sleep if sleep is not None else (lambda _s: None), clock=clock,
        ping=lambda _h: True, probe=lambda _h, _p: False)
    return result, calls


def _specs(calls):
    return [_SPEC.search(cmd).group(1) for cmd in calls]


def test_balanced_keeps_the_historical_command_and_order():
    result, calls = _run("balanced")
    assert _specs(calls) == rl.port_chunks(8192)
    for cmd in calls:
        assert "-sT" in cmd and "-T4" in cmd and "--min-rate 1200" in cmd
        assert "-g " not in cmd and "-sS" not in cmd
    assert all(c.jitter_s == 0 for c in result.chunks)
    assert "jitter=0.00s" in result.chunks[0].marker()


def test_seed_makes_a_blend_run_deterministic():
    _r1, first = _run("blend", seed=7)
    _r2, second = _run("blend", seed=7)
    assert first == second


def test_shuffled_order_still_covers_every_port_exactly_once():
    _result, calls = _run("blend", seed=7)
    specs = _specs(calls)
    assert len(specs) == len(set(specs))
    covered = set()
    for spec in specs:
        start, end = (int(x) for x in spec.split("-"))
        covered.update(range(start, end + 1))
    assert covered == set(range(1, 65536))
    assert specs != sorted(specs), "blend must actually reorder the chunks"


def test_jitter_is_bounded_by_the_remaining_budget():
    clock_time = [0.0]
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        clock_time[0] += seconds

    result, _calls = _run(
        "blend", seed=3, budget=6, sleep=sleep, clock=lambda: clock_time[0])
    assert result.jitter_total_s <= 6
    assert result.elapsed <= 6
    assert sleeps, "blend should insert at least one delay"
    # budget 6 leaves only 1s above the 5s reserve, so no delay may exceed it
    assert max(sleeps) <= 1.0 + 1e-9


def test_quiet_is_slower_and_quieter_than_balanced():
    _r, balanced = _run("balanced")
    result, quiet = _run("quiet", seed=11)
    assert all("--min-rate 300" in c and "-T2" in c for c in quiet)
    assert all("-T4" not in c for c in quiet)
    assert float(quiet[0].split("--min-rate ")[1].split()[0]) < 1200
    assert result.profile == "quiet"
    assert all(c.source_port is None for c in result.chunks)


def test_source_port_rotation_happens_only_in_blend():
    _r, blend = _run("blend", seed=5)
    ports = []
    for cmd in blend:
        match = re.search(r"-g (\d+)", cmd)
        assert match, cmd
        ports.append(int(match.group(1)))
    assert set(ports) <= set(rl.SOURCE_PORTS)
    assert len(set(ports)) > 1


def test_syn_is_never_used_without_an_explicit_opt_in():
    _r, calls = _run("blend", seed=2)
    assert not any("-sS" in c for c in calls)


def test_syn_appears_only_when_allowed():
    _r, calls = _run("blend", seed=2, allow_syn=True)
    techniques = {"-sS" if "-sS" in c else "-sT" for c in calls}
    assert techniques == {"-sS", "-sT"}


def test_profile_for_agent_maps_the_operator_posture():
    agent = SimpleNamespace(wm=SimpleNamespace(scan_style="balanced"),
                            stealth=False, aggressive=False, speed=False)
    assert rl.profile_for_agent(agent) == "balanced"
    agent.stealth = True
    assert rl.profile_for_agent(agent) == "quiet"
    agent.stealth = False
    agent.aggressive = True
    assert rl.profile_for_agent(agent) == "blend"
    agent.aggressive = False
    agent.speed = True
    assert rl.profile_for_agent(agent) == "blend"
    agent.speed = False
    agent.wm.scan_style = "full_stealth"
    assert rl.profile_for_agent(agent) == "quiet"
    agent.wm.scan_style = "top_fast"
    assert rl.profile_for_agent(agent) == "blend"


def test_the_agent_default_profile_is_used_when_none_is_passed():
    rl.set_default_profile("quiet")
    try:
        result, calls = _run(None, seed=1)
    finally:
        rl.set_default_profile("balanced")
    assert result.profile == "quiet"
    assert all("--min-rate 300" in c for c in calls)


def test_unknown_profile_is_refused():
    with pytest.raises(ValueError):
        rl.run_ladder("10.0.0.5", profile="invisible",
                      runner=lambda *_a: (True, ""))


def test_blend_markers_expose_profile_jitter_and_source_port():
    result, _calls = _run("blend", seed=9)
    marker = result.chunks[0].marker()
    assert "profile=blend" in marker
    assert "jitter=" in marker
    assert "sport=" in marker
    assert "profile=blend" in result.marker()
