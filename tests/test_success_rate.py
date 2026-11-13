"""The success-rate harness: measure a run, do not estimate it (6.7)."""
import pytest

from phantom.automation.success_rate import (
    GOAL_RESULT_KEYS, ScenarioOutcome, find_cycles, find_repeated_failures,
    goal_reached, outcome, summarize)


def _run(cap, command):
    return ("run", {"capability": cap, "command": command})


class TestGoalReached:
    @pytest.mark.parametrize("goal,result,expected", [
        ("deliver", {"beacon_established": True}, True),
        ("deliver", {"beacon_established": False}, False),
        ("footprint", {"services_enumerated": 3}, True),
        ("footprint", {"services_enumerated": 0}, False),
        ("creds", {"creds_found": 1}, True),
        ("crack", {"cracked_hashes": 0}, False),
    ])
    def test_terminal_fact_is_read_from_the_result(self, goal, result, expected):
        assert goal_reached(result, goal) is expected

    def test_an_unknown_goal_is_never_claimed_as_reached(self):
        assert goal_reached({"beacon_established": True}, "no_such_goal") is False

    def test_every_supported_goal_has_a_terminal_key(self):
        assert GOAL_RESULT_KEYS["cleanup"] == "cleanup_done"


class TestCycleDetection:
    def test_the_same_command_repeated_is_a_cycle(self):
        events = [_run("scan_tcp", "nmap -Pn -sT -p 22 10.0.0.5")] * 3
        cycles = find_cycles(events)
        assert len(cycles) == 1
        assert next(iter(cycles.values())) == 3

    def test_the_same_capability_with_different_args_is_not(self):
        events = [_run("scan_tcp", f"nmap -Pn -sT -p {p} 10.0.0.5")
                  for p in ("22", "80", "443", "3306")]
        assert find_cycles(events) == {}

    def test_repeated_identical_failures_are_detected(self):
        events = [("failed", {"capability": "beacon_deploy",
                              "reason": "refused: tool not installed"})] * 3
        repeated = find_repeated_failures(events)
        assert len(repeated) == 1


class TestOutcome:
    def test_reaching_the_goal_is_reached(self):
        o = outcome({"beacon_established": True, "actions_taken": 9},
                    [("run", {"command": "x"})], "deliver")
        assert o.verdict == "reached"
        assert o.ok and o.honest

    def test_cycling_without_the_goal_is_flagged_not_hidden(self):
        events = [_run("scan_tcp", "nmap -Pn -sT -p 22 10.0.0.5")] * 4
        o = outcome({"beacon_established": False}, events, "deliver")
        assert o.verdict == "cycled"
        assert not o.ok and not o.honest

    def test_a_clean_halt_is_honest_even_though_it_failed(self):
        events = [("halt", {"reason": "no affordable path to goal"})]
        o = outcome({"beacon_established": False}, events, "deliver")
        assert o.verdict == "halted"
        assert not o.ok and o.honest
        assert "no affordable path" in o.halt_reason

    def test_degradation_is_recorded(self):
        events = [("degraded", {"layer": "arbiter", "detail": "boom"})]
        o = outcome({}, events, "creds")
        assert o.degraded == ["arbiter"]

    def test_a_reached_goal_outranks_a_partial_cycle(self):
        events = [_run("scan_tcp", "same")] * 5
        o = outcome({"beacon_established": True}, events, "deliver")
        assert o.verdict == "reached"


class TestSummarize:
    def test_success_and_honest_rates_are_reported_apart(self):
        outcomes = [
            ScenarioOutcome("deliver", "reached"),
            ScenarioOutcome("creds", "cycled"),
            ScenarioOutcome("footprint", "halted"),
        ]
        s = summarize(outcomes)
        assert s["success_rate"] == pytest.approx(1 / 3, abs=0.001)
        assert s["honest_rate"] == pytest.approx(2 / 3, abs=0.001)
        assert s["cycled"] == 1
