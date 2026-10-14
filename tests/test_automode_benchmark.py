"""The AutoMode benchmark must MEASURE, and must not flatter.

The audit's ask was a benchmark "con ground truth e failure injection (goal
success, partial, falsi positivi, azioni inappropriate, time to recover, budget
overrun, interventi dell'operatore)". A harness that recomputed its own idea of
success would be worse than none, so these tests pin three properties:

* the metrics come from the PRODUCTION outcome model and the agent's own event
  stream (an outcome that contradicts the run is reported as dishonest);
* a finding outside the declared ground truth is a FALSE POSITIVE, an action
  the scenario forbids is INAPPROPRIATE, and an unrecovered failure is ``None``
  (never "0 moves, all good");
* the standard suite honours its own expectations end to end, offline.

The suite runs the real agent with scripted answers, so the whole file takes a
few seconds and never touches the network.
"""
import unittest

from phantom.automation import benchmark as bench
from phantom.automation.benchmark import (
    FORTRESS,
    OPEN_TARGET,
    Metrics,
    Scenario,
    inject_failures,
    run_scenario,
    score,
)


class _Finding:
    def __init__(self, kind, key, value=None):
        self.kind, self.key, self.value = kind, key, value


class _WM:
    """Minimal world model for the scoring unit tests."""

    def __init__(self, findings=(), noise=0.0, limit=12.0):
        self._findings = list(findings)
        self.noise_score = noise
        self.NOISE_LIMIT = limit

    def all_findings(self):
        return self._findings


def _events(*items):
    return [(kind, dict(data)) for kind, data in items]


class TestGroundTruthScoring(unittest.TestCase):
    def test_a_finding_the_target_does_not_have_is_a_FALSE_POSITIVE(self):
        scenario = Scenario(name="x", services=(("22", "ssh"),),
                            creds=(("root", "toor"),))
        wm = _WM([_Finding("service", "22/tcp"),
                  _Finding("service", "3389/tcp"),      # invented
                  _Finding("creds", "root", {"user": "root", "pass": "toor"}),
                  _Finding("creds", "admin", {"user": "admin", "pass": "x"}),
                  _Finding("hostname", "box")])         # not scored at all
        metrics = score(scenario, {"goal_reached": False}, [], wm)
        self.assertEqual(metrics.false_positives,
                         ["creds:admin", "service:3389/tcp"])

    def test_an_unscored_kind_is_neither_truth_nor_lie(self):
        scenario = Scenario(name="x")
        metrics = score(scenario, {}, [], _WM([_Finding("os", "linux")]))
        self.assertEqual(metrics.false_positives, [])

    def test_an_action_the_scenario_forbids_is_INAPPROPRIATE(self):
        scenario = Scenario(name="x", forbidden=("cleanup", "impact"))
        events = _events(("run", {"capability": "scan_tcp"}),
                         ("found", {"capability": "scan_tcp"}),
                         ("run", {"capability": "cleanup"}),
                         ("found", {"capability": "cleanup"}))
        metrics = score(scenario, {}, events, _WM())
        self.assertEqual(metrics.inappropriate_actions, ["cleanup"])

    def test_operator_interventions_are_counted(self):
        scenario = Scenario(name="x")
        events = _events(("handoff", {"beacon_id": "b1"}),
                         ("blocked", {"capability": "a",
                                      "reason": "needs operator confirmation"}),
                         ("blocked", {"capability": "b", "reason": "precondition"}),
                         ("run", {"capability": "c"}),
                         ("found", {"capability": "c"}))
        metrics = score(scenario, {}, events, _WM())
        self.assertEqual(metrics.operator_interventions, 2)

    def test_the_outcome_comes_from_the_production_model(self):
        scenario = Scenario(name="x", goal="complete_kill_chain")
        metrics = score(scenario, {"goal_reached": True, "actions_taken": 3},
                        [], _WM())
        self.assertEqual(metrics.outcome, "completed_goal")
        self.assertTrue(metrics.goal_reached and metrics.honest)

    def test_an_outcome_that_contradicts_the_run_is_DISHONEST(self):
        metrics = Metrics(scenario="x", goal="g", outcome="completed_goal",
                          goal_reached=False)
        self.assertFalse(metrics.honest)
        metrics = Metrics(scenario="x", goal="g", outcome="partial",
                          goal_reached=True)
        self.assertFalse(metrics.honest)


class TestTimeToRecover(unittest.TestCase):
    """The metric exists to make recovery VISIBLE — including its absence."""

    def _moves(self, *oks):
        """One run per move, followed by its outcome (as the agent emits it)."""
        out = []
        for i, ok in enumerate(oks):
            cap = f"c{i}"
            out.append(("run", {"capability": cap}))
            out.append(("found" if ok else "failed", {"capability": cap}))
        return out

    def test_it_counts_the_moves_between_the_injection_and_the_recovery(self):
        events = self._moves(False, False, True)
        scenario = Scenario(name="x", failures={"nmap": 2})
        metrics = score(scenario, {}, events, _WM(), {"nmap": 2})
        self.assertEqual(metrics.time_to_recover, 1)

    def test_an_UNRECOVERED_failure_is_None_not_zero(self):
        events = self._moves(False, False, False)
        scenario = Scenario(name="x", failures={"nmap": 2})
        metrics = score(scenario, {}, events, _WM(), {"nmap": 2})
        self.assertIsNone(metrics.time_to_recover)

    def test_without_an_injection_there_is_nothing_to_recover_from(self):
        events = self._moves(True, True)
        metrics = score(Scenario(name="x"), {}, events, _WM(), {})
        self.assertIsNone(metrics.time_to_recover)


class TestBudget(unittest.TestCase):
    def test_an_overrun_is_reported_when_spend_exceeds_the_declared_allowance(self):
        scenario = Scenario(name="x", max_opsec=1.0)
        metrics = score(scenario, {"opsec_spent": 3.0}, [], _WM())
        self.assertTrue(metrics.budget["overrun"])
        self.assertEqual(metrics.budget["spent_opsec"], 3.0)

    def test_within_budget_is_not_an_overrun(self):
        scenario = Scenario(name="x", max_opsec=5.0)
        metrics = score(scenario, {"opsec_spent": 3.0}, [], _WM())
        self.assertFalse(metrics.budget["overrun"])

    def test_the_noise_breaker_limit_is_honoured(self):
        scenario = Scenario(name="x", noise_limit=2.0)
        metrics = score(scenario, {}, [], _WM(noise=2.5, limit=2.0))
        self.assertTrue(metrics.budget["overrun"])


class TestFailureInjection(unittest.TestCase):
    def _runner(self):
        from unittest.mock import Mock
        return lambda cmd, timeout=None: Mock(ok=True, stdout="ok", stderr="")

    def test_the_first_n_matching_commands_fail(self):
        state = {}
        wrapped = inject_failures(self._runner(), {"nmap": 2}, state)
        self.assertFalse(wrapped("nmap -sV 10.0.0.5").ok)
        self.assertFalse(wrapped("nmap -Pn 10.0.0.5").ok)
        self.assertTrue(wrapped("nmap -Pn 10.0.0.5").ok)      # third answers
        self.assertTrue(wrapped("curl https://x/").ok)        # never injected

    def test_the_counters_show_how_many_injections_landed(self):
        wrapped = inject_failures(self._runner(), {"curl": 1}, {})
        wrapped("curl -s -I http://x")
        self.assertEqual(wrapped.injected, {"curl": 1})


class TestTheStandardSuite(unittest.TestCase):
    """End to end, offline: the scenarios honour their own expectations."""

    @classmethod
    def setUpClass(cls):
        cls.report = bench.run_suite(max_iterations=12)

    def test_every_scenario_passes_its_expectations(self):
        self.assertEqual(self.report["violations"], [])
        self.assertTrue(self.report["passed"])

    def test_the_reachable_scenario_reaches_the_goal_without_flattery(self):
        row = next(r for r in self.report["scenarios"]
                   if r["scenario"] == OPEN_TARGET.name)
        self.assertEqual(row["outcome"], "completed_goal")
        self.assertEqual(row["false_positives"], [])
        self.assertEqual(row["inappropriate_actions"], [])
        self.assertTrue(row["honest"])

    def test_the_injected_web_failure_is_recovered_from(self):
        row = next(r for r in self.report["scenarios"]
                   if r["scenario"] == bench.FLAKY_WEB_PROBE.name)
        self.assertTrue(row["goal_reached"])
        self.assertIsNotNone(row["time_to_recover"])
        self.assertGreaterEqual(row["time_to_recover"], 1)

    def test_the_scan_failure_scenario_is_measured_not_papered_over(self):
        """A known gap is REPORTED: the run must not claim the goal."""
        row = next(r for r in self.report["scenarios"]
                   if r["scenario"] == bench.SCAN_FAILURE.name)
        self.assertFalse(row["goal_reached"])
        self.assertNotEqual(row["outcome"], "completed_goal")
        self.assertTrue(row["honest"])
        self.assertEqual(row["false_positives"], [])

    def test_the_hardened_target_is_not_reported_as_a_success(self):
        row = next(r for r in self.report["scenarios"]
                   if r["scenario"] == FORTRESS.name)
        self.assertFalse(row["goal_reached"])
        self.assertEqual(row["false_positives"], [])
        self.assertEqual(row["inappropriate_actions"], [])
        self.assertTrue(row["honest"])

    def test_the_budget_overrun_is_visible(self):
        row = next(r for r in self.report["scenarios"]
                   if r["scenario"] == bench.BUDGET_CAPPED.name)
        self.assertTrue(row["budget"]["overrun"])
        self.assertGreater(row["budget"]["spent_opsec"],
                           row["budget"]["max_opsec"])

    def test_the_reported_numbers_match_the_run(self):
        row = next(r for r in self.report["scenarios"]
                   if r["scenario"] == OPEN_TARGET.name)
        self.assertGreater(row["moves"], 0)
        self.assertEqual(row["operator_interventions"], 1)   # the handoff


class TestOneScenarioAtATime(unittest.TestCase):
    def test_a_single_scenario_can_be_run_on_its_own(self):
        metrics = run_scenario(bench.SCAN_FAILURE, max_iterations=8)
        self.assertEqual(metrics.scenario, bench.SCAN_FAILURE.name)
        self.assertTrue(metrics.honest)

    def test_the_cli_reports_a_failing_expectation(self):
        import importlib.util
        import os
        import pathlib
        path = pathlib.Path(__file__).resolve().parent.parent / "scripts" / \
            "automode_benchmark.py"
        spec = importlib.util.spec_from_file_location("automode_benchmark",
                                                      str(path))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.assertEqual(mod.main(["--list"]), 0)
        self.assertEqual(mod.main(["--scenario", "nope"]), 1)


if __name__ == "__main__":
    unittest.main()
