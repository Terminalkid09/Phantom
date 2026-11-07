"""The AI benchmark must be able to produce a non-zero answer, or say why not.

Measured 2026-11-05: `PHANTOM_AI_MODE=off` and `integrated` produced identical
reports, so nobody could tell whether the layer contributed. The fix was to
make the gap visible; this file pins the second half — the number that CAN
move (agreement with the scenario's ground truth) and the honest statement
that a behavioural delta is structurally zero for a simulated runner.
"""
import unittest

from phantom.automation import benchmark as bench


class TestTheAIBenchmarkCanMeasureAdvice(unittest.TestCase):

    def test_the_report_carries_advice_agreement(self):
        report = bench._ai_report()
        ai = report.get("ai", report)
        agreement = ai["agreement"]
        for key in ("scenarios_with_ground_truth", "deterministic_pct",
                    "ai_pct", "delta_pct"):
            self.assertIn(key, agreement)
        self.assertGreaterEqual(agreement["deterministic_pct"], 0.0)
        self.assertLessEqual(agreement["deterministic_pct"], 100.0)
        # A net delta can hide one win and one loss, so both are reported.
        for key in ("ai_wins", "ai_losses", "neutral", "mean_scoreable_pct"):
            self.assertIn(key, agreement)
        self.assertEqual(agreement["ai_wins"] + agreement["ai_losses"]
                         + agreement["neutral"],
                         agreement["scenarios_with_ground_truth"])

    def test_off_runs_consult_nothing_and_have_no_delta(self):
        report = bench._run_with_provider_mode("off", (bench.OPEN_TARGET,), 5)
        ai = report["ai"]
        self.assertEqual(ai["consulted"], 0)
        self.assertEqual(ai["changed_decisions"], 0)
        self.assertIn("indistinguishable", ai["note"])

    def test_the_comparison_reports_a_structural_zero_with_its_reason(self):
        report = bench.run_comparison((bench.OPEN_TARGET,), max_iterations=5)
        self.assertIn("zero by construction", report["note"])
        self.assertEqual(report["delta"]["goal_reached_pct"], 0.0)
        self.assertIn("advice_agreement_pct", report["delta"])
        self.assertEqual(report["baseline"]["mode"], "off")

    def test_ground_truth_prefers_a_known_credential_over_a_web_probe(self):
        # The id is the PRODUCTION one (`noncve:service:<svc>:<port>`), because
        # the promoted ranker is keyed by that vocabulary: an answer key in a
        # private namespace cannot be compared with a prediction.
        self.assertEqual(bench._ground_truth_best(bench.OPEN_TARGET),
                         "noncve:service:ssh:22")
        self.assertEqual(bench._ground_truth_best(bench.OPEN_TARGET),
                         bench._candidate_ids(bench.OPEN_TARGET)[0])
        # an unreachable host has no right answer: "" is not a missing value,
        # it is the absence of a claim.
        self.assertEqual(bench._ground_truth_best(bench.FORTRESS), "")


if __name__ == "__main__":
    unittest.main()
