"""P0: the engagement outcome — the second axis next to the job lifecycle.

`AutoJob.state` answers "is the process still working?"; `outcome` answers
"did the engagement reach anything?". These pin the vocabulary, the
conservative derivation (nothing is ever reported as reached without the
run affirming it), the aggregation rule, and the fail-closed preflight that
refuses a callback-bound goal with no listener BEFORE it deploys anything.
"""
import unittest
from unittest.mock import patch

from phantom.automation.engagement_outcome import (
    CALLBACK_GOALS,
    GOAL_REACHED_OUTCOMES,
    OUTCOMES,
    board_goal_reached,
    derive_engagement,
    derive_target_outcome,
    missing_goal_facts,
    needs_callback,
    outcome_is_success,
    outcome_label,
)


class TestVocabulary(unittest.TestCase):
    def test_covers_every_token_the_audit_requires(self):
        for token in ("not_started", "blocked_preflight", "running",
                      "partial", "completed_goal", "completed_without_goal",
                      "failed_infrastructure", "failed_policy",
                      "failed_capability", "awaiting_operator", "cancelled"):
            self.assertIn(token, OUTCOMES, token)

    def test_only_completed_goal_counts_as_success(self):
        self.assertEqual(GOAL_REACHED_OUTCOMES, frozenset({"completed_goal"}))
        self.assertTrue(outcome_is_success("completed_goal"))
        for token in ("partial", "completed_without_goal", "cancelled",
                      "blocked_preflight", "failed_capability"):
            self.assertFalse(outcome_is_success(token), token)

    def test_callback_goals_are_exactly_the_beacon_bound_ones(self):
        self.assertEqual(
            CALLBACK_GOALS,
            frozenset({"beacon", "deliver", "complete_kill_chain",
                       "post_exploit", "deep"}))
        self.assertTrue(needs_callback("deliver"))
        self.assertFalse(needs_callback("footprint"))
        self.assertFalse(needs_callback("identity"))

    def test_every_token_has_a_label(self):
        for token in OUTCOMES:
            self.assertTrue(outcome_label(token))


class TestDerivationPrecedence(unittest.TestCase):
    def test_a_preflight_block_outranks_everything_else(self):
        # even a reached goal cannot undo "we refused to start"
        token = derive_target_outcome(
            "deliver", {"goal_reached": True}, preflight_blocked=True,
            error="boom", cancelled=True)
        self.assertEqual(token, "blocked_preflight")

    def test_a_crash_is_infrastructure_not_a_target_failure(self):
        self.assertEqual(
            derive_target_outcome("creds", {}, error="kaboom"),
            "failed_infrastructure")

    def test_cancelled_and_awaiting_operator_are_distinct(self):
        self.assertEqual(derive_target_outcome("creds", {}, cancelled=True),
                         "cancelled")
        self.assertEqual(
            derive_target_outcome("creds", {}, awaiting_operator=True),
            "awaiting_operator")

    def test_a_policy_refusal_keeps_its_own_token(self):
        self.assertEqual(
            derive_target_outcome("creds", {"actions_taken": 0},
                                  policy_blocked=True),
            "failed_policy")


class TestDerivationIsConservative(unittest.TestCase):
    def test_an_affirmed_goal_is_completed_goal(self):
        token = derive_target_outcome("deliver", {"goal_reached": True,
                                                  "beacon_established": True})
        self.assertEqual(token, "completed_goal")

    def test_without_the_stamp_it_falls_back_to_the_result_keys(self):
        # the swarm path / an older checkpoint carries no `goal_reached`
        self.assertEqual(
            derive_target_outcome("deliver", {"beacon_established": True}),
            "completed_goal")

    def test_finishing_without_evidence_is_completed_without_goal(self):
        self.assertEqual(
            derive_target_outcome("deliver", {"goal_reached": False,
                                              "actions_taken": 0}),
            "completed_without_goal")

    def test_progress_without_the_goal_is_partial(self):
        self.assertEqual(
            derive_target_outcome("creds", {"goal_reached": False,
                                            "creds_found": 2,
                                            "actions_taken": 7}),
            "partial")

    def test_nothing_rannable_at_all_is_failed_capability(self):
        self.assertEqual(
            derive_target_outcome("identity", {"goal_reached": False,
                                               "actions_taken": 0,
                                               "failures": 4}),
            "failed_capability")

    def test_an_unknown_goal_is_never_reported_as_reached(self):
        token = derive_target_outcome("no_such_goal", {"actions_taken": 3})
        self.assertNotEqual(token, "completed_goal")

    def test_no_result_at_all_does_not_invent_success(self):
        self.assertEqual(derive_target_outcome("deliver"),
                         "completed_without_goal")

    def test_missing_facts_are_surfaced_only_when_the_run_marks_them(self):
        self.assertEqual(
            missing_goal_facts("deliver", {"goal_facts_missing":
                                           ["beacon", "persistence"]}),
            ["beacon", "persistence"])
        self.assertEqual(missing_goal_facts("deliver", {}), [])


class TestEngagementAggregation(unittest.TestCase):
    def test_all_targets_reached_is_a_reached_engagement(self):
        e = derive_engagement("deliver", {"a": "completed_goal",
                                          "b": "completed_goal"})
        self.assertEqual(e["outcome"], "completed_goal")
        self.assertTrue(e["goal_reached"])
        self.assertEqual(e["reached"], ["a", "b"])

    def test_one_of_five_reached_is_partial_never_completed(self):
        e = derive_engagement("deliver", {
            "a": "completed_goal", "b": "partial", "c": "partial",
            "d": "completed_without_goal", "e": "failed_capability"})
        self.assertEqual(e["outcome"], "partial")
        self.assertFalse(e["goal_reached"])
        self.assertEqual(e["reached"], ["a"])

    def test_all_blocked_keeps_the_blocked_token(self):
        e = derive_engagement("deliver", {"a": "blocked_preflight",
                                          "b": "blocked_preflight"})
        self.assertEqual(e["outcome"], "blocked_preflight")

    def test_a_uniform_failure_keeps_its_cause(self):
        e = derive_engagement("creds", {"a": "failed_capability",
                                        "b": "failed_capability"})
        self.assertEqual(e["outcome"], "failed_capability")

    def test_no_targets_is_not_started_not_success(self):
        self.assertEqual(derive_engagement("deliver", {})["outcome"],
                         "not_started")
        self.assertEqual(
            derive_engagement("deliver", {}, error="x")["outcome"],
            "failed_infrastructure")


class _Board:
    """Minimal board double: `count(target, kind)` exactly as the swarm uses."""

    def __init__(self, facts):
        self._facts = facts

    def count(self, target, kind):
        return self._facts.get(target, {}).get(kind, 0)


class TestSwarmBoardOutcome(unittest.TestCase):
    def test_a_terminal_fact_on_any_target_reaches_the_goal(self):
        board = _Board({"10.0.0.5": {"beacon": 1},
                        "10.0.0.6": {}})
        self.assertTrue(board_goal_reached("deliver", board,
                                           ["10.0.0.5", "10.0.0.6"]))

    def test_footprint_reads_its_own_terminal_facts(self):
        board = _Board({"h": {"service": 3}})
        self.assertTrue(board_goal_reached("footprint", board, ["h"]))
        self.assertFalse(board_goal_reached("deliver", board, ["h"]))

    def test_an_empty_board_is_not_reached(self):
        self.assertFalse(board_goal_reached("deliver", _Board({}), ["h"]))

    def test_a_board_without_count_reports_not_reached(self):
        self.assertFalse(board_goal_reached("deliver", object(), ["h"]))


class TestFailClosedPreflight(unittest.TestCase):
    """A callback-bound goal with no listener must refuse BEFORE deploying."""

    @staticmethod
    def _quiet(am):
        return (
            patch.object(am.notifier, "success"),
            patch.object(am.notifier, "info"),
            patch.object(am.notifier, "warn"),
            patch.object(am.notifier, "error"),
        )

    def test_deliver_without_listener_never_reaches_the_deploy(self):
        import phantom.core.automode as am
        from phantom.core.session import session
        session.target = ""
        session.scope = []
        n = self._quiet(am)
        with n[0], n[1], n[2], n[3], \
                patch.object(am, "_ensure_c2_listener", return_value=False), \
                patch.object(am, "_run_agent_single") as m_single, \
                patch("phantom.utils.config.get", return_value=False):
            out = am.run_auto_mode(targets=["10.0.0.5"], goal="deliver")
        m_single.assert_not_called()
        self.assertEqual(out["outcome"], "blocked_preflight")
        self.assertFalse(out["goal_reached"])
        self.assertEqual(out["targets"], {"10.0.0.5": "blocked_preflight"})

    def test_a_non_callback_goal_is_not_gated(self):
        import phantom.core.automode as am
        from phantom.core.session import session
        session.target = ""
        # A DECLARED scope: this test is about the LISTENER gate, and with no
        # scope at all the (correctly) fail-closed scope preflight refuses a
        # network run before the listener question is ever asked.
        session.scope = ["10.0.0.0/24"]
        n = self._quiet(am)
        result = {"beacon_established": False, "actions_taken": 2,
                  "services_enumerated": 2, "goal_reached": True}
        with n[0], n[1], n[2], n[3], \
                patch.object(am, "_ensure_c2_listener", return_value=False), \
                patch.object(am, "_run_agent_single",
                             return_value=(result, unittest.mock.Mock())), \
                patch.object(am, "_write_agent_reports",
                             return_value=("t", {})), \
                patch.object(am, "_merge_results_to_session",
                             return_value={}), \
                patch.object(am, "_report_out_dir", return_value="tmp"), \
                patch("phantom.utils.config.get", return_value=False):
            out = am.run_auto_mode(targets=["10.0.0.5"], goal="footprint")
        self.assertEqual(out["outcome"], "completed_goal")

    def test_an_explicit_override_allows_a_listenerless_run(self):
        import phantom.core.automode as am
        from phantom.core.session import session
        session.target = ""
        # see above: the run needs an authorized scope before the listener
        # override is the thing being tested
        session.scope = ["10.0.0.0/24"]
        n = self._quiet(am)

        def _cfg(key, default=None, env=None):
            if key == "c2.allow_listenerless":
                return True
            return default

        result = {"beacon_established": True, "beacon_id": "B-1",
                  "goal_reached": True, "actions_taken": 5}
        with n[0], n[1], n[2], n[3], \
                patch.object(am, "_ensure_c2_listener", return_value=False), \
                patch.object(am, "_run_agent_single",
                             return_value=(result, unittest.mock.Mock())) as m_single, \
                patch.object(am, "_write_agent_reports",
                             return_value=("t", {})), \
                patch.object(am, "_merge_results_to_session",
                             return_value={}), \
                patch.object(am, "_report_out_dir", return_value="tmp"), \
                patch.object(am, "_handoff_c2"), \
                patch("phantom.utils.config.get", side_effect=_cfg):
            out = am.run_auto_mode(targets=["10.0.0.5"], goal="deliver",
                                   handoff_c2=False)
        m_single.assert_called_once()
        self.assertEqual(out["outcome"], "completed_goal")


class TestJobSnapshotCarriesTheOutcome(unittest.TestCase):
    """The API must expose the achievement axis, not only the lifecycle."""

    @staticmethod
    def _job():
        from phantom.api.server import AutoJob
        return AutoJob("job_test", ["10.0.0.5"], "default",
                       "enterprise", "deliver")

    def test_a_fresh_job_is_not_started_on_both_axes(self):
        snap = self._job().snapshot()
        self.assertEqual(snap["outcome"], "not_started")
        self.assertIn("state", snap)

    def test_recording_an_outcome_keeps_the_token_and_derives_the_label(self):
        job = self._job()
        self.assertTrue(job.set_outcome(
            {"outcome": "partial", "targets": {"10.0.0.5": "partial"}}))
        snap = job.snapshot()
        self.assertEqual(snap["outcome"], "partial")
        self.assertEqual(snap["outcome_label"], "partial (goal not reached)")
        self.assertEqual(snap["targets_outcome"], {"10.0.0.5": "partial"})

    def test_an_unknown_token_is_refused_not_stored(self):
        job = self._job()
        self.assertFalse(job.set_outcome({"outcome": "totally_made_up"}))
        self.assertFalse(job.set_outcome({}))
        self.assertEqual(job.snapshot()["outcome"], "not_started")

    def test_the_idle_answer_declares_the_field_too(self):
        from phantom.api import server
        self.assertIn("outcome", server._IDLE_STATUS)
        self.assertIn("targets_outcome", server._IDLE_STATUS)

    def test_job_lifecycle_and_outcome_stay_independent(self):
        # completed as a PROCESS, no achievement: both must be readable.
        job = self._job()
        job.set_outcome({"outcome": "completed_without_goal",
                         "targets": {"10.0.0.5": "completed_without_goal"}})
        self.assertEqual(job.finish("sequence complete"), "completed")
        snap = job.snapshot()
        self.assertEqual(snap["state"], "completed")
        self.assertEqual(snap["outcome"], "completed_without_goal")
        self.assertFalse(snap["outcome"] in GOAL_REACHED_OUTCOMES)


if __name__ == "__main__":
    unittest.main()
