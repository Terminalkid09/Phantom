"""P1 (requisito 4): a report at the end of EVERY phase, for every goal.

The requirement is that an auto-mode run leaves an artifact at the end of
each phase of whatever goal — a one-stage `identity` run exactly like the
five-stage `deep` ladder. These pin the writer, the per-stage ordering, the
link between "stage satisfied" and the reported outcome, and the fact that
the failure of a phase artifact is loud but never fatal.
"""
import json
import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch

from phantom.automation.belief import WorldModel
from phantom.core.automode_report import write_phase_report


class _StubAgent:
    """The smallest object the report layer actually reads."""

    def __init__(self, goal="deliver", target="10.0.0.5"):
        self.wm = WorldModel(target=target, target_type="ip")
        self.target = target
        self.goal = goal
        self.sink = type("Sink", (), {"events": []})()
        self._session = None
        self.trace = None
        self._plan_choice = None
        self._identity_field_model = None


class TestWritePhaseReport(unittest.TestCase):
    def setUp(self):
        self.out = tempfile.mkdtemp(prefix="phantom-phase-")

    def _read(self, path):
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)

    def test_a_single_stage_goal_writes_its_own_artifact(self):
        # goal=identity is a ladder of length 1 and must still leave a report
        paths = write_phase_report(_StubAgent(goal="identity"), "enterprise",
                                   self.out, "identity", 1, 1, True)
        self.assertTrue(paths)
        self.assertIn(os.path.join("phases", "01_identity"), paths["raw"])
        self.assertTrue(os.path.exists(paths["client"]))

    def test_the_artifact_carries_the_phase_and_the_outcome(self):
        paths = write_phase_report(_StubAgent(goal="deep"), "enterprise",
                                   self.out, "identity", 1, 1, True)
        data = self._read(paths["raw"])
        self.assertEqual(data["phase"], "identity")
        self.assertEqual(data["phase_index"], 1)
        self.assertEqual(data["phase_total"], 1)
        self.assertIs(data["phase_ok"], True)
        self.assertEqual(data["outcome"], "completed_goal")
        self.assertTrue(data["outcome_label"])

    def test_each_stage_gets_its_own_numbered_directory(self):
        agent = _StubAgent(goal="deep")
        first = write_phase_report(agent, "enterprise", self.out,
                                   "deliver", 1, 5, True)
        second = write_phase_report(agent, "enterprise", self.out,
                                    "post_exploit", 2, 5, False)
        self.assertIn("01_deliver", first["raw"])
        self.assertIn("02_post_exploit", second["raw"])
        self.assertNotEqual(first["raw"], second["raw"])
        # a later stage never overwrites an earlier one
        self.assertTrue(os.path.exists(first["raw"]))
        self.assertTrue(os.path.exists(second["raw"]))

    def test_an_unsatisfied_stage_is_never_reported_as_reached(self):
        paths = write_phase_report(_StubAgent(goal="deep"), "enterprise",
                                   self.out, "ad", 3, 5, False)
        data = self._read(paths["raw"])
        self.assertIs(data["phase_ok"], False)
        self.assertNotEqual(data["outcome"], "completed_goal")

    def test_a_missing_run_directory_writes_nothing_and_says_nothing(self):
        self.assertEqual(
            write_phase_report(_StubAgent(), "enterprise", "", "deliver",
                               1, 1, True), {})

    def test_a_write_failure_is_loud_but_never_fatal(self):
        with patch("phantom.automation.reporting.ReportWriter") as writer, \
                patch("phantom.core.automode_report.notifier") as notifier:
            writer.return_value.write.side_effect = OSError("disk full")
            out = write_phase_report(_StubAgent(), "enterprise", self.out,
                                     "deliver", 1, 1, True)
        self.assertEqual(out, {})
        self.assertTrue(notifier.warn.called)


class _HookHost:
    """Carries the hook + the degradation recorder the agent uses."""

    def __init__(self):
        self.stage_hook = None
        self.degraded = None

    def _degrade(self, layer, exc):        # pragma: no cover - exercised below
        self.degraded = (layer, str(exc))


class TestStageHook(unittest.TestCase):
    def test_the_boundary_is_announced_with_its_position(self):
        from phantom.automation.agent import AutonomousAgent
        seen = []
        host = _HookHost()
        host.stage_hook = lambda agent, stage, index, total, ok: seen.append(
            (agent, stage, index, total, ok))
        AutonomousAgent._notify_stage(host, "deliver", 1, 5, True)
        self.assertEqual(seen, [(host, "deliver", 1, 5, True)])

    def test_no_hook_is_a_no_op(self):
        from phantom.automation.agent import AutonomousAgent
        AutonomousAgent._notify_stage(_HookHost(), "deliver", 1, 1, True)

    def test_a_raising_hook_never_aborts_a_finished_stage(self):
        from phantom.automation.agent import AutonomousAgent
        host = _HookHost()

        def _boom(*_args):
            raise RuntimeError("reporting exploded")

        host.stage_hook = _boom
        AutonomousAgent._notify_stage(host, "deliver", 1, 1, True)
        self.assertEqual(host.degraded[0], "stage_report")


class TestPhaseReportWiring(unittest.TestCase):
    """Source contract, like the other wiring tests in this repo: a hook
    nobody calls is exactly the failure mode this pins."""

    @classmethod
    def setUpClass(cls):
        root = pathlib.Path(__file__).resolve().parent.parent
        cls.agent_src = (root / "phantom" / "automation" /
                         "agent.py").read_text(encoding="utf-8")
        cls.am_src = (root / "phantom" / "core" /
                      "automode.py").read_text(encoding="utf-8")

    def test_the_deep_ladder_reports_every_stage(self):
        self.assertIn("self._notify_stage(_sg, _idx, len(stages), _ok)",
                      self.agent_src)

    def test_a_single_goal_run_reports_its_one_stage(self):
        self.assertIn("self._notify_stage(goal, 1, 1, self._goal_reached(goal))",
                      self.agent_src)

    def test_the_hook_is_forwarded_from_the_entry_point_to_the_run(self):
        # run_autonomous AND run_campaign both forward it, and the campaign's
        # per-target worker fan-out carries it too.
        self.assertGreaterEqual(self.agent_src.count("stage_hook=stage_hook"), 3)

    def test_the_orchestrator_supplies_a_hook_on_both_paths(self):
        self.assertIn("stage_hook=_stage_hook", self.am_src)
        self.assertIn("stage_hook=_campaign_stage_hook", self.am_src)

    def test_the_campaign_writes_phases_per_target(self):
        self.assertIn("os.path.join(state_dir, _safe_target_dir(_agent.target))",
                      self.am_src)


if __name__ == "__main__":
    unittest.main()
