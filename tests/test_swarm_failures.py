"""Tests: failure attribution + learning (Fase 5).

task-fail -> bounded requeue with rotated profile (replan-lite).
agent-fail -> NO retry; priors already recorded; FailureCase packaged
for the evolution loop (default verdict "unstable": one run observes,
it does not convict).
"""
import json

from phantom.automation.swarm.failures import AGENT, TASK, classify
from phantom.automation.swarm.worker import TaskResult

TARGET = "10.0.0.5"


def _task(goal="footprint"):
    from phantom.automation.swarm.tasks import SwarmTask
    return SwarmTask(id="t-0", goal=goal, targets=[TARGET])


def _result(ok=False, actions=0, staged=0, stall="", crashed=False):
    return TaskResult(task_id="t-0", target=TARGET, ok=ok,
                      staged=[{"kind": "service", "key": f"k{i}"}
                              for i in range(staged)],
                      actions_taken=actions, iterations=4,
                      stall=stall, crashed=crashed)


class TestClassify:
    def test_ok_has_no_kind(self):
        assert classify(_task(), _result(ok=True)) == ""

    def test_crash_is_agent(self):
        assert classify(_task(), _result(), crashed=True) == AGENT

    def test_no_action_is_task(self):
        assert classify(_task(), _result(actions=0)) == TASK

    def test_acted_learned_nothing_is_agent(self):
        assert classify(_task(), _result(actions=5, staged=0,
                                         stall="no_path")) == AGENT

    def test_partial_progress_is_task(self):
        assert classify(_task(), _result(actions=5, staged=2)) == TASK


def _fake_runner():
    from unittest.mock import Mock

    def runner(cmd, timeout=None):
        res = Mock()
        res.ok = True
        res.stderr = ""
        res.stdout = "PHANTOM"
        return res
    return runner


class TestRouting:
    def test_task_failure_requeued_once_with_rotated_profile(self):
        from phantom.automation.swarm import run_swarm
        from phantom.automation.swarm.tasks import SwarmTask
        import phantom.automation.swarm as swarm_pkg
        # ban every execution category: the planner finds no move at all
        # (actions == 0) -> task-kind -> exactly one requeue
        orig_build = swarm_pkg.build_tasks

        def _banned(chain, targets, seed=0, budget=10, aggressive=False):
            tasks = orig_build(chain, targets, seed=seed, budget=budget,
                               aggressive=aggressive)
            for t in tasks:
                t.banned_categories = frozenset({
                    "recon", "osint", "service", "creds", "exploit",
                    "lateral", "persistence", "beacon", "exfil",
                    "social", "hunt"})
            return tasks

        swarm_pkg.build_tasks = _banned
        try:
            summary = run_swarm([TARGET], chain="footprint",
                                runner=_fake_runner(), budget=2)
        finally:
            swarm_pkg.build_tasks = orig_build
        task = summary["tasks"][0]
        assert task["failure_kind"] == TASK
        assert task["attempts"] == 2
        assert task["profile"] == "balanced"  # rotated from "" on requeue
        kinds = [f["kind"] for f in summary["failures"]]
        assert kinds and all(k == TASK for k in kinds)
        assert summary["evolution_cases"] == []

    def test_agent_crash_no_retry_but_case_packaged(self, tmp_path):
        from phantom.automation.swarm import run_swarm
        from phantom.automation.swarm.board import Board
        import phantom.automation.swarm.board as board_mod
        orig = board_mod.Board.snapshot

        def _boom(self, target):
            raise RuntimeError("boom")

        board_mod.Board.snapshot = _boom
        try:
            log = str(tmp_path / "cases.jsonl")
            summary = run_swarm([TARGET], chain="footprint",
                                runner=_fake_runner(), budget=2,
                                failure_log=log)
        finally:
            board_mod.Board.snapshot = orig
        task = summary["tasks"][0]
        assert task["failure_kind"] == AGENT
        assert task["attempts"] == 1  # no requeue for agent failures
        assert len(summary["failures"]) == 1
        assert len(summary["evolution_cases"]) == 1
        case = summary["evolution_cases"][0]
        assert case["technique"] == "swarm:footprint:balanced"
        assert case["verdict"] == "unstable"  # n=1: observe, don't convict
        assert len(case["case_id"]) == 16
        assert summary["cases_persisted"] == 1
        with open(log, encoding="utf-8") as fh:
            lines = fh.read().strip().splitlines()
        assert len(lines) == 1
        assert json.loads(lines[0])["technique"] == "swarm:footprint:balanced"

    def test_case_id_stable_across_operations(self):
        from phantom.automation.swarm.failures import case_id_for
        assert case_id_for("swarm:footprint:balanced", "unknown", "service") == \
            case_id_for("swarm:footprint:balanced", "unknown", "service")
