"""Tests: swarm fan-out (Fase 7) — upfront CONTACT_NONE slots, stall
helpers with adversarial profiles, and the `auto --swarm` CLI entry.
"""
from unittest.mock import Mock

TARGET = "10.0.0.5"


def _board(targets=(TARGET,)):
    from phantom.automation.swarm.board import Board
    return Board(list(targets))


def _orch(worker):
    from phantom.automation.belief import WorldModel
    from phantom.automation.orchestrator import Orchestrator
    return Orchestrator(wm=WorldModel(target="t"), stealth=None,
                        worker=worker, max_agents=10)


class TestUpfrontFanout:
    def test_contact_none_fans_out_upfront(self):
        from phantom.automation.swarm.scheduler import schedule
        from phantom.automation.swarm.tasks import build_tasks
        board = _board()
        tasks = build_tasks("identity", [TARGET])
        osint = next(t for t in tasks if t.goal == "identity")
        assert osint.max_agents == 5  # ACTING_CAP[none]
        seen = []

        def worker(action, ctx):
            seen.append(action.capability_id)
            action.task.status = "done"
            board.commit(action.task.id, TARGET,
                         [{"kind": "identity", "key": "id:1",
                           "value": {}, "confidence": 0.6,
                           "source": action.task.id},
                          {"kind": "victim_ip", "key": "ip:10.9.9.9",
                           "value": {"ip": "10.9.9.9"}, "confidence": 0.6,
                           "source": action.task.id}])
            return True

        summary = schedule(_orch(worker), board, tasks, drain_timeout=10)
        slots = sorted(c for c in seen if c.startswith("swarm:identity-0#w"))
        assert len(slots) == 5  # five workers, same task, upfront
        # the recon task released on the discovered victim IP afterwards
        assert board.has(TARGET, "victim_ip") is True

    def test_contact_tasks_run_single_lead(self):
        from phantom.automation.swarm.scheduler import schedule
        from phantom.automation.swarm.tasks import build_tasks
        board = _board()
        tasks = build_tasks("full", [TARGET])
        seen = []

        def worker(action, ctx):
            seen.append(action.capability_id)
            action.task.status = "done"
            return True

        schedule(_orch(worker), board, tasks, drain_timeout=10)
        assert seen.count("swarm:footprint-0#w0#10.0.0.5") == 1
        assert not [c for c in seen if c.startswith(
            "swarm:complete_kill_chain-1#w") and "#w0#" not in c]


class TestStallHelper:
    def _failed_task(self):
        from phantom.automation.swarm.tasks import SwarmTask
        task = SwarmTask(id="x-0", goal="footprint", targets=[TARGET],
                         needs=frozenset(), provides=frozenset({"service"}),
                         profile="balanced", attempts=1)
        task.status = "failed"
        task.failure_kind = "agent"
        return task

    def test_helper_prepared_with_adversarial_profile_and_avoid(self):
        from phantom.automation.swarm.profiles import PROFILES
        from phantom.automation.swarm.scheduler import _prepare_helpers
        task = self._failed_task()
        sink = {"failures": [{"task": "x-0", "kind": "agent",
                              "stall": "no_path", "target": TARGET}],
                "cases": [],
                "tried": {("x-0", TARGET): {"scan_tcp", "http_probe"}},
                "lock": __import__("threading").Lock()}
        helpers = _prepare_helpers([task], sink)
        assert len(helpers) == 1
        _task, origin, profile, avoid, seed = helpers[0]
        assert origin == TARGET
        assert profile in PROFILES and profile != "balanced"
        assert set(avoid) == {"scan_tcp", "http_probe"}
        assert seed == (task.seed ^ 0x5F3759DF)

    def test_no_stall_no_helper(self):
        from phantom.automation.swarm.scheduler import _prepare_helpers
        import threading
        task = self._failed_task()
        sink = {"failures": [{"task": "x-0", "kind": "agent",
                              "stall": "", "target": TARGET}],
                "cases": [], "tried": {}, "lock": threading.Lock()}
        assert _prepare_helpers([task], sink) == []

    def test_gate_answers_facts_not_status(self):
        # the gate is deliberately status-blind (completion is enforced
        # by WHAT gets submitted, one action per slot per wave): a failed
        # task with met needs still opens, so helpers can run.
        from phantom.automation.swarm.board import Board
        from phantom.automation.swarm.scheduler import _gate_for
        board = Board([TARGET])
        task = self._failed_task()
        task.needs = frozenset()
        assert _gate_for(task, board)() is True


class TestSwarmCli:
    def test_auto_swarm_routes_to_run_swarm(self, monkeypatch):
        import phantom.automation.swarm as swarm_pkg
        from phantom.core.session import session
        from phantom.core.shell import PhantomShell
        calls = {}

        def _fake_run_swarm(targets, **kwargs):
            calls["targets"] = list(targets)
            calls.update(kwargs)
            return {"ok": True, "tasks": [
                {"id": "footprint-0", "goal": "footprint",
                 "status": "done", "note": "+2 ~0"}],
                "added": 2, "failures": []}

        monkeypatch.setattr(swarm_pkg, "run_swarm", _fake_run_swarm)
        session.target = ""
        session.scope = []
        shell = PhantomShell()
        shell.auto_run = True  # never prompt in tests
        shell.do_auto("--swarm --chain footprint 10.0.0.5")
        assert calls["targets"] == ["10.0.0.5"]
        assert calls["chain"] == "footprint"
