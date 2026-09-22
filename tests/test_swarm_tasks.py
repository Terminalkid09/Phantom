"""Tests: swarm orchestration core (Fase 3) — tasks, board, worker, gates.

Acceptance bar: a single-worker swarm run is finding-for-finding
identical to the legacy direct-agent run (same runner/seed/budget),
while workers never write the shared board live (scratch isolation).
"""
from unittest.mock import Mock

from phantom.automation.belief import WorldModel

TARGET = "10.0.0.5"


def _fake_runner():
    """Deterministic tool responses (no network, no globals)."""
    def runner(cmd, timeout=None):
        res = Mock()
        res.ok = True
        res.stderr = ""
        if "nmap" in cmd:
            res.stdout = ("22/tcp open ssh OpenSSH 7.9p1\n"
                          "80/tcp open http Apache httpd 2.4.49")
        elif "nc -w" in cmd:
            res.stdout = "SSH-2.0-OpenSSH_7.9p1 Debian-10"
        elif "curl" in cmd:
            res.stdout = "Server: nginx/1.18.0\n<title>Login</title>"
        else:
            res.stdout = "PHANTOM"
        return res
    return runner


def _svc_staged():
    return [{"kind": "service", "key": "tcp/80",
             "value": {"port": "80", "service": "http"},
             "confidence": 0.9, "source": "t"}]


class TestSwarmTasks:
    def test_templates_build_fact_dag(self):
        from phantom.automation.swarm.tasks import build_tasks
        tasks = build_tasks("deep", [TARGET])
        by_goal = {t.goal: t for t in tasks}
        assert set(by_goal) == {"footprint", "complete_kill_chain",
                                "creds", "post_exploit", "ad", "crack",
                                "lateral"}
        assert by_goal["footprint"].needs == frozenset()
        assert "service" in by_goal["complete_kill_chain"].needs
        assert "service" in by_goal["creds"].needs
        assert "beacon" in by_goal["post_exploit"].needs
        assert "beacon" in by_goal["ad"].needs
        assert "ad_creds" in by_goal["crack"].needs
        assert {"beacon", "creds"} <= by_goal["lateral"].needs

    def test_unknown_chain_rejected(self):
        from phantom.automation.swarm.tasks import build_tasks
        try:
            build_tasks("nope", [TARGET])
        except ValueError:
            return
        raise AssertionError("unknown chain accepted")

    def test_ready_gating(self):
        from phantom.automation.swarm.board import Board
        from phantom.automation.swarm.tasks import build_tasks
        board = Board([TARGET])
        exploit = [t for t in build_tasks("full", [TARGET])
                   if t.goal == "complete_kill_chain"][0]
        assert exploit.ready(board) is False
        board.commit(exploit.id, TARGET, _svc_staged())
        assert exploit.ready(board) is True

    def test_dynamic_victim_targets(self):
        from phantom.automation.swarm.board import Board
        from phantom.automation.swarm.tasks import build_tasks
        board = Board(["victim@corp.com"])
        recon = [t for t in build_tasks("identity", ["victim@corp.com"])
                 if t.target_source == "victim_ip"][0]
        assert recon.ready(board) is False
        board.commit("osint-0", "victim@corp.com",
                     [{"kind": "victim_ip", "key": "ip:10.9.9.9",
                       "value": {"ip": "10.9.9.9"},
                       "confidence": 0.8, "source": "osint-0"}])
        assert recon.ready(board) is True
        assert "10.9.9.9" in recon.effective_targets(board)


class TestBoard:
    def test_snapshot_is_isolated_scratch(self):
        from phantom.automation.swarm.board import Board
        board = Board([TARGET])
        snap = board.snapshot(TARGET)
        snap.add_finding("service", "tcp/80", {"port": "80"},
                         confidence=0.9, source="sibling")
        assert board.has(TARGET, "service") is False

    def test_commit_first_writer_wins(self):
        from phantom.automation.swarm.board import Board
        board = Board([TARGET])
        assert board.commit("a", TARGET, _svc_staged()) == (1, 0)
        assert board.commit("b", TARGET, _svc_staged()) == (0, 1)
        assert board.has(TARGET, "service") is True


class TestWorker:
    def test_worker_stages_without_live_writes(self):
        from phantom.automation.swarm.board import Board
        from phantom.automation.swarm.tasks import build_tasks
        from phantom.automation.swarm.worker import run_swarm_task
        board = Board([TARGET])
        task = build_tasks("footprint", [TARGET], budget=6)[0]
        result = run_swarm_task(task, TARGET, board,
                                runner=_fake_runner())
        assert board.has(TARGET, "service") is False  # never writes live
        kinds = {s["kind"] for s in result.staged}
        assert "service" in kinds
        assert result.actions_taken <= 6 * 4  # bounded by task budget
        assert result.ok is True

    def test_single_worker_matches_legacy_run(self):
        """Acceptance: swarm worker == legacy direct agent run,
        finding-for-finding (same runner/seed/budget)."""
        from phantom.automation.agent import AutonomousAgent
        from phantom.automation.guidance.stealth import (
            StealthConfig, StealthEngine)
        from phantom.automation.runtime.stealth_runtime import (
            StealthRuntime, TimingGovernor)
        from phantom.automation.runtime.toolchain import ToolRegistry
        from phantom.automation.swarm.board import Board
        from phantom.automation.swarm.tasks import build_tasks
        from phantom.automation.swarm.worker import run_swarm_task

        board = Board([TARGET])
        task = build_tasks("footprint", [TARGET], budget=6, seed=41)[0]
        result = run_swarm_task(task, TARGET, board,
                                runner=_fake_runner())

        legacy_wm = WorldModel(target=TARGET, target_type="ip")
        agent = AutonomousAgent(
            target=TARGET, target_type="ip", shared_wm=legacy_wm,
            toolchain=ToolRegistry(installed={"nmap", "curl", "nc"}),
            command_seed=41)
        agent.runtime = StealthRuntime(
            agent.stealth_engine, runner=_fake_runner(),
            cost_per_action=0.5,
            governor=TimingGovernor(base_delay=0.0, jitter=0.0))
        agent.run(goal="footprint", max_iterations=6)
        legacy_keys = {(f.get("kind", ""), f.get("key", ""))
                       for f in legacy_wm.to_dict().get("findings", [])}
        staged_keys = {(s["kind"], s["key"]) for s in result.staged}
        assert staged_keys == legacy_keys


class TestScheduler:
    def test_gate_blocks_until_ready(self):
        from phantom.automation.belief import WorldModel
        from phantom.automation.orchestrator import Orchestrator
        ran = []
        orch = Orchestrator(wm=WorldModel(target="t"),
                            stealth=None,
                            worker=lambda a, c: ran.append(a.task_id) or True,
                            max_agents=2)
        gate = {"open": False}
        orch.submit("cap", "e1", 10.0, task_id="t1",
                    gate=lambda: gate["open"])
        orch.run(drain_timeout=1.0)
        assert ran == []
        gate["open"] = True
        orch.run(drain_timeout=5.0)
        assert ran == ["t1"]

    def test_footprint_end_to_end(self):
        from phantom.automation.swarm import run_swarm
        summary = run_swarm([TARGET], chain="footprint",
                            runner=_fake_runner(), budget=6)
        assert summary["ok"] is True
        assert "service" in summary["board"][TARGET]
        assert summary["tasks"][0]["status"] == "done"

    def test_exploit_waits_for_recon_commit(self):
        from phantom.automation.swarm import run_swarm
        summary = run_swarm([TARGET], chain="full",
                            runner=_fake_runner(), budget=6)
        by_id = {t["id"]: t for t in summary["tasks"]}
        assert by_id["footprint-0"]["status"] == "done"
        # exploit attempted only after recon committed service
        assert by_id["complete_kill_chain-1"]["attempts"] >= 1
        order = [e["capability"] for e in summary["trail"]]
        recon_at = next(i for i, c in enumerate(order)
                        if c.startswith("swarm:footprint-0"))
        exploit_at = next(i for i, c in enumerate(order)
                          if c.startswith("swarm:complete_kill_chain-1"))
        assert recon_at < exploit_at
