"""Tests: dynamic reasoning (Fase 4) — info-value ranking, diversity axes,
learned profile selection.

Default behavior is byte-identical (value_weight=0.0): the existing
planner/agent suite pins it. Everything new is opt-in.
"""
import pytest

from phantom.automation.belief import WorldModel

TARGET = "10.0.0.5"


def _wm():
    return WorldModel(target=TARGET, target_type="ip")


def _planner(caps, value_weight=0.0):
    from phantom.automation.guidance.commands import Registry
    from phantom.automation.guidance.stealth import (
        StealthConfig, StealthEngine)
    from phantom.automation.guidance.threatmodel import BlueTeamModel
    from phantom.automation.planner import Planner
    reg = Registry()
    for cap in caps:
        reg.register(cap)
    wm = _wm()
    stealth = StealthEngine(wm, StealthConfig(),
                            BlueTeamModel.for_profile("enterprise"))
    return Planner(reg, stealth, value_weight=value_weight), wm


def _cap(cap_id, effects, cost=1.0):
    from phantom.automation.guidance.commands import Capability
    return Capability(id=cap_id, category="recon", description=cap_id,
                      effects=list(effects), opsec_cost=cost,
                      preconditions=[lambda wm: True])


@pytest.fixture()
def fact_sources(monkeypatch):
    import phantom.automation.planner as P
    patched = dict(P._FACT_SOURCES)
    patched["creds"] = ["cheap_creds", "rich_creds"]
    monkeypatch.setattr(P, "_FACT_SOURCES", patched)


class TestInfoValue:
    def test_default_keeps_registry_order(self, fact_sources):
        planner, wm = _planner([
            _cap("cheap_creds", ["creds"], cost=1.0),
            _cap("rich_creds", ["creds", "os"], cost=9.0),
        ])
        plan = planner.plan(wm, goal="creds")
        assert plan.steps
        assert plan.steps[0].capability.id == "cheap_creds"

    def test_value_weight_prefers_novel_move(self, fact_sources):
        planner, wm = _planner([
            _cap("cheap_creds", ["creds"], cost=1.0),
            _cap("rich_creds", ["creds", "os"], cost=9.0),
        ], value_weight=1.0)
        plan = planner.plan(wm, goal="creds")
        assert plan.steps
        assert plan.steps[0].capability.id == "rich_creds"

    def test_evidence_first_wires_value_weight(self):
        from phantom.automation.agent import AutonomousAgent
        agent = AutonomousAgent(target=TARGET,
                                reason_profile="evidence_first")
        assert agent.planner.value_weight == 1.0
        plain = AutonomousAgent(target=TARGET)
        assert plain.planner.value_weight == 0.0


def _fake_runner():
    from unittest.mock import Mock

    def runner(cmd, timeout=None):
        res = Mock()
        res.ok = True
        res.stderr = ""
        if "nmap" in cmd:
            res.stdout = ("22/tcp open ssh OpenSSH 7.9p1\n"
                          "80/tcp open http Apache httpd 2.4.49")
        else:
            res.stdout = "PHANTOM"
        return res
    return runner


class TestDiversityAxes:
    def test_avoid_caps_steers_off_sibling_move(self):
        from phantom.automation.swarm.board import Board
        from phantom.automation.swarm.tasks import build_tasks
        from phantom.automation.swarm.worker import run_swarm_task
        board = Board([TARGET])
        task = build_tasks("footprint", [TARGET], budget=6)[0]
        task.avoid_caps = frozenset({"scan_tcp"})
        ran = []
        run_swarm_task(task, TARGET, board, runner=_fake_runner(),
                       on_event=lambda k, d: ran.append(
                           (k, (d or {}).get("capability"))))
        tried = {cap for kind, cap in ran if kind == "run"}
        assert "scan_tcp" not in tried

    def test_banned_categories_subset_registry(self):
        from phantom.automation.swarm.board import Board
        from phantom.automation.swarm.tasks import build_tasks
        from phantom.automation.swarm.worker import run_swarm_task
        board = Board([TARGET])
        task = build_tasks("footprint", [TARGET], budget=4)[0]
        task.banned_categories = frozenset({"recon"})
        result = run_swarm_task(task, TARGET, board,
                                runner=_fake_runner())
        # the banned category produces nothing (reasoning-derived facts
        # like attack_path may still appear — they are analysis, not moves)
        assert "service" not in {s["kind"] for s in result.staged}
        assert result.ok is False


class TestProfilePicker:
    def test_pick_is_deterministic(self):
        from phantom.automation.brain.priors import TechniquePriors
        from phantom.automation.swarm.profiles import pick_profile
        priors = TechniquePriors(path=":memory:")
        priors._data = {}
        first = [pick_profile("footprint", "generic", priors, seed=7,
                              round_idx=r) for r in range(8)]
        second = [pick_profile("footprint", "generic", priors, seed=7,
                               round_idx=r) for r in range(8)]
        assert first == second

    def test_recorded_wins_steer_exploit_rounds(self, tmp_path):
        from phantom.automation.brain.priors import TechniquePriors
        from phantom.automation.swarm.profiles import pick_profile
        priors = TechniquePriors(path=str(tmp_path / "p.json"))
        for _ in range(5):
            priors.record("swarm:footprint:evidence_first", "generic", True)
            priors.record("swarm:footprint:balanced", "generic", False)
        exploit_rounds = []
        for r in range(16):
            import hashlib
            h = int(hashlib.sha256(
                f"7:footprint:{r}".encode()).hexdigest(), 16)
            if h % 4 != 0:
                exploit_rounds.append(r)
        assert exploit_rounds
        for r in exploit_rounds:
            assert pick_profile("footprint", "generic", priors, seed=7,
                                round_idx=r) == "evidence_first"

    def test_scheduler_feeds_priors(self, tmp_path):
        from phantom.automation.brain.priors import TechniquePriors
        from phantom.automation.swarm import run_swarm
        priors = TechniquePriors(path=str(tmp_path / "priors.json"))
        summary = run_swarm([TARGET], chain="footprint",
                            runner=_fake_runner(), budget=6, priors=priors)
        assert summary["ok"] is True
        data = priors.summary()
        assert any(k.startswith("swarm:footprint:") and v.get("generic", {}).get("runs", 0) >= 1
                   for k, v in data.items())
