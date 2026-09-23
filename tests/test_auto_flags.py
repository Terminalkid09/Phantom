"""The auto/agent flag contract: every documented flag actually reaches code.

`--reason` was accepted by the parser and passed to `run_auto_mode`, but the
`--swarm` branch ignored it entirely — the flag parsed, the run started, and
the reasoning objective had no effect. `--verbose` was the same on that path
(it printed only the closing summary). These tests pin the wiring so the
help text cannot promise something the code does not do.
"""
import pytest


class _Shell:
    auto_run = True


class TestSwarmFlagWiring:
    def _capture(self, monkeypatch):
        captured = {}
        import phantom.automation.swarm as swarm_pkg

        def _fake_run_swarm(targets, **kwargs):
            captured["targets"] = targets
            captured.update(kwargs)
            return {"ok": True, "tasks": [], "added": 0}

        monkeypatch.setattr(swarm_pkg, "run_swarm", _fake_run_swarm)
        return captured

    def test_reason_reaches_the_swarm(self, monkeypatch):
        from phantom.core.shell.commands.auto import cmd_auto
        captured = self._capture(monkeypatch)
        cmd_auto(_Shell(), "10.0.0.5 --swarm --reason evidence_first")
        assert captured.get("reason_profile") == "evidence_first"

    def test_swarm_streams_events_so_verbose_is_not_a_noop(self, monkeypatch):
        from phantom.core.shell.commands.auto import cmd_auto
        captured = self._capture(monkeypatch)
        cmd_auto(_Shell(), "10.0.0.5 --swarm --verbose")
        assert callable(captured.get("on_event"))


class TestRunSwarmReasonProfile:
    """`--reason` used to be unreachable from the swarm path."""

    def _tasks_at_schedule(self, monkeypatch, **kwargs):
        """Capture the task objects `run_swarm` hands to the scheduler.

        The scheduler ROTATES the profile on a requeue, so asserting on the
        returned summary would test the rotation, not the fill.
        """
        import phantom.automation.swarm.scheduler as sched
        captured = {}

        def _fake_schedule(orchs, board, tasks, **kw):
            captured["tasks"] = list(tasks)
            return {"tasks": [], "board": {}, "added": 0, "skipped": 0,
                    "trail": [], "failures": [], "evolution_cases": [],
                    "actions_taken": 0}

        monkeypatch.setattr(sched, "schedule", _fake_schedule)
        from phantom.automation.swarm import run_swarm
        run_swarm(["10.0.0.5"], chain="full",
                  runner=lambda cmd, timeout=60: None, **kwargs)
        return captured["tasks"]

    def _explicit_profiles(self):
        from phantom.automation.swarm.tasks import build_tasks
        return {t.id: t.profile for t in build_tasks("full", ["10.0.0.5"])}

    def test_reason_profile_reaches_the_tasks_without_one(self, monkeypatch):
        tasks = self._tasks_at_schedule(monkeypatch,
                                        reason_profile="evidence_first")
        explicit = self._explicit_profiles()
        assert tasks, "the full chain must define tasks"
        unset = [t for t in tasks if not explicit.get(t.id)]
        assert unset, "the chain must have at least one auto-profiled task"
        assert all(t.profile == "evidence_first" for t in unset)

    def test_explicit_task_profiles_still_win(self, monkeypatch):
        tasks = self._tasks_at_schedule(monkeypatch,
                                        reason_profile="evidence_first")
        explicit = self._explicit_profiles()
        for task in tasks:
            if explicit.get(task.id):
                assert task.profile == explicit[task.id], task.id

    def test_no_reason_profile_leaves_the_task_profile_alone(self, monkeypatch):
        tasks = self._tasks_at_schedule(monkeypatch)
        explicit = self._explicit_profiles()
        assert all(t.profile == explicit[t.id] for t in tasks)

    def test_run_swarm_signature_keeps_the_two_knobs_distinct(self):
        import inspect
        from phantom.automation.swarm import run_swarm
        params = inspect.signature(run_swarm).parameters
        assert "reason_profile" in params
        assert "profile" in params   # the environment class, kept distinct


class TestAutoModeFlagMatrix:
    """Each documented run flag reaches `run_auto_mode` under its own name."""

    @pytest.mark.parametrize("flag,key,expected", [
        ("--stealth", "stealth", True),
        ("--aggressive", "aggressive", True),
        ("--speed", "speed", True),
        ("--plan", "plan", True),
        ("--verbose", "verbose", True),
        ("--force-network", "force_network", True),
        ("--reason evidence_first", "reason_profile", "evidence_first"),
        ("--goal beacon", "goal", "beacon"),
        ("--profile cloud", "profile", "cloud"),
        ("-a2", "agents", 2),
    ])
    def test_flag_reaches_run_auto_mode(self, monkeypatch, flag, key, expected):
        captured = {}
        import phantom.core.automode as automode

        def _fake_run_auto_mode(**kwargs):
            captured.update(kwargs)
            return {}

        monkeypatch.setattr(automode, "run_auto_mode", _fake_run_auto_mode)
        from phantom.core.shell.commands.auto import cmd_auto
        cmd_auto(_Shell(), f"10.0.0.5 {flag}")
        assert captured.get(key) == expected, (flag, key, captured)
