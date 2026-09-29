"""The swarm worker must not assume a hardcoded toolset.

`swarm/worker.py` used to construct `ToolRegistry(installed={"nmap",
"curl", "nc"})` inline, so the engine planned against a set the box may
not have. The worker now takes a `toolchain`; operator paths (CLI
`auto --swarm`, the auto-mode swarm engine) inject a REAL detector, and
the offline default is only for tests / bare environments.
"""
import pytest

T = "10.0.0.5"


class _Res:
    def __init__(self, ok=True, stdout=""):
        self.ok = ok
        self.stdout = stdout
        self.stderr = ""


def _runner(cmd, timeout=None):
    return _Res(True, "22/tcp open ssh OpenSSH_8.9")


def _ran_capabilities(toolchain):
    from phantom.automation.runtime.toolchain import ToolRegistry
    from phantom.automation.swarm.board import Board
    from phantom.automation.swarm.tasks import build_tasks
    from phantom.automation.swarm.worker import run_swarm_task
    board = Board([T])
    task = build_tasks("footprint", [T], budget=3)[0]
    kinds = []
    run_swarm_task(task, T, board, runner=_runner,
                   on_event=lambda k, d: kinds.append(k),
                   toolchain=toolchain)
    return kinds


class TestInjectedToolchain:
    def test_empty_toolchain_blocks_planning(self):
        from phantom.automation.runtime.toolchain import ToolRegistry
        kinds = _ran_capabilities(ToolRegistry(installed=set()))
        assert "run" not in kinds

    def test_standard_toolchain_plans_a_move(self):
        from phantom.automation.runtime.toolchain import ToolRegistry
        kinds = _ran_capabilities(
            ToolRegistry(installed={"nmap", "curl", "nc"}))
        assert "run" in kinds

    def test_default_is_the_offline_planning_set(self):
        # no injection: the documented offline default, not a hidden one
        kinds = _ran_capabilities(None)
        assert "run" in kinds


class TestOperatorPathsInjectRealDetection:
    def test_cli_swarm_passes_a_real_tool_registry(self, monkeypatch):
        captured = {}
        import phantom.automation.swarm as swarm_pkg

        def _fake_run_swarm(targets, **kwargs):
            captured.update(kwargs)
            return {"ok": True, "tasks": [], "added": 0}

        monkeypatch.setattr(swarm_pkg, "run_swarm", _fake_run_swarm)

        class _Shell:
            auto_run = True

        from phantom.automation.runtime.toolchain import ToolRegistry
        from phantom.core.shell.commands.auto import cmd_auto
        cmd_auto(_Shell(), "10.0.0.5 --swarm")
        assert isinstance(captured.get("toolchain"), ToolRegistry)

    def test_run_swarm_threads_the_toolchain_to_the_worker(self, monkeypatch):
        import phantom.automation.swarm as swarm_pkg
        sentinel = object()
        seen = {}

        def _fake_task(task, target, board, **kwargs):
            seen["toolchain"] = kwargs.get("toolchain")
            from phantom.automation.swarm.worker import TaskResult
            return TaskResult(task_id=task.id, target=target, ok=True)

        monkeypatch.setattr(swarm_pkg, "run_swarm_task", _fake_task)
        swarm_pkg.run_swarm([T], chain="footprint", budget=1,
                            runner=lambda cmd, timeout=None: None,
                            toolchain=sentinel)
        assert seen.get("toolchain") is sentinel
