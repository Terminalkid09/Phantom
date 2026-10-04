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
    events = []
    run_swarm_task(task, T, board, runner=_runner,
                   on_event=lambda k, d: events.append(
                       (k, (d or {}).get("capability"))),
                   toolchain=toolchain)
    return events


def _ran(events):
    return {cap for kind, cap in events if kind == "run"}


class TestInjectedToolchain:
    def test_empty_toolchain_blocks_tool_dependent_moves(self):
        from phantom.automation.runtime.toolchain import ToolRegistry
        events = _ran_capabilities(ToolRegistry(installed=set()))
        ran = _ran(events)
        # every TOOL-DEPENDENT move is blocked by the missing tool...
        assert "scan_tcp" not in ran
        assert "curl_probe" not in ran
        assert "version_detect" not in ran
        # ...and each is reported as tool_missing, not silently skipped
        missing = {cap for kind, cap in events if kind == "tool_missing"}
        assert {"scan_tcp", "curl_probe", "version_detect"} <= missing
        # a TOOL-FREE passive engine (external_recon needs no binary) may
        # still run: with no scanner on the box the passive public-intel
        # fallback is exactly what keeps the footprint moving.
        assert ran <= {"external_recon"}

    def test_standard_toolchain_plans_a_move(self):
        from phantom.automation.runtime.toolchain import ToolRegistry
        events = _ran_capabilities(
            ToolRegistry(installed={"nmap", "curl", "nc"}))
        assert _ran(events)

    def test_default_is_the_offline_planning_set(self):
        # no injection: the documented offline default, not a hidden one
        events = _ran_capabilities(None)
        assert _ran(events)


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
