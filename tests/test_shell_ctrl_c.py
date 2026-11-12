"""Ctrl+C must never make the interactive shell feel unkillable.

At an idle prompt it closes the shell; during a run it aborts that run and
returns to the prompt (the next command gets a chance to decide).
"""

import pytest

from phantom.core.shell.base import PhantomShell


def _shell_without_chrome():
    class Shell(PhantomShell):
        def preloop(self):
            pass

        def postloop(self):
            pass

        def postcmd(self, stop, line):
            return stop

    return Shell()


def test_ctrl_c_at_idle_prompt_exits(monkeypatch):
    shell = _shell_without_chrome()

    def interrupt(_prompt=""):
        raise KeyboardInterrupt()

    monkeypatch.setattr("builtins.input", interrupt)
    with pytest.raises(SystemExit):
        shell.cmdloop()


def test_ctrl_c_during_run_returns_to_prompt(monkeypatch):
    shell = _shell_without_chrome()
    shell.onecmd = lambda line: (_ for _ in ()).throw(KeyboardInterrupt()) \
        if line == "longrun" else (line == "exit")
    answers = iter(["longrun", "exit"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))

    shell.cmdloop()          # must return, not raise / not swallow the run
    assert next(answers, None) is None
