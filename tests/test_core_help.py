"""The core `help` panel must not hide a command that exists.

The audit found `phantom/core/shell/commands/system.py` — the file that renders
`help` — mentioned four registered commands (`malleable`, `guardrails`, `deps`,
`llm`) exactly ZERO times, and `base.py` claimed "the 36 `do_*` commands" while
46 were registered. In a tool whose selling point is "everything is in here",
an operator had to already know a command existed in order to discover it.

Two defenses, because they fail differently:

* the panel is now CHECKED against the registry (`command_names()`), and
  whatever the curated tables miss is printed from the handlers' own docstrings
  — so a new command cannot be added and stay invisible;
* the counts in prose are gone, so they cannot go stale.

`phantom/core/c2_help.py` already proves this pattern (one registry, gated and
enumerated); this is the core shell catching up to it.
"""
import io
import re
import sys
import unittest

from phantom.core.shell import PhantomShell
from phantom.core.shell.registry import command_names


def _capture(fn) -> str:
    """Run `fn` with stdout redirected and return what a terminal would show.

    Rich's console resolves ``sys.stdout`` at write time, so this captures the
    tables AND the notifier's lines without patching either module.
    """
    buffer = io.StringIO()
    original = sys.stdout
    sys.stdout = buffer
    try:
        fn()
    finally:
        sys.stdout = original
    return buffer.getvalue()


class _patched_command:
    """Temporarily add a handler to a group module's COMMANDS dict."""

    def __init__(self, name, handler, module):
        self.name = name
        self.handler = handler
        self.module = module

    def __enter__(self):
        self.module.COMMANDS[self.name] = self.handler
        return self

    def __exit__(self, *exc):
        self.module.COMMANDS.pop(self.name, None)
        return False


class TestHelpListsEveryCommand(unittest.TestCase):
    def test_every_registered_command_appears_in_the_panel(self):
        text = _capture(lambda: PhantomShell().do_help(""))
        missing = []
        for name in command_names():
            spelled = [name, name.replace("_", "-")]
            if not any(re.search(rf"(?<![\w-]){re.escape(s)}(?![\w-])", text)
                       for s in spelled):
                missing.append(name)
        self.assertEqual(missing, [],
                         "registered commands the `help` panel never shows — "
                         "an operator cannot discover them from the docs")

    def test_a_command_added_to_the_registry_is_shown_without_editing_help(self):
        """The `Also available` panel is GENERATED, not hand-maintained."""
        from phantom.core.shell.commands import system as system_cmd

        def cmd_zzz_probe(shell, arg: str):
            """zzz-probe — a command that only exists in this test"""

        with _patched_command("zzz_probe", cmd_zzz_probe, system_cmd):
            text = _capture(lambda: PhantomShell().do_help(""))
        self.assertIn("zzz-probe", text)

    def test_help_for_one_command_still_shows_the_full_docstring(self):
        text = _capture(lambda: PhantomShell().do_help("workflow"))
        # the panel lists only the FIRST line of a handler's docstring; the
        # per-command help is the whole thing.
        self.assertIn("next_moves", text)


class TestNoStaleCountInTheShellDocs(unittest.TestCase):
    def test_base_docstring_does_not_state_a_command_count(self):
        from phantom.core.shell import base

        doc = base.__doc__ or ""
        self.assertNotRegex(doc, r"\b\d+\s+``do_\*``",
                            "a command count in prose is a claim nothing "
                            "checks; the registry is the count")


class TestLegacyWorkflowEngineIsReachable(unittest.TestCase):
    """`phantom/core/workflow.py` was a second kill-chain engine no command
    wired — dead surface that drifts. It is now inspectable (`workflow`)."""

    def test_the_command_is_registered_and_wired(self):
        self.assertTrue(callable(getattr(PhantomShell(), "do_workflow", None)))
        self.assertIn("workflow", command_names())

    def test_show_prints_the_phase_chain_for_the_requested_target_type(self):
        from phantom.core.workflow import workflow_manager

        text = _capture(lambda: PhantomShell().do_workflow("show ip"))
        for phase in workflow_manager.get_phases("ip"):
            self.assertIn(phase, text)

    def test_the_command_never_executes_a_phase(self):
        """Inspection only: it prints the model, it does not run the chain."""
        from phantom.core.workflow import WorkflowManager

        ran = []

        def spy(self, phase):
            ran.append(phase)
            return WorkflowManager.execute_phase(self, phase)

        original = WorkflowManager.execute_phase
        WorkflowManager.execute_phase = spy
        try:
            shell = PhantomShell()
            _capture(lambda: (shell.do_workflow("show ip"),
                              shell.do_workflow("types"),
                              shell.do_workflow("next ip")))
        finally:
            WorkflowManager.execute_phase = original
        self.assertEqual(ran, [], "the legacy chain must not execute")

    def test_an_unknown_target_type_is_refused_with_the_valid_ones(self):
        from phantom.core.workflow import workflow_manager

        text = _capture(lambda: PhantomShell().do_workflow("show not-a-type"))
        self.assertIn("Unknown target type", text)
        for name in sorted(workflow_manager.phases):
            self.assertIn(name, text)

    def test_types_lists_every_target_type_with_its_chain(self):
        from phantom.core.workflow import workflow_manager

        text = _capture(lambda: PhantomShell().do_workflow("types"))
        for name, chain in workflow_manager.phases.items():
            self.assertIn(name, text)
            self.assertIn(chain[0], text)

    def test_registered_phases_is_the_public_view_of_the_executor_map(self):
        from phantom.core.workflow import WorkflowManager

        manager = WorkflowManager()
        self.assertEqual(manager.registered_phases(), [])
        manager.register_executor("scan", lambda: True)
        self.assertEqual(manager.registered_phases(), ["scan"])


if __name__ == "__main__":
    unittest.main()
