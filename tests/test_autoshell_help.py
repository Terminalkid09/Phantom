"""Section E3 — `help` and `flags` answer the question that was asked.

The AUTO shell's help was hand-written and its `flags` docstring carried
literal placeholders: ``goal (<choices>)``, ``profile (<choices>)``. The 12
goals and the 6 profiles were constants in the same file, so the operator who
asked "which goals are there?" was answered with the word "<choices>".

`flags profile` with no value was no better: ``Usage: flags profile <value>``.
The accepted values appeared only AFTER a wrong one was typed — the answer
existed, hidden behind an error. And the help row for `flags` listed the keys
but not their values, having already lost `verbose` and `evolution`, which the
`flags` table itself prints.

These pin the registry (`phantom/core/auto_help.py`) TO the shell in both
directions, so the two cannot drift apart again.
"""
import io
import unittest
from unittest import mock

from phantom.core import auto_help
from phantom.core.auto_shell import AutoShell


def _render(call) -> str:
    """Run `call` against a real rich Console writing to a buffer.

    The assertions must see the RENDERED text, not the markup source: rich
    treats `[` as a style tag, which is exactly the trap a usage string like
    `guardrails [list | why | ...]` falls into. A recorder that captures
    `.rows` would hide the difference between "escaped so it shows" and
    "swallowed silently".
    """
    from rich.console import Console
    from phantom.core import auto_shell
    buf = io.StringIO()
    original = auto_shell.console
    auto_shell.console = Console(file=buf, width=400, no_color=True,
                                 highlight=False)
    try:
        call()
    finally:
        auto_shell.console = original
    return buf.getvalue()


class TestTheRegistryMatchesTheShell(unittest.TestCase):
    """Neither direction may drift: a command without a spec is invisible in
    help, and a spec without a handler is a lie in help."""

    def test_every_command_has_a_handler(self):
        for spec in auto_help.COMMANDS:
            self.assertTrue(
                hasattr(AutoShell, "do_" + spec.handler_name),
                f"{spec.name} declares handler do_{spec.handler_name}")

    def test_every_handler_is_documented(self):
        documented = set(auto_help.handler_names())
        handlers = {name[3:] for name in dir(AutoShell)
                    if name.startswith("do_")}
        # `quit` is an alias (do_quit = do_exit) and is documented as an alias
        # of `exit`, so it is not a command of its own.
        handlers.discard("quit")
        self.assertFalse(handlers - documented,
                         f"undocumented commands: {sorted(handlers - documented)}")

    def test_every_flag_of_the_shell_is_documented(self):
        self.assertEqual(set(AutoShell().flags), set(auto_help.flag_keys()))

    def test_the_flag_defaults_come_from_the_registry(self):
        self.assertEqual(AutoShell().flags, auto_help.default_flags())

    def test_the_bool_keys_are_derived(self):
        shell = AutoShell()
        for key in shell._BOOL_KEYS:
            self.assertEqual(auto_help.flag_by_key(key).kind, "bool")


class TestFlagsAnswerTheQuestion(unittest.TestCase):
    def test_a_missing_value_lists_the_accepted_values(self):
        shell = AutoShell()
        with mock.patch("phantom.utils.notifier.notifier.usage") as m:
            shell.do_flags("profile")
        m.assert_called_once()
        hint = m.call_args.kwargs.get("hint", "")
        self.assertIn("mobile", hint)          # a real choice, not "<choices>"
        self.assertEqual(shell.flags["profile"], "enterprise")   # unchanged

    def test_a_wrong_choice_names_the_values_and_keeps_the_old_one(self):
        shell = AutoShell()
        with mock.patch("phantom.utils.notifier.notifier.unknown") as m:
            shell.do_flags("goal not-a-goal")
        m.assert_called_once()
        self.assertEqual(m.call_args.kwargs.get("options"),
                         list(auto_help.GOALS))
        self.assertEqual(shell.flags["goal"], "deliver")

    def test_an_unknown_key_lists_the_keys(self):
        shell = AutoShell()
        with mock.patch("phantom.utils.notifier.notifier.unknown") as m:
            shell.do_flags("psrofile mobile")
        m.assert_called_once()
        self.assertEqual(m.call_args.kwargs.get("options"),
                         auto_help.flag_keys())

    def test_force_profile_is_reachable_from_the_repl(self):
        """The CLI had `--force-profile` and `run_auto_mode` accepted it, but
        the REPL could not set it — so `flags profile mobile` on an IP was
        silently overruled and the warning told the operator to use a flag
        they could not type here."""
        shell = AutoShell()
        shell.do_flags("force_profile on")
        self.assertTrue(shell.flags["force_profile"])
        self.assertTrue(shell._run_kwargs()["force_profile"])

    def test_the_table_shows_a_value_column_and_an_accepts_column(self):
        shell = AutoShell()
        text = _render(lambda: shell.do_flags(""))
        self.assertIn("Accepts", text)
        for key in auto_help.flag_keys():
            self.assertIn(key, text)
        self.assertIn("mobile", text)     # the profile choices are visible
        self.assertIn("deliver", text)    # and the goal choices


class TestHelpIsRenderedFromTheRegistry(unittest.TestCase):
    def test_help_flags_prints_the_value_table(self):
        shell = AutoShell()
        text = _render(lambda: shell.do_help("flags"))
        self.assertIn("mobile", text)
        self.assertIn("deliver", text)
        self.assertNotIn("<choices>", text)

    def test_the_overview_lists_every_registered_command(self):
        shell = AutoShell()
        text = _render(lambda: shell.do_help(""))
        for spec in auto_help.COMMANDS:
            self.assertIn(spec.usage.split()[0], text)

    def test_the_overview_names_every_flag_key(self):
        """The old row had lost `verbose` and `evolution`."""
        shell = AutoShell()
        text = _render(lambda: shell.do_help(""))
        for key in auto_help.flag_keys():
            self.assertIn(key, text)

    def test_a_usage_string_with_brackets_renders_literally(self):
        """`guardrails [list | ...]` is DATA: rich must not eat the bracket."""
        shell = AutoShell()
        text = _render(lambda: shell.do_help(""))
        self.assertIn("[list | why | enable <k> | disable <k> | record]", text)

    def test_help_for_an_unknown_command_does_not_raise(self):
        shell = AutoShell()
        _render(lambda: shell.do_help("zzqqxx"))

    def test_help_for_one_command_shows_its_usage(self):
        shell = AutoShell()
        text = _render(lambda: shell.do_help("scope"))
        self.assertIn("scope add <cidr>", text)


class TestStatusBarShowsWhatDecidesTheRun(unittest.TestCase):
    def _bar(self, scope, run_secs=""):
        from phantom.core import auto_shell
        from phantom.core.session import session
        old = list(session.scope or [])
        try:
            session.scope = scope
            shell = AutoShell()
            return auto_shell._status_bar(shell.targets, shell.flags, run_secs)
        finally:
            session.scope = old

    def test_profile_scope_and_both_clocks(self):
        bar = self._bar(["10.0.0.0/24"], "3s")
        # the profile is present (markup sits between the label and the
        # value, so assert the parts, not a contiguous string)
        self.assertIn("profile", bar)
        self.assertIn("enterprise", bar)
        self.assertIn("10.0.0.0/24", bar)
        self.assertIn("eng ", bar)       # the engagement age, labelled
        self.assertIn("run 3s", bar)     # and the run clock, separately

    def test_no_scope_says_so_instead_of_hiding_it(self):
        bar = self._bar([])
        self.assertIn("none", bar)
        self.assertIn("refused", bar)

    def test_an_override_is_visible_in_the_bar(self):
        """`force_network` used to be absent from the hand-listed subset."""
        from phantom.core import auto_shell
        shell = AutoShell()
        shell.do_flags("force_network on")
        bar = auto_shell._status_bar(shell.targets, shell.flags)
        self.assertIn("force_network", bar)


class TestTheContextHintNamesTheBlockingStep(unittest.TestCase):
    def test_an_unscoped_target_run_is_told_to_declare_a_scope(self):
        from phantom.core import auto_shell
        from phantom.core.session import session
        old = list(session.scope or [])
        try:
            session.scope = []
            hint = auto_shell._context_hint(["10.0.0.5"], False)
        finally:
            session.scope = old
        self.assertIn("scope add <cidr>", hint)
        self.assertIn("launch", hint)

    def test_a_scoped_target_run_is_not_nagged(self):
        from phantom.core import auto_shell
        from phantom.core.session import session
        old = list(session.scope or [])
        try:
            session.scope = ["10.0.0.0/24"]
            hint = auto_shell._context_hint(["10.0.0.5"], False)
        finally:
            session.scope = old
        self.assertNotIn("scope add", hint)


if __name__ == "__main__":
    unittest.main()
