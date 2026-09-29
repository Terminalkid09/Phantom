"""One error shape for the whole shell.

The point is not pretty output: an error that only names the problem (or
renders a different way in each module) makes the operator go read the
source. These tests pin the SHAPE — one box, one Usage line, one optional
hint — and pin that the legacy `notifier.error("Usage: ...")` call sites
are funnelled through it instead of drifting.
"""
import unittest

from phantom.utils import notifier as N


class _Recorder:
    """Captures what the notifier would print, without a terminal."""

    def __init__(self):
        self.lines = []

    def print(self, *args, **kwargs):
        self.lines.append(" ".join(str(a) for a in args))

    @property
    def text(self):
        return "\n".join(self.lines)


class _Capture:
    def __enter__(self):
        self.recorder = _Recorder()
        self._saved = N.console
        N.console = self.recorder
        return self.recorder

    def __exit__(self, *exc):
        N.console = self._saved
        return False


class TestUniformShape(unittest.TestCase):
    def test_usage_renders_one_box_and_one_usage_line(self):
        with _Capture() as rec:
            N.notifier.usage("use", "<module>", hint="try 'plugins'")
        self.assertIn("ERROR: missing or invalid arguments", rec.text)
        self.assertIn("Usage: use <module>", rec.text)
        self.assertIn("try 'plugins'", rec.text)

    def test_usage_does_not_need_a_command(self):
        with _Capture() as rec:
            N.notifier.usage("", "<name>")
        self.assertIn("Usage: <name>", rec.text)
        self.assertNotIn("Usage:  ", rec.text)

    def test_a_legacy_usage_message_is_normalized(self):
        # the ~30 pre-existing call sites must not render a different box
        with _Capture() as rec:
            N.notifier.error("Usage: craft wait <code> [seconds]")
        self.assertIn("ERROR: missing or invalid arguments", rec.text)
        self.assertIn("Usage: craft wait <code>", rec.text)
        self.assertIn("seconds]", rec.text)
        # and it must not be printed a second time as a plain error
        self.assertNotIn("ERROR: Usage:", rec.text)

    def test_brackets_in_syntax_do_not_break_rich(self):
        # "[seconds]" is rich markup unless escaped: an error must never
        # raise while reporting an error
        with _Capture() as rec:
            N.notifier.usage("craft wait", "<code> [seconds]")
        self.assertIn("[seconds]", rec.text)

    def test_a_plain_error_keeps_its_hint(self):
        with _Capture() as rec:
            N.notifier.error("No target set.", hint="run 'set target <ip>'")
        self.assertIn("ERROR: No target set.", rec.text)
        self.assertIn("run 'set target <ip>'", rec.text)

    def test_an_exception_is_shown_and_does_not_escape(self):
        with _Capture() as rec:
            N.notifier.error("Cannot load.", exc=ValueError("bad json"))
        self.assertIn("bad json", rec.text)


class TestUnknownSuggestion(unittest.TestCase):
    def test_a_typo_gets_a_closest_match(self):
        with _Capture() as rec:
            N.notifier.unknown("module", "scna",
                               ["scan", "osint", "web"])
        self.assertIn("Unknown module: 'scna'", rec.text)
        self.assertIn("scan", rec.text)

    def test_a_wild_value_gets_no_bogus_suggestion(self):
        with _Capture() as rec:
            N.notifier.unknown("module", "zzqqxx",
                               ["scan", "osint"])
        self.assertIn("Unknown module: 'zzqqxx'", rec.text)
        self.assertNotIn("Did you mean", rec.text)

    def test_no_options_is_still_safe(self):
        with _Capture() as rec:
            N.notifier.unknown("profile", "x")
        self.assertIn("Unknown profile: 'x'", rec.text)


class TestShellWiring(unittest.TestCase):
    def test_use_without_argument_prints_the_usage_box(self):
        from phantom.core.shell.commands.modules import cmd_use

        class _Shell:
            MODULE_ALIASES = {}
            _plugin_modules = {}

        with _Capture() as rec:
            cmd_use(_Shell(), "")
        self.assertIn("Usage: use <module>", rec.text)

    def test_unknown_module_is_refused_with_a_suggestion(self):
        from phantom.core.shell.commands.modules import cmd_use

        class _Shell:
            MODULE_ALIASES = {}
            _plugin_modules = {}

        with _Capture() as rec:
            cmd_use(_Shell(), "scna")
        self.assertIn("Unknown module: 'scna'", rec.text)

    def test_profile_names_helper_is_safe_without_a_directory(self):
        from phantom.core.shell import PhantomShell
        names = PhantomShell._saved_profile_names()
        self.assertIsInstance(names, list)


if __name__ == "__main__":
    unittest.main()
