"""C2 shell UX alignment with the main shell.

Covers:
- status bar renders (listener, beacons, target)
- context hint adapts to state (no listener / no beacons / no active / active)
- a single Ctrl+C at the prompt exits (SystemExit)
- a Ctrl+C during a command aborts the run and returns to the prompt
- help command shows the C2 command table including config
"""
import io
import sys
import unittest
from unittest.mock import patch

from phantom.core import c2_shell as C2S
from phantom.core.c2_shell import C2Shell
from phantom.core.session import session


class TestC2StatusBar(unittest.TestCase):
    def test_status_bar_renders(self):
        s = C2S._c2_status_bar()
        self.assertIn("C2", s)

    def test_status_bar_shows_target(self, ):
        old = session.target
        try:
            session.target = "10.0.0.5"
            s = C2S._c2_status_bar()
            self.assertIn("10.0.0.5", s)
        finally:
            session.target = old

    def test_status_bar_has_timer(self):
        old = session.target
        try:
            session.target = "10.0.0.5"
            s = C2S._c2_status_bar()
            self.assertIn("⏱", s)
        finally:
            session.target = old

    def test_dashboard_panel_renders(self):
        panel = C2S._c2_dashboard()
        text = panel.renderable
        self.assertIn("Listener", str(text))
        self.assertIn("mTLS", str(text))

    def test_separator_is_short_and_dim(self):
        s = C2S._c2_separator()
        self.assertIn("dim", s)
        self.assertTrue(len(s) < 100)


class TestC2ContextHint(unittest.TestCase):
    def test_hint_without_listener(self):
        from phantom.core.c2_server import server_instance
        with patch.object(server_instance, "thread", None):
            hint = C2S._c2_context_hint()
            self.assertIn("listeners start", hint)

    def test_hint_with_active_beacon(self):
        from phantom.core.c2_server import server_instance, c2_state
        fake_thread = type("T", (), {"is_alive": lambda self: True})()
        with patch.object(server_instance, "thread", fake_thread), \
             patch.object(c2_state, "get_beacons", return_value={"B-1": {}}):
            hint = C2S._c2_context_hint(active_beacon="B-1")
            self.assertIn("results", hint)


class TestC2Help(unittest.TestCase):
    def test_help_lists_config(self):
        sh = C2Shell()
        buf = io.StringIO()
        orig = sys.stdout
        sys.stdout = buf
        try:
            sh.do_help("")
        finally:
            sys.stdout = orig
        out = buf.getvalue()
        self.assertIn("config", out)
        self.assertIn("listeners", out)
        self.assertIn("v3.0.0", out)  # version footer

    def test_help_specific_command(self):
        sh = C2Shell()
        buf = io.StringIO()
        orig = sys.stdout
        sys.stdout = buf
        try:
            sh.do_help("config")
        finally:
            sys.stdout = orig
        self.assertIn("rotate-api-token", buf.getvalue())


class TestC2CtrlC(unittest.TestCase):
    @staticmethod
    def _shell():
        sh = C2Shell()
        sh.preloop = lambda: None
        sh.postloop = lambda: None
        sh.postcmd = lambda stop, line: stop
        return sh

    @patch("builtins.input", side_effect=KeyboardInterrupt)
    def test_single_ctrl_c_at_idle_exits(self, _input):
        """At an idle prompt ONE Ctrl+C closes the C2 shell (clean exit)."""
        with self.assertRaises(SystemExit):
            self._shell().cmdloop()

    def test_ctrl_c_during_command_returns_to_prompt(self):
        """During a run Ctrl+C aborts the run, not the whole C2 shell."""
        sh = self._shell()
        sh.onecmd = lambda line: (_ for _ in ()).throw(KeyboardInterrupt()) \
            if line == "longrun" else (line == "exit")
        answers = iter(["longrun", "exit"])
        with patch("builtins.input", side_effect=lambda _p="": next(answers)):
            sh.cmdloop()
        self.assertFalse(sh._busy)
        self.assertIsNone(next(answers, None))


if __name__ == "__main__":
    unittest.main()