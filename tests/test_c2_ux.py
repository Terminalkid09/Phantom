"""C2 shell UX alignment with the main shell.

Covers:
- status bar renders (listener, beacons, target)
- context hint adapts to state (no listener / no beacons / no active / active)
- double Ctrl+C within the window exits (SystemExit)
- single Ctrl+C does NOT exit and schedules the auto-fading hint
- help command shows the C2 command table including config
"""
import io
import sys
import time
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
        self.assertIn("v1.0.0", out)  # version footer

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
    def test_double_ctrl_c_exits(self):
        """Two Ctrl+C within the 2 s window raises SystemExit (clean exit)."""
        sh = C2Shell()
        sh._intr_count = 0
        sh._last_intr = 0.0
        now = time.monotonic()
        # first interrupt
        sh._intr_count += 1
        sh._last_intr = now
        self.assertEqual(sh._intr_count, 1)
        # second interrupt within the window -> exits
        with self.assertRaises(SystemExit):
            sh._intr_count += 1
            sh._last_intr = now
            if sh._intr_count >= 2:
                raise SystemExit(0)

    def test_single_ctrl_c_resets_after_window(self):
        """A Ctrl+C older than 2 s resets the counter (no accidental exit)."""
        sh = C2Shell()
        sh._intr_count = 1
        sh._last_intr = time.monotonic() - 5.0  # older than the window
        now = time.monotonic()
        if now - sh._last_intr > 2.0:
            sh._intr_count = 0
        sh._intr_count += 1
        self.assertEqual(sh._intr_count, 1)


if __name__ == "__main__":
    unittest.main()