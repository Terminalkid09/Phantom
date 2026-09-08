"""Tests for non-interactive execution (execute_quiet / BackgroundProcess)."""
import os
import sys
import time
import unittest

from phantom.core.executor import (
    execute_quiet,
    execute_quiet_bg,
    QuietResult,
    BackgroundProcess,
)


class TestExecuteQuiet(unittest.TestCase):

    def _py(self, code: str) -> str:
        q = '"' if os.name == "nt" else "'"
        return f'{sys.executable} -c {q}{code}{q}'

    def test_success_result(self):
        r = execute_quiet(self._py("print(1+1)"))
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.combined, "2")
        self.assertTrue(r.ok)

    def test_failure_result(self):
        r = execute_quiet(self._py("import sys; sys.exit(3)"))
        self.assertEqual(r.returncode, 3)
        self.assertFalse(r.ok)

    def test_never_raises_on_bad_command(self):
        r = execute_quiet("this-command-does-not-exist-xyz 123")
        self.assertIsInstance(r, QuietResult)
        self.assertFalse(r.ok)

    def test_missing_tool_returns_error(self):
        r = execute_quiet("definitely-not-a-tool-xyz")
        self.assertIn("not installed", (r.error or ""))
        self.assertEqual(r.returncode, -1)

    def test_timeout_kills(self):
        r = execute_quiet(self._py("import time; time.sleep(30)"), timeout=0.5)
        self.assertTrue(r.timed_out)

    def test_out_of_scope_blocked(self):
        from phantom.core.session import session
        session.scope = "10.0.0.0/8"
        try:
            r = execute_quiet("echo hi", target_ip="192.168.1.1")
            self.assertEqual(r.returncode, -1)
            self.assertIn("out of scope", r.error)
        finally:
            session.scope = None


class TestBackgroundProcess(unittest.TestCase):

    def _py(self, code: str) -> str:
        q = '"' if os.name == "nt" else "'"
        return f'{sys.executable} -u -c {q}{code}{q}'

    def test_read_output(self):
        p = execute_quiet_bg(self._py("import time; print('A'); time.sleep(0.3); print('B')"))
        time.sleep(0.6)
        out = ""
        while p.is_alive():
            out += p.read()
            time.sleep(0.05)
        out += p.read()
        self.assertIn("A", out)
        self.assertIn("B", out)

    def test_write_stdin(self):
        p = execute_quiet_bg(
            self._py("import sys; [sys.stdout.write((l or '').upper()) for l in sys.stdin]")
        )
        p.write("hello\n")
        time.sleep(0.3)
        out = p.read()
        self.assertIn("HELLO", out)
        p.terminate()

    def test_kill(self):
        p = execute_quiet_bg(self._py("import time; time.sleep(30)"))
        self.assertTrue(p.is_alive())
        p.kill()
        p.wait(timeout=5)
        self.assertFalse(p.is_alive())


if __name__ == "__main__":
    unittest.main()
