"""Tests for the dependency-install flow (build_helper.py).

Guards the user requirement: the install prompt must ask, install and
proceed on 'y', and MUST NOT hang or dead-end when the user declines or
when the session is non-interactive.
"""
import io
import sys
import unittest
from unittest import mock

from phantom.utils.build_helper import (
    _INSTALL_TIMEOUT,
    _UPDATE_TIMEOUT,
    _safe_choice,
    install_dependencies,
)


class TestSafeChoice(unittest.TestCase):

    def test_eof_returns_default_without_raising(self):
        with mock.patch("builtins.input", side_effect=EOFError):
            self.assertEqual(_safe_choice("? "), "n")

    def test_keyboard_interrupt_returns_default(self):
        with mock.patch("builtins.input", side_effect=KeyboardInterrupt):
            self.assertEqual(_safe_choice("? ", default="y"), "y")

    def test_returns_normalized_choice(self):
        with mock.patch("builtins.input", return_value=" Y "):
            self.assertEqual(_safe_choice("? "), "y")


class TestInstallDependencies(unittest.TestCase):

    def test_non_interactive_prints_instructions_and_returns_false(self):
        """CI / piped stdin must not block — it prints manual steps and
        returns False so the caller can skip the step gracefully."""
        with mock.patch.object(sys.stdin, "isatty", return_value=False), \
                mock.patch("builtins.input") as inp:
            result = install_dependencies(["libssl-dev"], manager="apt")
        self.assertFalse(result)
        inp.assert_not_called()

    def test_decline_interactive_returns_false_without_subprocess(self):
        with mock.patch.object(sys.stdin, "isatty", return_value=True), \
                mock.patch("builtins.input", return_value="n"), \
                mock.patch("subprocess.run") as run:
            result = install_dependencies(["libssl-dev"], manager="apt")
        self.assertFalse(result)
        run.assert_not_called()  # no install attempt on decline

    def test_accept_runs_install_with_bounded_timeout(self):
        # geteuid does not exist on Windows — build_helper catches it; we
        # only stub `which` (None -> no sudo prefix)
        with mock.patch.object(sys.stdin, "isatty", return_value=True), \
                mock.patch("builtins.input", return_value="y"), \
                mock.patch("shutil.which", return_value=None), \
                mock.patch("subprocess.run", return_value=mock.Mock()) as run:
            result = install_dependencies(["libssl-dev"], manager="apt")
        self.assertTrue(result)
        install_call = run.call_args_list[-1]
        self.assertIn("install", install_call.args[0])
        self.assertEqual(install_call.kwargs.get("timeout"), _INSTALL_TIMEOUT)

    def test_bounded_timeouts_are_set(self):
        # the whole point: no unbounded subprocess in the install flow
        self.assertGreater(_INSTALL_TIMEOUT, 0)
        self.assertGreater(_UPDATE_TIMEOUT, 0)
        self.assertLess(_INSTALL_TIMEOUT, 3600)

    def test_timeout_expired_returns_false_gracefully(self):
        from subprocess import TimeoutExpired
        with mock.patch.object(sys.stdin, "isatty", return_value=True), \
                mock.patch("builtins.input", return_value="y"), \
                mock.patch("shutil.which", return_value=None), \
                mock.patch("subprocess.run",
                           side_effect=TimeoutExpired("apt-get", 300)):
            result = install_dependencies(["libssl-dev"], manager="apt")
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
