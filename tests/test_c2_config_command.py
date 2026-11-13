"""C2 shell `config` command: status, rotate, mTLS toggle."""
import io
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

from phantom.core.c2_shell import C2Shell


class TestC2ConfigCommand(unittest.TestCase):

    def _capture(self):
        """Redirect sys.stdout so we can assert on printed output."""
        buf = io.StringIO()
        self.addCleanup(lambda: setattr(sys, "stdout", sys.__stdout__))
        return buf

    def _fresh_state(self, buf):
        state_file = tempfile.mktemp(prefix="phant-", suffix=".json")
        self.addCleanup(lambda: os.path.exists(state_file) and os.unlink(state_file))
        return state_file

    def test_config_status_does_not_crash(self):
        buf = self._capture()
        state_file = self._fresh_state(buf)
        shell = C2Shell()
        sys.stdout = buf
        with patch.dict(os.environ, {"PHANTOM_STATE_FILE": state_file}, clear=True):
            shell.do_config("")
        out = buf.getvalue()
        self.assertIn("Phantom C2", out)  # table title renders

    def test_config_rotate_rotates_api_token(self):
        buf = self._capture()
        state_file = self._fresh_state(buf)
        shell = C2Shell()
        sys.stdout = buf
        with patch.dict(os.environ, {"PHANTOM_STATE_FILE": state_file}, clear=True):
            from phantom.utils.c2_crypto import get_api_token
            before = get_api_token()
            shell.do_config("rotate")
            after = get_api_token()
        self.assertNotEqual(before, after)

    def test_config_mtls_toggle_persists(self):
        buf = self._capture()
        state_file = self._fresh_state(buf)
        shell = C2Shell()
        sys.stdout = buf
        with patch.dict(os.environ, {"PHANTOM_STATE_FILE": state_file}, clear=True):
            from phantom.utils.state import get_flag
            self.assertTrue(get_flag("PHANTOM_MTLS_REQUIRED", True))
            shell.do_config("mtls-off")
            self.assertFalse(get_flag("PHANTOM_MTLS_REQUIRED", True))
            shell.do_config("mtls-on")
            self.assertTrue(get_flag("PHANTOM_MTLS_REQUIRED", True))

    def test_config_unknown_action_falls_back_to_status(self):
        buf = self._capture()
        state_file = self._fresh_state(buf)
        shell = C2Shell()
        sys.stdout = buf
        with patch.dict(os.environ, {"PHANTOM_STATE_FILE": state_file}, clear=True):
            shell.do_config("bogus-action")  # must not raise
        self.assertIn("Phantom C2", buf.getvalue())


if __name__ == "__main__":
    unittest.main()