"""OSINT username handling must not turn operator input into shell syntax.

`do_sherlock` builds `sherlock <username> ...` and calls `run_command`, whose
executor validates only the TARGET — with no target the command string reaches
`subprocess.Popen(..., shell=True)` unchecked. A username carrying `;`/`|`/`&`
therefore becomes shell syntax. These tests pin the fail-closed sanitizer.
"""
import unittest
from unittest import mock

from phantom.core.session import session
from phantom.modules.osint import OsintModule, _clean_username


class TestUsernameSafety(unittest.TestCase):
    def setUp(self):
        self._target = session.target
        session.target = ""

    def tearDown(self):
        session.target = self._target

    def test_safe_usernames_pass_through(self):
        for name in ("mario.rossi", "john_doe", "user@example.com",
                     "a-b.c_d"):
            self.assertEqual(_clean_username(name), name.lstrip("@"), name)

    def test_shell_metacharacters_are_refused(self):
        for bad in ("user; rm -rf /", "user && whoami", "user|nc 1.2.3.4",
                    "`id`", "$(id)", "user name", "user\nid", "user'q",
                    'user"q', "user>out", "user&bg"):
            self.assertEqual(_clean_username(bad), "", bad)

    def test_leading_at_is_stripped(self):
        self.assertEqual(_clean_username("@handle"), "handle")

    def test_empty_and_none_are_empty(self):
        self.assertEqual(_clean_username(""), "")
        self.assertEqual(_clean_username(None), "")

    def test_get_username_rejects_unsafe_candidates(self):
        osint = OsintModule()
        self.assertEqual(osint._get_username("bad name;id"), "")
        self.assertEqual(osint._get_username("mario_rossi"), "mario_rossi")
        self.assertEqual(osint._get_username("10.0.0.5"), "")

    def test_sherlock_refuses_an_unsafe_username(self):
        osint = OsintModule()
        with mock.patch("phantom.modules.osint.run_command") as run, \
                mock.patch("phantom.modules.osint.notifier") as notifier:
            osint.do_sherlock("evil; rm -rf /")
        run.assert_not_called()
        self.assertTrue(notifier.error.called)


if __name__ == "__main__":
    unittest.main()
