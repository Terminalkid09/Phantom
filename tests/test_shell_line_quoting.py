"""One wrong QUOTE made the whole passive-recon surface lie.

Live evidence (2026-10-16): `social graph --run` on the Instagram handle
`polo_1300__` reported `state=missing conf=1.00` at every platform, while a
direct fetch of the same URL returned 586 KB containing the handle. The recon
builds shell LINES that `execute_quiet` runs with `shell=True`; on Windows
that shell is cmd.exe, which has NO single-quote quotes:

    curl -s -L -m 15 -A 'Mozilla/5.0 (X11)' 'https://www.instagram.com/x/'

reaches curl as `["-A", "'Mozilla/5.0", "(X11)'", "'https://…/'"]` — four
arguments, rc=3 "URL malformed", empty stdout, and `_fetch` returns "" which
`_state_vote` reads as "the profile does not exist".

The defect is the ARGUMENT COUNT, not the quote character, so the test drives
the real shell and inspects the argv a child process receives.
"""
import json
import os
import sys
import unittest
from unittest import mock

from phantom.core.executor import execute_quiet, quote_arg


def _argv_echo(args):
    """A command line that prints the argv it receives, as JSON."""
    code = "import sys, json; print(json.dumps(sys.argv[1:]))"
    return sys.executable + ' -c "' + code + '" ' + " ".join(
        quote_arg(a) for a in args)


class TestQuoteArg(unittest.TestCase):

    def test_arguments_survive_the_real_shell(self):
        args = ["Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                "https://www.example.com/a b?x=1&y=2"]
        res = execute_quiet(_argv_echo(args), timeout=60)
        self.assertTrue(res.stdout, f"no output: {res!r}")
        self.assertEqual(json.loads(res.stdout.strip()), args)

    def test_a_cookie_header_stays_one_argument(self):
        args = ["Cookie: sessionid=abc123; csrftoken=def456",
                "https://example.com/"]
        res = execute_quiet(_argv_echo(args), timeout=60)
        self.assertEqual(json.loads(res.stdout.strip()), args)

    @unittest.skipUnless(os.name == "nt", "single quotes are only wrong on cmd.exe")
    def test_single_quotes_are_not_quotes_on_windows(self):
        """The exact broken form, kept as the reason the helper exists."""
        code = "import sys, json; print(json.dumps(sys.argv[1:]))"
        line = (sys.executable + ' -c "' + code + '" '
                "-A 'Mozilla/5.0 (X11)' 'https://example.com/'")
        res = execute_quiet(line, timeout=60)
        parsed = json.loads(res.stdout.strip())
        self.assertNotEqual(parsed, ["-A", "Mozilla/5.0 (X11)",
                                     "https://example.com/"])


class TestReconFetchUsesThisShellsQuoting(unittest.TestCase):

    def _line_for(self, url="https://x.example/a", ua="UA with space"):
        import phantom.automation.social.recon as recon

        class _R:
            returncode = 0
            stdout = "body"
            stderr = ""

        seen = {}

        def _spy(line, *a, **k):
            seen["line"] = line
            return _R()

        with mock.patch("phantom.core.executor.execute_quiet", side_effect=_spy):
            body = recon._fetch(url, timeout=1, ua=ua)
        return seen["line"], body

    def test_fetch_line_is_not_posix_quoted_on_windows(self):
        line, body = self._line_for()
        self.assertEqual(body, "body")
        if os.name == "nt":
            self.assertNotIn("'", line,
                             f"cmd.exe will not read these quotes: {line}")
            self.assertIn('"', line)
        else:
            self.assertIn("'", line)

    def test_fetch_line_keeps_the_url_whole(self):
        line, _ = self._line_for(url="https://x.example/a?b=1&c=2")
        self.assertIn("https://x.example/a?b=1&c=2", line)
        # the UA must not be split by its own spaces
        self.assertIn("UA with space", line)

    def test_surface_fetch_line_is_not_posix_quoted_on_windows(self):
        from phantom.automation import surface
        seen = {}

        class _R:
            returncode = 0
            stdout = "body"
            stderr = ""

        def _spy(line, *a, **k):
            seen["line"] = line
            return _R()

        with mock.patch("phantom.core.executor.execute_quiet", side_effect=_spy):
            surface._fetch("https://x.example/a b")
        line = seen["line"]
        if os.name == "nt":
            self.assertNotIn("'", line)
        else:
            self.assertIn("'", line)


class TestPosixRedirectsOnWindows(unittest.TestCase):
    """`2>/dev/null` does not "do nothing politely" on cmd.exe: it fails with
    "path not found" and the command never runs (verified on this host)."""

    def test_translation_matches_the_shell(self):
        from phantom.core.executor import _to_cmd_redirects
        if os.name != "nt":
            self.assertEqual(_to_cmd_redirects("x 2>/dev/null"),
                             "x 2>/dev/null")
            return
        self.assertEqual(_to_cmd_redirects("yt-dlp q 2>/dev/null"),
                         "yt-dlp q 2>NUL")
        self.assertEqual(_to_cmd_redirects("x &>/dev/null"), "x >NUL 2>&1")
        self.assertEqual(_to_cmd_redirects("x >/dev/null"), "x >NUL")

    def test_an_argument_is_not_a_redirect(self):
        from phantom.core.executor import _to_cmd_redirects
        line = "ssh -o UserKnownHostsFile=/dev/null -o BatchMode=yes u@h id"
        self.assertEqual(_to_cmd_redirects(line), line)

    def test_a_redirected_line_actually_runs(self):
        code = "import sys; print(7)"
        res = execute_quiet(f'{sys.executable} -c "{code}" 2>/dev/null',
                            timeout=60)
        self.assertEqual((res.stdout or "").strip(), "7",
                         f"command did not run: {res!r}")


if __name__ == "__main__":
    unittest.main()
