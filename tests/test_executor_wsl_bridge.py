"""The WSL bridge and the wrapper-word rule (Windows-first operator flow).

On the operator's Windows box the toolset lives in the Kali WSL distro, and
the command templates say `sudo nmap ...` the way every Linux tutorial does.
Two assumptions in the executor were wrong for that combination, and both
failures were silent — the sweep simply did not happen and the run reported
"0 services" on a host that has some:

* the FIRST token was treated as "the tool". On Windows 11 that token is
  often `sudo`, whose native sudo.exe is disabled, so `_rewrite_wsl` decided
  the command was native and handed it to cmd.exe, and `_is_tool_installed`
  called a missing binary present;
* `sudo` inside the distro wants a password the child has no tty to supply.
  WSL can elevate directly (`-u root`), which is how `install_tool` already
  does it.
"""
import contextlib
import io
import os
import unittest
from unittest import mock

from phantom.core.executor import (
    QuietResult,
    _command_head,
    _is_tool_installed,
    _wrap_wsl_redirects,
    _win_paths_to_wsl,
)

SCAN_CMD = ("sudo nmap -sV -sC -p- -oX "
            r"C:\Users\op\phantom\data\sessions\scan_192.168.1.18.xml "
            "192.168.1.18   # enables exploit module")


class TestCommandHead(unittest.TestCase):
    """The wrapper is not the tool — one rule, used by every caller."""

    def test_plain_command(self):
        self.assertEqual(_command_head("nmap -sV 10.0.0.1"),
                         ("", "nmap", "-sV 10.0.0.1"))

    def test_privilege_wrapper(self):
        self.assertEqual(_command_head("sudo nmap -sV 10.0.0.1"),
                         ("sudo", "nmap", "-sV 10.0.0.1"))

    def test_wrapper_flag_belongs_to_the_wrapper(self):
        # `sudo -n nmap ...`: `-n` is sudo's, not the command's
        self.assertEqual(_command_head("sudo -n nmap 10.0.0.1"),
                         ("sudo -n", "nmap", "10.0.0.1"))

    def test_stacked_wrappers(self):
        self.assertEqual(_command_head("sudo env nmap -sV x"),
                         ("sudo env", "nmap", "-sV x"))

    def test_quoting_of_the_rest_survives(self):
        _p, tool, rest = _command_head("sudo nmap --script 'smb-os-discovery' x")
        self.assertEqual(tool, "nmap")
        self.assertEqual(rest, "--script 'smb-os-discovery' x")

    def test_comment_line_has_no_tool(self):
        self.assertEqual(_command_head("# nothing to run"), ("", "#", "nothing to run"))

    def test_empty(self):
        self.assertEqual(_command_head(""), ("", "", ""))


class TestWrapperAwareGate(unittest.TestCase):

    def test_wrapper_is_not_reported_as_installed_tool(self):
        # the regression: `sudo` resolves on Windows 11 (disabled sudo.exe)
        # and on any Linux box, so `sudo <missing-tool>` passed the gate
        self.assertFalse(_is_tool_installed("sudo definitely-not-a-tool-xyz 1"))
        self.assertFalse(_is_tool_installed("sudo -n definitely-not-a-tool-xyz 1"))

    def test_empty_command_is_not_a_missing_tool(self):
        self.assertTrue(_is_tool_installed(""))


class TestWindowsPathsToWsl(unittest.TestCase):

    def test_drive_path_becomes_mnt(self):
        self.assertEqual(_win_paths_to_wsl(r"-oX C:\a\b.xml 1.2.3.4"),
                         "-oX /mnt/c/a/b.xml 1.2.3.4")

    def test_forward_slashes_too(self):
        self.assertEqual(_win_paths_to_wsl("-oX C:/a/b.xml"),
                         "-oX /mnt/c/a/b.xml")

    def test_host_port_and_urls_are_left_alone(self):
        # `p:/` inside `http://` must not become a drive: the lookbehind
        # rejects a letter glued to a word character
        self.assertEqual(_win_paths_to_wsl("nmap -p 8080 http://x/y h:1"),
                         "nmap -p 8080 http://x/y h:1")


class TestWrapWslRedirects(unittest.TestCase):
    """`-u root` lives between `wsl` and the tool: it is part of the prefix."""

    def test_distro_user_prefix_stays_outside_the_quoted_command(self):
        got = _wrap_wsl_redirects("wsl -d kali-linux -u root nmap -sV x 2>/dev/null")
        self.assertEqual(got, 'wsl -d kali-linux -u root sh -c "nmap -sV x 2>/dev/null"')

    def test_plain_prefix_still_wraps(self):
        got = _wrap_wsl_redirects("wsl -d kali-linux nmap -sV x | grep foo")
        self.assertEqual(got, 'wsl -d kali-linux sh -c "nmap -sV x | grep foo"')

    def test_nothing_linux_specific_is_untouched(self):
        cmd = "wsl -d kali-linux nmap -sV x"
        self.assertEqual(_wrap_wsl_redirects(cmd), cmd)


@unittest.skipUnless(os.name == "nt", "the WSL bridge only rewrites on Windows")
class TestRewriteWsl(unittest.TestCase):
    """Windows: a Linux-only tool is routed through the distro."""

    def _rewrite(self, cmd, wrapper="wsl -d kali-linux nmap"):
        with mock.patch("phantom.core.executor.shutil.which", return_value=None), \
             mock.patch("phantom.automation.runtime.toolchain._wsl_which",
                        return_value=wrapper):
            from phantom.core.executor import _rewrite_wsl
            return _rewrite_wsl(cmd)

    def test_plain_tool_is_routed(self):
        self.assertEqual(self._rewrite("nmap -sV 1.2.3.4"),
                         "wsl -d kali-linux nmap -sV 1.2.3.4")

    def test_privilege_becomes_u_root_not_sudo(self):
        # sudo inside the distro prompts for a password there is no tty for
        got = self._rewrite(SCAN_CMD)
        self.assertNotIn("sudo", got)
        self.assertTrue(got.startswith("wsl -d kali-linux -u root nmap"), got)

    def test_output_path_is_reachable_from_the_distro(self):
        got = self._rewrite(SCAN_CMD)
        self.assertIn("/mnt/c/Users/op/phantom/data/sessions/scan_192.168.1.18.xml", got)
        self.assertNotIn(r"C:\Users", got)

    def test_non_privilege_wrapper_is_preserved(self):
        got = self._rewrite("env FOO=1 hydra -l root 1.2.3.4 ssh")
        self.assertIn(" env ", got)
        self.assertNotIn("-u root", got)

    def test_default_distro_wrapper_does_not_duplicate_the_tool(self):
        # `wsl -e nmap` names the tool already: re-appending it used to emit
        # `wsl -e nmap nmap -sV ...`
        got = self._rewrite("nmap -sV 1.2.3.4", wrapper="wsl -e nmap")
        self.assertEqual(got, "wsl -e nmap -sV 1.2.3.4")

    def test_native_tool_is_left_alone(self):
        with mock.patch("phantom.core.executor.shutil.which",
                        return_value=r"C:\Windows\System32\where.exe"):
            from phantom.core.executor import _rewrite_wsl
            self.assertEqual(_rewrite_wsl("where nmap"), "where nmap")


class TestQuietBudget(unittest.TestCase):
    """A killed command must not read as a finished one."""

    def test_scan_module_gives_full_sweeps_a_longer_budget(self):
        from phantom.modules.scan import ScanModule
        m = ScanModule()
        self.assertEqual(m.quiet_timeout_seconds(SCAN_CMD),
                         ScanModule.FULL_SWEEP_QUIET_TIMEOUT)
        self.assertGreater(ScanModule.FULL_SWEEP_QUIET_TIMEOUT,
                           m.quiet_timeout_default)
        # the budget must cover the MEASURED duration: on this LAN a
        # `-sV -sC -p-` sweep of a fully firewalled host COMPLETED in
        # 13 552 s (~3 h 46 m, all 65535 ports filtered). When nmap is killed
        # mid-sweep the XML file is EMPTY — the host entry is written only on
        # completion — so a too-small ceiling is not a partial answer, it is
        # no answer
        self.assertGreaterEqual(ScanModule.FULL_SWEEP_QUIET_TIMEOUT, 13552)

    def test_long_budget_says_so_before_waiting(self):
        from phantom.modules.scan import ScanModule
        killed = QuietResult(cmd="nmap", stdout="", timed_out=True)
        with mock.patch("phantom.core.executor.execute_quiet",
                        return_value=killed), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            ScanModule()._run_quiet({"g": ["nmap -sV -sC -p- 1.2.3.4"]})
        text = out.getvalue()
        self.assertIn("long-running command", text)
        self.assertIn("TIMED OUT", text)

    def test_scan_module_keeps_the_short_leash_for_quick_commands(self):
        from phantom.modules.scan import ScanModule
        m = ScanModule()
        self.assertEqual(m.quiet_timeout_seconds("nc -nv 1.2.3.4 22"),
                         m.quiet_timeout_default)

    def test_run_quiet_says_when_the_command_was_killed(self):
        from phantom.modules.base_module import BaseModule
        m = BaseModule()
        killed = QuietResult(cmd="nmap", stdout="80/tcp open http",
                             timed_out=True)
        with mock.patch("phantom.core.executor.execute_quiet",
                        return_value=killed), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            m._run_quiet({"g": ["nmap -p- 1.2.3.4"]})
        self.assertIn("80/tcp open http", out.getvalue())
        self.assertIn("TIMED OUT", out.getvalue())
        self.assertIn("PARTIAL", out.getvalue())

    def test_run_quiet_stays_quiet_when_the_command_finished(self):
        from phantom.modules.base_module import BaseModule
        done = QuietResult(cmd="nmap", stdout="80/tcp open http")
        with mock.patch("phantom.core.executor.execute_quiet",
                        return_value=done), \
             contextlib.redirect_stdout(io.StringIO()) as out:
            m = BaseModule()
            m._run_quiet({"g": ["nmap 1.2.3.4"]})
        self.assertNotIn("TIMED OUT", out.getvalue())
        self.assertEqual(m.quiet_timeout_default, 120)


class TestExitToleratesClosedStdin(unittest.TestCase):

    def test_eof_returns_the_default(self):
        from phantom.core.shell.commands.system import _ask
        with mock.patch("builtins.input", side_effect=EOFError):
            self.assertEqual(_ask("note? ", "d"), "d")


if __name__ == "__main__":
    unittest.main()
