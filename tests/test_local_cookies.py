"""Tests: local cookie reader (no beacon) + start-gate CLI.

* the reader touches only %LOCALAPPDATA% files (sqlite copy, DPAPI),
  imports nothing network-capable, never raises;
* plaintext cookie rows parse; missing browser -> [];
* CLI start-gate previews + confirms before launch.
"""
import json
import os
import sqlite3
import unittest


def _chrome_tree(root, cookies=()):
    from pathlib import Path
    prof = Path(root) / "Google" / "Chrome" / "User Data" / "Default"
    prof.mkdir(parents=True, exist_ok=True)
    (Path(root) / "Google" / "Chrome" / "User Data" / "Local State"
     ).write_text(json.dumps({"os_crypt": {}}), encoding="utf-8")
    db = prof / "Cookies"
    con = sqlite3.connect(str(db))
    con.execute("CREATE TABLE cookies (host_key TEXT, name TEXT, "
                "path TEXT, value TEXT, encrypted_value BLOB)")
    for host, name, path, value in cookies:
        con.execute("INSERT INTO cookies VALUES (?,?,?,?,?)",
                    (host, name, path, value, b""))
    con.commit()
    con.close()
    return root


class TestLocalReader(unittest.TestCase):
    def test_plaintext_rows_parse(self):
        import tempfile
        from phantom.automation.social.local_cookies import (
            read_browser_cookies)
        tmp = tempfile.mkdtemp(prefix="phantom-cookie-test-")
        _chrome_tree(tmp, [(".instagram.com", "sessionid", "/", "abc"),
                           (".tiktok.com", "sid", "/", "xyz")])
        try:
            entries = read_browser_cookies(base_dir=tmp)
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)
        by_host = {e["host"]: e for e in entries}
        self.assertEqual(by_host[".instagram.com"]["value"], "abc")
        self.assertEqual(by_host[".tiktok.com"]["name"], "sid")

    def test_domain_filter(self):
        import tempfile
        from phantom.automation.social.local_cookies import (
            read_browser_cookies)
        tmp = tempfile.mkdtemp(prefix="phantom-cookie-test-")
        _chrome_tree(tmp, [(".instagram.com", "a", "/", "1"),
                           (".x.com", "b", "/", "2")])
        try:
            entries = read_browser_cookies(
                base_dir=tmp, domains=["instagram.com"])
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["host"], ".instagram.com")

    def test_missing_browser_gives_empty(self):
        import tempfile
        from phantom.automation.social.local_cookies import (
            read_browser_cookies)
        tmp = tempfile.mkdtemp(prefix="phantom-cookie-test-")
        try:
            self.assertEqual(read_browser_cookies(base_dir=tmp), [])
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_non_windows_gives_empty(self):
        from unittest.mock import patch
        from phantom.automation.social.local_cookies import (
            read_browser_cookies)
        with patch("os.name", "posix"):
            self.assertEqual(read_browser_cookies(base_dir="whatever"), [])

    def test_no_network_imports(self):
        import pathlib
        src = pathlib.Path(
            "phantom/automation/social/local_cookies.py").read_text(
                encoding="utf-8")
        for mod in ("socket", "requests", "urllib", "http.client",
                    "subprocess", "os.system", "os.popen"):
            self.assertNotIn(f"import {mod}", src)
            self.assertNotIn(f"from {mod}", src)


class TestCliStartGate(unittest.TestCase):
    def _shell(self):
        from unittest.mock import Mock
        shell = Mock()
        shell.auto_run = False
        return shell

    def _run_gate(self, user_input):
        from phantom.core.shell.commands import auto as auto_mod
        from phantom.core.session import session
        from unittest.mock import Mock, patch
        old_target = session.target
        shell = self._shell()
        prof = Mock()
        prof.username = "u"
        prof.platform = "instagram"
        try:
            with patch("sys.stdin.isatty", return_value=True), \
                    patch("sys.stdout.isatty", return_value=True), \
                    patch("phantom.automation.guidance.targets.classify_target",
                          return_value="username"), \
                    patch("phantom.automation.social.recon.preview_profile",
                          return_value=prof), \
                    patch("phantom.automation.social.recon.present_candidate",
                          return_value="@u"), \
                    patch("builtins.input", return_value=user_input), \
                    patch("phantom.core.automode.run_auto_mode") as m_run:
                auto_mod.cmd_auto(
                    shell, "someuser --platform instagram --goal identity")
            return m_run
        finally:
            session.target = old_target

    def test_cancel_on_wrong_profile(self):
        m_run = self._run_gate("n")
        m_run.assert_not_called()

    def test_proceed_on_confirm(self):
        m_run = self._run_gate("")
        self.assertTrue(m_run.called)


if __name__ == "__main__":
    unittest.main()
