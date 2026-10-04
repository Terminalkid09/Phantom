"""Unified external-service key plane + extensible toolbelt catalog.

`api_keys` is the single place a key is declared (config path + legacy env
override + label). These tests pin: env beats the file, values persisted to
the config file survive and are masked in `status()`, and the toolbelt
catalog can be extended from config so a tool Phantom never shipped is
selectable.
"""
import os
import unittest
from contextlib import contextmanager

from phantom.utils import config as cfg
from phantom.utils import api_keys


@contextmanager
def _env(**pairs):
    saved = {k: os.environ.get(k) for k in pairs}
    try:
        for k, v in pairs.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


@contextmanager
def _temp_config(tmpdir):
    """Repoint the config plane at a throwaway file for the duration."""
    import tempfile
    path = os.path.join(tmpdir, "config.json")
    saved_path, saved_loaded = cfg._CONFIG_PATH, cfg._loaded
    cfg._CONFIG_PATH = path
    cfg._loaded = None
    try:
        yield
    finally:
        cfg._CONFIG_PATH, cfg._loaded = saved_path, saved_loaded


class TestRegistryBasics(unittest.TestCase):
    def test_registry_declares_expected_keys(self):
        for name in ("shodan", "nvd", "github", "hibp", "breach_api"):
            self.assertIn(name, api_keys.KEY_REGISTRY)

    def test_set_get_roundtrip_and_clear(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d, _temp_config(d):
            self.assertEqual(api_keys.get("shodan"), "")
            api_keys.set("shodan", "abc123")
            self.assertEqual(api_keys.get("shodan"), "abc123")
            self.assertEqual(api_keys.source("shodan"), "config")
            api_keys.set("shodan", "")
            self.assertEqual(api_keys.get("shodan"), "")
            self.assertEqual(api_keys.source("shodan"), "none")

    def test_unknown_key_raises_on_set(self):
        with self.assertRaises(KeyError):
            api_keys.set("nope", "x")

    def test_unknown_key_get_is_default(self):
        self.assertEqual(api_keys.get("nope", "fallback"), "fallback")

    def test_env_override_wins(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d, _temp_config(d):
            api_keys.set("nvd", "from-file")
            with _env(PHANTOM_NVD_API_KEY="from-env"):
                self.assertEqual(api_keys.get("nvd"), "from-env")
                self.assertEqual(api_keys.source("nvd"), "env")
            self.assertEqual(api_keys.get("nvd"), "from-file")

    def test_mask_never_reveals_short_secret(self):
        self.assertEqual(api_keys.mask("short"), "•" * 5)
        masked = api_keys.mask("1234567890abcdef")
        self.assertTrue(masked.startswith("1234"))
        self.assertTrue(masked.endswith("cdef"))
        self.assertNotIn("567890ab", masked)


class TestStatus(unittest.TestCase):
    def test_status_is_masked_and_reports_source(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d, _temp_config(d):
            api_keys.set("github", "ghp_verysecretvalue0000")
            st = api_keys.status()
            self.assertTrue(st["github"]["configured"])
            self.assertEqual(st["github"]["source"], "config")
            # raw secret must never appear in status
            self.assertNotIn("verysecretvalue", st["github"]["masked"])

    def test_unset_key_reports_not_configured(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d, _temp_config(d):
            st = api_keys.status()
            self.assertFalse(st["shodan"]["configured"])
            self.assertEqual(st["shodan"]["source"], "none")


class TestWrappersUseRegistry(unittest.TestCase):
    """The external wrappers resolve their key from the registry, so a key
    set via CLI/Electron is honoured without threading it through callers."""

    class _Resp:
        def __init__(self, data):
            self.status_code = 200
            self._data = data

        def raise_for_status(self):
            return None

        def json(self):
            return self._data

    def test_shodan_lookup_uses_registry_key(self):
        import tempfile
        from phantom.utils import api as ext
        captured = {}

        def fake_get(url, *a, **k):
            captured["url"] = url
            return self._Resp({})

        with tempfile.TemporaryDirectory() as d, _temp_config(d):
            api_keys.set("shodan", "KEY123")
            saved = ext.requests.get
            ext.requests.get = fake_get
            try:
                with _env(PHANTOM_SHODAN_KEY=None, SHODAN_API_KEY=None):
                    ext.shodan_lookup("1.2.3.4")
            finally:
                ext.requests.get = saved
        self.assertIn("api.shodan.io", captured["url"])
        self.assertIn("KEY123", captured["url"])

    def test_shodan_lookup_keyless_when_unset(self):
        import tempfile
        from phantom.utils import api as ext
        captured = {}

        def fake_get(url, *a, **k):
            captured["url"] = url
            return self._Resp({})

        with tempfile.TemporaryDirectory() as d, _temp_config(d):
            saved = ext.requests.get
            ext.requests.get = fake_get
            try:
                with _env(PHANTOM_SHODAN_KEY=None, SHODAN_API_KEY=None):
                    ext.shodan_lookup("1.2.3.4")
            finally:
                ext.requests.get = saved
        self.assertIn("internetdb.shodan.io", captured["url"])

    def test_github_poc_uses_registry_token(self):
        import tempfile
        from phantom.utils import api as ext
        captured = {}

        def fake_get(url, *a, **k):
            captured["headers"] = k.get("headers") or {}
            return self._Resp({"total_count": 1})

        with tempfile.TemporaryDirectory() as d, _temp_config(d):
            api_keys.set("github", "ghp_token")
            saved = ext.requests.get
            ext.requests.get = fake_get
            try:
                with _env(PHANTOM_GITHUB_TOKEN=None):
                    ext.github_poc_lookup("CVE-2024-0001")
            finally:
                ext.requests.get = saved
        self.assertEqual(captured["headers"].get("Authorization"),
                         "Bearer ghp_token")


class TestConfigSchema(unittest.TestCase):
    def test_api_keys_declared_in_schema(self):
        for key in ("api_keys.shodan", "api_keys.nvd", "api_keys.github"):
            self.assertIn(key, cfg.SCHEMA)

    def test_api_keys_defaults_present(self):
        self.assertIn("api_keys", cfg.DEFAULTS)


class TestExtensibleToolbeltCatalog(unittest.TestCase):
    def _tb(self, installed):
        from phantom.automation.brain.toolbelt import Toolbelt
        from phantom.automation.runtime.toolchain import ToolRegistry
        return Toolbelt(ToolRegistry(installed=set(installed)))

    def test_extra_tool_is_selectable_for_new_capability(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d, _temp_config(d):
            cfg.set("toolbelt.extra", {
                "custom_scan": [
                    {"name": "rustscan", "rank": 5,
                     "styles": ["default", "speed"]},
                ],
            })
            tb = self._tb({"rustscan"})
            self.assertEqual(tb.pick("custom_scan").tool, "rustscan")

    def test_extra_tool_augments_builtin_capability(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d, _temp_config(d):
            cfg.set("toolbelt.extra", {
                "scan_tcp": [
                    {"name": "nmap", "rank": 1,
                     "styles": ["default", "stealth"]},
                ],
            })
            tb = self._tb({"nmap", "masscan", "nc"})
            # the operator-declared rank-1 nmap is preferred over built-in
            self.assertEqual(tb.pick("scan_tcp").tool, "nmap")

    def test_malformed_extra_entries_are_dropped(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d, _temp_config(d):
            cfg.set("toolbelt.extra", {
                "scan_tcp": ["not-a-dict", {"rank": 5}, {"name": ""}],
            })
            tb = self._tb({"nmap", "masscan", "nc"})
            # built-in catalog survives; the bad entries never crash or win
            self.assertEqual(tb.pick("scan_tcp").tool, "nmap")

    def test_status_includes_extra_capability(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d, _temp_config(d):
            cfg.set("toolbelt.extra", {
                "custom_scan": [{"name": "rustscan", "rank": 5}],
            })
            tb = self._tb({"rustscan"})
            self.assertIn("custom_scan", tb.status())


if __name__ == "__main__":
    unittest.main()
