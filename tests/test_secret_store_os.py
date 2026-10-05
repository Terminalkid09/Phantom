"""Optional OS-keychain backend for API keys (Fase 3 secret store).

Pins the two properties that make the feature safe: the OS vault is used
ONLY when explicitly enabled AND a usable backend exists, and every path
degrades to the hardened config file otherwise (no crash, no lost key).
"""
import os
import tempfile
import unittest
from contextlib import contextmanager

from phantom.utils import api_keys
from phantom.utils import config as cfg
from phantom.utils import secret_store


class FakeVault:
    """A dict-backed stand-in for the `keyring` module."""

    def __init__(self):
        self.data = {}

    def get_password(self, service, account):
        return self.data.get((service, account))

    def set_password(self, service, account, value):
        self.data[(service, account)] = value

    def delete_password(self, service, account):
        self.data.pop((service, account), None)


class BrokenVault:
    """A backend that is present but cannot persist anything."""

    def get_password(self, service, account):
        return None

    def set_password(self, service, account, value):
        raise OSError("vault locked")

    def delete_password(self, service, account):
        raise OSError("vault locked")


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
    path = os.path.join(tmpdir, "config.json")
    saved_path, saved_loaded = cfg._CONFIG_PATH, cfg._loaded
    cfg._CONFIG_PATH = path
    cfg._loaded = None
    try:
        yield
    finally:
        cfg._CONFIG_PATH, cfg._loaded = saved_path, saved_loaded


@contextmanager
def _backend(backend):
    saved = secret_store._backend, secret_store._backend_resolved
    secret_store.set_backend(backend)
    try:
        yield
    finally:
        secret_store._backend, secret_store._backend_resolved = saved


class TestKeystoreBackend(unittest.TestCase):
    def test_roundtrip_through_a_backend(self):
        vault = FakeVault()
        with _backend(vault):
            self.assertTrue(secret_store.os_keystore_available())
            self.assertIsNone(secret_store.os_get("shodan"))
            self.assertTrue(secret_store.os_set("shodan", "ABC"))
            self.assertEqual(secret_store.os_get("shodan"), "ABC")
            self.assertTrue(secret_store.os_delete("shodan"))
            self.assertIsNone(secret_store.os_get("shodan"))

    def test_broken_backend_never_raises(self):
        with _backend(BrokenVault()):
            self.assertFalse(secret_store.os_set("shodan", "ABC"))
            self.assertIsNone(secret_store.os_get("shodan"))
            self.assertFalse(secret_store.os_delete("shodan"))

    def test_empty_account_is_a_noop(self):
        with _backend(FakeVault()):
            self.assertIsNone(secret_store.os_get(""))
            self.assertFalse(secret_store.os_set("", "x"))
            self.assertFalse(secret_store.os_delete(""))

    def test_uses_the_stable_service_namespace(self):
        vault = FakeVault()
        with _backend(vault):
            secret_store.os_set("github", "tok")
        self.assertIn((secret_store.OS_SERVICE, "github"), vault.data)


class TestApiKeysOsStore(unittest.TestCase):
    def test_enabled_store_roundtrips_and_removes_plaintext(self):
        vault = FakeVault()
        with tempfile.TemporaryDirectory() as d, _temp_config(d), \
                _backend(vault), \
                _env(PHANTOM_OS_KEYSTORE="1", PHANTOM_SHODAN_KEY=None,
                     SHODAN_API_KEY=None):
            api_keys.set("shodan", "SECRETKEY")
            self.assertEqual(api_keys.get("shodan"), "SECRETKEY")
            self.assertEqual(api_keys.source("shodan"), "os")
            # the plaintext copy in the config file was cleared
            self.assertEqual(cfg.get("api_keys.shodan", ""), "")
            self.assertEqual(vault.data[(secret_store.OS_SERVICE, "shodan")],
                             "SECRETKEY")

    def test_status_reports_os_backend_and_masks(self):
        vault = FakeVault()
        with tempfile.TemporaryDirectory() as d, _temp_config(d), \
                _backend(vault), _env(PHANTOM_OS_KEYSTORE="1"):
            api_keys.set("github", "ghp_verysecretvalue0000")
            st = api_keys.status()["github"]
            self.assertTrue(st["configured"])
            self.assertEqual(st["source"], "os")
            self.assertEqual(st["backend"], "os")
            self.assertNotIn("verysecretvalue", st["masked"])

    def test_env_still_beats_the_os_store(self):
        vault = FakeVault()
        with tempfile.TemporaryDirectory() as d, _temp_config(d), \
                _backend(vault), \
                _env(PHANTOM_OS_KEYSTORE="1", PHANTOM_NVD_API_KEY="from-env"):
            api_keys.set("nvd", "from-store")
            self.assertEqual(api_keys.get("nvd"), "from-env")
            self.assertEqual(api_keys.source("nvd"), "env")

    def test_disabled_store_keeps_using_the_config_file(self):
        vault = FakeVault()
        with tempfile.TemporaryDirectory() as d, _temp_config(d), \
                _backend(vault), _env(PHANTOM_OS_KEYSTORE=None):
            api_keys.set("shodan", "abc")
            self.assertEqual(api_keys.get("shodan"), "abc")
            self.assertEqual(api_keys.source("shodan"), "config")
            self.assertFalse(vault.data)

    def test_broken_backend_falls_back_to_the_file(self):
        with tempfile.TemporaryDirectory() as d, _temp_config(d), \
                _backend(BrokenVault()), _env(PHANTOM_OS_KEYSTORE="1"):
            api_keys.set("shodan", "abc")
            self.assertEqual(api_keys.get("shodan"), "abc")
            self.assertEqual(api_keys.source("shodan"), "config")
            self.assertEqual(cfg.get("api_keys.shodan", ""), "abc")


class TestConfigSchema(unittest.TestCase):
    def test_os_store_is_declared(self):
        self.assertIn("secrets.os_store", cfg.SCHEMA)
        self.assertIn("secrets", cfg.DEFAULTS)


if __name__ == "__main__":
    unittest.main()
