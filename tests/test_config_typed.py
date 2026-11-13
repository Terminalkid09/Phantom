"""Tests for the typed config accessors and the declared SCHEMA.

These lock the ONE canonical way to read a setting: no more ad-hoc
`str(...) not in (...)` / `bool(...) in (...)` parsing scattered across
call sites, which parsed the same value differently depending on where it
was read (notably `c2.ssl=false` was read as True).
"""
import os
import unittest
from contextlib import contextmanager

from phantom.utils import config as cfg


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


class TestGetBool(unittest.TestCase):
    def test_truthy_strings(self):
        for token in ("1", "true", "TRUE", " yes ", "on"):
            with _env(PHANTOM_C2_SSL=token):
                self.assertTrue(
                    cfg.get_bool("c2.ssl", False, env="PHANTOM_C2_SSL"),
                    token)

    def test_falsy_strings(self):
        for token in ("0", "false", "False", "no", "off"):
            with _env(PHANTOM_C2_SSL=token):
                self.assertFalse(
                    cfg.get_bool("c2.ssl", True, env="PHANTOM_C2_SSL"),
                    token)

    def test_c2_ssl_false_is_actually_false(self):
        # regression: the old `bool(v) in (True,1,"1","true","True")` parsed
        # bool("false") == True, so disabling TLS silently kept it ON
        with _env(PHANTOM_C2_SSL="false"):
            self.assertFalse(cfg.get_bool("c2.ssl", True,
                                          env="PHANTOM_C2_SSL"))

    def test_blank_env_falls_back_to_default(self):
        with _env(PHANTOM_C2_SSL=""):
            self.assertTrue(cfg.get_bool("c2.ssl", True,
                                         env="PHANTOM_C2_SSL"))

    def test_unrecognized_falls_back_to_default(self):
        with _env(PHANTOM_C2_SSL="maybe"):
            self.assertTrue(cfg.get_bool("c2.ssl", True,
                                         env="PHANTOM_C2_SSL"))
            self.assertFalse(cfg.get_bool("c2.ssl", False,
                                          env="PHANTOM_C2_SSL"))


class TestGetInt(unittest.TestCase):
    def test_parses_int(self):
        with _env(PHANTOM_C2_PORT="9091"):
            self.assertEqual(cfg.get_int("c2.port", 8080,
                                         env="PHANTOM_C2_PORT"), 9091)

    def test_garbage_falls_back(self):
        with _env(PHANTOM_C2_PORT="not-a-port"):
            self.assertEqual(cfg.get_int("c2.port", 8080,
                                         env="PHANTOM_C2_PORT"), 8080)

    def test_absent_key_uses_default(self):
        with _env(PHANTOM_REMOTE_SESSION_TTL=None):
            self.assertEqual(
                cfg.get_int("c2.remote_session_ttl", 21600,
                            env="PHANTOM_REMOTE_SESSION_TTL"), 21600)


class TestGetStr(unittest.TestCase):
    def test_env_wins(self):
        with _env(PHANTOM_C2_HOST="10.9.9.9"):
            self.assertEqual(cfg.get_str("c2.host", "",
                                         env="PHANTOM_C2_HOST"), "10.9.9.9")


class TestSchema(unittest.TestCase):
    def test_every_entry_is_wellformed(self):
        # dict is allowed for structured settings (e.g. toolbelt.extra);
        # scalar settings remain str/int/bool/float
        for key, spec in cfg.SCHEMA.items():
            self.assertIn(spec["type"], (str, int, bool, float, dict), key)
            env = spec["env"]
            self.assertTrue(env is None or
                            (isinstance(env, str) and env.startswith("PHANTOM_")),
                            key)

    def test_env_names_are_unique(self):
        seen = {}
        for key, spec in cfg.SCHEMA.items():
            env = spec["env"]
            if not env:
                continue
            self.assertNotIn(env, seen,
                             f"{env} bound by both {seen.get(env)} and {key}")
            seen[env] = key

    def test_declared_keys_resolve_without_raising(self):
        for key, spec in cfg.SCHEMA.items():
            sentinel = {str: "", int: 0, bool: False, float: 0.0,
                        dict: {}}[spec["type"]]
            # must not raise and must return the declared kind (or default)
            value = cfg.get(key, sentinel)
            self.assertIn(type(value), (spec["type"], dict), key)


class TestMigratedCallSites(unittest.TestCase):
    def test_aitm_enabled_reads_env(self):
        from phantom.automation.social import aitm
        with _env(PHANTOM_AITM="on"):
            self.assertTrue(aitm.enabled())
        with _env(PHANTOM_AITM="0"):
            self.assertFalse(aitm.enabled())

    def test_unscoped_gate_reads_env(self):
        from phantom.api import backend
        # deterministic: without the explicit opt-in the gate is closed
        with _env(PHANTOM_ALLOW_UNSCOPED="0"):
            self.assertFalse(backend._unscoped_allowed())
        with _env(PHANTOM_ALLOW_UNSCOPED="1"):
            self.assertTrue(backend._unscoped_allowed())


if __name__ == "__main__":
    unittest.main()
