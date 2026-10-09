"""Tests: the settings nucleus (phantom/utils/settings.py).

Pins what the five-plane configuration must give: a DECLARED schema
(name, type, default, allowed sources), explicit per-setting resolution
order with the winning plane visible, and the api-token divergence policy
expressed as ORDER instead of the state._env special case.
"""
import unittest

from phantom.utils import settings as S


def _readers(**by_plane):
    """Injected plane readers: a plane absent from the dict is silent."""
    return {plane: (lambda s, v=v: v) for plane, v in by_plane.items()}


class TestSchema(unittest.TestCase):
    def test_every_setting_is_well_formed(self):
        for s in S.SETTINGS.values():
            with self.subTest(setting=s.name):
                self.assertIn(s.kind, S._KINDS)
                self.assertTrue(s.sources)
                for plane in s.sources:
                    self.assertIn(plane, S.PLANES)
                    if plane in ("env", "config", "state"):
                        self.assertTrue(s.key_for(plane))

    def test_no_duplicate_names(self):
        names = [s.name for s in S.SETTINGS.values()]
        self.assertEqual(len(names), len(set(names)))

    def test_unknown_setting_raises(self):
        with self.assertRaises(KeyError):
            S.resolve("no.such.setting")
        with self.assertRaises(KeyError):
            S.get("no.such.setting")


class TestResolutionOrder(unittest.TestCase):
    def test_param_beats_everything(self):
        value, source = S.resolve("automation.experience",
                                  param=False, cli=True,
                                  readers=_readers(env="1", config=True,
                                                   state=True))
        self.assertIs(value, False)
        self.assertEqual(source, "param")

    def test_cli_beats_env(self):
        value, source = S.resolve("automation.experience", cli=False,
                                  readers=_readers(env="1", config=True))
        self.assertIs(value, False)
        self.assertEqual(source, "cli")

    def test_env_beats_config(self):
        value, source = S.resolve("automation.experience",
                                  readers=_readers(env="0", config=True))
        self.assertIs(value, False)
        self.assertEqual(source, "env")

    def test_config_beats_default(self):
        value, source = S.resolve("automation.experience",
                                  readers=_readers(config=False))
        self.assertIs(value, False)
        self.assertEqual(source, "config")

    def test_default_when_every_plane_is_silent(self):
        value, source = S.resolve("automation.experience",
                                  readers=_readers())
        self.assertIs(value, True)      # the declared default
        self.assertEqual(source, "default")

    def test_an_empty_string_is_not_a_hit(self):
        value, source = S.resolve("c2.transport_backend",
                                  readers=_readers(env="  ", config="go"))
        self.assertEqual(value, "go")
        self.assertEqual(source, "config")


class TestApiTokenDivergencePolicy(unittest.TestCase):
    """state first = the policy that state._env hacked in by hand."""

    def test_state_wins_over_a_divergent_env_copy(self):
        value, source = S.resolve("c2.api_token",
                                  readers=_readers(state="persisted-token",
                                                   env="stale-token"))
        self.assertEqual(value, "persisted-token")
        self.assertEqual(source, "state")

    def test_env_fills_in_when_state_is_empty(self):
        value, source = S.resolve("c2.api_token",
                                  readers=_readers(state=None,
                                                   env="fresh-token"))
        self.assertEqual(value, "fresh-token")
        self.assertEqual(source, "env")

    def test_other_secrets_keep_env_first(self):
        value, source = S.resolve("c2.key",
                                  readers=_readers(env="env-key",
                                                   state="state-key"))
        self.assertEqual(value, "env-key")
        self.assertEqual(source, "env")


class TestCoercion(unittest.TestCase):
    def test_bool_strings(self):
        for falsy in ("0", "false", "no", "off", "n", "OFF", " False "):
            with self.subTest(raw=falsy):
                value, _ = S.resolve("beacon.auth_required",
                                     readers=_readers(env=falsy))
                self.assertIs(value, False)
        for truthy in ("1", "true", "yes", "on"):
            with self.subTest(raw=truthy):
                value, _ = S.resolve("beacon.auth_required",
                                     readers=_readers(env=truthy))
                self.assertIs(value, True)

    def test_state_bool_is_not_stringified(self):
        value, _ = S.resolve("beacon.auth_required",
                             readers=_readers(state=False))
        self.assertIs(value, False)

    def test_int_and_str(self):
        value, _ = S.resolve("c2.transport_backend",
                             readers=_readers(env=123))
        self.assertEqual(value, "123")   # str kind stringifies


class TestDescribe(unittest.TestCase):
    def test_secrets_never_leak_values(self):
        rows = S.describe()
        self.assertTrue(rows)
        for row in rows:
            with self.subTest(setting=row["name"]):
                self.assertIn(row["kind"], S._KINDS)
                self.assertIn("sources", row)
                if row["kind"] == "secret":
                    self.assertIn(row["default"], ("", "<empty>"))


class TestRealPlanesSmoke(unittest.TestCase):
    def test_resolves_against_the_real_planes(self):
        # no injection: the adapters read env/config/state for real and
        # must never raise on a declared setting
        for name in S.SETTINGS:
            with self.subTest(setting=name):
                value, source = S.resolve(name)
                self.assertIn(source, tuple(S.PLANES) + ("default",))


if __name__ == "__main__":
    unittest.main()
