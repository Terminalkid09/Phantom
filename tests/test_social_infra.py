"""Tests for the lure infrastructure preflight (social/infra.py).

The failures it catches are the SILENT ones: a lure link on a LAN address, a
relay whose session cookie is dropped because the page is plain HTTP, a port
nobody is listening on. None of them raise at the moment they happen, and all
of them look like "nobody was interested".

No test here touches the network: DNS is either skipped (`resolve=False`) or
monkeypatched, and config is stubbed so no file is read.
"""
import unittest
from unittest import mock

from phantom.automation.social import infra


class _Base(unittest.TestCase):
    """Deterministic config: nothing is read from disk or the environment."""

    def setUp(self):
        self._cfg = mock.patch.object(infra, "_config_value", return_value="")
        self._cfg.start()
        self.addCleanup(self._cfg.stop)
        self._flag = mock.patch.object(infra, "_config_flag",
                                       return_value=False)
        self._flag.start()
        self.addCleanup(self._flag.stop)


class TestTheReport(_Base):
    def test_ok_is_true_when_only_warnings(self):
        rep = infra.infra_preflight(public_url="http://lure.example",
                                    redirect="https://acme.example/landing",
                                    brand="Acme", aitm=False, resolve=False)
        self.assertTrue(rep.ok)
        self.assertEqual(rep.codes(infra.BLOCKER), [])
        self.assertIn("public_url_not_https", rep.codes(infra.WARNING))

    def test_ok_is_false_when_blocked(self):
        rep = infra.infra_preflight(public_url="", aitm=False, resolve=False)
        self.assertFalse(rep.ok)
        self.assertEqual(rep.codes(infra.BLOCKER), ["public_url_missing"])

    def test_a_fully_configured_infrastructure_has_no_checks(self):
        rep = infra.infra_preflight(public_url="https://lure.example",
                                    redirect="https://acme.example/landing",
                                    brand="Acme", skin="tiktok", aitm=False,
                                    resolve=False)
        self.assertTrue(rep.ok)
        self.assertEqual(rep.checks, [])

    def test_render_is_one_line_and_named(self):
        rep = infra.infra_preflight(public_url="", resolve=False)
        line = rep.render()
        self.assertIn("INFRA:", line)
        self.assertIn("ok=", line)
        self.assertIn("blockers=", line)
        self.assertIn("public_url_missing", line)

    def test_lines_put_the_blockers_first(self):
        rep = infra.infra_preflight(public_url="http://203.0.113.9",
                                    aitm=True, resolve=False)
        severities = [line.split("]")[0].lstrip(" [") for line in rep.lines()[1:]]
        self.assertEqual(severities[0], infra.BLOCKER)
        self.assertIn(infra.WARNING, severities)

    def test_top_remedy_names_the_worst_problem(self):
        rep = infra.infra_preflight(public_url="", resolve=False)
        self.assertIn("public_url_missing", rep.top_remedy())


class TestReachability(_Base):
    def test_a_missing_public_url_is_a_blocker(self):
        rep = infra.infra_preflight(public_url="", resolve=False)
        self.assertIn("public_url_missing", rep.codes(infra.BLOCKER))

    def test_plain_http_is_a_warning_without_aitm(self):
        rep = infra.infra_preflight(public_url="http://lure.example",
                                    aitm=False, resolve=False)
        self.assertIn("public_url_not_https", rep.codes(infra.WARNING))
        self.assertEqual(rep.codes(infra.BLOCKER), [])

    def test_plain_http_is_a_blocker_with_aitm(self):
        """A Secure/SameSite=None cookie is dropped on plain HTTP, so the
        relay breaks AFTER the credentials are typed."""
        rep = infra.infra_preflight(public_url="http://lure.example",
                                    aitm=True, resolve=False)
        self.assertIn("public_url_not_https", rep.codes(infra.BLOCKER))
        self.assertFalse(rep.ok)

    def test_a_bare_ip_public_host_is_flagged(self):
        rep = infra.infra_preflight(public_url="https://203.0.113.9",
                                    aitm=False, resolve=False)
        self.assertIn("public_url_is_ip", rep.codes(infra.WARNING))

    def test_an_unresolvable_host_is_a_warning_not_a_blocker(self):
        with mock.patch.object(infra, "_resolves", return_value=False):
            rep = infra.infra_preflight(public_url="https://lure.example")
        self.assertIn("public_url_unresolvable", rep.codes(infra.WARNING))
        self.assertTrue(rep.ok)

    def test_an_inconclusive_lookup_says_nothing(self):
        """A resolver we could not reach says nothing about the name."""
        with mock.patch.object(infra, "_resolves", return_value=None):
            rep = infra.infra_preflight(public_url="https://lure.example")
        self.assertNotIn("public_url_unresolvable", rep.codes())

    def test_resolve_false_skips_the_lookup_entirely(self):
        with mock.patch.object(infra, "_resolves") as lookup:
            infra.infra_preflight(public_url="https://lure.example",
                                  resolve=False)
        lookup.assert_not_called()

    def test_a_broken_lookup_never_raises(self):
        with mock.patch.object(infra, "_resolves",
                               side_effect=RuntimeError("resolver gone")):
            rep = infra.infra_preflight(public_url="https://lure.example")
        self.assertTrue(rep.ok)

    def test_the_lookup_itself_never_raises(self):
        """`_resolves` swallows everything: a DNS failure is not an error the
        operator's engagement should die on."""
        self.assertIn(infra._resolves(""), (None,))
        self.assertIsNone(infra._resolves(""))


class TestPresentation(_Base):
    def test_the_default_redirect_is_flagged(self):
        rep = infra.infra_preflight(public_url="https://lure.example",
                                    redirect="https://example.com",
                                    brand="Acme", resolve=False)
        self.assertIn("redirect_default", rep.codes(infra.WARNING))

    def test_a_real_redirect_is_not_flagged(self):
        rep = infra.infra_preflight(public_url="https://lure.example",
                                    redirect="https://acme.example/landing/",
                                    brand="Acme", resolve=False)
        self.assertNotIn("redirect_default", rep.codes())

    def test_the_default_brand_is_information(self):
        rep = infra.infra_preflight(public_url="https://lure.example",
                                    redirect="https://acme.example/landing",
                                    brand="Account verification",
                                    resolve=False)
        self.assertIn("brand_default", rep.codes(infra.INFO))
        self.assertTrue(rep.ok)

    def test_an_unknown_kit_says_which_one_renders(self):
        rep = infra.infra_preflight(public_url="https://lure.example",
                                    redirect="https://acme.example/l",
                                    brand="Acme", skin="youube",
                                    resolve=False)
        self.assertIn("kit_unknown", rep.codes(infra.WARNING))
        detail = [c.detail for c in rep.checks if c.code == "kit_unknown"][0]
        self.assertIn("youube", detail)
        self.assertIn("youtube", detail)     # the kit actually rendered

    def test_a_known_kit_is_not_flagged(self):
        rep = infra.infra_preflight(public_url="https://lure.example",
                                    redirect="https://acme.example/l",
                                    brand="Acme", skin="instagram",
                                    resolve=False)
        self.assertNotIn("kit_unknown", rep.codes())


class TestLiability(_Base):
    def test_aitm_on_an_ip_is_a_blocker(self):
        rep = infra.infra_preflight(public_url="https://203.0.113.9",
                                    aitm=True, resolve=False)
        self.assertIn("aitm_without_domain", rep.codes(infra.BLOCKER))

    def test_aitm_with_no_public_url_is_a_blocker(self):
        rep = infra.infra_preflight(public_url="", aitm=True, resolve=False)
        self.assertIn("aitm_without_domain", rep.codes(infra.BLOCKER))

    def test_aitm_on_a_domain_is_allowed_but_announced(self):
        rep = infra.infra_preflight(public_url="https://lure.example",
                                    redirect="https://acme.example/l",
                                    brand="Acme", aitm=True, resolve=False)
        self.assertNotIn("aitm_without_domain", rep.codes())
        self.assertIn("aitm_enabled", rep.codes(infra.INFO))
        self.assertTrue(rep.ok)

    def test_aitm_off_says_nothing_about_liability(self):
        rep = infra.infra_preflight(public_url="https://lure.example",
                                    aitm=False, resolve=False)
        self.assertNotIn("aitm_enabled", rep.codes())


class TestTransport(_Base):
    def test_an_unbindable_port_is_a_blocker(self):
        with mock.patch("phantom.automation.social.tracker._port_available",
                        return_value=False):
            rep = infra.infra_preflight(public_url="https://lure.example",
                                        port=8080, resolve=False)
        self.assertIn("port_unavailable", rep.codes(infra.BLOCKER))

    def test_a_free_port_is_not_flagged(self):
        with mock.patch("phantom.automation.social.tracker._port_available",
                        return_value=True):
            rep = infra.infra_preflight(public_url="https://lure.example",
                                        port=8080, resolve=False)
        self.assertNotIn("port_unavailable", rep.codes())

    def test_the_probe_is_best_effort(self):
        """An unavailable probe says nothing — never an exception."""
        with mock.patch("phantom.automation.social.tracker._port_available",
                        side_effect=OSError("no probe")):
            rep = infra.infra_preflight(public_url="https://lure.example",
                                        port=8080, resolve=False)
        self.assertNotIn("port_unavailable", rep.codes())


class TestConfigIsTheFallback(_Base):
    def test_an_omitted_argument_is_read_from_config(self):
        values = {"tracker.public_url": "https://lure.example"}

        def _value(key, _env, default=""):
            return values.get(key, default or "")

        with mock.patch.object(infra, "_config_value", side_effect=_value):
            rep = infra.infra_preflight(aitm=False, resolve=False)
        self.assertNotIn("public_url_missing", rep.codes())

    def test_an_explicit_argument_wins_over_config(self):
        with mock.patch.object(infra, "_config_value",
                               return_value="https://from-config.example"):
            rep = infra.infra_preflight(public_url="",
                                        resolve=False)
        # the empty argument falls through to config, which is the point;
        # an explicitly passed value is used as-is
        self.assertNotIn("public_url_missing", rep.codes())
        rep2 = infra.infra_preflight(public_url="https://passed.example",
                                     aitm=False, resolve=False)
        self.assertNotIn("public_url_missing", rep2.codes())


if __name__ == "__main__":
    unittest.main()
