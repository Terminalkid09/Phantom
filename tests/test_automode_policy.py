"""Tests: auto-mode range/scope policy (extracted to automode_policy).

Pins the policy that `auto` used to inline: how raw tokens become targets,
what a network range authorizes (discovery, never an assault), and the
callback/scope preflights. A range is not intent.
"""
import unittest
from unittest.mock import Mock, patch

from phantom.core import automode_policy as pol


class TestExtractNetworks(unittest.TestCase):
    def test_only_valid_cidr_tokens(self):
        self.assertEqual(pol.extract_networks(["10.0.0.0/24"]),
                         ["10.0.0.0/24"])
        self.assertEqual(pol.extract_networks(["10.0.0.0/24,192.168.1.0/30"]),
                         ["10.0.0.0/24", "192.168.1.0/30"])

    def test_plain_and_invalid_tokens_are_not_networks(self):
        self.assertEqual(pol.extract_networks(["10.0.0.5", "example.com"]),
                         [])
        self.assertEqual(pol.extract_networks(["https://example.com/a/b"]),
                         [])
        self.assertEqual(pol.extract_networks(["10.0.0.0/not-a-mask"]), [])

    def test_empty_input(self):
        self.assertEqual(pol.extract_networks([]), [])
        self.assertEqual(pol.extract_networks(None), [])


class TestExpandTargets(unittest.TestCase):
    def test_dedupe_and_comma_split(self):
        self.assertEqual(pol.expand_targets(["1.2.3.4,1.2.3.4", "5.6.7.8"]),
                         ["1.2.3.4", "5.6.7.8"])

    def test_slash_30_gives_two_usable_hosts(self):
        self.assertEqual(pol.expand_targets(["10.0.0.0/30"]),
                         ["10.0.0.1", "10.0.0.2"])

    def test_url_with_slash_is_not_a_cidr(self):
        self.assertEqual(pol.expand_targets(["https://example.com/a/b"]),
                         ["https://example.com/a/b"])

    def test_expansion_is_capped_and_says_so(self):
        with patch.object(pol.notifier, "warn") as m_warn:
            out = pol.expand_targets(["10.0.0.0/23"])  # 510 usable hosts
        self.assertEqual(len(out), pol.MAX_CIDR_HOSTS)
        self.assertTrue(any("limitata" in str(c.args[0])
                            for c in m_warn.call_args_list))

    def test_out_of_scope_network_target_is_dropped_with_a_warning(self):
        with patch.object(pol.notifier, "warn") as m_warn:
            out = pol.expand_targets(["8.8.8.8"], scope_list=["10.0.0.0/24"])
        self.assertEqual(out, [])
        m_warn.assert_called_once()
        self.assertIn("fuori scope", m_warn.call_args.args[0])

    def test_identity_targets_bypass_the_machine_scope(self):
        # the engagement SUBJECT is never filtered by the machine scope list
        out = pol.expand_targets(["mario.rossi@gmail.com"],
                                 scope_list=["10.0.0.0/24"])
        self.assertEqual(out, ["mario.rossi@gmail.com"])


class TestRangePolicyVerdict(unittest.TestCase):
    def test_range_without_force_is_discovery_only(self):
        self.assertEqual(
            pol.range_policy_verdict(["10.0.0.0/24"], ["10.0.0.1", "x"],
                                     ["10.0.0.0/24"], False, False),
            "discovery_only")

    def test_force_network_engages(self):
        self.assertEqual(
            pol.range_policy_verdict(["10.0.0.0/24"], ["10.0.0.1"],
                                     ["10.0.0.0/24"], True, False),
            "engage")

    def test_dry_run_always_engages_nothing_but_passes(self):
        self.assertEqual(
            pol.range_policy_verdict(["10.0.0.0/24"], ["10.0.0.1"],
                                     ["10.0.0.0/24"], False, True),
            "engage")

    def test_no_network_token_is_not_a_range(self):
        self.assertEqual(
            pol.range_policy_verdict([], ["10.0.0.5"], ["10.0.0.5"],
                                     False, False),
            "engage")


class TestApplyRangePolicy(unittest.TestCase):
    def test_discovery_only_announces_and_stops(self):
        with patch.object(pol.notifier, "info") as m_info, \
                patch.object(pol.notifier, "warn") as m_warn:
            go = pol.apply_range_policy(["10.0.0.0/24"],
                                        ["10.0.0.1", "10.0.0.2"],
                                        ["10.0.0.0/24"], False, False)
        self.assertFalse(go)
        texts = [str(c.args[0]) for c in m_info.call_args_list]
        self.assertTrue(any("discovery-only" in t for t in texts))
        self.assertTrue(any("--force-network" in t for t in texts))
        m_warn.assert_not_called()

    def test_force_network_warns_and_engages(self):
        with patch.object(pol.notifier, "info") as m_info, \
                patch.object(pol.notifier, "warn") as m_warn:
            go = pol.apply_range_policy(["10.0.0.0/24"], ["10.0.0.1"],
                                        ["10.0.0.0/24"], True, False)
        self.assertTrue(go)
        self.assertTrue(any("FORCE-NETWORK" in str(c.args[0])
                            for c in m_warn.call_args_list))
        self.assertFalse(any("discovery-only" in str(c.args[0])
                             for c in m_info.call_args_list))


class TestTriageTargets(unittest.TestCase):
    def test_discovered_hosts_replace_the_expansion(self):
        tri = {"ranked": [{"ip": "10.0.0.9"}, {"ip": "10.0.0.5"}],
               "hosts": [{}, {}]}
        with patch("phantom.core.netmap.triage_networks",
                   return_value=tri), \
                patch.object(pol.notifier, "info"), \
                patch.object(pol.notifier, "success"):
            out = pol.triage_targets(
                ["10.0.0.0/24", "keepme.example.com"], ["10.0.0.0/24"],
                ["10.0.0.1", "10.0.0.2"])
        # explicit operator tokens first, then ranked discovered hosts
        self.assertEqual(out, ["keepme.example.com", "10.0.0.9", "10.0.0.5"])

    def test_no_network_token_skips_discovery(self):
        out = pol.triage_targets(["10.0.0.5"], [], ["10.0.0.5"])
        self.assertEqual(out, ["10.0.0.5"])

    def test_empty_discovery_keeps_the_expansion(self):
        with patch("phantom.core.netmap.triage_networks",
                   return_value={"ranked": [], "hosts": []}), \
                patch.object(pol.notifier, "info"), \
                patch.object(pol.notifier, "warn") as m_warn:
            out = pol.triage_targets(["10.0.0.0/24"], ["10.0.0.0/24"],
                                     ["10.0.0.1"])
        self.assertEqual(out, ["10.0.0.1"])
        m_warn.assert_called_once()


class TestScopeAndCallbackPreflight(unittest.TestCase):
    def test_network_targets_without_scope_warn(self):
        with patch.object(pol.notifier, "warn") as m_warn:
            pol.warn_missing_scope(["10.0.0.5"])
        m_warn.assert_called_once()
        self.assertIn("no scope declared", m_warn.call_args.args[0])
        # the remedy names a command that EXISTS in the shell that shows it
        self.assertIn("scope add <cidr>", m_warn.call_args.args[0])

    def test_identity_targets_alone_need_no_scope(self):
        with patch.object(pol.notifier, "warn") as m_warn:
            pol.warn_missing_scope(["mario.rossi@gmail.com"])
        m_warn.assert_not_called()

class TestScopePreflightRefusesBeforeTheRun(unittest.TestCase):
    """A-6, the FAILURE half.

    The warning told the operator a network run without a scope would be
    refused, but nothing refused it: the listener started, the session dir
    and the checkpoint were written, and the run ended on a late "out of
    scope" that read like the goal had simply failed. The preflight is the
    counterpart of `callback_preflight` — knowable now, so refused now.
    """

    @staticmethod
    def _optout(allowed):
        return patch("phantom.core.scope.unscoped_allowed",
                     return_value=allowed)

    def test_network_targets_without_scope_are_refused(self):
        with self._optout(False):
            v = pol.scope_preflight(["10.0.0.5"], scope_list=[])
        self.assertFalse(v.ok)
        self.assertIn("no engagement scope", v.message)
        self.assertEqual(v.network_targets, ("10.0.0.5",))

    def test_the_refusal_names_a_command_that_exists_in_the_shell(self):
        with self._optout(False):
            v = pol.scope_preflight(["10.0.0.5"], scope_list=[])
        self.assertIn("scope add <cidr>", v.hint)
        self.assertIn("PHANTOM_ALLOW_UNSCOPED=1", v.hint)

    def test_a_declared_scope_passes(self):
        with self._optout(False):
            v = pol.scope_preflight(["10.0.0.5"], scope_list=["10.0.0.0/24"])
        self.assertTrue(v.ok)

    def test_the_documented_optout_passes(self):
        with self._optout(True):
            v = pol.scope_preflight(["10.0.0.5"], scope_list=[])
        self.assertTrue(v.ok)

    def test_identity_targets_need_no_scope_at_all(self):
        with self._optout(False):
            v = pol.scope_preflight(["mario.rossi@gmail.com"], scope_list=[])
        self.assertTrue(v.ok)

    def test_a_broken_optout_check_never_blocks_the_run(self):
        """This check exists to SAVE an engagement, never to become a new
        way for a launch to fail."""
        with patch("phantom.core.scope.unscoped_allowed",
                   side_effect=RuntimeError("boom")):
            v = pol.scope_preflight(["10.0.0.5"], scope_list=[])
        self.assertTrue(v.ok)

    def test_run_auto_mode_returns_blocked_preflight(self):
        """End to end: the orchestrator reports the documented outcome
        instead of "finished without reaching the goal"."""
        from phantom.core import automode
        with self._optout(False), \
                patch.object(automode, "_callback_preflight"), \
                patch.object(automode, "_ensure_c2_listener") as m_listener:
            out = automode.run_auto_mode(targets=["10.0.0.5"],
                                         goal="deliver",
                                         on_event=lambda *a, **k: None)
        m_listener.assert_not_called()
        self.assertIsInstance(out, dict)
        self.assertEqual(out.get("outcome"), "blocked_preflight")
        self.assertFalse(out.get("goal_reached"))

    def test_non_beacon_goals_are_never_preflighted(self):
        rec = Mock()
        pol.callback_preflight(["8.8.8.8"], "recon", notifier=rec)
        self.assertEqual(rec.method_calls, [])

    def test_beacon_goal_names_an_implausible_callback(self):
        rec = Mock()
        with patch("phantom.utils.network.callback_plausibility",
                   return_value=(False, "loopback advertised")), \
                patch("phantom.utils.network.get_c2_endpoint",
                      return_value=("127.0.0.1", 443)):
            pol.callback_preflight(["8.8.8.8"], "beacon", notifier=rec)
        rec.warn.assert_called_once()
        self.assertIn("8.8.8.8", rec.warn.call_args.args[0])

    def test_all_targets_implausible_is_an_error(self):
        rec = Mock()
        with patch("phantom.utils.network.callback_plausibility",
                   return_value=(False, "no route")), \
                patch("phantom.utils.network.get_c2_endpoint",
                      return_value=("127.0.0.1", 443)):
            pol.callback_preflight(["8.8.8.8"], "deliver", notifier=rec)
        rec.error.assert_called_once()


if __name__ == "__main__":
    unittest.main()
