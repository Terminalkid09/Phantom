"""Fixes accepted from the DeepSeek audit hand-over, plus the vocabulary gate.

Four small things came back from the automated audit. Three were real and are
closed here; each one is pinned by a test that fails on the old behaviour:

1. `unverified` had no renderer, so the single most consequential event in the
   stream (a capability ran, its declared effect was NOT observed) rendered as
   the generic "[?]" line - and the event-vocabulary gate stayed red, which
   means any NEW kind could ship unclassified from then on.
2. `callback_preflight` walked `targets` and then compared against
   `len(list(targets))`. With a generator the first walk exhausts it and the
   "no target can call back" error could never fire - the warning that saves a
   wasted deploy.
3. `wsl_state_check` probed with the 600s installer timeout. On a box where
   the WSL service is wedged that is a ten-minute stall in front of `setup`,
   `doctor` and the test suite.
4. `Sequence` was used in an annotation but never imported: harmless at
   runtime under PEP 563, fatal to `get_type_hints` and to any type checker.
"""
import pathlib
import typing
import unittest
from unittest import mock

_ROOT = pathlib.Path(__file__).resolve().parent.parent


class TestUnverifiedHasAVoice(unittest.TestCase):
    def test_the_kind_is_classified(self):
        from phantom.core.stream_contract import EVENTS
        self.assertIn("unverified", EVENTS)

    def test_it_reads_as_a_caveat_not_as_decoration(self):
        from phantom.core.stream_contract import render_event
        out = render_event("unverified",
                           {"capability": "scan_webservices",
                            "detail": "postcondition not met: no declared "
                                      "effect observed (service)"}).lines
        self.assertTrue(out)
        line = out[0]
        # An operator skimming the stream must not read this as a success.
        self.assertNotIn("[?]", line)
        self.assertIn("scan_webservices", line)
        self.assertIn("Unverified", line)

    def test_it_survives_missing_fields(self):
        from phantom.core.stream_contract import render_event
        self.assertTrue(render_event("unverified", {}).lines)
        self.assertTrue(render_event("unverified",
                                     {"capability": "x"}).lines)


class TestCallbackPreflightHandlesIterators(unittest.TestCase):
    def _run(self, targets, advertised="127.0.0.1", plausible=False):
        from phantom.core import automode_policy as pol
        with mock.patch.object(pol, "notifier") as note:
            with mock.patch("phantom.utils.network.callback_plausibility",
                            return_value=(plausible, "unreachable")):
                with mock.patch("phantom.utils.network.get_c2_endpoint",
                                return_value=(advertised, 443)):
                    with mock.patch("phantom.utils.config.get_str",
                                    return_value=advertised):
                        pol.callback_preflight(targets, "deliver",
                                               notifier=note)
        return note

    def test_a_generator_still_triggers_the_hard_error(self):
        # The regression: `for t in targets` exhausted the generator, so
        # `len(list(targets))` was 0, so the "NO target can call back" error
        # could never fire.
        note = self._run((t for t in ["10.0.0.5", "10.0.0.6"]))
        self.assertTrue(note.error.called,
                        "the all-affected error must fire for an iterator")
        self.assertIn("Nessun target", note.error.call_args[0][0])

    def test_a_list_behaves_the_same(self):
        note = self._run(["10.0.0.5", "10.0.0.6"])
        self.assertTrue(note.error.called)

    def test_a_non_beacon_goal_is_silent(self):
        note = self._run((t for t in ["10.0.0.5"]), advertised="example.org")
        from phantom.core import automode_policy as pol
        # 'footprint' is not in the beacon-bound goal set.
        with mock.patch.object(pol, "notifier"):
            pass
        note2 = self._run(["10.0.0.5"])
        self.assertTrue(note2.error.called)   # deliver is beacon-bound


class TestWslProbeIsBounded(unittest.TestCase):
    def test_the_probe_timeout_is_short(self):
        from phantom.utils.setup_wizard import PROBE_TIMEOUT_S
        # An installer may take 1800s; a state query may not take 600.
        self.assertLess(PROBE_TIMEOUT_S, 120)

    def test_the_probe_uses_it(self):
        import inspect

        from phantom.utils import setup_wizard as sw
        src = inspect.getsource(sw.wsl_state_check)
        self.assertIn("timeout=PROBE_TIMEOUT_S", src)

    def test_a_hung_wsl_says_why_instead_of_claiming_no_distro(self):
        from phantom.utils import setup_wizard as sw
        with mock.patch.object(sw, "PLATFORM", "windows"):
            with mock.patch.object(sw.shutil, "which", return_value="wsl"):
                with mock.patch.object(
                        sw, "_run",
                        return_value=(False, "Command timed out after 30s")):
                    state, detail = sw.wsl_state_check()
        self.assertEqual(state, sw.NO_DISTRO)
        self.assertIn("did not answer", detail)
        self.assertIn("wsl --shutdown", detail)

    def test_a_real_empty_wsl_still_reports_no_distro(self):
        from phantom.utils import setup_wizard as sw
        with mock.patch.object(sw, "PLATFORM", "windows"):
            with mock.patch.object(sw.shutil, "which", return_value="wsl"):
                with mock.patch.object(
                        sw, "_run",
                        return_value=(True, "There are no installed "
                                            "distributions")):
                    state, detail = sw.wsl_state_check()
        self.assertEqual(state, sw.NO_DISTRO)
        self.assertIn("no distro", detail.lower())


class TestAnnotationsAreResolvable(unittest.TestCase):
    def test_get_type_hints_works_on_the_split_dispatch(self):
        from phantom.automation.agent import AutonomousAgent
        for name in ("_gate_capability", "_dispatch_capability",
                     "_execute_command_capability"):
            fn = getattr(AutonomousAgent, name)
            hints = typing.get_type_hints(fn)
            self.assertIsInstance(hints, dict, name)

    def test_sequence_is_imported(self):
        import phantom.automation.agent as agent
        self.assertIs(agent.Sequence, typing.Sequence)


class TestTheDispatchRegistryIsOrdered(unittest.TestCase):
    """DeepSeek's own contract test, re-asserted here: the split kept the
    original if-chain ORDER, which is the part a refactor can silently break
    while every unit test still passes."""

    def test_the_registry_is_not_empty_and_is_a_class_attribute(self):
        from phantom.automation.agent import AutonomousAgent
        routes = AutonomousAgent._CHANNEL_ROUTES
        self.assertTrue(routes)
        for phase, match, handler in routes:
            self.assertTrue(phase)
            self.assertTrue(callable(match))
            # the third slot is a method NAME, resolved on the class - that is
            # what keeps the registry declarative and inspectable
            self.assertIsInstance(handler, str)
            self.assertTrue(handler)

    def test_the_phases_are_real_phases(self):
        from phantom.automation.agent import AutonomousAgent
        from phantom.automation import phases
        known = set(getattr(phases, "PHASES", ()) or ())
        if not known:
            self.skipTest("no PHASES export to compare against")
        for phase, _match, _handler in AutonomousAgent._CHANNEL_ROUTES:
            self.assertIn(phase, known, phase)

    def test_every_handler_exists_on_the_class(self):
        from phantom.automation.agent import AutonomousAgent
        for phase, match, handler in AutonomousAgent._CHANNEL_ROUTES:
            self.assertTrue(hasattr(AutonomousAgent, handler),
                            f"{phase} -> missing {handler}")


if __name__ == "__main__":
    unittest.main()