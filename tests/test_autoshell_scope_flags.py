"""Section E2 — the scope-changing controls the REPL could not reach.

``force_network`` and ``engine`` were accepted by ``run_auto_mode`` and by the
CLI, but ``AutoShell.flags`` did not contain them and ``do_flags`` refuses any
key it does not know, so from the REPL neither could be set. Worse,
``_announce_guardrails`` already read ``self.flags.get("force_network", False)``
— a guard that could never fire.

These pin the wiring AND the visible consequence: with the flag on, the
guardrail manifest the operator sees names the ``network_range`` override.
"""
import pathlib
import unittest
from unittest import mock

from phantom.core import auto_shell
from phantom.core.auto_shell import AutoShell
from phantom.utils import guardrails as gr


class _Recorder:
    def __init__(self):
        self.text = ""

    def print(self, *args, **_kw):
        for arg in args:
            self.text += str(arg) + "\n"
            for row in getattr(arg, "rows", ()):
                self.text += " ".join(str(c) for c in row) + "\n"


class TestTheFlagsAreReachable(unittest.TestCase):
    def test_they_exist_with_safe_defaults(self):
        shell = AutoShell()
        self.assertIn("force_network", shell.flags)
        self.assertIn("engine", shell.flags)
        self.assertFalse(shell.flags["force_network"])
        self.assertTrue(shell.flags["engine"])

    def test_flags_force_network_on_persists(self):
        shell = AutoShell()
        shell.do_flags("force_network on")
        self.assertTrue(shell.flags["force_network"])
        self.assertTrue(shell._run_kwargs()["force_network"])

    def test_flags_engine_accepts_the_known_engines(self):
        shell = AutoShell()
        for engine in ("agent", "swarm"):
            shell.do_flags(f"engine {engine}")
            self.assertEqual(shell.flags["engine"], engine)
            self.assertEqual(shell._run_kwargs()["engine"], engine)

    def test_an_unknown_engine_is_refused(self):
        shell = AutoShell()
        shell.do_flags("engine warp-drive")
        self.assertEqual(shell.flags["engine"], "agent")

    def test_run_kwargs_forwards_both(self):
        shell = AutoShell()
        shell.do_flags("force_network on")
        shell.do_flags("engine swarm")
        kwargs = shell._run_kwargs()
        self.assertIs(kwargs["force_network"], True)
        self.assertEqual(kwargs["engine"], "swarm")


class TestTheManifestShowsTheOverride(unittest.TestCase):
    def test_a_forced_range_is_an_override_in_the_manifest(self):
        manifest = gr.build(scope=["10.0.0.0/24"], targets=["10.0.0.5"],
                            force_network=True)
        keys = [g.key for g in manifest.overrides]
        self.assertIn("network_range", keys)
        self.assertIn("FULL RANGE ENGAGEMENT", gr.render(manifest))

    def test_the_launch_banner_carries_it(self):
        shell = AutoShell()
        shell.targets = ["10.0.0.5"]
        shell.do_flags("force_network on")
        recorder = _Recorder()
        original = auto_shell.console
        auto_shell.console = recorder
        try:
            with mock.patch.object(
                    gr, "snapshot_to_audit", return_value={"seq": 1}) as log:
                allowed = shell._announce_guardrails()
        finally:
            auto_shell.console = original
        self.assertTrue(allowed)
        self.assertIn("Network range policy", recorder.text)
        self.assertIn("FULL RANGE ENGAGEMENT", recorder.text)
        # and it is recorded, not just printed
        self.assertTrue(log.called)

    def test_without_the_flag_there_is_no_override(self):
        shell = AutoShell()
        shell.targets = ["10.0.0.5"]
        recorder = _Recorder()
        original = auto_shell.console
        auto_shell.console = recorder
        try:
            with mock.patch.object(gr, "snapshot_to_audit",
                                   return_value={"seq": 1}):
                shell._announce_guardrails()
        finally:
            auto_shell.console = original
        self.assertNotIn("FULL RANGE ENGAGEMENT", recorder.text)


class TestTheStrictModeDecision(unittest.TestCase):
    """Decision, pinned: strict mode does NOT refuse a forced range.

    ``Manifest.blocking_overrides()`` excludes ``network_range`` on purpose —
    it is a per-run flag typed deliberately for THIS run, not a stale env or
    config override carried in from a previous session, which is what strict
    mode exists to catch. Blocking it would make strict mode refuse the exact
    legitimate case (engaging a whole range) and leave no way forward except
    switching strict off wholesale. What must NOT happen is the override
    passing unseen: it is rendered in the banner and appended to the audit
    log (``snapshot_to_audit``), so an override is recorded either way.
    """

    @staticmethod
    def _cfg_bool(strict, unscoped):
        """A deterministic control-source stub: no dependence on the host's
        config.json or on an env var another test may have leaked."""
        def _inner(key, env):
            if key == "engagement.strict_guardrails":
                return strict, "config"
            if key == "engagement.allow_unscoped":
                return unscoped, "config"
            return False, "default"
        return _inner

    def _announce(self, strict, unscoped, force_network):
        shell = AutoShell()
        shell.targets = ["10.0.0.5"]
        if force_network:
            shell.do_flags("force_network on")
        recorder = _Recorder()
        original = auto_shell.console
        auto_shell.console = recorder
        try:
            with mock.patch.object(gr, "_cfg_bool",
                                   self._cfg_bool(strict, unscoped)), \
                 mock.patch.object(gr, "snapshot_to_audit",
                                   return_value={"seq": 1}) as log:
                allowed = shell._announce_guardrails()
        finally:
            auto_shell.console = original
        return allowed, recorder.text, log

    def test_strict_mode_does_not_block_a_forced_range(self):
        allowed, text, log = self._announce(strict=True, unscoped=False,
                                            force_network=True)
        self.assertTrue(allowed)
        # the per-run override is still announced and still logged
        self.assertIn("FULL RANGE ENGAGEMENT", text)
        self.assertTrue(log.called)

    def test_strict_mode_does_block_the_other_overrides(self):
        allowed, _text, log = self._announce(strict=True, unscoped=True,
                                             force_network=False)
        self.assertFalse(allowed)
        self.assertTrue(log.called)


class TestTheApiRecordsTheSameOverride(unittest.TestCase):
    """F2: the panel's `force_network` checkbox must leave a trace.

    The CLI announces the protection level at launch and appends it to the
    audit log. `/api/automode/run` did neither, so a scope-widening override
    sent from the UI could not be found in any record afterwards — the exact
    "override with no trace" this project must never allow.
    """

    def test_the_api_run_records_the_manifest(self):
        from phantom.api import server
        with mock.patch.object(gr, "snapshot_to_audit",
                               return_value={"seq": 1}) as log:
            payload = server._record_automode_guardrails(["10.0.0.5"], True)
        self.assertIn("network_range", payload["overrides"])
        self.assertTrue(log.called)
        self.assertEqual(log.call_args.kwargs.get("event"),
                         "guardrails_at_launch")

    def test_without_the_flag_there_is_no_network_override(self):
        from phantom.api import server
        with mock.patch.object(gr, "snapshot_to_audit",
                               return_value={"seq": 1}):
            payload = server._record_automode_guardrails(["10.0.0.5"], False)
        self.assertNotIn("network_range", payload["overrides"])

    def test_the_endpoint_actually_calls_it(self):
        from phantom.api import server
        src = pathlib.Path(server.__file__).read_text(encoding="utf-8")
        block = src[src.index("async def automode_run"):][:4000]
        self.assertIn("_record_automode_guardrails(", block)
        self.assertIn('"guardrails": guardrails', block)


if __name__ == "__main__":
    unittest.main()
