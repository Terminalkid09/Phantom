"""Guardrails: an override must never be invisible.

The scope gate, beacon HMAC, mTLS and API auth are all on by default and all
overridable — correct for lab work and for real engagements. The gap this
covers: `PHANTOM_ALLOW_UNSCOPED=1`, `--force-network` and an emptied
`PHANTOM_API_TOKEN` all change what an engagement may do, and afterwards the
report reads exactly like a run where nothing was touched. In a real
engagement that is not cosmetic: the operator cannot tell a flag they set last
week is still set, and the deliverable cannot demonstrate the declared limits
were respected.

So: the manifest must observe (never change) each control, must record WHICH
LAYER decided it, must survive into the report, and must be toggleable from
both the CLI and the UI without a switch that writes nowhere.

Hermetic by construction: config and the state/secrets file are redirected to
a temp dir and every ambient PHANTOM_* variable is cleared, so these tests can
neither read nor damage the operator's real configuration. That isolation is
itself part of the contract — a feature that can only be tested against live
state is a feature nobody will test.
"""
import contextlib
import os
import pathlib
import tempfile
import unittest
from unittest import mock

from phantom.utils import guardrails as gr

_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _isolated():
    """Point config + state at a temp dir and drop ambient PHANTOM_* vars.

    The environment is restored EXHAUSTIVELY on exit — cleared, then the
    original mapping put back — instead of merely merged. Merging only
    re-adds the vars that were dropped here, so a test that SETS one (a
    strict-mode test setting ``PHANTOM_STRICT_GUARDRAILS`` and not popping
    it) leaked strict mode into every later test in the same process: that
    is how ``tests/test_autoshell_scope_flags.py`` failed when it ran after
    this file and passed when it ran before it.
    """
    stack = contextlib.ExitStack()

    original_env = dict(os.environ)

    def _restore_env():
        os.environ.clear()
        os.environ.update(original_env)

    tmp = tempfile.TemporaryDirectory()
    stack.callback(tmp.cleanup)
    os.environ["PHANTOM_STATE_FILE"] = os.path.join(tmp.name,
                                                    "phantom_state.json")

    import phantom.utils.config as cfg
    stack.enter_context(mock.patch.object(
        cfg, "_CONFIG_PATH", os.path.join(tmp.name, "config.json")))
    # load_config() memoises the merged document per process, so without this
    # a test would read the FIRST test's file for the whole run.
    cfg._loaded = None
    stack.callback(lambda: setattr(cfg, "_loaded", None))

    for key in [k for k in os.environ if k.startswith("PHANTOM_")]:
        if key != "PHANTOM_STATE_FILE":
            os.environ.pop(key, None)
    stack.callback(_restore_env)
    return stack


class _Hermetic(unittest.TestCase):
    def setUp(self):
        self._iso = _isolated()
        self._iso.__enter__()
        self.addCleanup(self._iso.__exit__, None, None, None)

    def build(self, **kwargs):
        return gr.build(**kwargs)


class TestObservationOnly(_Hermetic):
    def test_build_never_changes_a_control(self):
        """A reporting layer that can change what it reports is not a
        reporting layer."""
        before = {g.key: (g.enabled, g.source)
                  for g in self.build(scope=["10.0.0.0/24"]).guards}
        after = {g.key: (g.enabled, g.source)
                 for g in self.build(scope=["10.0.0.0/24"]).guards}
        self.assertEqual(before, after)
        self.assertTrue(before["scope_gate"][0])

    def test_reading_twice_gives_the_same_digest(self):
        self.assertEqual(self.build().digest(), self.build().digest())

    def test_build_survives_a_broken_config(self):
        with mock.patch("phantom.utils.config.get",
                        side_effect=RuntimeError("boom")):
            m = self.build()          # must not raise
        self.assertTrue(m.guards)


class TestSourceResolution(_Hermetic):
    """'off' and 'off because you set it last week' are different risks."""

    def test_an_env_override_is_attributed_to_env(self):
        os.environ["PHANTOM_ALLOW_UNSCOPED"] = "1"
        try:
            guard = self.build().get("scope_gate")
        finally:
            os.environ.pop("PHANTOM_ALLOW_UNSCOPED", None)
        self.assertFalse(guard.enabled)
        self.assertEqual(guard.source, gr.ENV)
        self.assertTrue(guard.overridden)

    def test_force_network_is_attributed_to_the_run(self):
        guard = self.build(force_network=True).get("network_range")
        self.assertFalse(guard.enabled)
        self.assertEqual(guard.source, gr.RUN)

    def test_an_untouched_control_is_not_an_override(self):
        for guard in self.build().guards:
            if guard.source == gr.DEFAULT:
                self.assertFalse(guard.overridden, guard.key)

    def test_an_untouched_control_is_never_called_an_override(self):
        # Note what is NOT asserted: that everything is ON. On a checkout that
        # has never run, the generated secrets legitimately do not exist yet.
        # The invariant is about ATTRIBUTION, not about the machine being set
        # up — a control nobody touched must not appear in the override list.
        for guard in self.build().guards:
            self.assertFalse(guard.overridden, guard.key)

    def test_an_empty_env_token_is_not_read_as_an_operator_override(self):
        # The subtle one: PHANTOM_API_TOKEN="" must NOT read as "auth off".
        # Empty means "use what is stored" — the whole point of the persisted
        # secret design. Here the store is empty too, so the honest answer is
        # "absent"; what matters is that it is not blamed on the operator.
        os.environ["PHANTOM_API_TOKEN"] = ""
        try:
            guard = gr._g_api_auth()
        finally:
            os.environ.pop("PHANTOM_API_TOKEN", None)
        self.assertFalse(guard.overridden)

    def test_an_empty_env_token_uses_the_persisted_value_when_present(self):
        with mock.patch.object(gr, "_secret", return_value=(True, gr.STATE)):
            os.environ["PHANTOM_API_TOKEN"] = ""
            try:
                guard = gr._g_api_auth()
            finally:
                os.environ.pop("PHANTOM_API_TOKEN", None)
        self.assertTrue(guard.enabled)

    def test_a_genuinely_absent_token_is_reported_off_and_loud(self):
        with mock.patch.object(gr, "_secret", return_value=(False, gr.DEFAULT)):
            guard = gr._g_api_auth()
        self.assertFalse(guard.enabled)
        self.assertIn("UNPROTECTED", guard.detail.upper())


class TestManifestAccounting(_Hermetic):
    def test_the_counts_add_up(self):
        m = self.build()
        self.assertEqual(len(m.active) + len(m.off), len(m.guards))
        self.assertEqual(len(m.overrides),
                         len([g for g in m.guards if not g.enabled
                              and g.source != gr.DEFAULT]))

    def test_a_fresh_machine_reports_the_secrets_as_absent_not_off_by_choice(
            self):
        # Nothing here was disabled by a human: on a checkout that has never
        # run, the generated secrets do not exist yet. The manifest must say
        # "absent" (source=default), NOT "the operator turned it off" — an
        # override list polluted with first-run noise trains the operator to
        # ignore it.
        m = self.build()
        for guard in m.guards:
            if guard.source == gr.DEFAULT:
                self.assertFalse(guard.overridden, guard.key)
        self.assertEqual(m.overrides, [])

    def test_the_summary_names_the_override_count(self):
        os.environ["PHANTOM_ALLOW_UNSCOPED"] = "1"
        try:
            summary = self.build(force_network=True).summary()
        finally:
            os.environ.pop("PHANTOM_ALLOW_UNSCOPED", None)
        self.assertIn("disabled by the operator", summary)

    def test_the_digest_tracks_decisions_not_context(self):
        # Two engagements on different targets with the same protection share
        # a digest: that is what lets the audit log say "nothing changed".
        a = self.build(scope=["10.0.0.0/24"], targets=["10.0.0.5"])
        b = self.build(scope=["192.168.0.0/24"], targets=["192.168.0.9"])
        self.assertEqual(a.digest(), b.digest())

    def test_the_digest_changes_when_a_control_changes(self):
        base = self.build().digest()
        os.environ["PHANTOM_ALLOW_UNSCOPED"] = "1"
        try:
            self.assertNotEqual(base, self.build().digest())
        finally:
            os.environ.pop("PHANTOM_ALLOW_UNSCOPED", None)

    def test_get_returns_none_for_an_unknown_key(self):
        self.assertIsNone(self.build().get("nope"))


class TestRendering(_Hermetic):
    def test_the_plain_block_shows_state_and_source(self):
        os.environ["PHANTOM_ALLOW_UNSCOPED"] = "1"
        try:
            text = gr.render(self.build())
        finally:
            os.environ.pop("PHANTOM_ALLOW_UNSCOPED", None)
        self.assertIn("Scope gate", text)
        self.assertIn("OFF", text)
        self.assertIn("env", text)

    def test_no_overrides_says_so_explicitly(self):
        # Silence would be ambiguous: "no overrides" and "we did not look".
        self.assertIn("No operator overrides", gr.render(self.build()))

    def test_overrides_are_listed_with_a_remedy(self):
        os.environ["PHANTOM_ALLOW_UNSCOPED"] = "1"
        try:
            text = gr.render(self.build())
        finally:
            os.environ.pop("PHANTOM_ALLOW_UNSCOPED", None)
        self.assertIn("DISABLED BY THE OPERATOR", text)
        self.assertIn("PHANTOM_ALLOW_UNSCOPED", text)

    def test_the_markdown_is_a_table_with_the_digest(self):
        md = gr.report_block(self.build())
        self.assertIn("| Control | State | Set by | Detail |", md)
        self.assertIn("digest", md)


class TestToggling(_Hermetic):
    def test_a_non_toggleable_key_is_refused_with_a_reason(self):
        ok, msg = gr.set_guardrail("network_range", False)
        self.assertFalse(ok)
        self.assertIn("not operator-toggleable", msg)

    def test_an_unknown_key_is_refused(self):
        ok, _ = gr.set_guardrail("does_not_exist", True)
        self.assertFalse(ok)

    def test_every_toggleable_key_names_the_knob_it_writes(self):
        for entry in gr.toggleable():
            self.assertTrue(entry["env"], entry["key"])
            self.assertTrue(entry["config_key"] or entry["env"], entry["key"])

    def test_a_config_backed_toggle_round_trips(self):
        ok, msg = gr.set_guardrail("scope_gate", False)
        self.assertTrue(ok, msg)
        self.assertFalse(self.build().get("scope_gate").enabled)
        ok2, _ = gr.set_guardrail("scope_gate", True)
        self.assertTrue(ok2)
        self.assertTrue(self.build().get("scope_gate").enabled)

    def test_a_switch_never_writes_the_opposite_of_what_it_says(self):
        # The scope gate is ON when `allow_unscoped` is FALSE. A toggle that
        # forgot the polarity would turn the gate OFF when the operator asked
        # to turn it ON — the worst failure a control can have, and one no
        # "did the call return True" assertion would catch.
        ok, _ = gr.set_guardrail("scope_gate", True)
        self.assertTrue(ok)
        self.assertTrue(self.build().get("scope_gate").enabled,
                        "turning the gate ON must leave it enforcing")
        import phantom.utils.config as cfg
        self.assertFalse(
            cfg.get_bool("engagement.allow_unscoped", False),
            "the stored value must be the inverse of the guard state")

        ok, _ = gr.set_guardrail("scope_gate", False)
        self.assertTrue(ok)
        self.assertFalse(self.build().get("scope_gate").enabled)
        self.assertTrue(
            cfg.get_bool("engagement.allow_unscoped", False),
            "turning the gate OFF must actually allow unscoped targets")

    def test_a_state_backed_toggle_round_trips(self):
        ok, msg = gr.set_guardrail("mtls", False)
        self.assertTrue(ok, msg)
        self.assertFalse(self.build().get("mtls").enabled)
        self.assertTrue(gr.set_guardrail("mtls", True)[0])
        self.assertTrue(self.build().get("mtls").enabled)


class TestAuditSnapshot(_Hermetic):
    def test_the_control_name_survives_redaction(self):
        # A dict key literally called "key" is replaced with [REDACTED] by
        # phantom.utils.redact, which would make every audit record
        # unanswerable. The audit copy must say WHICH control changed.
        with mock.patch("phantom.utils.audit_log.audit_log") as log:
            log.append.return_value = {"seq": 1}
            gr.snapshot_to_audit(self.build(), event="guardrails_test")
        self.assertTrue(log.append.called)
        args, kwargs = log.append.call_args
        names = [g.get("control") for g in kwargs["guards"]]
        self.assertIn("scope_gate", names)
        for g in kwargs["guards"]:
            self.assertNotIn("key", g)
            self.assertNotEqual(g.get("control"), "[REDACTED]")

    def test_it_appends_the_decision_record(self):
        with mock.patch("phantom.utils.audit_log.audit_log") as log:
            log.append.return_value = {"seq": 1}
            gr.snapshot_to_audit(self.build(), event="guardrails_test",
                                 targets=["10.0.0.5"])
        args, kwargs = log.append.call_args
        self.assertEqual(args[0] if args else kwargs.get("event"),
                         "guardrails_test")
        self.assertIn("digest", kwargs)
        self.assertEqual(kwargs["targets"], ["10.0.0.5"])

    def test_it_is_best_effort(self):
        # A report must still be produced when the audit store is unwritable:
        # the report carries the manifest text either way.
        with mock.patch("phantom.utils.audit_log.audit_log") as log:
            log.append.side_effect = OSError("disk full")
            self.assertIsNone(gr.snapshot_to_audit(self.build(), event="x"))


class TestTheReportCarriesIt(_Hermetic):
    def test_the_client_report_has_a_guardrails_section(self):
        from phantom.automation.reporting import ClientReport
        md = ClientReport("10.0.0.5").to_markdown()
        self.assertIn("## Guardrails", md)
        self.assertIn("Scope gate", md)

    def test_the_section_names_overrides_when_present(self):
        from phantom.automation.reporting import ClientReport
        os.environ["PHANTOM_ALLOW_UNSCOPED"] = "1"
        try:
            md = ClientReport("10.0.0.5").to_markdown()
        finally:
            os.environ.pop("PHANTOM_ALLOW_UNSCOPED", None)
        self.assertIn("Overrides applied by the operator", md)

    def test_a_broken_manifest_does_not_lose_the_report(self):
        from phantom.automation.reporting import ClientReport
        with mock.patch.object(gr, "build", side_effect=RuntimeError("boom")):
            md = ClientReport("10.0.0.5").to_markdown()
        self.assertIn("Assessment", md)
        self.assertIn("Guardrail manifest unavailable", md)


class TestCliSurface(_Hermetic):
    def _run(self, arg):
        from phantom.core.auto_shell import AutoShell
        AutoShell().do_guardrails(arg)

    def test_the_command_exists_in_both_shells(self):
        from phantom.core.auto_shell import AutoShell
        from phantom.core.shell.commands.ops import COMMANDS
        self.assertTrue(hasattr(AutoShell(), "do_guardrails"))
        self.assertIn("guardrails", COMMANDS)

    def test_list_does_not_raise(self):
        self._run("list")

    def test_why_does_not_raise(self):
        self._run("why")

    def test_record_reports_the_digest_or_a_clear_failure(self):
        with mock.patch.object(gr, "snapshot_to_audit", return_value=None):
            with mock.patch("phantom.core.shell.commands.ops.notifier") as n:
                self._run("record")
        # Either outcome is fine; silently "succeeding" on a failed append is not.
        self.assertTrue(n.error.called or n.success.called)

    def test_the_launch_banner_keeps_the_source_attribution(self):
        # render() emits "[env]", "[config]", "[run]". Passed into rich as
        # markup those are swallowed as unknown style tags, which deleted the
        # source from the banner - the one thing the line exists to say.
        import io
        from rich.console import Console
        from phantom.core.auto_shell import AutoShell
        os.environ["PHANTOM_ALLOW_UNSCOPED"] = "1"
        buf = io.StringIO()
        console = Console(file=buf, width=200, no_color=True, legacy_windows=False)
        import phantom.core.auto_shell as shell_mod
        original = shell_mod.console
        shell_mod.console = console
        try:
            AutoShell()._announce_guardrails()
        finally:
            shell_mod.console = original
            os.environ.pop("PHANTOM_ALLOW_UNSCOPED", None)
        out = buf.getvalue()
        self.assertIn("[env]", out)
        self.assertIn("[default]", out)

    def test_a_toggle_through_the_cli_warns_that_it_is_recorded(self):
        with mock.patch("phantom.core.shell.commands.ops.notifier") as n:
            self._run("disable scope_gate")
        self.assertTrue(n.success.called or n.error.called)
        self._run("enable scope_gate")

    def test_an_unknown_subcommand_explains_the_usage(self):
        with mock.patch("phantom.core.shell.commands.ops.notifier") as n:
            self._run("frobnicate")
        self.assertTrue(n.error.called)
        self.assertIn("Usage", n.info.call_args[0][0])


class TestStrictMode(_Hermetic):
    """Lock mode: the escape hatches are for lab work, and some engagements
    do not want them reachable at all."""

    def _strict(self, on=True):
        if on:
            os.environ["PHANTOM_STRICT_GUARDRAILS"] = "1"
        else:
            os.environ.pop("PHANTOM_STRICT_GUARDRAILS", None)

    def test_strict_off_lets_overrides_through(self):
        self._strict(False)
        os.environ["PHANTOM_ALLOW_UNSCOPED"] = "1"
        try:
            m = self.build()
        finally:
            os.environ.pop("PHANTOM_ALLOW_UNSCOPED", None)
        self.assertEqual(m.blocking_overrides(), [])

    def test_strict_on_names_the_offending_control(self):
        self._strict(True)
        os.environ["PHANTOM_ALLOW_UNSCOPED"] = "1"
        try:
            blocking = [g.key for g in self.build().blocking_overrides()]
        finally:
            os.environ.pop("PHANTOM_ALLOW_UNSCOPED", None)
        self.assertEqual(blocking, ["scope_gate"])

    def test_force_network_is_allowed_even_under_strict(self):
        # --force-network widens ONE engagement on purpose; locking it out
        # would refuse the legitimate case strict mode must leave room for.
        self._strict(True)
        try:
            m = self.build(force_network=True)
        finally:
            self._strict(False)
        self.assertFalse(m.get("network_range").enabled)
        self.assertEqual(m.blocking_overrides(), [])

    def test_strict_never_blocks_itself(self):
        self._strict(True)
        try:
            m = self.build()
        finally:
            self._strict(False)
        self.assertNotIn("strict_guardrails",
                         [g.key for g in m.blocking_overrides()])

    def test_launch_is_refused_before_any_action(self):
        self._strict(True)
        os.environ["PHANTOM_ALLOW_UNSCOPED"] = "1"
        try:
            from unittest import mock
            from phantom.core.auto_shell import AutoShell
            shell = AutoShell()
            shell.targets = ["10.0.0.5"]
            with mock.patch("phantom.core.automode.run_auto_mode") as run:
                with mock.patch("phantom.core.shell.commands.ops.notifier"):
                    shell.do_launch("")
            self.assertFalse(run.called, "the run must not start")
            self.assertFalse(shell.has_run)
        finally:
            os.environ.pop("PHANTOM_ALLOW_UNSCOPED", None)
            self._strict(False)

    def test_launch_proceeds_when_nothing_is_overridden(self):
        from unittest import mock
        from phantom.core.auto_shell import AutoShell
        shell = AutoShell()
        shell.targets = ["10.0.0.5"]
        with mock.patch("phantom.core.automode.run_auto_mode") as run:
            shell.do_launch("")
        self.assertTrue(run.called)
        self.assertTrue(shell.has_run)

    def test_a_broken_manifest_cannot_block_a_run(self):
        # The reporting layer must never be able to stop an engagement by
        # failing: "cannot tell" has to mean "allow", not "refuse".
        from unittest import mock
        from phantom.core.auto_shell import AutoShell
        shell = AutoShell()
        shell.targets = ["10.0.0.5"]
        with mock.patch.object(gr, "build", side_effect=RuntimeError("boom")):
            with mock.patch("phantom.core.automode.run_auto_mode") as run:
                shell.do_launch("")
        self.assertTrue(run.called)


class TestEngagementDigest(_Hermetic):
    def test_it_includes_scope_and_targets(self):
        a = self.build(scope=["10.0.0.0/24"], targets=["10.0.0.5"])
        b = self.build(scope=["10.0.0.0/24"], targets=["10.0.0.9"])
        # Same protection (same digest), different target (different
        # engagement digest) - so "protection changed" and "aim changed" stay
        # distinguishable in the audit log.
        self.assertEqual(a.digest(), b.digest())
        self.assertNotEqual(a.engagement_digest(), b.engagement_digest())

    def test_it_is_order_independent(self):
        a = self.build(scope=["10.0.0.0/24", "10.1.0.0/16"],
                       targets=["10.0.0.9", "10.0.0.5"])
        b = self.build(scope=["10.1.0.0/16", "10.0.0.0/24"],
                       targets=["10.0.0.5", "10.0.0.9"])
        self.assertEqual(a.engagement_digest(), b.engagement_digest())

    def test_it_is_exported(self):
        self.assertTrue(self.build().to_dict()["engagement_digest"])


class TestTheApiSurface(unittest.TestCase):
    def test_both_verbs_are_allowlisted_for_the_renderer(self):
        text = (_ROOT / "electron" / "electron" /
                "endpoint_allowlist.ts").read_text(encoding="utf-8")
        self.assertIn("'/api/guardrails', methods: ['GET']", text)
        self.assertIn("'/api/guardrails', methods: ['POST']", text)

    def test_the_write_is_a_mutating_group_not_a_silent_one(self):
        text = (_ROOT / "electron" / "electron" /
                "endpoint_allowlist.ts").read_text(encoding="utf-8")
        self.assertIn(
            "{ pattern: '/api/guardrails', methods: ['POST'], "
            "group: 'mutating' }", text)

    def test_the_ui_offers_a_switch_only_for_toggleable_keys(self):
        panel = (_ROOT / "electron" / "src" / "components" /
                 "SettingsPanel.tsx").read_text(encoding="utf-8")
        self.assertIn("guardrails.toggleable.includes(g.key)", panel)

    def test_the_ui_shows_the_digest_and_the_override_warning(self):
        panel = (_ROOT / "electron" / "src" / "components" /
                 "SettingsPanel.tsx").read_text(encoding="utf-8")
        self.assertIn("guardrails.digest", panel)
        self.assertIn("operator override", panel)

    def test_button_tags_balance_in_the_panel(self):
        # A row-level <button> wrapping the ON/OFF <button> is invalid HTML and
        # fires the handler twice.
        panel = (_ROOT / "electron" / "src" / "components" /
                 "SettingsPanel.tsx").read_text(encoding="utf-8")
        self.assertEqual(panel.count("<button"), panel.count("</button>"))


if __name__ == "__main__":
    unittest.main()