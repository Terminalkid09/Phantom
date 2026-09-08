"""Tests for the auto-mode routing (planner-agent default) and helpers."""
import unittest
from unittest.mock import Mock, patch

from phantom.core.automode import (
    _auto_workers,
    _classify_target,
    _expand_targets,
    _fmt_elapsed,
    _stream_agent_event,
    run_auto_mode,
)


class TestTargetClassification(unittest.TestCase):

    def test_ip_target(self):
        self.assertEqual(_classify_target("192.168.1.1"), "ip")

    def test_domain_target(self):
        self.assertEqual(_classify_target("example.com"), "domain")

    def test_url_target(self):
        self.assertEqual(_classify_target("https://example.com/path"), "url")

    def test_email_target(self):
        self.assertEqual(_classify_target("user@example.com"), "email")

    def test_username_with_at(self):
        self.assertEqual(_classify_target("user@host"), "username")

    def test_username_with_underscore(self):
        self.assertEqual(_classify_target("john_doe"), "username")


class TestExpandTargets(unittest.TestCase):

    def test_comma_split_and_dedupe(self):
        self.assertEqual(
            _expand_targets(["1.2.3.4,1.2.3.4", "5.6.7.8"]),
            ["1.2.3.4", "5.6.7.8"],
        )

    def test_cidr_expansion(self):
        # /30 -> 2 usable hosts: .1 and .2
        self.assertEqual(_expand_targets(["10.0.0.0/30"]),
                         ["10.0.0.1", "10.0.0.2"])

    def test_plain_target_passthrough(self):
        self.assertEqual(_expand_targets(["example.com"]), ["example.com"])

    def test_url_with_slash_is_not_cidr(self):
        self.assertEqual(_expand_targets(["https://example.com/a/b"]),
                         ["https://example.com/a/b"])


class TestElapsedTimer(unittest.TestCase):

    def test_format_seconds(self):
        self.assertEqual(_fmt_elapsed(0), "0s")
        self.assertEqual(_fmt_elapsed(45), "45s")
        self.assertEqual(_fmt_elapsed(192), "3m 12s")
        self.assertEqual(_fmt_elapsed(3723), "1h 2m 3s")

    def test_auto_workers_decides_from_dry_run_plan(self):
        # a target with web services -> exploit deepening is worthwhile
        n = _auto_workers("example.com", "deliver", "enterprise",
                          False, False, False)
        self.assertIn(n, (1, 2))          # never more than a lead + worker
        self.assertGreaterEqual(n, 1)

    def test_auto_workers_identity_target_gets_deepen_worker(self):
        # an identity target runs a social chain: the default plan should
        # include the DEEPEN sub-agent so the wait for the human is never
        # idle (OSINT/breach/profile digging + grabber polling in parallel)
        n = _auto_workers("mario.rossi@gmail.com", "deliver", "enterprise",
                          False, False, False)
        self.assertEqual(n, 2)


class TestRunAutoModeRouting(unittest.TestCase):
    """`auto` now delegates to the planner agent (single -> run_autonomous,
    multi -> run_campaign); the legacy sequence loop is gone."""

    @staticmethod
    def _quiet(am):
        return (
            patch.object(am.notifier, "success"),
            patch.object(am.notifier, "info"),
            patch.object(am.notifier, "warn"),
            patch.object(am.notifier, "error"),
        )

    @staticmethod
    def _result(**kw):
        base = {"beacon_established": False, "beacon_id": "",
                "persistence_installed": False, "creds_found": 0,
                "victim_ips": 0, "hypotheses": 0, "hypotheses_confirmed": 0,
                "actions_taken": 0}
        base.update(kw)
        return base

    def test_single_target_routes_to_agent(self):
        import phantom.core.automode as am
        n = self._quiet(am)
        agent = Mock()
        with n[0], n[1], n[2], n[3], \
             patch.object(am, "_run_agent_single",
                          return_value=(self._result(), agent)) as m_single, \
             patch.object(am, "_run_agent_campaign") as m_campaign, \
             patch.object(am, "_report_out_dir", return_value="tmp"), \
             patch.object(am, "_write_agent_reports",
                          return_value=("tmp/t", {"raw": "r", "client": "c"})) as m_wr:
            run_auto_mode(targets=["192.168.1.1"])
        m_single.assert_called_once()
        m_campaign.assert_not_called()
        m_wr.assert_called_once()  # a report is produced for the run

    def test_multi_target_routes_to_campaign(self):
        import phantom.core.automode as am
        n = self._quiet(am)
        result = {"results": {}, "beacons": 0, "persistent": 0,
                  "compromised_creds": 0, "_agents": {}}
        fake_writer = Mock()
        fake_writer.write_campaign.return_value = {"campaign_json": "x",
                                                   "campaign_md": "y"}
        with n[0], n[1], n[2], n[3], \
             patch.object(am, "_run_agent_campaign",
                          return_value=result) as m_campaign, \
             patch.object(am, "_run_agent_single") as m_single, \
             patch.object(am, "_report_out_dir", return_value="tmp"), \
             patch("phantom.automation.reporting.ReportWriter",
                   return_value=fake_writer):
            run_auto_mode(targets=["1.1.1.1", "2.2.2.2"])
        m_campaign.assert_called_once()
        m_single.assert_not_called()
        fake_writer.write_campaign.assert_called_once()

    def test_verbose_flag_threads_to_single(self):
        import phantom.core.automode as am
        n = self._quiet(am)
        with n[0], n[1], n[2], n[3], \
             patch.object(am, "_run_agent_single",
                          return_value=(self._result(), Mock())) as m_single, \
             patch.object(am, "_report_out_dir", return_value="tmp"), \
             patch.object(am, "_write_agent_reports",
                          return_value=("tmp/t", {})):
            run_auto_mode(targets=["192.168.1.1"], verbose=True)
        # verbose is the 9th positional arg of _run_agent_single
        self.assertTrue(m_single.call_args.args[8])

    def test_no_target_aborts(self):
        import phantom.core.automode as am
        from phantom.core.session import session
        session.target = ""
        with patch.object(am, "_run_agent_single") as m_single, \
             patch.object(am, "_run_agent_campaign") as m_campaign, \
             patch.object(am.notifier, "error") as m_err:
            run_auto_mode(targets=[])
        m_single.assert_not_called()
        m_campaign.assert_not_called()
        m_err.assert_called()

    def test_plan_mode_does_not_execute(self):
        import phantom.core.automode as am
        n = self._quiet(am)
        fake_plan = Mock(steps=[])
        with n[0], n[1], n[2], n[3], \
             patch.object(am, "_dry_run_plan",
                          return_value=(fake_plan, "ip", "network",
                                        ["beacon"])) as m_plan, \
             patch.object(am, "_run_agent_single") as m_single, \
             patch.object(am, "_run_agent_campaign") as m_campaign:
            run_auto_mode(targets=["192.168.1.1"], plan=True)
        m_plan.assert_called_once()
        m_single.assert_not_called()
        m_campaign.assert_not_called()


class TestVerboseStream(unittest.TestCase):
    """--verbose gates the live reasoning trace (inference/reason/hypothesis)."""

    def test_verbose_renders_reasoning_events(self):
        import phantom.core.automode as am
        with patch.object(am.notifier, "info") as m_info:
            _stream_agent_event("reason",
                                {"hypotheses": [{"capability": "ssh_login",
                                                 "reason": "test reuse",
                                                 "priority": 0.85}]},
                                verbose=True)
            _stream_agent_event("hypothesis",
                                {"resolved": [{"capability": "ssh_login",
                                               "status": "confirmed"}]},
                                verbose=True)
        self.assertTrue(m_info.called)

    def test_quiet_mode_suppresses_reasoning(self):
        import phantom.core.automode as am
        with patch.object(am.notifier, "info") as m_info:
            _stream_agent_event("reason",
                                {"hypotheses": [{"capability": "ssh_login",
                                                 "reason": "test reuse",
                                                 "priority": 0.85}]},
                                verbose=False)
        m_info.assert_not_called()


if __name__ == "__main__":
    unittest.main()
