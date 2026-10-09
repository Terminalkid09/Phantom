"""Tests: auto-mode reporting tail (extracted to automode_report).

Pins what a finished engagement prints: elapsed formatting, report paths,
the swarm summary file (board_ref excluded: live objects are not JSON), the
single/campaign tails and the swarm stage ladder.
"""
import json
import os
import unittest
from unittest.mock import Mock, patch

from phantom.core import automode_report as rep


class _BoomExperience:
    """An agent whose learning receipt explodes on access."""
    @property
    def experience(self):
        raise RuntimeError("boom")


class TestFmtElapsed(unittest.TestCase):
    def test_formatting(self):
        self.assertEqual(rep.fmt_elapsed(0), "0s")
        self.assertEqual(rep.fmt_elapsed(45), "45s")
        self.assertEqual(rep.fmt_elapsed(192), "3m 12s")
        self.assertEqual(rep.fmt_elapsed(3723), "1h 2m 3s")


class TestSafeTargetDir(unittest.TestCase):
    def test_sanitizes_path_chars(self):
        self.assertEqual(rep.safe_target_dir("10.0.0.5"), "10.0.0.5")
        self.assertEqual(rep.safe_target_dir("https://x/y"), "https___x_y")


class TestWriteSwarmSummary(unittest.TestCase):
    def test_json_without_board_ref(self):
        import tempfile
        out = tempfile.mkdtemp()
        paths = rep.write_swarm_summary(
            {"tasks": [], "actions_taken": 3, "board_ref": object()},
            out, "10.0.0.5")
        self.assertEqual(sorted(paths), ["summary"])
        with open(paths["summary"], encoding="utf-8") as fh:
            data = json.load(fh)
        self.assertEqual(data["actions_taken"], 3)
        self.assertNotIn("board_ref", data)

    def test_unwritable_dir_warns_and_returns_empty(self):
        with patch.object(rep.notifier, "warn") as m_warn, \
                patch("os.makedirs", side_effect=OSError("nope")):
            paths = rep.write_swarm_summary({"tasks": []}, "/x", "t")
        self.assertEqual(paths, {})
        m_warn.assert_called_once()


class TestSwarmTail(unittest.TestCase):
    def _result(self, **kw):
        base = {"beacon_established": False, "persistence_installed": False,
                "system_privilege": False, "ad_creds": 0, "cracked_hashes": 0,
                "lateral_movements": 0, "actions_taken": 2, "creds_found": 1,
                "stages": {}}
        base.update(kw)
        return base

    def test_deep_prints_the_stage_ladder(self):
        summary = {"tasks": [{"status": "done"}, {"status": "pending"}]}
        with patch.object(rep.notifier, "success") as m_suc, \
                patch.object(rep.notifier, "info") as m_info, \
                patch.object(rep.notifier, "warn"):
            rep.print_swarm_tail(
                self._result(stages={"deliver": True, "post_exploit": False,
                                     "ad": False, "crack": False,
                                     "lateral": False}),
                summary, "/tmp", 0, "deep")
        texts = [str(c.args[0]) for c in m_info.call_args_list]
        self.assertTrue(any("Stage ladder:" in t and "deliver=✔" in t
                            and "post_exploit=—" in t for t in texts))
        self.assertTrue(any("1/2 task" in str(c.args[0])
                            for c in m_suc.call_args_list))

    def test_no_beacon_says_no_handoff(self):
        with patch.object(rep.notifier, "success"), \
                patch.object(rep.notifier, "info"), \
                patch.object(rep.notifier, "warn") as m_warn:
            rep.print_swarm_tail(self._result(), {"tasks": []}, "/tmp", 0,
                                 "footprint")
        self.assertTrue(any("niente handoff" in str(c.args[0])
                            for c in m_warn.call_args_list))

    def test_beacon_points_the_operator_at_c2(self):
        with patch.object(rep.notifier, "success"), \
                patch.object(rep.notifier, "info") as m_info, \
                patch.object(rep.notifier, "warn"):
            rep.print_swarm_tail(self._result(beacon_established=True),
                                 {"tasks": []}, "/tmp", 0, "footprint")
        self.assertTrue(any("c2" in str(c.args[0])
                            for c in m_info.call_args_list))


class TestAgentSingleTail(unittest.TestCase):
    def _result(self, **kw):
        base = {"beacon_established": False, "persistence_installed": False,
                "system_privilege": False, "ad_creds": 0, "cracked_hashes": 0,
                "lateral_movements": 0, "actions_taken": 7, "creds_found": 2,
                "victim_ips": 1, "hypotheses": 3, "hypotheses_confirmed": 1,
                "stages": {}}
        base.update(kw)
        return base

    def test_deliver_tail_reports_totals_paths_and_checkpoint(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with patch.object(rep.notifier, "success") as m_suc, \
                patch.object(rep.notifier, "info") as m_info, \
                redirect_stdout(buf):
            elapsed = rep.print_agent_single_tail(
                self._result(), {"raw": "r.md"}, Mock(), "deliver", 0,
                "/out")
        self.assertIn("h ", elapsed)  # epoch-0 start = a big duration
        suc_text = " ".join(str(c.args[0]) for c in m_suc.call_args_list)
        self.assertIn("Deliver completo", suc_text)
        self.assertIn("azioni=7", suc_text)
        self.assertIn("r.md", buf.getvalue())  # paths go to the console
        texts = [str(c.args[0]) for c in m_info.call_args_list]
        self.assertTrue(any("checkpoint.json" in t for t in texts))

    def test_deep_tail_prints_the_ladder(self):
        with patch.object(rep.notifier, "success"), \
                patch.object(rep.notifier, "info") as m_info:
            rep.print_agent_single_tail(
                self._result(stages={"deliver": True}), {}, Mock(), "deep",
                0, "/out")
        self.assertTrue(any("Stage ladder:" in t for t in
                            (str(c.args[0]) for c in m_info.call_args_list)))

    def test_learning_receipt_failure_never_breaks_the_tail(self):
        with patch.object(rep.notifier, "success"), \
                patch.object(rep.notifier, "info") as m_info:
            rep.print_agent_single_tail(self._result(), {},
                                        _BoomExperience(), "deliver", 0,
                                        "/out")
        self.assertTrue(m_info.called)  # the tail still completed


class TestCampaignTail(unittest.TestCase):
    def test_totals_and_report_paths(self):
        campaign = {"beacons": 1, "persistent": 1, "compromised_creds": 4}
        with patch.object(rep.notifier, "success") as m_suc, \
                patch.object(rep.notifier, "info") as m_info:
            elapsed = rep.print_campaign_tail(
                campaign, {"10.0.0.5": {"dir": "/d"}},
                {"campaign_json": "c.json"}, "3m 12s")
        self.assertEqual(elapsed, "3m 12s")
        self.assertIn("1 beacon", str(m_suc.call_args.args[0]))
        self.assertTrue(any("Report (per-target + campaign)" in str(c.args[0])
                            for c in m_info.call_args_list))


if __name__ == "__main__":
    unittest.main()
