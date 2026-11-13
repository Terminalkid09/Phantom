"""G15 / G16 / G18 — resumability, honest run outcomes, machine-readable export.

G16  A module result must say WHY a run produced what it did: a missing tool,
     an out-of-scope target and a genuinely empty run are three different
     facts, and the report must be able to tell them apart.
G15  A 40-minute manual batch must be resumable, not restartable.
G18  The evidence must be consumable mechanically, one record per capability.
"""
import json
import os
import unittest

import pytest

from phantom.modules import report as rep
from phantom.core.session import session
from phantom.core.knowledge import reset_wm, session_wm
from phantom.core.executor import RunStatus, run_commands
from phantom.core.manual_checkpoint import ManualCheckpoint


@pytest.fixture(autouse=True)
def _clean_session():
    saved_results = dict(session.results)
    saved_status = dict(session.result_status)
    saved_target = session.target
    session.results = {}
    session.result_status = {}
    reset_wm("10.0.0.5")
    yield
    session.results = saved_results
    session.result_status = saved_status
    session.target = saved_target


# ── G16 ─────────────────────────────────────────────────────────────────────

class TestRunOutcomeIsNotInferred(unittest.TestCase):
    def test_missing_tool_is_an_error_not_an_empty_result(self):
        from phantom.core import executor
        orig = executor._is_tool_installed
        executor._is_tool_installed = lambda cmd: False
        try:
            status = RunStatus()
            out = executor.run_command("definitely-not-a-tool -x", "", status=status)
        finally:
            executor._is_tool_installed = orig
        assert out == ""
        assert status.outcome == "error"
        assert "not installed" in status.error

    def test_genuinely_empty_run_is_empty_not_error(self):
        status = RunStatus()
        status.ran("nmap -sn 10.0.0.5", "")
        assert status.outcome == "empty"
        assert status.error is None

    def test_run_with_output_is_ok(self):
        status = RunStatus()
        status.ran("nmap -sn 10.0.0.5", "Host is up")
        assert status.outcome == "ok"

    def test_session_keeps_status_and_reports_three_states(self):
        status = RunStatus()
        status.refused_command("nmap", "tool 'nmap' not installed")
        session.add_result("scan", {}, status=status)
        assert session.result_outcome("scan") == "error"
        assert session.result_outcome("exploit") == "not-run"
        session.add_result("web", {"x": 1})
        # no status recorded -> derived conservatively, never "error"
        assert session.result_outcome("web") == "ok"


class TestReportShowsCoverage(unittest.TestCase):
    def test_coverage_table_distinguishes_blocked_from_clean(self):
        status = RunStatus()
        status.refused_command("nikto -h t", "tool 'nikto' not installed")
        session.add_result("web", {}, status=status)
        session.add_result("exploit", {"ranked": []})
        client = rep._build_client_markdown()
        assert "Assessment Coverage" in client
        assert "not installed" in client
        operator = rep._build_operator_markdown()
        assert "Module Outcomes" in operator


# ── G15 ─────────────────────────────────────────────────────────────────────

class TestManualCheckpoint(unittest.TestCase):
    def test_round_trip_and_atomic_save(self, tmp_path=None):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ck.json")
            ck = ManualCheckpoint("brute", "10.0.0.5", path=path)
            ck.mark("hydra -l a", "no valid password")
            ck.mark("hydra -l b", "password found")
            assert os.path.isfile(path)
            with open(path, encoding="utf-8") as fh:
                json.load(fh)  # parseable -> the atomic write landed

            again = ManualCheckpoint("brute", "10.0.0.5", path=path)
            assert again.completed()["hydra -l a"] == "no valid password"
            assert again.progress() == 2
            again.finish()
            assert ManualCheckpoint("brute", "10.0.0.5", path=path).is_finished()

    def test_run_commands_skips_completed_and_finishes(self, tmp_path=None):
        import tempfile
        from phantom.core import executor
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "ck.json")
            ck = ManualCheckpoint("brute", "t", path=path)
            ck.mark("cmd-a", "old-a")

            calls = []
            orig = executor.run_command
            executor.run_command = (
                lambda cmd, target_ip="", status=None: calls.append(cmd) or "new")
            try:
                status = RunStatus()
                out = run_commands(["cmd-a", "cmd-b"], "", status=status,
                                   checkpoint=ck)
            finally:
                executor.run_command = orig

            assert calls == ["cmd-b"], "the completed command must not re-run"
            assert out["cmd-a"] == "old-a"
            assert out["cmd-b"] == "new"
            assert ck.is_finished()
            assert ck.completed()["cmd-b"] == "new"


# ── G18 ─────────────────────────────────────────────────────────────────────

class TestMachineReadableExport(unittest.TestCase):
    def test_capabilities_are_typed_records(self):
        session_wm().add_finding("vuln", "CVE-2026-7777",
                                 {"cve": "CVE-2026-7777"},
                                 confidence=0.8, source="exploit")
        rows = rep._capabilities()
        row = next(r for r in rows if r["key"] == "CVE-2026-7777")
        for key in ("capability", "key", "confidence", "source", "evidence"):
            assert key in row
        assert row["capability"] == "vuln"
        assert abs(row["confidence"] - 0.8) < 1e-9

    def test_export_capabilities_writes_json(self):
        import tempfile
        session.target = "10.0.0.5"
        session_wm().add_finding("service", "tcp/80",
                                 {"port": "80", "service": "http"},
                                 confidence=0.7, source="scan")
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "caps.json")
            rep.ReportModule()._export_capabilities(path)
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        assert data["target"] == "10.0.0.5"
        assert data["capabilities"]
        assert "module_outcomes" in data

    def test_generate_capabilities_format(self):
        import tempfile
        from unittest import mock
        session.target = "10.0.0.5"
        with tempfile.TemporaryDirectory() as d:
            with mock.patch("phantom.utils.paths.reports_dir",
                            lambda: d):
                out = rep.ReportModule().generate("capabilities")
            assert out["format"] == "capabilities"
            assert os.path.isfile(out["raw_path"])
            assert out["raw_path"].endswith("capabilities.json")


if __name__ == "__main__":
    unittest.main()
