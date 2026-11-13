"""Assisted capability discovery (AutoModeBrief §4.3)."""
import os
import tempfile
import unittest

from phantom.automation.runtime import import_tool
from phantom.automation.runtime.capability_registry import CapabilityRegistry


class _Runner:
    """Records the argv the probe runs and answers each flag."""

    def __init__(self):
        self.calls = []

    def __call__(self, argv, timeout):
        self.calls.append(list(argv))
        flag = argv[-1]
        if flag == "--version":
            return 0, "myprobe 1.2.3"
        if flag == "--help":
            return 0, "usage: myprobe [options] TARGET"
        return 1, ""


class TestProbe(unittest.TestCase):
    def test_probe_runs_only_help_and_version(self):
        runner = _Runner()
        # point at a real file so resolve_binary finds a path
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as fh:
            path = fh.name
        try:
            result = import_tool.probe(path, runner=runner)
        finally:
            os.unlink(path)
        flags = [c[-1] for c in runner.calls]
        self.assertEqual(sorted(flags), ["--help", "--version"])
        self.assertIn("1.2.3", result.version)
        self.assertIn("usage", result.help_text)
        self.assertTrue(result.sha256)

    def test_missing_binary_is_reported_not_run(self):
        runner = _Runner()
        result = import_tool.probe("definitely-not-a-real-binary-xyz",
                                   runner=runner)
        self.assertFalse(result.found)
        self.assertEqual(runner.calls, [])
        self.assertTrue(result.findings)


class TestPropose(unittest.TestCase):
    def _bin(self):
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as fh:
            path = fh.name
        self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
        return path

    def test_candidate_has_no_command_and_is_disabled(self):
        proposal = import_tool.propose(self._bin(), runner=_Runner())
        self.assertNotIn("command", proposal.manifest)
        self.assertNotIn("argv", proposal.manifest)
        self.assertTrue(proposal.manifest.get("_candidate"))
        self.assertEqual(proposal.source, "unknown")

    def test_registry_records_a_candidate_not_enabled(self):
        reg = CapabilityRegistry(path=os.devnull)
        proposal = import_tool.propose(self._bin(), runner=_Runner(),
                                       registry=reg)
        row = reg.of(proposal.cap_id)
        self.assertIsNotNone(row)
        self.assertEqual(row.state, "candidate")
        self.assertFalse(row.enabled)
        self.assertNotIn(proposal.cap_id, reg.enabled_ids())

    def test_incomplete_candidate_is_denied_by_policy(self):
        proposal = import_tool.propose(self._bin(), runner=_Runner())
        decision = import_tool.expected_action(proposal.manifest)
        self.assertTrue(decision.denied)
        self.assertTrue(any("command" in r for r in decision.requirements))

    def test_render_writes_a_file(self):
        tmp = tempfile.mkdtemp()
        proposal = import_tool.propose(self._bin(), runner=_Runner())
        path = import_tool.render_manifest(proposal, tmp)
        self.assertTrue(path and os.path.isfile(path))
        self.assertTrue(path.endswith(".candidate.json"))


if __name__ == "__main__":
    unittest.main()
