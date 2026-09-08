"""Tests for the sandbox pre-flight engine (Docker + Defender + VM)."""
import os
import tempfile
import unittest
from unittest.mock import Mock, patch

from phantom.automation.sandbox.sandbox import (
    SandboxEngine,
    SandboxBackend,
    SandboxResult,
    SandboxVerdict,
    DockerBackend,
    DefenderBackend,
)


class _FakeBackend(SandboxBackend):
    def __init__(self, name, ok=True, detected=False, available=True):
        self._name, self._ok, self._detected, self._avail = name, ok, detected, available
        self.runs = 0

    @property
    def name(self):
        return self._name

    def available(self):
        return self._avail

    def run_sample(self, sample_path):
        self.runs += 1
        return SandboxResult(backend=self._name, ok=self._ok,
                             detected=self._detected,
                             error="" if self._ok else "sample flagged")


class TestSandboxEngine(unittest.TestCase):

    def test_approved_when_all_pass(self):
        engine = SandboxEngine(backends=[
            _FakeBackend("docker"), _FakeBackend("defender")])
        verdict = engine.preflight("sample.bin")
        self.assertTrue(verdict.approved)
        self.assertEqual(len(verdict.results), 2)

    def test_denied_when_any_fails(self):
        engine = SandboxEngine(backends=[
            _FakeBackend("docker"), _FakeBackend("defender", ok=False)])
        verdict = engine.preflight("sample.bin")
        self.assertFalse(verdict.approved)
        self.assertIn("defender", verdict.reason)

    def test_detection_flags_as_denied(self):
        engine = SandboxEngine(backends=[
            _FakeBackend("defender", detected=True, ok=False)])
        verdict = engine.preflight("sample.bin")
        self.assertFalse(verdict.approved)

    def test_skipped_when_no_backend_available(self):
        # no backend available = conscious skip, never a silent block:
        # the engagement proceeds (the sample was NOT pre-flighted)
        engine = SandboxEngine(backends=[_FakeBackend("docker", available=False)])
        verdict = engine.preflight("sample.bin")
        self.assertTrue(verdict.skipped)
        self.assertTrue(verdict.approved)
        self.assertIn("no sandbox backend", verdict.reason)

    def test_unavailable_backends_skipped_but_others_run(self):
        engine = SandboxEngine(backends=[
            _FakeBackend("docker", available=False), _FakeBackend("defender")])
        verdict = engine.preflight("sample.bin")
        self.assertTrue(verdict.approved)
        self.assertEqual(len(verdict.results), 1)

    def test_backend_exception_is_a_failure(self):
        class _Boom(SandboxBackend):
            name = "boom"
            def available(self):
                return True
            def run_sample(self, path):
                raise RuntimeError("docker daemon down")
        verdict = SandboxEngine(backends=[_Boom()]).preflight("x")
        self.assertFalse(verdict.approved)
        self.assertIn("boom", verdict.reason)


class TestDockerBackend(unittest.TestCase):

    def _sample(self):
        fd, path = tempfile.mkstemp(prefix="phantom_sandbox_", suffix=".bin")
        os.write(fd, b"#!/bin/sh\necho ok\n")
        os.close(fd)
        self.addCleanup(os.unlink, path)
        return path

    def test_missing_sample(self):
        backend = DockerBackend()
        res = backend.run_sample(os.path.join(tempfile.gettempdir(), "nope_xyz.bin"))
        self.assertFalse(res.ok)
        self.assertIn("missing", res.error)

    def test_clean_execution_parses_exit_code(self):
        backend = DockerBackend()
        with patch.object(backend, "available", return_value=True), \
             patch("phantom.automation.sandbox.sandbox.execute_quiet") as eq:
            eq.return_value.ok = True
            eq.return_value.returncode = 0
            eq.return_value.stdout = "hello\nEXIT:0\n"
            eq.return_value.stderr = ""
            eq.return_value.timed_out = False
            res = backend.run_sample(self._sample())
            self.assertTrue(res.ok)
            cmd = eq.call_args[0][0]
            self.assertIn("--network=none", cmd)
            self.assertIn("docker run", cmd)

    def test_nonzero_exit_denied(self):
        backend = DockerBackend()
        with patch("phantom.automation.sandbox.sandbox.execute_quiet") as eq:
            eq.return_value.ok = True
            eq.return_value.returncode = 0
            eq.return_value.stdout = "EXIT:1\n"
            eq.return_value.stderr = ""
            eq.return_value.timed_out = False
            res = backend.run_sample(self._sample())
            self.assertFalse(res.ok)

    def test_timeout_denied(self):
        # execute_quiet hitting its own deadline means the container never
        # exited (docker itself wedged) — that stays a deny. A sample that
        # runs until the INNER `timeout <bound>` (rc 124) is mapped to 0 and
        # approved: a persistent implant staying alive IS a clean run.
        backend = DockerBackend()
        with patch("phantom.automation.sandbox.sandbox.execute_quiet") as eq:
            eq.return_value.timed_out = True
            res = backend.run_sample(self._sample())
            self.assertFalse(res.ok)
            self.assertIn("container did not exit", res.error)

    def test_persistent_sample_still_running_at_bound_is_approved(self):
        # The inner `timeout <bound>` kills a long-running sample and rc 124
        # is remapped to 0: beacons/implants never exit, so "alive at the
        # bound" must be a PASS, not a crash.
        backend = DockerBackend()
        with patch.object(backend, "available", return_value=True), \
             patch("phantom.automation.sandbox.sandbox.execute_quiet") as eq:
            eq.return_value.ok = True
            eq.return_value.returncode = 0
            eq.return_value.stdout = "EXIT:0\n"
            eq.return_value.stderr = ""
            eq.return_value.timed_out = False
            res = backend.run_sample(self._sample())
            self.assertTrue(res.ok)
            cmd = eq.call_args[0][0]
            self.assertIn("timeout", cmd)
            self.assertIn("rc=$?", cmd)

    def test_available_checks_docker_binary(self):
        backend = DockerBackend()
        with patch("phantom.automation.sandbox.sandbox.shutil.which") as w, \
             patch("phantom.automation.sandbox.sandbox.subprocess.run") as r:
            w.return_value = "/usr/bin/docker"
            r.return_value.returncode = 0
            self.assertTrue(backend.available())


class TestDefenderBackend(unittest.TestCase):

    def _sample(self):
        fd, path = tempfile.mkstemp(prefix="phantom_defender_", suffix=".exe")
        os.write(fd, b"MZ\x90\x00")
        os.close(fd)
        self.addCleanup(os.unlink, path)
        return path

    def test_available_only_on_windows(self):
        backend = DefenderBackend()
        self.assertEqual(backend.available(), os.name == "nt")

    def test_no_threat_means_approved(self):
        backend = DefenderBackend()
        with patch("phantom.automation.sandbox.sandbox.execute_quiet") as eq:
            def _side(cmd, timeout=None):
                m = Mock()
                m.returncode = 0
                m.stderr = ""
                m.timed_out = False
                if "Start-MpScan" in cmd:
                    m.ok = True
                    m.stdout = ""
                else:
                    m.ok = True
                    m.stdout = "NO_THREAT"
                return m
            eq.side_effect = _side
            res = backend.run_sample(self._sample())
            self.assertTrue(res.ok)
            self.assertFalse(res.detected)

    def test_threat_found_is_denied(self):
        # Threat is reported differently per backend path: MpCmdRun returns
        # exit code 2 on a detection; the PowerShell provider surfaces the
        # threat name through Get-MpThreat. Both must deny.
        backend = DefenderBackend()
        with patch("phantom.automation.sandbox.sandbox.execute_quiet") as eq:
            def _side(cmd, timeout=None):
                m = Mock()
                m.stderr = ""
                m.timed_out = False
                m.ok = True
                if "MpCmdRun" in cmd:
                    m.returncode = 2
                    m.stdout = "Threat Found"
                else:
                    m.returncode = 0
                    m.stdout = "Trojan:Win32/Phantom" if "Get-MpThreat" in cmd else ""
                return m
            eq.side_effect = _side
            res = backend.run_sample(self._sample())
            self.assertFalse(res.ok)
            self.assertTrue(res.detected)


class TestVerdict(unittest.TestCase):

    def test_summary(self):
        self.assertEqual(SandboxVerdict(approved=False, results=[]).summary(),
                         "no sandbox backend available — sample not pre-flighted")
        v = SandboxVerdict(approved=True,
                           results=[SandboxResult(backend="docker", ok=True)])
        self.assertEqual(v.summary(), "approved by all available sandbox backends")


if __name__ == "__main__":
    unittest.main()
