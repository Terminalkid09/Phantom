"""In-process engines run at EXECUTION time, never while a command is built.

The chain preview builds every candidate's command; a live socket probe in
there is a bug — it made the suite hang (the conftest guard exists for it)
and it made `fingerprint_services` queue its FINGERPRINT: markers as a
shell task, which can never work. These tests pin the split: make_command
is pure, the engine runs under a timeout through `run_engine`, and its
result is cached for the run.
"""
import time
import unittest
from unittest import mock

from phantom.automation.belief import WorldModel
from phantom.automation.guidance.commands import make_registry, run_engine


class TestEngineCapabilities(unittest.TestCase):
    def setUp(self):
        self.wm = WorldModel("10.0.0.5", "ip")
        self.wm.add_finding("service", "tcp/22",
                            {"service": "ssh", "port": "22"},
                            confidence=0.9, source="scan")
        self.reg = make_registry()

    def test_fingerprint_is_an_in_process_engine(self):
        cap = self.reg.get("fingerprint_services")
        self.assertEqual(cap.exec_class, "in_process_engine")
        self.assertIsNotNone(cap.engine)

    def test_make_command_does_not_touch_the_network(self):
        from phantom.automation.fingerprint import probes
        cap = self.reg.get("fingerprint_services")
        with mock.patch.object(
                probes, "_connect",
                side_effect=AssertionError("network during make_command")
        ) as spy:
            cmd = cap.make_command(self.wm, {})
        spy.assert_not_called()
        self.assertIn("in-process engine", cmd)

    def test_the_engine_runs_once_and_is_cached(self):
        calls = {"n": 0}

        def fake_engine(wm, slots):
            calls["n"] += 1
            return "FINGERPRINT:22:ssh:OpenSSH:8.9"

        cap = self.reg.get("fingerprint_services")
        cap.engine = fake_engine
        wm = WorldModel("10.9.9.9", "ip")          # fresh cache key
        first = run_engine(cap, wm, {})
        second = run_engine(cap, wm, {})
        self.assertEqual(first, second)
        self.assertEqual(calls["n"], 1)

    def test_a_hung_engine_times_out_into_a_comment(self):
        cap = self.reg.get("fingerprint_services")
        cap.timeout = 1
        cap.engine = lambda wm, slots: (time.sleep(5) or "never")
        out = run_engine(cap, WorldModel("10.8.8.8", "ip"), {})
        self.assertIn("timed out", out)

    def test_a_broken_engine_is_a_comment_not_a_crash(self):
        cap = self.reg.get("fingerprint_services")

        def boom(wm, slots):
            raise RuntimeError("engine blew up")

        cap.engine = boom
        out = run_engine(cap, WorldModel("10.7.7.7", "ip"), {})
        self.assertIn("engine blew up", out)


if __name__ == "__main__":
    unittest.main()
