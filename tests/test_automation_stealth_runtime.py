"""Tests for the stealth runtime: timing, scan splitting, egress discipline."""
import random
import unittest
from unittest.mock import Mock

from phantom.automation.belief import WorldModel
from phantom.automation.guidance.stealth import StealthEngine, StealthConfig
from phantom.automation.runtime.egress import EgressManager, Egress
from phantom.automation.runtime.stealth_runtime import (
    TimingGovernor,
    ScanSplitter,
    StealthRuntime,
)


class TestTimingGovernor(unittest.TestCase):

    def test_delays_stay_in_range(self):
        gov = TimingGovernor(base_delay=2.0, jitter=0.5, rng=random.Random(1))
        for _ in range(50):
            self.assertGreaterEqual(gov.next_delay(), 1.5 - 1e-9)
            self.assertLessEqual(gov.next_delay(), 2.5 + 1e-9)

    def test_wait_sleeps(self):
        gov = TimingGovernor(base_delay=0.05, jitter=0.01, rng=random.Random(2))
        t0 = __import__("time").time()
        gov.wait()
        self.assertGreaterEqual(__import__("time").time() - t0, 0.03)

    def test_not_periodic_with_jitter(self):
        gov = TimingGovernor(base_delay=1.0, jitter=0.4, rng=random.Random(3))
        for _ in range(10):
            gov.next_delay()
        self.assertFalse(gov.is_periodic())

    def test_periodic_detection(self):
        gov = TimingGovernor(rng=random.Random(4))
        gov._last = [1.0] * 8
        self.assertTrue(gov.is_periodic())


class TestScanSplitter(unittest.TestCase):

    def test_small_list_single_command(self):
        s = ScanSplitter(chunk_size=5, rng=random.Random(5))
        cmds = s.split_ports(["1", "2", "3"], base="nmap -sT")
        self.assertEqual(len(cmds), 1)
        self.assertIn("-p 1,2,3", cmds[0])

    def test_large_list_chunked(self):
        s = ScanSplitter(chunk_size=5, rng=random.Random(6))
        ports = [str(i) for i in range(1, 21)]
        cmds = s.split_ports(ports, base="nmap -sT")
        self.assertEqual(len(cmds), 4)
        total = sum(len(c.split(" ")[-1].split(",")) for c in cmds)
        self.assertEqual(total, 20)
        for c in cmds:
            self.assertLessEqual(len(c.split(" ")[-1].split(",")), 5)

    def test_chunks_shuffled(self):
        rng = random.Random(7)
        s = ScanSplitter(chunk_size=4, rng=rng)
        ports = [str(i) for i in range(1, 17)]
        c1 = s.split_ports(ports)
        c2 = s.split_ports(ports)
        # at least sometimes the order differs
        self.assertNotEqual(c1, c2)

    def test_gap_range(self):
        s = ScanSplitter(gap_range=(1.0, 2.0), rng=random.Random(8))
        for _ in range(20):
            g = s.gap_between_chunks()
            self.assertGreaterEqual(g, 1.0)
            self.assertLessEqual(g, 2.0)


class TestEgressManager(unittest.TestCase):

    def test_acquire_release(self):
        mgr = EgressManager([Egress("a", "local"), Egress("b", "docker")])
        e = mgr.acquire("agent-1")
        self.assertEqual(e.name, "a")
        self.assertFalse(mgr.single_egress_ok() is False)
        self.assertEqual(mgr.active(), [e])
        mgr.release(e)
        self.assertEqual(mgr.active(), [])

    def test_single_egress_discipline(self):
        mgr = EgressManager([Egress("a", "local"), Egress("b", "docker")])
        e1 = mgr.acquire("agent-1")
        e2 = mgr.acquire("agent-2")  # lease falls back to the second box
        self.assertIsNotNone(e2)
        self.assertEqual(len(mgr.active()), 2)
        self.assertFalse(mgr.single_egress_ok())

    def test_busy_returns_none(self):
        mgr = EgressManager([Egress("only", "local")])
        mgr.acquire("agent-1")
        self.assertIsNone(mgr.acquire("agent-2"))


class TestStealthRuntime(unittest.TestCase):

    def _rt(self, runner=None):
        wm = WorldModel()
        stealth = StealthEngine(wm, StealthConfig())
        return StealthRuntime(stealth, runner=runner,
                              governor=TimingGovernor(base_delay=0.0, jitter=0.0),
                              splitter=ScanSplitter(chunk_size=3, gap_range=(0.0, 0.0)))

    def test_run_executes_and_records_opsec(self):
        runner = Mock(return_value=Mock(ok=True, stdout="ports..."))
        rt = self._rt(runner=runner)
        run = rt.run("nmap -sT 10.0.0.5", category="recon")
        self.assertTrue(run.ok)
        runner.assert_called_once()
        self.assertGreater(rt.stealth.wm.opsec_spent, 0)

    def test_never_blocks_on_opsec(self):
        rt = self._rt(runner=Mock(return_value=Mock(ok=True, stdout="x")))
        for _ in range(5):
            run = rt.run("cmd", category="recon")
            self.assertTrue(run.ok, run.output)

    def test_split_scan_runs_all_chunks(self):
        runner = Mock(return_value=Mock(ok=True, stdout="ports..."))
        rt = self._rt(runner=runner)
        runs = rt.run_split_scan([str(i) for i in range(1, 10)],
                                 base="nmap -sT", agent="agent-1")
        self.assertEqual(len(runs), 3)
        self.assertTrue(all(r.ok for r in runs))

    def test_split_scan_stops_on_failure(self):
        results = [Mock(ok=True, stdout="a"), Mock(ok=False, stdout="")]
        runner = Mock(side_effect=lambda cmd, timeout=None: results.pop(0) if results else Mock(ok=False, stdout=""))
        rt = self._rt(runner=runner)
        runs = rt.run_split_scan([str(i) for i in range(1, 10)],
                                 base="nmap -sT", agent="agent-1")
        self.assertLessEqual(len(runs), 2)
        self.assertFalse(runs[-1].ok)


if __name__ == "__main__":
    unittest.main()
