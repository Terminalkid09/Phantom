"""Deterministic AutoMode decision replay (Fase 3 / P2 #5).

Pins that a recorded arbitration reproduces exactly, survives a JSON
round-trip, and that a tampered trace is DETECTED as a divergence instead of
passing silently.
"""
import unittest

from phantom.automation import replay
from phantom.automation.brain.lenses import CapabilityView, WorldSignals


def _views():
    return [
        CapabilityView(id="scan_tcp", category="scan", opsec_cost=1.4,
                       detection_risk=0.6, stealth_level="noisy"),
        CapabilityView(id="curl_probe", category="recon", opsec_cost=0.4,
                       detection_risk=0.2, stealth_level="quiet"),
        CapabilityView(id="exploit_web", category="exploit", opsec_cost=1.0,
                       detection_risk=0.5, stealth_level="active",
                       effects=("beacon",), goal_facts=("beacon",)),
    ]


def _signals():
    return WorldSignals(visibility=True, noise_ratio=0.2, stage="exploit")


class TestRecordReplay(unittest.TestCase):
    def _bundle(self):
        return replay.record("balanced", _views(),
                             {"scan_tcp": 1.0, "curl_probe": 1.0,
                              "exploit_web": 1.0},
                             _signals(), stage="exploit")

    def test_replay_reproduces_the_trace(self):
        bundle = self._bundle()
        report = replay.verify(bundle)
        self.assertTrue(report.identical, report.explain())
        self.assertEqual(len(report.replayed), len(report.recorded))
        caps = {e.capability for e in report.replayed}
        self.assertEqual(caps, {"scan_tcp", "curl_probe", "exploit_web"})

    def test_replay_is_stable_across_a_json_roundtrip(self):
        import json
        bundle = self._bundle()
        revived = replay.ReplayBundle.from_dict(
            json.loads(json.dumps(bundle.to_dict())))
        report = replay.verify(revived)
        self.assertTrue(report.identical, report.explain())

    def test_two_replays_agree(self):
        bundle = self._bundle()
        first = replay.replay(bundle)
        second = replay.replay(bundle)
        # `ts` is the ONLY by-design non-deterministic field (a clock stamp);
        # every value that drove the decision must reproduce exactly.
        def strip(entries):
            return [{k: v for k, v in e.to_dict().items() if k != "ts"}
                    for e in entries]
        self.assertEqual(strip(first), strip(second))

    def test_a_tampered_driver_is_detected(self):
        bundle = self._bundle()
        self.assertTrue(bundle.trace.get("entries"))
        bundle.trace["entries"][0]["driver"] = "a-lens-that-never-ran"
        report = replay.verify(bundle)
        self.assertFalse(report.identical)
        self.assertTrue(report.differences)
        self.assertIn("driver", report.explain())

    def test_a_dropped_move_is_detected(self):
        bundle = self._bundle()
        bundle.trace["entries"] = bundle.trace["entries"][:-1]
        report = replay.verify(bundle)
        self.assertFalse(report.identical)
        self.assertTrue(any("length" in d for d in report.differences))

    def test_signals_stall_key_is_accepted(self):
        # WorldSignals.to_dict emits "stall"; from_dict must read it back
        signals = _signals()
        data = signals.to_dict()
        self.assertIn("stall", data)
        scenario = replay.ReplayScenario(
            profile="balanced", candidates=[], base_of={}, signals=data)
        self.assertEqual(scenario.build_signals().stall_class,
                         signals.stall_class)


if __name__ == "__main__":
    unittest.main()
