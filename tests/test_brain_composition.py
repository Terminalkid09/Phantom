"""Fase 2 gate tests: compositional reasoning.

The acceptance criterion: the engine derives an attack chain that is NOT
in any registry (upload + traversal -> webshell -> RCE), verifies it with
probes, and the loop confirm/refute works with full event provenance.
"""
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.brain.composition import CompositionEngine
from phantom.automation.brain.hypotheses import HypothesisLedger
from phantom.automation.brain.operators import default_operators


def _engine(depth: int = 5):
    reg = default_operators()
    return CompositionEngine(reg, max_depth=depth), reg


class TestComposition(unittest.TestCase):
    def test_derives_unregistered_rce_chain(self):
        """THE gate: from web facts, derive upload->rce (not a registered
        capability — a COMPOSITION of primitives)."""
        eng, _ = _engine()
        comp = eng.search({"web.app", "web.param", "web.upload"}, "rce.web")
        self.assertIsNotNone(comp, "no composition found to rce.web")
        self.assertEqual(comp.describe(), "web.upload_shell -> web.write_rce")
        self.assertLess(comp.total_cost, 4.0)

    def test_derives_cloud_keys_via_ssrf(self):
        eng, _ = _engine()
        comp = eng.search({"web.ssrf"}, "cloud.keys")
        self.assertEqual(comp.describe(),
                         "web.ssrf_meta -> cloud.harvest_keys")

    def test_cross_service_credential_reuse(self):
        eng, _ = _engine()
        comp = eng.search({"web.param", "service.ssh"}, "creds.ssh")
        self.assertEqual(comp.describe(), "web.sqli_read -> ssh.use_creds")

    def test_no_path_from_empty_world(self):
        eng, _ = _engine()
        self.assertIsNone(eng.search(set(), "rce.web"))

    def test_satisfied_goal_is_empty_composition(self):
        eng, _ = _engine()
        comp = eng.search({"creds.any"}, "creds.any")
        self.assertTrue(comp.empty)

    def test_respects_noise_budget(self):
        eng, _ = _engine()
        # upload->rce costs 0.95 noise; a 0.3 budget must forbid it
        comp = eng.search({"web.app", "web.param", "web.upload"}, "rce.web",
                          noise_budget=0.3)
        self.assertTrue(comp is None or comp.total_noise <= 0.3)

    def test_no_operator_repeats_in_chain(self):
        eng, _ = _engine()
        comp = eng.search({"web.app"}, "creds.ssh")
        if comp and not comp.empty:
            ids = [s.op_id for s in comp.steps]
            self.assertEqual(len(ids), len(set(ids)))

    def test_worldmodel_projection(self):
        eng, _ = _engine()
        wm = WorldModel(target="10.0.0.9")
        wm.add_finding("hunt_anomaly", "p", {"class": "sqli"})
        wm.add_finding("service", "tcp/22", {"service": "ssh", "port": 22})
        facts = eng.facts_from_worldmodel(wm)
        self.assertIn("web.param", facts)
        self.assertIn("service.ssh", facts)
        self.assertNotIn("web.upload", facts)


class TestHypothesisLoop(unittest.TestCase):
    def _wm_rich(self) -> WorldModel:
        wm = WorldModel(target="10.0.0.9")
        wm.add_finding("hunt_anomaly", "param",
                       {"class": "sqli", "endpoint": "/item?id=1"})
        wm.add_finding("hunt_anomaly", "upload",
                       {"class": "upload", "endpoint": "/upload"})
        return wm

    def test_propose_probe_confirm(self):
        eng, reg = _engine()
        events = []
        led = HypothesisLedger(reg, on_event=lambda k, d: events.append(k))
        comp = eng.search({"web.app", "web.param", "web.upload"}, "rce.web")
        hyp = led.propose(comp)
        self.assertIsNotNone(hyp)
        self.assertEqual(hyp.status, "proposed")
        led.probe(hyp, self._wm_rich())
        self.assertIn(hyp.status, ("probing", "confirmed"))
        if hyp.status == "probing":
            led.confirm(hyp)
        self.assertEqual(hyp.status, "confirmed")
        self.assertEqual(led.preference_ids(), ["web.upload_shell"])
        for expected in ("hypothesis_proposed", "hypothesis_probing",
                         "hypothesis_confirmed"):
            self.assertIn(expected, events)

    def test_failing_probe_refutes_with_reason(self):
        eng, reg = _engine()
        led = HypothesisLedger(reg)
        # chain that requires web.upload, world lacks it -> refuted
        comp = eng.search({"web.app"}, "rce.web")
        hyp = led.propose(comp)
        led.probe(hyp, WorldModel(target="10.0.0.9"))
        self.assertEqual(hyp.status, "refuted")
        self.assertIn("NOT proven", hyp.verdict_reason)
        self.assertEqual(led.confirmed_chains(), [])

    def test_dedupe_and_bounds(self):
        eng, reg = _engine()
        led = HypothesisLedger(reg, max_open=2)
        comp = eng.search({"web.app", "web.param", "web.upload"}, "rce.web")
        h1 = led.propose(comp)
        self.assertIsNotNone(h1)
        self.assertIsNone(led.propose(comp))     # dedupe
        led.probe(h1, self._wm_rich())
        if h1.status == "probing":
            led.confirm(h1)
        self.assertIsNone(led.propose(comp))     # settled chains dedupe too

    def test_manual_refute_records_reason(self):
        eng, reg = _engine()
        led = HypothesisLedger(reg)
        comp = eng.search({"web.ssrf"}, "cloud.keys")
        hyp = led.propose(comp)
        led.refute(hyp, "metadata endpoint filtered")
        self.assertEqual(hyp.status, "refuted")
        self.assertEqual(hyp.verdict_reason, "metadata endpoint filtered")
        self.assertEqual(led.stats()["refuted"], 1)

    def test_to_dict_shape(self):
        eng, reg = _engine()
        led = HypothesisLedger(reg)
        hyp = led.propose(eng.search({"web.app", "web.param", "web.upload"},
                                     "rce.web"))
        d = hyp.to_dict()
        for key in ("id", "chain", "goal", "status", "confidence"):
            self.assertIn(key, d)


if __name__ == "__main__":
    unittest.main()
