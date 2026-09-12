"""Fase 4 gate tests: generative fuzzing with differential oracles."""
import unittest

from phantom.automation.brain.fuzz.engine import FuzzEngine
from phantom.automation.brain.fuzz.grammar import Grammar, Mutation
from phantom.automation.brain.fuzz.oracles import DifferentialOracle, Response


class TestGrammar(unittest.TestCase):
    def test_seed_payloads_cover_families(self):
        g = Grammar(families=["sqli", "path"])
        seeds = g.seed_payloads(["id"])
        families = {m.family for m in seeds}
        self.assertEqual(families, {"sqli", "path"})

    def test_evolution_increments_generation(self):
        g = Grammar(seed=1)
        seeds = g.seed_payloads(["id"])
        evolved = g.evolve(seeds[:2])
        self.assertTrue(all(m.generation == 1 for m in evolved))
        self.assertTrue(all(m.parent for m in evolved))

    def test_mutations_change_payload(self):
        g = Grammar(seed=7)
        base = "' OR '1'='1"
        mutated = {g._mutate(base) for _ in range(12)}
        # at least some mutations actually differ (stochastic ops)
        self.assertTrue(any(m != base for m in mutated))


class TestOracles(unittest.TestCase):
    def setUp(self):
        self.o = DifferentialOracle()

    def test_error_based_sqli(self):
        base = Response(status=200, body="welcome")
        mut = Response(status=200, body="Warning: mysql_fetch_array():")
        v = self.o.evaluate(base, mut)
        self.assertTrue(v.interesting)
        self.assertEqual(v.family_hint, "sqli")

    def test_no_error_in_baseline_is_required(self):
        # an error ALREADY in the baseline is not a finding
        base = Response(status=200, body="Warning: mysql_fetch_array():")
        mut = Response(status=200, body="Warning: mysql_fetch_array(): more")
        self.assertFalse(self.o.evaluate(base, mut).interesting)

    def test_path_content_oracle(self):
        base = Response(status=200, body="index")
        mut = Response(status=200, body="root:x:0:0:root:/root:/bin/bash")
        v = self.o.evaluate(base, mut)
        self.assertTrue(v.interesting)
        self.assertEqual(v.family_hint, "path")

    def test_time_based_oracle(self):
        v = self.o.evaluate(Response(status=200, body="ok", elapsed=0.1),
                            Response(status=200, body="ok", elapsed=2.0))
        self.assertTrue(v.interesting)
        self.assertEqual(v.oracle, "time_based")

    def test_waf_boundary_is_informative_not_fatal(self):
        v = self.o.evaluate(Response(status=200, body="page"),
                            Response(status=403, body="blocked"))
        self.assertTrue(v.interesting)
        self.assertEqual(v.oracle, "filter_boundary")

    def test_clean_response_not_interesting(self):
        v = self.o.evaluate(Response(status=200, body="page", elapsed=0.1),
                            Response(status=200, body="page!", elapsed=0.12))
        self.assertFalse(v.interesting)


class TestFuzzDriver(unittest.TestCase):
    def _engine(self, sender, **kw):
        return FuzzEngine(sender, rounds=kw.get("rounds", 2),
                          max_requests=kw.get("max_requests", 40),
                          seed=42)

    def test_finds_time_based_sqli(self):
        def sender(param, payload):
            if param == "id" and "WAITFOR" in payload:
                return Response(status=200, body="ok", elapsed=2.2)
            return Response(status=200, body="ok", elapsed=0.08)
        eng = self._engine(sender)
        findings = eng.run(["id", "q"])
        self.assertTrue(any(f.verdict.oracle == "time_based" and
                            f.mutation.param == "id" for f in findings))
        self.assertLessEqual(eng.requests_sent, 40)

    def test_request_budget_is_hard(self):
        def sender(param, payload):
            return Response(status=200, body="x" * 500)   # big diff always
        eng = self._engine(sender, rounds=3, max_requests=10)
        eng.run(["a", "b", "c", "d"])
        self.assertLessEqual(eng.requests_sent, 10)

    def test_sender_exceptions_do_not_crash(self):
        def sender(param, payload):
            raise ConnectionError("boom")
        eng = self._engine(sender, max_requests=10)
        self.assertEqual(eng.run(["a"]), [])

    def test_projection_feeds_composition(self):
        from phantom.automation.brain.fuzz.oracles import Verdict
        findings = [FuzzEngine.__init__ and
                    type("F", (), {"mutation": Mutation("sqli", "x", "id"),
                                   "verdict": Verdict("error_based", True,
                                                      "mysql", "sqli"),
                                   "baseline_status": 200,
                                   "mutated_status": 500})()]
        facts = FuzzEngine.to_composition_facts(findings)
        self.assertTrue(any(t == "web.param" for t, _ in facts))

    def test_fuzz_findings_to_dict(self):
        def sender(param, payload):
            if param == "id" and "'" in payload:
                return Response(status=500, body="Unclosed quotation mark",
                                elapsed=0.1)
            return Response(status=200, body="ok", elapsed=0.05)
        eng = self._engine(sender, max_requests=20)
        findings = eng.run(["id"])
        self.assertTrue(findings)
        d = findings[0].to_dict()
        for key in ("family", "param", "oracle"):
            self.assertIn(key, d)


if __name__ == "__main__":
    unittest.main()
