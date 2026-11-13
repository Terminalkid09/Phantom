"""The planner ranker: corpus, gate, runtime features, and the wiring bug.

The model is only useful if the runtime scores it with the SAME features the
trainer used and actually passes the decision context. Both were wrong in the
first wiring: the advisor called ``score(cid, {})`` and ``rank(ids)`` with no
context, so every interaction weight was multiplied by zero and a promoted
model behaved like a frozen id order.
"""

from __future__ import annotations

import json
import types
import unittest
from pathlib import Path
from unittest import mock

from phantom.automation.ai import linear, planner_features
from phantom.automation.ai.registry import ModelRegistry, manifest_errors
from training import planner_ranker, planner_vocab


ROOT = Path(__file__).resolve().parents[1]


def _row(**overrides):
    payload = {
        "fact": "service",
        "goal": "footprint",
        "profile": "enterprise",
        "noise_breaker": False,
        "known_facts": [],
        "candidates": [
            {"id": "scan_tcp", "category": "recon",
             "stealth_level": "active", "opsec_cost": 2.0,
             "detection_risk": 0.35, "forceful": False,
             "effects": ["service"]},
            {"id": "external_recon", "category": "recon",
             "stealth_level": "passive", "opsec_cost": 0.1,
             "detection_risk": 0.0, "forceful": False,
             "effects": ["service", "hostname"]},
        ],
        "already_tried": [],
    }
    payload.update(overrides)
    return {"phase": "planner", "input": payload,
            "expected": {"ranking": ["scan_tcp", "external_recon"]},
            "baseline": {"ranking": ["scan_tcp", "external_recon"]}}


class CorpusTests(unittest.TestCase):
    def test_corpus_is_scoreable_and_has_a_static_baseline(self):
        rows = planner_vocab.build_rows()
        self.assertGreaterEqual(len(rows), 40)
        for row in rows:
            self.assertGreaterEqual(
                len(row["input"]["candidates"]), 2,
                f"{row['id']} is not an ordering")
            self.assertTrue(row["expected"]["ranking"])
            self.assertTrue(row["baseline"]["ranking"])
            self.assertEqual(
                set(row["expected"]["ranking"]),
                {c["id"] for c in row["input"]["candidates"]})

    def test_the_rubric_is_context_sensitive(self):
        """Stealth must reorder the same candidates the static index freezes."""
        rows = planner_vocab.build_rows()
        service = [row for row in rows
                   if row["input"]["fact"] == "service"]
        enterprise = next(row for row in service
                          if row["input"]["profile"] == "enterprise")
        stealth = next(row for row in service
                       if row["input"]["profile"] == "stealth")
        self.assertNotEqual(enterprise["expected"]["ranking"],
                            stealth["expected"]["ranking"])
        self.assertEqual(stealth["expected"]["ranking"][0],
                         "external_recon")


class GateTests(unittest.TestCase):
    def test_training_is_deterministic(self):
        rows = [_row(), _row(profile="stealth",
                             expected={"ranking": ["external_recon",
                                                   "scan_tcp"]})]
        first = planner_ranker.train(rows, epochs=40)
        second = planner_ranker.train(rows, epochs=40)
        self.assertEqual(first, second)
        model = planner_ranker.to_dict(first, "t")
        self.assertEqual(model["weights"], {})
        self.assertTrue(model["context"])
        self.assertIn("goal=footprint|id:scan_tcp", model["context"])


class RuntimeTests(unittest.TestCase):
    def test_promoted_manifest_is_installed_and_verified(self):
        manifest = ModelRegistry().promoted("planner")
        self.assertIsInstance(manifest, dict)
        self.assertEqual(manifest_errors(manifest, "planner",
                                         ROOT), [])
        self.assertEqual(manifest["kind"], "linear-ranker")
        self.assertTrue(manifest["eval_gate"]["verdict"] == "promote")

    def test_runtime_and_training_scores_agree_on_a_golden_row(self):
        row = next(iter(planner_ranker.load_rows()))
        weights = json.loads(
            (ROOT / "models" / "planner" / "planner-2026-11-08"
             / "ranker.json").read_text(encoding="utf-8"))
        ranker = linear.LinearRanker.from_dict(weights)
        contexts = planner_features.contexts(row["input"])
        ids = [c["id"] for c in row["input"]["candidates"]]
        self.assertEqual(ranker.rank(ids, contexts=contexts),
                         planner_ranker.rank(
                             {k: v for k, v in weights["context"].items()},
                             row["input"]))

    def test_advisor_passes_the_per_candidate_context(self):
        """The exact regression: an empty dict made every context weight dead."""
        from phantom.automation.ai.advisors import planning

        calls = {}

        class FakeRanker:
            version = "fake"

            def rank(self, ids, context=None, contexts=None):
                calls["contexts"] = contexts
                return list(reversed(ids))

            def score(self, cid, context):
                return float(len(context))

        def cap(cid, category, stealth, effects):
            return types.SimpleNamespace(
                id=cid, category=category, stealth_level=stealth,
                opsec_cost=0.5, detection_risk=0.1, forceful=False,
                effects=effects)

        caps = [cap("scan_tcp", "recon", "active", ["service"]),
                cap("external_recon", "recon", "passive",
                    ["service", "hostname"])]
        wm = types.SimpleNamespace(
            goal="footprint", profile="stealth", target_type="ip",
            findings=[], actions_taken=[], noise_breaker_tripped=lambda: False)
        with mock.patch("phantom.automation.ai.config.mode",
                        return_value="integrated"), \
                mock.patch.object(linear, "promoted",
                                  return_value=FakeRanker()):
            proposals = planning.propose(wm, "service", caps, goal="footprint")

        self.assertTrue(calls["contexts"])
        self.assertIn("scan_tcp", calls["contexts"])
        self.assertIn("goal=footprint|id:scan_tcp",
                      calls["contexts"]["scan_tcp"])
        self.assertEqual([p.capability_id for p in proposals],
                         ["external_recon", "scan_tcp"])


if __name__ == "__main__":
    unittest.main()
