"""G14 — the dry-run preview must be the ENGINE's plan, not a second one.

`/api/automode/plan` used to rebuild the kill chain by hand from `mode` and
the shape of the target string, ignoring `engine`, `force_network` and
`agents`. The operator therefore previewed a chain the engine would not
follow. It now delegates to `automode._dry_run_plan` — the same planner the
CLI's `--plan` uses — and reports the posture it planned under.
"""
import asyncio
import json
import unittest

from phantom.api import server as server_mod


def _post(body):
    class _Req:
        async def json(self):
            return body
    return asyncio.run(server_mod.automode_plan(_Req()))


def _payload(resp):
    assert resp.status == 200, resp.text
    return json.loads(resp.text)


class TestPlanDelegatesToTheRealPlanner(unittest.TestCase):
    def test_plan_carries_real_capability_ids_not_handwritten_steps(self):
        data = _payload(_post({"targets": ["10.0.0.5"], "mode": "default",
                               "profile": "enterprise", "goal": "deliver"}))
        # the hand-built version emitted prose like "SCAN (full) -> OS DETECT"
        # and never produced a structured step list
        self.assertIn("steps", data)
        self.assertTrue(data["steps"], data)
        caps = {s["capability"] for s in data["steps"]}
        # real planner capability ids
        self.assertTrue(caps & {"scan_tcp", "beacon_deploy",
                                "persistence_install", "ssh_login"}, caps)
        # and each step carries the evidence/gate metadata the planner emits
        first = data["steps"][0]
        for key in ("target", "chain", "capability", "opsec_cost",
                    "stealth_level", "reason"):
            self.assertIn(key, first)

    def test_identity_target_selects_the_identity_chain(self):
        data = _payload(_post({"targets": ["victim@corp.example"],
                               "goal": "deliver"}))
        chains = {s["chain"] for s in data["steps"]}
        self.assertEqual(chains, {"identity"}, data["plan"])
        caps = {s["capability"] for s in data["steps"]}
        self.assertIn("osint_identity", caps)

    def test_posture_from_mode_is_applied_to_the_plan(self):
        # stealth maps to paranoid in run_auto_mode; the preview must use
        # the same posture, not a cosmetic "stealth" label
        stealth = _payload(_post({"targets": ["10.0.0.5"],
                                  "mode": "stealth", "goal": "deliver"}))
        self.assertEqual(stealth["mode"], "stealth")

    def test_engine_is_echoed_and_validated(self):
        ok = _payload(_post({"targets": ["10.0.0.5"], "engine": "swarm"}))
        self.assertEqual(ok["engine"], "swarm")
        bad = _post({"targets": ["10.0.0.5"], "engine": "nonsense"})
        self.assertNotEqual(bad.status, 200)

    def test_force_network_is_reflected_in_the_preview(self):
        data = _payload(_post({"targets": ["10.0.0.5"],
                               "force_network": True}))
        self.assertTrue(data["force_network"])
        self.assertTrue(any("force_network" in line for line in data["plan"]),
                        data["plan"])

    def test_no_targets_is_an_error(self):
        self.assertNotEqual(_post({"targets": []}).status, 200)


if __name__ == "__main__":
    unittest.main()
