"""Tests: auto-mode stream step mapping (Electron contract).

The 8 fixed steps cover deliver; deep goals (lateral/AD/crack/hunt...)
allocate DYNAMIC steps from index 8 up with a name the panel appends.
Without this the UI froze on PERSIST while the agent kept working.
"""
import asyncio
import json
import unittest


def _run(coro):
    return asyncio.run(coro)


class TestStepMatcher(unittest.TestCase):
    def test_base_map_unchanged(self):
        from phantom.api.server import _match_step
        job = _job()
        try:
            self.assertEqual(_match_step("scan_tcp", job), (0, None))
            self.assertEqual(_match_step("beacon_deploy", job), (6, None))
            self.assertEqual(_match_step("persistence_install", job),
                             (7, None))
            self.assertEqual(_match_step("something_unknown", job),
                             (None, None))
        finally:
            _drop(job)

    def test_dynamic_labels_allocated_in_order(self):
        from phantom.api.server import _match_step
        job = _job()
        try:
            self.assertEqual(_match_step("lateral_pivot", job),
                             (8, "LATERAL"))
            # same label reuses the index (no duplicates)
            self.assertEqual(_match_step("smb_pivot", job), (8, "LATERAL"))
            self.assertEqual(_match_step("kerberoast", job), (9, "AD"))
            self.assertEqual(_match_step("hash_crack", job), (10, "CRACK"))
            self.assertEqual(_match_step("hunt_web", job), (11, "HUNT"))
        finally:
            _drop(job)


def _job():
    from phantom.api.server import auto_jobs
    return auto_jobs.create(["10.0.0.5"], "default", "enterprise", "deep")


def _drop(job):
    from phantom.api.server import auto_jobs
    auto_jobs._jobs.pop(job.id, None)
    if auto_jobs._active_id == job.id:
        auto_jobs._active_id = None


class TestStreamDynamicSteps(unittest.TestCase):
    def test_lateral_emits_named_step_update(self):
        from phantom.api.server import automode_stream
        job = _job()
        try:
            job.callback("run", {"capability": "lateral_pivot"})
            job.callback("found", {"capability": "lateral_pivot",
                                   "findings": ["pivot:ok"]})

            async def scenario():
                resp = await automode_stream(None)
                return json.loads(resp.text)

            data = _run(scenario())
            updates = [u for u in data["step_updates"] if u["step"] == 8]
            self.assertTrue(updates, data["step_updates"])
            self.assertEqual(updates[0]["name"], "LATERAL")
            self.assertIn(updates[0]["status"], ("running", "done"))
            # log lines still flow for unmapped context
            self.assertTrue(data["log"])
        finally:
            _drop(job)


if __name__ == "__main__":
    unittest.main()
