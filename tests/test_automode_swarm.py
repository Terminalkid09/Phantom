"""Tests: swarm as a first-class auto-mode engine (CLI/API/Electron).

engine="agent" (default) is byte-identical to before; engine="swarm"
runs fact-driven tasks over a shared board and merges back into the
manual session. Unknown goals fall back to the agent path loudly.
"""
import asyncio
import os
import tempfile
import unittest
from unittest.mock import Mock, patch

TARGET = "10.0.0.5"


class TestEngineRouting(unittest.TestCase):
    @staticmethod
    def _quiet(am):
        return (
            patch.object(am.notifier, "success"),
            patch.object(am.notifier, "info"),
            patch.object(am.notifier, "warn"),
            patch.object(am.notifier, "error"),
        )

    def test_swarm_engine_runs_tasks_and_merges(self):
        import phantom.core.automode as am
        from phantom.core.session import session
        session.target = ""
        session.scope = []
        summary = {"ok": True,
                   "tasks": [{"id": "footprint-0", "goal": "footprint",
                              "status": "done", "note": "+1 ~0"}],
                   "board": {TARGET: ["service"]}, "added": 1, "skipped": 0,
                   "actions_taken": 3, "trail": [], "failures": [],
                   "evolution_cases": []}
        n = self._quiet(am)
        with n[0], n[1], n[2], n[3], \
                patch.object(am, "_run_swarm_operation",
                             return_value=({"beacon_established": False,
                                            "beacon_id": "",
                                            "persistence_installed": False,
                                            "system_privilege": False,
                                            "ad_creds": 0, "cracked_hashes": 0,
                                            "lateral_movements": 0,
                                            "actions_taken": 3,
                                            "creds_found": 0, "victim_ips": 0,
                                            "hypotheses": 0,
                                            "hypotheses_confirmed": 0,
                                            "stages": {}},
                                           summary, {"10.0.0.5": {}})) as m_swarm, \
                patch.object(am, "_run_agent_single") as m_single, \
                patch.object(am, "_ensure_c2_listener", return_value=True), \
                patch.object(am, "_report_out_dir",
                             return_value=tempfile.mkdtemp()):
            am.run_auto_mode(targets=[TARGET], engine="swarm",
                             goal="footprint")
        m_swarm.assert_called_once()
        m_single.assert_not_called()

    def test_swarm_unknown_goal_falls_back_to_agent(self):
        import phantom.core.automode as am
        from phantom.core.session import session
        session.target = ""
        session.scope = []
        n = self._quiet(am)

        def _result(**kw):
            base = {"beacon_established": False, "beacon_id": "",
                    "persistence_installed": False, "creds_found": 0,
                    "victim_ips": 0, "hypotheses": 0,
                    "hypotheses_confirmed": 0, "actions_taken": 0}
            base.update(kw)
            return base

        agent = Mock()
        with n[0], n[1], n[2], n[3], \
                patch.object(am, "_run_swarm_operation") as m_swarm, \
                patch.object(am, "_run_agent_single",
                             return_value=(_result(), agent)), \
                patch.object(am, "_ensure_c2_listener", return_value=True), \
                patch.object(am, "_report_out_dir",
                             return_value=tempfile.mkdtemp()), \
                patch.object(am, "_write_agent_reports",
                             return_value=("t", {})), \
                patch.object(am, "_merge_results_to_session",
                             return_value={}):
            am.run_auto_mode(targets=[TARGET], engine="swarm",
                             goal="cleanup")
        m_swarm.assert_not_called()

    def test_goal_chain_map_covers_cli_goals(self):
        import phantom.core.automode as am
        for goal in ("footprint", "identity", "creds", "beacon", "deliver",
                     "complete_kill_chain", "deep", "post_exploit", "ad",
                     "crack", "lateral"):
            self.assertIn(goal, am._GOAL_CHAIN, goal)


class TestApiEnginePassthrough(unittest.TestCase):
    _ENV_KEYS = ("PHANTOM_STATE_FILE", "PHANTOM_API_TOKEN",
                 "PHANTOM_C2_KEY", "PHANTOM_C2_NONCE",
                 "PHANTOM_PAYLOAD_TOKEN")

    def setUp(self):
        self._saved_env = {k: os.environ.get(k) for k in self._ENV_KEYS}
        for k in self._ENV_KEYS:
            os.environ.pop(k, None)
        tmp = tempfile.mkdtemp(prefix="phantom-api-engine-")
        os.environ["PHANTOM_STATE_FILE"] = os.path.join(tmp, "state.json")

    def tearDown(self):
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_run_accepts_engine_and_threads_it(self):
        import phantom.api.server as server
        from phantom.utils import c2_crypto
        from aiohttp.test_utils import TestClient, TestServer

        async def scenario():
            client = TestClient(TestServer(server.create_app()))
            await client.start_server()
            try:
                token = c2_crypto.get_api_token()
                headers = {"Authorization": f"Bearer {token}"}
                with patch.object(server, "run_auto_mode",
                                  return_value=None) as m_run:
                    resp = await client.post(
                        "/api/automode/run",
                        json={"targets": [TARGET], "engine": "swarm",
                              "goal": "footprint"},
                        headers=headers)
                    assert resp.status == 200
                    data = await resp.json()
                    assert data["engine"] == "swarm"
                    job = server.auto_jobs.active()
                    assert job is not None
                    deadline = 30
                    while not job.done and deadline > 0:
                        await asyncio.sleep(0.2)
                        deadline -= 0.2
                    assert job.done
                    assert m_run.call_count == 1
                    assert m_run.call_args.kwargs.get("engine") == "swarm"
                    server.auto_jobs._jobs.pop(job.id, None)
                    if server.auto_jobs._active_id == job.id:
                        server.auto_jobs._active_id = None
            finally:
                await client.close()

        asyncio.run(scenario())

    def test_run_rejects_unknown_engine(self):
        import phantom.api.server as server
        from phantom.utils import c2_crypto
        from aiohttp.test_utils import TestClient, TestServer

        async def scenario():
            client = TestClient(TestServer(server.create_app()))
            await client.start_server()
            try:
                token = c2_crypto.get_api_token()
                headers = {"Authorization": f"Bearer {token}"}
                resp = await client.post(
                    "/api/automode/run",
                    json={"targets": [TARGET], "engine": "skynet"},
                    headers=headers)
                return resp.status
            finally:
                await client.close()

        self.assertEqual(asyncio.run(scenario()), 400)


if __name__ == "__main__":
    unittest.main()
