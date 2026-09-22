"""Tests: M3 per-target orchestration (own orchestrator + pool per target).

* every static target gets its own Orchestrator; a shared semaphore
  caps TOTAL concurrent workers operation-wide;
* gates release per origin target (service on T1 does not release T2);
* a multi-target task is done only when every static target delivered;
* auto-mode never overwrites the operator's global session.target;
* module suggest/preflight accept an explicit ?target=/body target
  without moving the global.
"""
import asyncio
import os
import tempfile
import threading
import unittest

T1 = "10.0.0.5"
T2 = "10.0.0.6"


def _board(targets):
    from phantom.automation.swarm.board import Board
    return Board(list(targets))


def _svc():
    return [{"kind": "service", "key": "tcp/80",
             "value": {"port": "80", "service": "http"},
             "confidence": 0.9, "source": "t"}]


class TestPerTargetPools(unittest.TestCase):
    def test_each_target_gets_its_own_orchestrator(self):
        from phantom.automation.belief import WorldModel
        from phantom.automation.orchestrator import Orchestrator
        from phantom.automation.swarm.scheduler import schedule
        from phantom.automation.swarm.tasks import build_tasks
        board = _board([T1, T2])
        tasks = build_tasks("footprint", [T1, T2])
        created = []

        def factory(sem, width):
            orch = Orchestrator(wm=WorldModel(target="swarm"), stealth=None,
                                worker=_commit_service, max_agents=width,
                                global_slot=sem)
            created.append(orch)
            return orch

        def _commit_service(action, ctx):
            board.commit(action.task.id, action.targets[0], _svc())
            action.task.done_targets.add(action.targets[0])
            action.task.status = "done"
            return True

        summary = schedule(None, board, tasks, drain_timeout=10,
                           grouped=True, orch_factory=factory)
        self.assertEqual(len(created), 2)
        self.assertEqual(summary["tasks"][0]["status"], "done")
        self.assertEqual(summary["tasks"][0]["targets_done"], [T1, T2])
        self.assertTrue(board.has(T1, "service"))
        self.assertTrue(board.has(T2, "service"))

    def test_global_ceiling_caps_concurrent_workers(self):
        from phantom.automation.belief import WorldModel
        from phantom.automation.orchestrator import Orchestrator
        from phantom.automation.swarm.scheduler import schedule
        from phantom.automation.swarm.tasks import build_tasks
        board = _board([T1, T2])
        tasks = build_tasks("footprint", [T1, T2])
        live = {"n": 0, "max": 0}
        lock = threading.Lock()

        def worker(action, ctx):
            with lock:
                live["n"] += 1
                live["max"] = max(live["max"], live["n"])
            try:
                import time
                time.sleep(0.3)
            finally:
                with lock:
                    live["n"] -= 1
            action.task.done_targets.add(action.targets[0])
            action.task.status = "done"
            return True

        def factory(sem, width):
            from phantom.automation.orchestrator import Orchestrator
            from phantom.automation.belief import WorldModel
            return Orchestrator(wm=WorldModel(target="swarm"), stealth=None,
                                worker=worker, max_agents=width,
                                global_slot=sem)

        schedule(None, board, tasks, drain_timeout=30, grouped=True,
                 orch_factory=factory, ceiling=1)
        self.assertEqual(live["max"], 1)

    def test_gate_releases_per_origin_only(self):
        from phantom.automation.swarm.board import Board
        from phantom.automation.swarm.scheduler import schedule
        from phantom.automation.swarm.tasks import build_tasks, SwarmTask
        from phantom.automation.belief import WorldModel
        from phantom.automation.orchestrator import Orchestrator
        board = Board([T1, T2])
        board.commit("seed", T1, _svc())  # service ONLY on T1
        task = SwarmTask(id="x-0", goal="footprint", targets=[T1, T2],
                         needs=frozenset({"service"}),
                         provides=frozenset({"service"}))
        ran = []

        def worker(action, ctx):
            ran.append(action.targets[0])
            action.task.done_targets.add(action.targets[0])
            action.task.status = "done"
            return True

        def factory(sem, width):
            return Orchestrator(wm=WorldModel(target="swarm"), stealth=None,
                                worker=worker, max_agents=width,
                                global_slot=sem)

        summary = schedule(None, board, [task], drain_timeout=5,
                           grouped=True, orch_factory=factory)
        self.assertEqual(ran, [T1])
        self.assertEqual(summary["tasks"][0]["targets_done"], [T1])


class TestDynamicOriginPools(unittest.TestCase):
    """A task with target_source (victim IPs from identity/osint) resolves
    EXTRA origins at release time. Each dynamic origin needs its own lazy
    pool; the grouped factory takes (sem, width), so the lazy creation
    path must pass them through (regression: factory() was called with no
    args -> TypeError aborted the whole swarm operation)."""

    VICTIM = "10.0.0.99"

    def test_dynamic_origin_gets_lazy_pool(self):
        from phantom.automation.swarm.board import Board
        from phantom.automation.swarm.scheduler import schedule
        from phantom.automation.swarm.tasks import SwarmTask
        from phantom.automation.belief import WorldModel
        from phantom.automation.orchestrator import Orchestrator

        board = Board([T1])
        board.commit("seed", T1, [
            {"kind": "victim_ip", "key": self.VICTIM,
             "value": {"ip": self.VICTIM},
             "confidence": 0.9, "source": "seed"}])
        task = SwarmTask(id="identity-1", goal="footprint", targets=[T1],
                         needs=frozenset({"victim_ip"}),
                         provides=frozenset({"service"}),
                         target_source="victim_ip")
        created = []

        def worker(action, ctx):
            action.task.done_targets.add(action.targets[0])
            action.task.status = "done"
            return True

        def factory(sem, width):
            orch = Orchestrator(wm=WorldModel(target="swarm"), stealth=None,
                                worker=worker, max_agents=width,
                                global_slot=sem)
            created.append(orch)
            return orch

        schedule(None, board, [task], drain_timeout=5,
                 grouped=True, orch_factory=factory)
        # one pool for the static origin + one for the dynamically
        # resolved victim, created lazily with the shared semaphore
        self.assertEqual(len(created), 2)


class TestNoGlobalOverwrite(unittest.TestCase):
    def test_automode_run_keeps_session_target(self):
        import phantom.api.server as server
        from phantom.core import session as session_mod
        from unittest.mock import patch

        async def scenario():
            from aiohttp.test_utils import TestClient, TestServer
            from phantom.utils import c2_crypto
            client = TestClient(TestServer(server.create_app()))
            await client.start_server()
            try:
                # set AFTER boot: app creation restores the persisted
                # session from disk (pre-existing behavior, unrelated)
                session_mod.session.target = "ORIG-OPERATOR-TARGET"
                session_mod.session.scope = []
                token = c2_crypto.get_api_token()
                headers = {"Authorization": f"Bearer {token}"}
                with patch.object(server, "run_auto_mode",
                                  return_value=None) as m_run:
                    resp = await client.post(
                        "/api/automode/run",
                        json={"targets": ["9.9.9.9"],
                              "goal": "footprint"},
                        headers=headers)
                    assert resp.status == 200
                    job = server.auto_jobs.active()
                    import asyncio as _aio
                    deadline = 30
                    while not job.done and deadline > 0:
                        await _aio.sleep(0.2)
                        deadline -= 0.2
                    assert job.done
                    assert m_run.call_count == 1
                    server.auto_jobs._jobs.pop(job.id, None)
                    if server.auto_jobs._active_id == job.id:
                        server.auto_jobs._active_id = None
            finally:
                await client.close()

        try:
            asyncio.run(scenario())
            self.assertEqual(session_mod.session.target,
                             "ORIG-OPERATOR-TARGET")
        finally:
            session_mod.session.target = ""
            session_mod.session.scope = []


class TestScopedSuggest(unittest.TestCase):
    def test_module_detail_scopes_without_moving_global(self):
        import json
        from unittest.mock import Mock
        from phantom.api.server import module_detail
        from phantom.core import session as session_mod
        session_mod.session.target = "8.8.8.8"
        try:
            req = Mock()
            req.match_info = {"module_name": "scan"}
            req.rel_url.query = {"target": "9.9.9.9"}

            async def scenario():
                resp = await module_detail(req)
                self.assertEqual(resp.status, 200)
                return json.loads(resp.text)

            data = asyncio.run(scenario())
            self.assertEqual(data["target"], "9.9.9.9")
            blob = json.dumps(data["suggestions"])
            self.assertIn("9.9.9.9", blob)
            self.assertEqual(session_mod.session.target, "8.8.8.8")
        finally:
            session_mod.session.target = ""


if __name__ == "__main__":
    unittest.main()
