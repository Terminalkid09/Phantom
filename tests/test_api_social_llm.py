"""Route tests for the two new surfaces: identity graph + email gate, and the
LLM proposal queue.

These run the real aiohttp app (bearer token included) because the point of the
test is the CONTRACT the Electron panel consumes: shape of the JSON, and the
fact that the mutating routes refuse without an explicit confirm.
"""
import asyncio
import os
import tempfile
import unittest

from aiohttp.test_utils import TestClient, TestServer

from phantom.api.server import create_app
from phantom.utils import c2_crypto

_ENV_KEYS = ("PHANTOM_STATE_FILE", "PHANTOM_API_TOKEN", "PHANTOM_C2_KEY",
             "PHANTOM_C2_NONCE", "PHANTOM_PAYLOAD_TOKEN")


class _ApiCase(unittest.TestCase):
    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in _ENV_KEYS}
        for k in _ENV_KEYS:
            os.environ.pop(k, None)
        os.environ["PHANTOM_STATE_FILE"] = os.path.join(
            tempfile.mkdtemp(prefix="phantom-api-social-"), "state.json")

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def _run(self, coro):
        return asyncio.run(coro)

    @staticmethod
    def _headers():
        return {"Authorization": f"Bearer {c2_crypto.get_api_token()}"}


class TestSocialRoutes(_ApiCase):
    def test_graph_returns_nodes_edges_stats_and_graphml(self):
        async def scenario():
            client = TestClient(TestServer(create_app()))
            await client.start_server()
            try:
                resp = await client.get("/api/social/graph",
                                        headers=self._headers())
                return resp.status, await resp.json()
            finally:
                await client.close()

        status, payload = self._run(scenario())
        assert status == 200
        assert set(payload) >= {"graph", "text", "graphml", "pivots", "topics"}
        assert "nodes" in payload["graph"] and "edges" in payload["graph"]
        assert "stats" in payload["graph"]
        assert payload["graphml"].startswith("<?xml")

    def test_the_email_plan_names_the_services_and_the_urls(self):
        async def scenario():
            client = TestClient(TestServer(create_app()))
            await client.start_server()
            try:
                resp = await client.get(
                    "/api/social/emails/plan?email=person@example.com",
                    headers=self._headers())
                return resp.status, await resp.json()
            finally:
                await client.close()

        status, payload = self._run(scenario())
        assert status == 200 and payload["ok"] is True
        assert payload["masked"] == "p*****@example.com"
        assert payload["plan"] and "url" in payload["plan"][0]
        assert "person@example.com" not in payload["masked"]

    def test_the_plan_refuses_a_non_address(self):
        async def scenario():
            client = TestClient(TestServer(create_app()))
            await client.start_server()
            try:
                resp = await client.get("/api/social/emails/plan?email=nope",
                                        headers=self._headers())
                return resp.status
            finally:
                await client.close()

        assert self._run(scenario()) == 400

    def test_enumeration_without_confirm_asks_nothing_and_returns_the_plan(self):
        """The load-bearing property: opening a panel cannot touch a service."""
        async def scenario():
            client = TestClient(TestServer(create_app()))
            await client.start_server()
            try:
                resp = await client.post(
                    "/api/social/emails",
                    json={"email": "person@example.com"},
                    headers=self._headers())
                return resp.status, await resp.json()
            finally:
                await client.close()

        status, payload = self._run(scenario())
        assert status == 200 and payload["ok"] is False
        assert "confirm=true" in payload["message"]
        assert payload["plan"]

    def test_enumeration_with_confirm_runs_and_reports_verdicts(self):
        """confirm=true is the operator's decision: the route then asks. The
        fake transport keeps this offline."""
        from phantom.automation.social import email_enum as ee
        original = ee.fetch_with_status
        ee.fetch_with_status = lambda url, timeout=12.0: (
            200, '{"total_count":1}' if "github" in url else "nothing")
        try:
            async def scenario():
                client = TestClient(TestServer(create_app()))
                await client.start_server()
                try:
                    resp = await client.post(
                        "/api/social/emails",
                        json={"email": "person@example.com", "confirm": True,
                              "services": ["github"]},
                        headers=self._headers())
                    return resp.status, await resp.json()
                finally:
                    await client.close()

            status, payload = self._run(scenario())
        finally:
            ee.fetch_with_status = original
        assert status == 200 and payload["ok"] is True
        assert payload["report"]["registered"] == ["github"]
        assert "person@example.com" not in payload["text"]


class TestLlmProposalRoutes(_ApiCase):
    def _clear(self):
        from phantom.automation import llm_proposals
        llm_proposals.queue.clear()

    def test_journal_and_proposals_start_readable_and_empty(self):
        async def scenario():
            client = TestClient(TestServer(create_app()))
            await client.start_server()
            try:
                journal = await client.get("/api/llm/journal",
                                           headers=self._headers())
                proposals = await client.get("/api/llm/proposals",
                                             headers=self._headers())
                return (journal.status, await journal.json(), proposals.status,
                        await proposals.json())
            finally:
                await client.close()

        j_status, journal, p_status, proposals = self._run(scenario())
        assert j_status == 200 and "stats" in journal and "text" in journal
        assert p_status == 200 and "proposals" in proposals
        assert "stats" in proposals

    def test_rejecting_a_queued_proposal_works_over_the_api(self):
        self._clear()
        from phantom.automation import llm_proposals
        prop = llm_proposals.queue.propose(command="nmap -sV 10.0.0.5",
                                           why="version scan")

        async def scenario():
            client = TestClient(TestServer(create_app()))
            await client.start_server()
            try:
                resp = await client.post(
                    "/api/llm/proposals",
                    json={"action": "reject", "id": prop.id,
                          "reason": "too loud"},
                    headers=self._headers())
                return resp.status, await resp.json()
            finally:
                await client.close()

        status, payload = self._run(scenario())
        assert status == 200 and payload["ok"] is True
        assert llm_proposals.queue.get(prop.id).state == "refused"
        assert llm_proposals.queue.get(prop.id).decision_reason == "too loud"
        self._clear()

    def test_accepting_without_a_target_refuses_and_records_the_reason(self):
        self._clear()
        from phantom.automation import llm_proposals
        from phantom.core.session import session
        from phantom.core import executor
        original_target = session.target
        original_runner = executor.run_command
        executor.run_command = lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("must not execute without a target"))
        try:
            prop = llm_proposals.queue.propose(command="nmap 10.0.0.5")

            async def scenario():
                client = TestClient(TestServer(create_app()))
                await client.start_server()
                try:
                    # the app restores a persisted session on startup, so the
                    # target is cleared AFTER it, which is the state this test
                    # is about
                    session.target = ""
                    resp = await client.post(
                        "/api/llm/proposals",
                        json={"action": "accept", "id": prop.id},
                        headers=self._headers())
                    return resp.status, await resp.json()
                finally:
                    await client.close()

            status, payload = self._run(scenario())
            assert status == 200 and payload["ok"] is False
            assert "no target" in payload["message"]
            assert llm_proposals.queue.get(prop.id).executed is True
            assert llm_proposals.queue.get(prop.id).result_ok is False
        finally:
            session.target = original_target
            executor.run_command = original_runner
            self._clear()

    def test_accepting_with_a_target_runs_through_the_executor(self):
        self._clear()
        from phantom.automation import llm_proposals
        from phantom.core.session import session
        from phantom.core import executor
        original_target, original_runner = session.target, executor.run_command
        original_scope = session.scope
        seen = {}
        executor.run_command = lambda cmd, target, status=None: seen.update(
            {"cmd": cmd, "target": target}) or "ok output"
        try:
            prop = llm_proposals.queue.propose(command="nmap -sV 10.0.0.5")

            async def scenario():
                client = TestClient(TestServer(create_app()))
                await client.start_server()
                try:
                    # after the startup session restore, so the engagement
                    # state is the one this test asserts on
                    session.target = "10.0.0.5"
                    session.scope = []
                    resp = await client.post(
                        "/api/llm/proposals",
                        json={"action": "accept", "id": prop.id},
                        headers=self._headers())
                    return resp.status, await resp.json()
                finally:
                    await client.close()

            status, payload = self._run(scenario())
            assert status == 200 and payload["ok"] is True
            assert seen == {"cmd": "nmap -sV 10.0.0.5", "target": "10.0.0.5"}
            assert payload["output"] == "ok output"
        finally:
            session.target, session.scope = original_target, original_scope
            executor.run_command = original_runner
            self._clear()

    def test_an_unknown_action_is_rejected(self):
        async def scenario():
            client = TestClient(TestServer(create_app()))
            await client.start_server()
            try:
                resp = await client.post("/api/llm/proposals",
                                         json={"action": "explode"},
                                         headers=self._headers())
                return resp.status
            finally:
                await client.close()

        assert self._run(scenario()) == 400


if __name__ == "__main__":
    unittest.main()
