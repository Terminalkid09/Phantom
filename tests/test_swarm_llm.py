"""Tests: LLM on-demand with operator approval (Fase 6).

Default DENIED (transport never touched); approval once/session;
consult output validated (whitelist + registry); failures surface
requests AND suggestions; the API flips approval live mid-run.
"""
import asyncio
import os
import tempfile
import unittest

TARGET = "10.0.0.5"


class TestApprovalGate(unittest.TestCase):
    def test_default_denied(self):
        from phantom.automation.swarm.llm import LLMApproval
        gate = LLMApproval()
        self.assertEqual(gate.state, "denied")
        self.assertFalse(gate.allows())

    def test_transitions(self):
        from phantom.automation.swarm.llm import LLMApproval
        gate = LLMApproval()
        self.assertEqual(gate.approve_session(), "session")
        self.assertTrue(gate.allows())
        self.assertEqual(gate.deny(), "denied")
        self.assertFalse(gate.allows())
        self.assertEqual(gate.approve_once(), "once")
        self.assertTrue(gate.allows())

    def test_once_consumed_by_consult(self):
        from phantom.automation.swarm.llm import LLMApproval, consult
        gate = LLMApproval()
        gate.approve_once()
        consult(None, None, gate, advisor_factory=lambda: _FakeAdvisor([]))
        self.assertEqual(gate.state, "denied")

    def test_requests_recorded_for_operator(self):
        from phantom.automation.swarm.llm import LLMApproval
        gate = LLMApproval()
        rid = gate.request("second opinion on t-0", context="goal=x")
        pending = gate.pending_requests()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["id"], rid)
        self.assertIn("t-0", pending[0]["reason"])

    def test_thread_safety_smoke(self):
        import threading
        from phantom.automation.swarm.llm import LLMApproval
        gate = LLMApproval()
        errors = []

        def hammer(n):
            try:
                for _ in range(50):
                    gate.request(f"r{n}")
                    gate.approve_session()
                    gate.consume()
                    gate.deny()
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=hammer, args=(i,))
                   for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertLessEqual(len(gate.pending_requests()), 20)


class _FakeAdvisor:
    """Advisor double: available iff configured so; suggest() unfiltered
    (the consult path must validate whitelist + registry itself)."""

    def __init__(self, suggestions, available=True):
        self._suggestions = list(suggestions)
        self._available = available
        self.calls = 0

    def available(self):
        return self._available

    def suggest(self, wm, registry=None):
        self.calls += 1
        return list(self._suggestions)


class TestConsult(unittest.TestCase):
    def test_denied_never_touches_transport(self):
        from phantom.automation.swarm.llm import LLMApproval, consult
        gate = LLMApproval()
        advisor = _FakeAdvisor(["scan_tcp"])
        out, why = consult(None, None, gate,
                           advisor_factory=lambda: advisor)
        self.assertEqual((out, why), ([], "denied"))
        self.assertEqual(advisor.calls, 0)

    def test_unavailable_model_reports_cleanly(self):
        from phantom.automation.swarm.llm import LLMApproval, consult
        gate = LLMApproval()
        gate.approve_session()
        out, why = consult(None, None, gate, advisor_factory=lambda:
                           _FakeAdvisor([], available=False))
        self.assertEqual((out, why), ([], "unavailable"))

    def test_advisor_receives_registry_for_validation(self):
        from phantom.automation.swarm.llm import LLMApproval, consult
        gate = LLMApproval()
        gate.approve_session()
        seen = {}

        class _RecordingAdvisor(_FakeAdvisor):
            def suggest(self, wm, registry=None):
                seen["registry"] = registry
                return super().suggest(wm, registry)

        sentinel_registry = object()
        out, why = consult(None, object(), gate,
                           advisor_factory=lambda: _RecordingAdvisor(
                               ["scan_tcp"]),
                           registry=sentinel_registry)
        # the consult hands the REAL registry to the advisor, which is
        # where whitelist+existence validation lives (LLMAdvisor.suggest)
        self.assertIs(seen.get("registry"), sentinel_registry)
        self.assertEqual((out, why), (["scan_tcp"], "consulted"))


def _boom_board():
    from phantom.automation.swarm.board import Board
    board = Board([TARGET])
    orig = Board.snapshot

    def _boom(self, target):
        raise RuntimeError("boom")

    Board.snapshot = _boom
    return orig


class TestSwarmWiring(unittest.TestCase):
    def test_denied_records_request_without_transport(self):
        from unittest.mock import Mock
        from phantom.automation.swarm import run_swarm
        import phantom.automation.swarm.board as board_mod
        orig = _boom_board()
        factory = Mock(side_effect=AssertionError("must not build"))
        try:
            summary = run_swarm([TARGET], chain="footprint", budget=2,
                                advisor_factory=factory)
        finally:
            board_mod.Board.snapshot = orig
        record = summary["failures"][0]
        self.assertTrue(record["llm_requested"])
        self.assertEqual(record["llm_suggestions"], [])
        self.assertEqual(record.get("llm_state"), "denied")
        factory.assert_not_called()

    def test_approved_consult_surfaces_suggestions(self):
        from phantom.automation.swarm import run_swarm
        from phantom.automation.swarm.llm import LLMApproval
        import phantom.automation.swarm.board as board_mod
        orig = _boom_board()
        gate = LLMApproval()
        gate.approve_session()
        advisor = _FakeAdvisor(["scan_tcp"])
        try:
            summary = run_swarm([TARGET], chain="footprint", budget=2,
                                llm_approval=gate,
                                advisor_factory=lambda: advisor)
        finally:
            board_mod.Board.snapshot = orig
        record = summary["failures"][0]
        self.assertEqual(record["llm_suggestions"], ["scan_tcp"])
        self.assertEqual(record.get("llm_state"), "consulted")
        self.assertEqual(advisor.calls, 1)
        self.assertEqual(gate.state, "session")  # session not consumed


class TestLlmEndpoint(unittest.TestCase):
    _ENV_KEYS = ("PHANTOM_STATE_FILE", "PHANTOM_API_TOKEN",
                 "PHANTOM_C2_KEY", "PHANTOM_C2_NONCE",
                 "PHANTOM_PAYLOAD_TOKEN")

    def setUp(self):
        self._saved_env = {k: os.environ.get(k) for k in self._ENV_KEYS}
        for k in self._ENV_KEYS:
            os.environ.pop(k, None)
        tmp = tempfile.mkdtemp(prefix="phantom-api-llm-")
        os.environ["PHANTOM_STATE_FILE"] = os.path.join(tmp, "state.json")

    def tearDown(self):
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    @staticmethod
    def _scenario(coro):
        return asyncio.run(coro)

    def test_llm_approval_flips_live(self):
        from aiohttp.test_utils import TestClient, TestServer
        from phantom.api.server import auto_jobs, create_app
        from phantom.utils import c2_crypto

        async def scenario():
            client = TestClient(TestServer(create_app()))
            await client.start_server()
            try:
                token = c2_crypto.get_api_token()
                headers = {"Authorization": f"Bearer {token}"}
                job = auto_jobs.create(["10.0.0.5"], "default",
                                       "enterprise", "deliver")
                try:
                    r = await client.post("/api/automode/llm",
                                          json={"allow": True},
                                          headers=headers)
                    first = (r.status, await r.json())
                    r = await client.get("/api/automode/status",
                                         headers=headers)
                    status = await r.json()
                    r = await client.post("/api/automode/llm",
                                          json={"allow": False},
                                          headers=headers)
                    second = (r.status, await r.json())
                    r = await client.post("/api/automode/llm",
                                          json={"allow": "maybe"},
                                          headers=headers)
                    third = r.status
                    return first, status, second, third
                finally:
                    auto_jobs._jobs.pop(job.id, None)
                    if auto_jobs._active_id == job.id:
                        auto_jobs._active_id = None
            finally:
                await client.close()

        (first, status, second, third) = self._scenario(scenario())
        self.assertEqual(first[0], 200)
        self.assertEqual(first[1]["llm"], "session")
        self.assertEqual(status["llm"], "session")
        self.assertEqual(second[1]["llm"], "denied")
        self.assertEqual(third, 400)

    def test_llm_flag_preapproves_session(self):
        from phantom.api.server import _preapprove_llm, auto_jobs
        job = auto_jobs.create(["10.0.0.5"], "default", "enterprise",
                               "deliver")
        try:
            self.assertEqual(job.llm_approval.state, "denied")
            _preapprove_llm(job, False)
            self.assertEqual(job.llm_approval.state, "denied")
            _preapprove_llm(job, True)
            self.assertEqual(job.llm_approval.state, "session")
        finally:
            auto_jobs._jobs.pop(job.id, None)
            if auto_jobs._active_id == job.id:
                auto_jobs._active_id = None


if __name__ == "__main__":
    unittest.main()
