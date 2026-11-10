"""The API's responsiveness and its input/output bounds.

Two defects this pins, both measured on a real server:

* a synchronous module run held aiohttp's only event loop, so a 22 s command
  made `/api/c2/state` exceed the Electron bridge's 15 s timeout and the UI
  reported "C2 unavailable" while the backend was healthy;
* nothing bounded a command, a batch or a tool's output, so one oversized
  request (or one very chatty scan) was copied through the loop, JSON and the
  renderer without a ceiling.
"""
import asyncio
import os
import tempfile
import time
import unittest
from types import SimpleNamespace

from aiohttp.test_utils import TestClient, TestServer

from phantom.api import server as api_server


def _result(stdout="ok", combined=None, error=""):
    text = stdout if combined is None else combined
    return SimpleNamespace(cmd="nmap -Pn 127.0.0.1", stdout=text,
                           stderr="", combined=text, returncode=0,
                           timed_out=False, error=error, duration=0.01)


class _ApiCase(unittest.TestCase):
    _ENV_KEYS = ("PHANTOM_STATE_FILE", "PHANTOM_API_TOKEN",
                 "PHANTOM_C2_KEY", "PHANTOM_C2_NONCE",
                 "PHANTOM_PAYLOAD_TOKEN")

    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in self._ENV_KEYS}
        for key in self._ENV_KEYS:
            os.environ.pop(key, None)
        self._tmp = tempfile.mkdtemp(prefix="phantom-api-hardening-")
        os.environ["PHANTOM_STATE_FILE"] = os.path.join(
            self._tmp, "state.json")

    def tearDown(self):
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def _auth(self):
        from phantom.utils import c2_crypto
        return {"Authorization": f"Bearer {c2_crypto.get_api_token()}"}

    def _run(self, coro):
        return asyncio.run(coro)


class TestEventLoopStaysResponsive(_ApiCase):
    def test_a_long_module_run_does_not_block_other_routes(self):
        original_run = api_server.backend_dispatcher.run_pipeline
        original_gate = api_server._validate_backend_command

        def slow_run(*_args, **_kwargs):
            time.sleep(0.6)
            return _result()

        api_server.backend_dispatcher.run_pipeline = slow_run
        api_server._validate_backend_command = lambda *_a, **_k: None

        async def scenario():
            client = TestClient(TestServer(api_server.create_app()))
            await client.start_server()
            try:
                run = asyncio.create_task(client.post(
                    "/api/modules/web/run",
                    json={"command": "nmap -Pn 127.0.0.1",
                          "target": "127.0.0.1", "timeout": 30},
                    headers=self._auth()))
                await asyncio.sleep(0.1)
                started = time.monotonic()
                poll = await client.get("/api/session", headers=self._auth())
                elapsed = time.monotonic() - started
                ran = await run
                return poll.status, elapsed, ran.status
            finally:
                await client.close()

        try:
            poll_status, elapsed, run_status = self._run(scenario())
        finally:
            api_server.backend_dispatcher.run_pipeline = original_run
            api_server._validate_backend_command = original_gate

        self.assertEqual(poll_status, 200)
        self.assertEqual(run_status, 200)
        # Before the fix this was ~0.6 s (the whole sleep): the event loop was
        # the thing sleeping. A small allowance keeps the test stable on a
        # loaded CI box while still failing if the run is inline again.
        self.assertLess(elapsed, 0.45,
                        f"a read waited {elapsed:.2f}s behind a module run")


class TestInputsAreBounded(_ApiCase):
    def test_an_oversized_command_is_a_json_400(self):
        async def scenario():
            client = TestClient(TestServer(api_server.create_app()))
            await client.start_server()
            try:
                resp = await client.post(
                    "/api/modules/web/run",
                    json={"command": "n" * (api_server.MAX_COMMAND_CHARS + 1)},
                    headers=self._auth())
                return resp.status, await resp.json()
            finally:
                await client.close()

        status, body = self._run(scenario())
        self.assertEqual(status, 400)
        self.assertIn("too long", body["error"])

    def test_an_oversized_group_is_refused_before_running(self):
        async def scenario():
            client = TestClient(TestServer(api_server.create_app()))
            await client.start_server()
            try:
                resp = await client.post(
                    "/api/modules/web/run-group",
                    json={"commands": ["nmap -Pn 127.0.0.1"]
                          * (api_server.MAX_GROUP_COMMANDS + 1)},
                    headers=self._auth())
                return resp.status, await resp.json()
            finally:
                await client.close()

        status, body = self._run(scenario())
        self.assertEqual(status, 400)
        self.assertIn("too many commands", body["error"])

    def test_invalid_json_is_a_json_400_not_an_html_500(self):
        async def scenario():
            client = TestClient(TestServer(api_server.create_app()))
            await client.start_server()
            try:
                resp = await client.post(
                    "/api/modules/web/run", data="{not json",
                    headers={**self._auth(),
                             "Content-Type": "application/json"})
                return resp.status, resp.content_type, await resp.json()
            finally:
                await client.close()

        status, content_type, body = self._run(scenario())
        self.assertEqual(status, 400)
        self.assertEqual(content_type, "application/json")
        self.assertIn("invalid request body", body["error"])


class TestOutputIsBounded(_ApiCase):
    def test_a_huge_tool_output_is_truncated_with_a_flag(self):
        original_run = api_server.backend_dispatcher.run_pipeline
        original_gate = api_server._validate_backend_command
        api_server.backend_dispatcher.run_pipeline = lambda *_a, **_k: _result(
            combined="x" * (api_server.MAX_OUTPUT_CHARS + 50))
        api_server._validate_backend_command = lambda *_a, **_k: None

        async def scenario():
            client = TestClient(TestServer(api_server.create_app()))
            await client.start_server()
            try:
                resp = await client.post(
                    "/api/modules/web/run",
                    json={"command": "nmap -Pn 127.0.0.1"},
                    headers=self._auth())
                return resp.status, await resp.json()
            finally:
                await client.close()

        try:
            status, body = self._run(scenario())
        finally:
            api_server.backend_dispatcher.run_pipeline = original_run
            api_server._validate_backend_command = original_gate

        self.assertEqual(status, 200)
        self.assertTrue(body["truncated"])
        self.assertIn("output truncated", body["combined"])
        # the marker is appended to the capped prefix, not to the whole log
        self.assertLess(len(body["combined"]),
                        api_server.MAX_OUTPUT_CHARS + 100)


class TestVersionIsExposed(_ApiCase):
    def test_capabilities_reports_the_single_version(self):
        from phantom.version import __version__

        async def scenario():
            client = TestClient(TestServer(api_server.create_app()))
            await client.start_server()
            try:
                resp = await client.get("/api/capabilities",
                                        headers=self._auth())
                return resp.status, await resp.json()
            finally:
                await client.close()

        status, body = self._run(scenario())
        self.assertEqual(status, 200)
        self.assertEqual(body["version"], __version__)


class TestWebModuleTargetHandling(unittest.TestCase):
    """A URL is one argv; the shell never sees its `&` or `?`."""

    def test_a_url_with_a_query_string_keeps_its_host_for_scope(self):
        from phantom.modules.web import _web_url
        url, host = _web_url("https://example.test/item?id=1&x=2")
        self.assertEqual(host, "example.test")
        self.assertIn("?id=1&x=2", url)

    def test_an_injected_host_is_refused_before_a_command_is_built(self):
        from phantom.modules.web import _web_url
        with self.assertRaises(ValueError):
            _web_url("http://example.test;rm -rf /")

    def test_an_injected_scheme_is_refused(self):
        from phantom.modules.web import _web_url
        with self.assertRaises(ValueError):
            _web_url("file:///etc/passwd")
