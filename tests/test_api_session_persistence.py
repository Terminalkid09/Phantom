"""Electron session persistence tests.

Covers the two regressions that made the Electron app lose operator
state:

1. Notes/history added in the UI were local-only and wiped by the 2s
   session poll -> the /api/session/notes and /api/session/history
   routes now persist them into the backend session.
2. The live session was in-memory only, so an app restart lost
   target/scope/notes -> _persist_session/_restore_session mirror it
   to data/sessions/_auto.json.
"""
import asyncio
import os
import tempfile
import unittest

from aiohttp.test_utils import TestClient, TestServer

from phantom.api import server as api_server
from phantom.api.server import create_app
from phantom.core.session import session
from phantom.utils import c2_crypto

_ENV_KEYS = ("PHANTOM_STATE_FILE", "PHANTOM_API_TOKEN",
             "PHANTOM_C2_KEY", "PHANTOM_C2_NONCE",
             "PHANTOM_PAYLOAD_TOKEN", "PHANTOM_DATA_DIR")


class TestApiSessionPersistence(unittest.TestCase):

    def setUp(self):
        self._saved_env = {k: os.environ.get(k) for k in _ENV_KEYS}
        for k in _ENV_KEYS:
            os.environ.pop(k, None)
        self._tmp = tempfile.mkdtemp(prefix="phantom-session-persist-")
        os.environ["PHANTOM_DATA_DIR"] = self._tmp
        os.environ["PHANTOM_STATE_FILE"] = os.path.join(self._tmp, "state.json")
        # isolate the live session object
        session.target = ""
        session.scope = []
        session.lhost = ""
        session.lport = 0
        session.notes = []
        session.history = []
        session.active_wordlist = ""

    def tearDown(self):
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    @staticmethod
    def _scenario(coro):
        return asyncio.run(coro)

    def _auth(self):
        return {"Authorization": f"Bearer {c2_crypto.get_api_token()}"}

    def test_notes_and_history_routes_persist_into_backend(self):
        async def scenario():
            client = TestClient(TestServer(create_app()))
            await client.start_server()
            try:
                h = self._auth()
                r1 = await client.post("/api/session/notes", json={"note": "nota uno"},
                                       headers=h)
                r2 = await client.post("/api/session/history", json={"cmd": "run scan"},
                                       headers=h)
                self.assertEqual(r1.status, 200)
                self.assertEqual(r2.status, 200)
                r3 = await client.get("/api/session", headers=h)
                data = await r3.json()
                self.assertEqual(len(data["notes"]), 1)
                self.assertEqual(data["notes"][0]["text"], "nota uno")
                self.assertEqual(data["history"], ["[%s] run scan" % data["history"][0][1:9]])
                return data
            finally:
                await client.close()

        data = self._scenario(scenario())
        # and they live in the backend session object, not just the response
        self.assertEqual(session.notes[0]["text"], "nota uno")

    def test_notes_route_rejects_empty(self):
        async def scenario():
            client = TestClient(TestServer(create_app()))
            await client.start_server()
            try:
                resp = await client.post("/api/session/notes", json={"note": "   "},
                                         headers=self._auth())
                return resp.status
            finally:
                await client.close()

        self.assertEqual(self._scenario(scenario()), 400)

    def test_auto_persist_roundtrip_after_restart(self):
        """set target -> persist -> wipe live session -> restore: everything
        the operator had set in Electron comes back at boot."""
        session.target = "10.0.0.5"
        session.notes = [{"timestamp": "18:00:00", "text": "nota persistente"}]
        session.scope = ["10.0.0.0/24"]
        api_server._persist_session()

        # simulate an app restart: fresh in-memory session
        session.target = ""
        session.notes = []
        session.scope = []
        api_server._restore_session()

        self.assertEqual(session.target, "10.0.0.5")
        self.assertEqual(session.scope, ["10.0.0.0/24"])
        self.assertEqual(len(session.notes), 1)
        self.assertEqual(session.notes[0]["text"], "nota persistente")

    def test_restore_ignores_missing_file(self):
        session.target = ""
        api_server._restore_session()
        self.assertEqual(session.target, "")

    def test_session_set_persists_to_auto_file(self):
        async def scenario():
            client = TestClient(TestServer(create_app()))
            await client.start_server()
            try:
                resp = await client.post("/api/session/set",
                                         json={"key": "target", "value": "10.0.0.9"},
                                         headers=self._auth())
                self.assertEqual(resp.status, 200)
                return True
            finally:
                await client.close()

        self.assertTrue(self._scenario(scenario()))
        # the target was mirrored to _auto.json by the route itself
        import json
        with open(api_server._auto_session_file(), encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["target"], "10.0.0.9")