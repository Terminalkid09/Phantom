"""Tests for the Electron .pm bundle API: list / export / import — the
Session Bundles tab contract (auto-export on app close is exercised by
the main-process code, the API here is its backend half)."""
import asyncio
import os
import tempfile
import unittest

from aiohttp.test_utils import TestClient, TestServer

from phantom.api.server import create_app
from phantom.core.session import session
from phantom.utils import c2_crypto

_ENV_KEYS = ("PHANTOM_STATE_FILE", "PHANTOM_API_TOKEN",
             "PHANTOM_C2_KEY", "PHANTOM_C2_NONCE",
             "PHANTOM_PAYLOAD_TOKEN", "PHANTOM_DATA_DIR")


class TestPmApi(unittest.TestCase):

    def setUp(self):
        self._saved_env = {k: os.environ.get(k) for k in _ENV_KEYS}
        for k in _ENV_KEYS:
            os.environ.pop(k, None)
        self._tmp = tempfile.mkdtemp(prefix="phantom-pm-api-")
        os.environ["PHANTOM_DATA_DIR"] = self._tmp
        os.environ["PHANTOM_STATE_FILE"] = os.path.join(self._tmp, "state.json")
        session.target = ""
        session.scope = []
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

    def test_export_then_list_then_import(self):
        session.target = "10.0.0.7"
        session.scope = ["10.0.0.0/24"]
        session.notes = [{"timestamp": "10:00:00", "text": "engagement note"}]

        async def scenario():
            client = TestClient(TestServer(create_app()))
            await client.start_server()
            try:
                h = self._auth()
                r1 = await client.post("/api/pm/export", json={"name": "test_engagement"},
                                       headers=h)
                self.assertEqual(r1.status, 200)
                d1 = await r1.json()
                self.assertEqual(d1["status"], "exported")
                self.assertTrue(d1["path"].endswith(".pm"))
                self.assertTrue(os.path.isfile(d1["path"]))

                r2 = await client.get("/api/pm/list", headers=h)
                self.assertEqual(r2.status, 200)
                d2 = await r2.json()
                names = [b["name"] for b in d2["bundles"]]
                self.assertIn("test_engagement.pm", names)
                bundle = next(b for b in d2["bundles"]
                              if b["name"] == "test_engagement.pm")
                self.assertEqual(bundle["target"], "10.0.0.7")

                # wipe live state, import restores it
                session.target = ""
                session.scope = []
                session.notes = []
                r3 = await client.post("/api/pm/import",
                                       json={"name": "test_engagement.pm"}, headers=h)
                self.assertEqual(r3.status, 200)
                d3 = await r3.json()
                self.assertEqual(d3["status"], "imported")
                self.assertEqual(d3["target"], "10.0.0.7")
                self.assertEqual(session.target, "10.0.0.7")
                self.assertEqual(session.scope, ["10.0.0.0/24"])
                self.assertEqual(len(session.notes), 1)
                return True
            finally:
                await client.close()

        self.assertTrue(self._scenario(scenario()))

    def test_import_missing_bundle_is_404(self):
        async def scenario():
            client = TestClient(TestServer(create_app()))
            await client.start_server()
            try:
                resp = await client.post("/api/pm/import",
                                         json={"name": "no_such.pm"},
                                         headers=self._auth())
                return resp.status
            finally:
                await client.close()

        self.assertEqual(self._scenario(scenario()), 404)

    def test_import_rejects_empty_name(self):
        async def scenario():
            client = TestClient(TestServer(create_app()))
            await client.start_server()
            try:
                resp = await client.post("/api/pm/import", json={"name": ""},
                                         headers=self._auth())
                return resp.status
            finally:
                await client.close()

        self.assertEqual(self._scenario(scenario()), 400)

    def test_list_endpoint_without_bundles_is_empty(self):
        async def scenario():
            client = TestClient(TestServer(create_app()))
            await client.start_server()
            try:
                resp = await client.get("/api/pm/list", headers=self._auth())
                self.assertEqual(resp.status, 200)
                d = await resp.json()
                return d["bundles"]
            finally:
                await client.close()

        self.assertEqual(self._scenario(scenario()), [])


if __name__ == "__main__":
    unittest.main()
