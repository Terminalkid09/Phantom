"""API server bearer-auth tests.

The localhost API must reject every request without a valid
`Authorization: Bearer <PHANTOM_API_TOKEN>` header so that other local
processes or malicious websites cannot read engagement data or revoke
beacon identities. OPTIONS preflight stays exempt for the CORS handshake.
"""
import asyncio
import os
import tempfile
import unittest

from aiohttp.test_utils import TestClient, TestServer

from phantom.api.server import create_app
from phantom.utils import c2_crypto

REAL_ROUTE = "/api/c2/beacon-auth"


class TestApiAuth(unittest.TestCase):
    # Env overrides win over the state file (documented), so tests must
    # isolate PHANTOM_* env vars (e.g. an operator .env may set the token).
    _ENV_KEYS = ("PHANTOM_STATE_FILE", "PHANTOM_API_TOKEN",
                 "PHANTOM_C2_KEY", "PHANTOM_C2_NONCE",
                 "PHANTOM_PAYLOAD_TOKEN")

    def setUp(self):
        self._saved_env = {k: os.environ.get(k) for k in self._ENV_KEYS}
        for k in self._ENV_KEYS:
            os.environ.pop(k, None)
        tmp = tempfile.mkdtemp(prefix="phantom-api-auth-")
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

    def test_401_without_token(self):
        async def scenario():
            client = TestClient(TestServer(create_app()))
            await client.start_server()
            try:
                return (await client.get(REAL_ROUTE)).status
            finally:
                await client.close()

        self.assertEqual(self._scenario(scenario()), 401)

    def test_401_with_wrong_token(self):
        async def scenario():
            client = TestClient(TestServer(create_app()))
            await client.start_server()
            try:
                return (await client.get(
                    REAL_ROUTE,
                    headers={"Authorization": "Bearer wrong-token"})).status
            finally:
                await client.close()

        self.assertEqual(self._scenario(scenario()), 401)

    def test_200_with_valid_token(self):
        async def scenario():
            client = TestClient(TestServer(create_app()))
            await client.start_server()
            try:
                token = c2_crypto.get_api_token()
                resp = await client.get(
                    REAL_ROUTE, headers={"Authorization": f"Bearer {token}"})
                return resp.status
            finally:
                await client.close()

        self.assertEqual(self._scenario(scenario()), 200)

    def test_options_preflight_exempt(self):
        async def scenario():
            client = TestClient(TestServer(create_app()))
            await client.start_server()
            try:
                return (await client.options(REAL_ROUTE)).status
            finally:
                await client.close()

        self.assertNotEqual(self._scenario(scenario()), 401)

    def test_rotation_invalidates_old_token(self):
        async def scenario():
            client = TestClient(TestServer(create_app()))
            await client.start_server()
            try:
                old = c2_crypto.get_api_token()
                new = c2_crypto.regenerate_api_token()
                old_status = (await client.get(
                    REAL_ROUTE, headers={"Authorization": f"Bearer {old}"})).status
                new_status = (await client.get(
                    REAL_ROUTE, headers={"Authorization": f"Bearer {new}"})).status
                return old_status, new_status
            finally:
                await client.close()

        old, new = self._scenario(scenario())
        self.assertEqual(old, 401)
        self.assertEqual(new, 200)


if __name__ == "__main__":
    unittest.main()