"""Tests for the capability registry (phantom/core/capabilities.py) and the
`GET /api/capabilities` endpoint.

This is the feature-gating seam of the modular monolith: a build shipping
only the manual core must announce core=true, c2/automode=false, so the
single Electron shell disables the absent sections instead of calling a
route that does not exist.
"""
import asyncio
import os
import unittest
from contextlib import contextmanager


@contextmanager
def _components(value):
    """Set PHANTOM_COMPONENTS for the duration of the block (or unset it)."""
    saved = os.environ.get("PHANTOM_COMPONENTS")
    try:
        if value is None:
            os.environ.pop("PHANTOM_COMPONENTS", None)
        else:
            os.environ["PHANTOM_COMPONENTS"] = value
        yield
    finally:
        if saved is None:
            os.environ.pop("PHANTOM_COMPONENTS", None)
        else:
            os.environ["PHANTOM_COMPONENTS"] = saved


class TestCapabilityRegistry(unittest.TestCase):
    def test_default_reports_every_component_available(self):
        from phantom.core import capabilities as caps
        with _components(None):
            avail = caps.available()
        self.assertEqual(set(avail), set(caps.COMPONENTS))
        self.assertTrue(avail["core"])
        self.assertTrue(avail["c2"])
        self.assertTrue(avail["automode"])

    def test_allowlist_ships_only_core(self):
        from phantom.core import capabilities as caps
        with _components("core"):
            avail = caps.available()
            names = caps.enabled_names()
        self.assertTrue(avail["core"])          # kernel is never absent
        self.assertFalse(avail["c2"])
        self.assertFalse(avail["automode"])
        self.assertEqual(names, ["core"])

    def test_allowlist_is_case_insensitive_and_trims(self):
        from phantom.core import capabilities as caps
        with _components("  CORE , c2 "):
            self.assertEqual(set(caps.enabled_names()), {"core", "c2"})

    def test_is_enabled_unknown_component_is_false(self):
        from phantom.core import capabilities as caps
        with _components(None):
            self.assertFalse(caps.is_enabled("nope"))


class TestCapabilitiesEndpoint(unittest.TestCase):
    def _get(self, path="/api/capabilities"):
        import phantom.api.server as server
        from phantom.utils import c2_crypto

        async def scenario():
            from aiohttp.test_utils import TestClient, TestServer
            client = TestClient(TestServer(server.create_app()))
            await client.start_server()
            try:
                token = c2_crypto.get_api_token()
                resp = await client.get(
                    path, headers={"Authorization": f"Bearer {token}"})
                return resp.status, await resp.json()
            finally:
                await client.close()

        return asyncio.run(scenario())

    def test_endpoint_announces_capabilities(self):
        from phantom.core.capabilities import COMPONENTS
        with _components(None):
            status, data = self._get()
        self.assertEqual(status, 200)
        self.assertEqual(set(data["capabilities"]), set(COMPONENTS))
        self.assertEqual(data["components"], list(COMPONENTS))

    def test_endpoint_reflects_core_only_build(self):
        with _components("core"):
            status, data = self._get()
        self.assertEqual(status, 200)
        self.assertTrue(data["capabilities"]["core"])
        self.assertFalse(data["capabilities"]["automode"])

    def test_endpoint_requires_auth(self):
        import phantom.api.server as server

        async def scenario():
            from aiohttp.test_utils import TestClient, TestServer
            client = TestClient(TestServer(server.create_app()))
            await client.start_server()
            try:
                resp = await client.get("/api/capabilities")
                return resp.status
            finally:
                await client.close()

        self.assertEqual(asyncio.run(scenario()), 401)


if __name__ == "__main__":
    unittest.main()
