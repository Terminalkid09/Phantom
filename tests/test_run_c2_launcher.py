"""The standalone C2 launcher must not be an unauthenticated control plane.

It used to build its own aiohttp app on `0.0.0.0:8080` with operator endpoints
but no middleware. These tests pin the loopback default and the real auth
middleware without starting a listener.
"""
from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path

import pytest
from aiohttp.test_utils import TestClient, TestServer

ROOT = Path(__file__).resolve().parent.parent
_SPEC = importlib.util.spec_from_file_location("_phantom_run_c2", ROOT / "_run_c2.py")
run_c2 = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(run_c2)


def test_default_bind_is_loopback(monkeypatch):
    monkeypatch.delenv("PHANTOM_C2_BIND", raising=False)
    assert run_c2._bind_host() == "127.0.0.1"


def test_non_loopback_bind_requires_explicit_opt_in(monkeypatch):
    monkeypatch.setenv("PHANTOM_C2_BIND", "0.0.0.0")
    monkeypatch.delenv("PHANTOM_C2_ALLOW_REMOTE", raising=False)
    with pytest.raises(SystemExit, match="PHANTOM_C2_ALLOW_REMOTE"):
        run_c2._bind_host()


def test_non_loopback_bind_is_allowed_with_opt_in(monkeypatch):
    monkeypatch.setenv("PHANTOM_C2_BIND", "0.0.0.0")
    monkeypatch.setenv("PHANTOM_C2_ALLOW_REMOTE", "1")
    assert run_c2._bind_host() == "0.0.0.0"


def test_missing_operator_token_refuses_to_start(monkeypatch):
    monkeypatch.setattr(run_c2.srv, "get_api_token", lambda: "")
    with pytest.raises(SystemExit, match="without an API token"):
        run_c2._require_api_token()


def test_operator_endpoints_require_the_api_token(monkeypatch):
    monkeypatch.setattr(run_c2.srv, "_current_api_token",
                        lambda: "test-operator-token")
    monkeypatch.setattr(run_c2.srv, "use_mtls", lambda: False)

    async def scenario():
        client = TestClient(TestServer(run_c2.build_app()))
        await client.start_server()
        try:
            missing = await client.get("/api/v1/beacons")
            wrong = await client.get(
                "/api/v1/beacons", headers={"X-Api-Token": "wrong"})
            ok = await client.get(
                "/api/v1/beacons",
                headers={"X-Api-Token": "test-operator-token"})
            return missing.status, wrong.status, ok.status
        finally:
            await client.close()

    assert asyncio.run(scenario()) == (403, 403, 200)
