"""F-01: rotating the API token must take effect in-process, no restart.

The C2 middleware used to capture ``API_TOKEN`` at import time; after a
rotation the OLD secret kept working (and the new one was rejected) until the
process restarted — a revocation that never revoked. The middleware now reads
the token at call time, so a rotation is authoritative immediately.
"""
import asyncio

import pytest


@pytest.fixture()
def isolated_state(tmp_path, monkeypatch):
    monkeypatch.setenv("PHANTOM_STATE_FILE", str(tmp_path / "state.json"))
    monkeypatch.delenv("PHANTOM_API_TOKEN", raising=False)
    yield


class _Req:
    """Minimal stand-in for ``aiohttp.web.Request`` (path/headers/remote)."""

    def __init__(self, path, token=None):
        self.path = path
        self.headers = {} if token is None else {"X-Api-Token": token}
        self.remote = "127.0.0.1"


async def _ok(_request):
    return "OK"


def _call(mw, req):
    return asyncio.run(mw(req, _ok))


def test_rotation_takes_effect_in_process(isolated_state):
    from phantom.core.c2_server import api_auth_middleware
    from phantom.utils.c2_crypto import get_api_token, regenerate_api_token

    old = get_api_token()
    # baseline: the current token is accepted by the middleware
    assert _call(api_auth_middleware, _Req("/api/v1/beacons", old)) == "OK"

    new = regenerate_api_token()
    assert new and new != old

    # the OLD secret is now rejected ...
    rejected = _call(api_auth_middleware, _Req("/api/v1/beacons", old))
    assert getattr(rejected, "status", None) == 403
    # ... and the NEW one is accepted — all without a process restart
    assert _call(api_auth_middleware, _Req("/api/v1/beacons", new)) == "OK"


def test_unprotected_path_needs_no_token(isolated_state):
    from phantom.core.c2_server import api_auth_middleware

    # a non-control path is never blocked, token or not
    assert _call(api_auth_middleware, _Req("/api/v1/ping")) == "OK"
