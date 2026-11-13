"""C2State integration checks for enrolled beacon request authentication."""
import os
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

from phantom.core.c2_server import C2State
from phantom.utils.beacon_auth import enroll_beacon, sign_request


def _request(headers, body):
    return SimpleNamespace(
        headers=headers,
        method="POST",
        path="/api/v1/ping",
        body=body,
    )


def test_server_accepts_registered_hmac_once_and_rejects_replay():
    with tempfile.TemporaryDirectory() as tmp:
        registry = os.path.join(tmp, "registry.json")
        with patch.dict(os.environ, {"PHANTOM_BEACON_REGISTRY": registry}, clear=False):
            identity = enroll_beacon("B-SERVER-1")
            body = "encrypted"
            headers = {
                "X-Beacon-Id": "B-SERVER-1",
                "X-Beacon-Timestamp": "1000",
                "X-Beacon-Counter": "1",
                "X-Beacon-Nonce": "nonce-1",
            }
            headers["X-Beacon-Auth"] = sign_request(
                identity["secret"], "POST", "/api/v1/ping", "1000", "1",
                "nonce-1", body,
            )
            state = C2State()
            with patch("phantom.utils.beacon_auth.time.time", return_value=1000):
                assert state.authenticate_beacon(_request(headers, body), body)
                assert not state.authenticate_beacon(_request(headers, body), body)


def test_registered_beacon_without_signature_is_rejected():
    with tempfile.TemporaryDirectory() as tmp:
        registry = os.path.join(tmp, "registry.json")
        with patch.dict(os.environ, {"PHANTOM_BEACON_REGISTRY": registry}, clear=False):
            enroll_beacon("B-SERVER-2")
            state = C2State()
            headers = {"X-Beacon-Id": "B-SERVER-2"}
            assert not state.authenticate_beacon(
                _request(headers, "body"), "body"
            )
