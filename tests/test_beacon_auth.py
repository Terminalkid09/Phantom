"""Unit tests for per-beacon channel authentication primitives."""
import os
import tempfile
from unittest.mock import patch

from phantom.utils import beacon_auth


def test_enroll_sign_and_verify_request():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "registry.json")
        with patch.dict(
            os.environ, {"PHANTOM_BEACON_REGISTRY": path}, clear=False
        ):
            identity = beacon_auth.enroll_beacon("B-AUTH-1")
            signature = beacon_auth.sign_request(
                identity["secret"], "POST", "/api/v1/ping", "1000", "1",
                "nonce-1", "encrypted-body",
            )
            assert beacon_auth.verify_request(
                identity["secret"], "POST", "/api/v1/ping", "1000", "1",
                "nonce-1", signature, "encrypted-body", now=1000,
            )
            assert not beacon_auth.verify_request(
                identity["secret"], "POST", "/api/v1/ping", "1000", "1",
                "nonce-1", signature, "changed-body", now=1000,
            )


def test_rotation_replaces_secret_and_revoke_disables_it():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "registry.json")
        with patch.dict(
            os.environ, {"PHANTOM_BEACON_REGISTRY": path}, clear=False
        ):
            first = beacon_auth.enroll_beacon("B-AUTH-2")
            rotated = beacon_auth.rotate_beacon("B-AUTH-2")
            assert rotated["version"] == 2
            assert rotated["secret"] != first["secret"]
            assert beacon_auth.get_beacon_secret("B-AUTH-2") == rotated["secret"]
            assert beacon_auth.revoke_beacon("B-AUTH-2")
            assert beacon_auth.get_beacon_secret("B-AUTH-2") is None


def test_mtls_material_and_generated_header_are_consistent():
    with tempfile.TemporaryDirectory() as tmp:
        registry = os.path.join(tmp, "registry.json")
        certs = os.path.join(tmp, "certs")
        with patch("phantom.utils.state.use_mtls", return_value=True), \
             patch.dict(os.environ, {
            "PHANTOM_BEACON_REGISTRY": registry,
            "PHANTOM_MTLS_CERT_DIR": certs,
        }, clear=False):
            beacon_dir = os.path.join(tmp, "beacon")
            path = beacon_auth.write_beacon_auth_config(beacon_dir)
            content = open(path, encoding="utf-8").read()
            assert "BEACON_MTLS_ENABLED 1" in content
            assert "BEACON_CLIENT_CERT_PEM" in content
            assert "BEACON_SERVER_FINGERPRINT" in content
            for name in ("client_ca.crt", "mtls_server.crt", "mtls_server.key"):
                assert os.path.exists(os.path.join(certs, name))


def test_replay_window_rejects_stale_requests():
    secret = b"x" * 32
    signature = beacon_auth.sign_request(
        secret, "GET", "/api/v1/ping", "1000", "4", "nonce-4", "",
    )
    assert not beacon_auth.verify_request(
        secret, "GET", "/api/v1/ping", "1000", "4", "nonce-4", signature,
        "", now=1201,
    )
