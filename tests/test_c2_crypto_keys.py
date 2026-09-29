"""Per-beacon envelope keys and download tokens.

One captured beacon must reveal only its OWN traffic and its OWN payload
authorisation — never a deployment-wide key. These tests pin the KDF vectors
shared with c2d/envelope.go and the beacon's crypto.h (a drift there is silent:
beacon traffic simply never decrypts), and cover the legacy fallback that keeps
beacons built before this scheme working.
"""
import os
import tempfile
from unittest.mock import patch

from phantom.utils import beacon_auth
from phantom.utils.c2_crypto import (
    beacon_download_token,
    beacon_envelope_key,
    decrypt_data,
    decrypt_for_beacon,
    derive_key,
    encrypt_data,
    encrypt_for_beacon,
    get_beacon_download_tokens,
    get_beacon_envelope_keys,
    write_beacon_c2_config,
    write_beacon_crypto_config,
)

# ── KDF parity ──────────────────────────────────────────────────────────────
# Generated once by phantom.utils.c2_crypto and mirrored verbatim in
# c2d/c2d_test.go (TestEnvelopeKeyDerivationVectors) and in the beacon's
# crypto.h. Three implementations, one format.
_VECTOR_SECRET = bytes(range(32))
_VECTORS = {
    "B-TEST": "275c2265389eb7081752b239a2ab65fab82938b05e579d7937ded40bc33b5afc",
    "": "88170beeb2e2a92e1c5875050d69741b6d7384ed20e930ceaa366d2fa50ba182",
    "B-\u00e8-t\u00e9st": "7c6eb272b1b1478f38248badb802e48e71c5af45b8a74b6c68aa67aeff7b337e",
}
_VECTOR_DOWNLOAD_TOKEN = (
    "f8a955bf74dc5a93aa0407d58429898600aade9123bb3b23f5bb38dadcb608d6"
)


def test_envelope_key_vectors_match_go_and_beacon():
    for beacon_id, expected in _VECTORS.items():
        assert beacon_envelope_key(_VECTOR_SECRET, beacon_id).hex() == expected


def test_download_token_vector_matches_go_and_beacon():
    assert beacon_download_token(_VECTOR_SECRET, "B-TEST") == _VECTOR_DOWNLOAD_TOKEN


def test_download_token_and_envelope_key_are_domain_separated():
    key = beacon_envelope_key(_VECTOR_SECRET, "B-TEST")
    assert key.hex() != beacon_download_token(_VECTOR_SECRET, "B-TEST")
    assert derive_key(_VECTOR_SECRET, b"phantom-envelope:B-TEST") == key


def test_derive_key_rejects_bad_input():
    assert derive_key(b"", b"info") == b""
    assert derive_key(_VECTOR_SECRET, b"info", length=0) == b""
    assert derive_key(_VECTOR_SECRET, b"info", length=64) == b""


def test_a_zeroed_secret_still_derives_a_distinct_key():
    """The beacon treats an all-zero secret as "not enrolled" and falls back to
    the deployment key; the derivation itself must not special-case it."""
    zeroed = beacon_envelope_key(bytes(32), "B-TEST")
    assert len(zeroed) == 32
    assert zeroed != beacon_envelope_key(_VECTOR_SECRET, "B-TEST")


# ── behaviour against the registry ──────────────────────────────────────────


def test_enrollment_drives_per_beacon_encryption():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "registry.json")
        with patch.dict(os.environ, {"PHANTOM_BEACON_REGISTRY": path},
                        clear=False):
            one = beacon_auth.enroll_beacon("B-KEY-1")
            two = beacon_auth.enroll_beacon("B-KEY-2")

            sealed = encrypt_for_beacon("tasks", "B-KEY-1")
            assert decrypt_for_beacon(sealed, "B-KEY-1") == "tasks"
            # Another identity's key must NOT open it.
            assert decrypt_for_beacon(sealed, "B-KEY-2") == ""
            # Nor must the deployment key alone.
            assert decrypt_data(sealed) == ""

            assert one["secret"] != two["secret"]
            assert (get_beacon_envelope_keys("B-KEY-1")
                    != get_beacon_envelope_keys("B-KEY-2"))


def test_legacy_deployment_key_is_still_accepted():
    """A beacon built before per-beacon derivation speaks the deployment key
    and must keep checking in without a rebuild."""
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "registry.json")
        with patch.dict(os.environ, {"PHANTOM_BEACON_REGISTRY": path},
                        clear=False):
            beacon_auth.enroll_beacon("B-LEGACY-1")
            legacy = encrypt_data("telemetry")
            assert decrypt_for_beacon(legacy, "B-LEGACY-1") == "telemetry"


def test_unknown_identity_falls_back_to_the_deployment_key():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "registry.json")
        with patch.dict(os.environ, {"PHANTOM_BEACON_REGISTRY": path},
                        clear=False):
            assert get_beacon_envelope_keys("B-NOBODY") == []
            sealed = encrypt_data("payload")
            assert decrypt_for_beacon(sealed, "B-NOBODY") == "payload"


def test_rotation_keeps_the_previous_key_usable():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "registry.json")
        with patch.dict(os.environ, {"PHANTOM_BEACON_REGISTRY": path},
                        clear=False):
            beacon_auth.enroll_beacon("B-ROT-1")
            sealed_old = encrypt_for_beacon("before", "B-ROT-1")
            rotated = beacon_auth.rotate_beacon("B-ROT-1")
            # A beacon that has not picked up the rotation yet must still be
            # able to talk (the previous secret is accepted for a grace
            # window), and the CURRENT secret must come first so responses are
            # sealed with the key a fresh beacon will derive.
            assert decrypt_for_beacon(sealed_old, "B-ROT-1") == "before"
            keys = get_beacon_envelope_keys("B-ROT-1")
            assert len(keys) == 2
            assert keys[0] == beacon_envelope_key(rotated["secret"], "B-ROT-1")


def test_revoked_identity_has_no_envelope_key():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "registry.json")
        with patch.dict(os.environ, {"PHANTOM_BEACON_REGISTRY": path},
                        clear=False):
            beacon_auth.enroll_beacon("B-REV-1")
            assert get_beacon_envelope_keys("B-REV-1")
            assert beacon_auth.revoke_beacon("B-REV-1")
            assert get_beacon_envelope_keys("B-REV-1") == []
            assert get_beacon_download_tokens("B-REV-1") == []


def test_download_tokens_are_per_identity():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "registry.json")
        with patch.dict(os.environ, {"PHANTOM_BEACON_REGISTRY": path},
                        clear=False):
            beacon_auth.enroll_beacon("B-DL-1")
            beacon_auth.enroll_beacon("B-DL-2")
            tokens = get_beacon_download_tokens("B-DL-1")
            assert len(tokens) == 1
            assert tokens[0] != get_beacon_download_tokens("B-DL-2")[0]


# ── generated headers ───────────────────────────────────────────────────────


def test_enrolled_build_embeds_no_deployment_payload_token():
    with tempfile.TemporaryDirectory() as tmp:
        write_beacon_c2_config(tmp, host="10.0.0.1", port=8443)
        header = write_beacon_crypto_config(tmp, payload_token="")
        with open(header, "r", encoding="utf-8") as handle:
            content = handle.read()
        assert '#define C2_PAYLOAD_TOKEN ""' in content
        # The C2 endpoint header must not carry the token at all: it is
        # emitted by crypto_config.h, which crypto.h includes itself.
        with open(os.path.join(tmp, "src", "c2_config.h"),
                  "r", encoding="utf-8") as handle:
            assert "C2_PAYLOAD_TOKEN" not in handle.read()


def test_legacy_build_still_embeds_the_deployment_payload_token():
    with tempfile.TemporaryDirectory() as tmp:
        header = write_beacon_crypto_config(tmp)
        with open(header, "r", encoding="utf-8") as handle:
            content = handle.read()
        assert '#define C2_PAYLOAD_TOKEN ""' not in content
        assert "#define C2_PAYLOAD_TOKEN \"" in content


def test_token_literal_refuses_to_break_the_string():
    with tempfile.TemporaryDirectory() as tmp:
        header = write_beacon_crypto_config(tmp, payload_token='ab"\\c')
        with open(header, "r", encoding="utf-8") as handle:
            content = handle.read()
        assert '#define C2_PAYLOAD_TOKEN "abc"' in content


def test_beacon_source_derives_the_key_instead_of_storing_it():
    """The regression guard for the original finding: crypto_config.h must no
    longer be the ONLY source of the envelope key, and the beacon must derive
    it from its per-beacon secret."""
    src = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "phantom", "payloads")
    for tree in ("beacon", "remote"):
        with open(os.path.join(src, tree, "src", "crypto.h"),
                  "r", encoding="utf-8") as handle:
            header = handle.read()
        assert "hkdf_sha256" in header, tree
        assert "envelope_key()" in header, tree
        assert "BEACON_AUTH_SECRET" in header, tree
        assert "(PUCHAR)AES_KEY" not in header, tree
        assert "EVP_EncryptInit_ex(ctx, NULL, NULL, AES_KEY, nonce)" not in header
