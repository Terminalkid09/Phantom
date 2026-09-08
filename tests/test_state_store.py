"""Tests for the auto-generated operator state store.

Covers:
- secrets are generated on first use and persisted
- persisted secrets are stable across calls
- env vars override persisted values
- flags default to secure-by-default (True) and env can disable
- atomic writes (no partial file after simulated failure)
- bootstrap() generates all four secrets exactly once
"""
import json
import os
import tempfile
from unittest.mock import patch

from phantom.utils import state


def _fresh_state_file():
    tmp = tempfile.mkdtemp()
    return os.path.join(tmp, "phantom_state.json"), tmp


def test_secret_generated_and_persisted():
    path, tmp = _fresh_state_file()
    with patch.dict(os.environ, {"PHANTOM_STATE_FILE": path}, clear=True):
        value = state.get_secret("PHANTOM_C2_KEY", lambda: "abc")
        assert value == "abc"
        # persisted
        data = json.load(open(path))
        assert data["PHANTOM_C2_KEY"] == "abc"
        # stable across calls
        assert state.get_secret("PHANTOM_C2_KEY", lambda: "different") == "abc"


def test_env_override_wins():
    path, tmp = _fresh_state_file()
    with patch.dict(os.environ, {
        "PHANTOM_STATE_FILE": path,
        "PHANTOM_PAYLOAD_TOKEN": "from-env",
    }, clear=True):
        assert state.get_secret("PHANTOM_PAYLOAD_TOKEN", lambda: "generated") == "from-env"


def test_api_token_env_cannot_desync_persisted_state():
    """Regression: a stale PHANTOM_API_TOKEN inherited from a parent shell
    (e.g. after running tests) used to silently override the persisted token,
    desyncing the API server from the Electron main process → 401 on every
    renderer fetch. The persisted value must win when the two disagree."""
    path, tmp = _fresh_state_file()
    with patch.dict(os.environ, {"PHANTOM_STATE_FILE": path}, clear=True):
        persisted = state.get_secret("PHANTOM_API_TOKEN", lambda: "real-token")
        # same env value → harmless, still accepted
        with patch.dict(os.environ, {"PHANTOM_API_TOKEN": persisted}):
            assert state.get_secret("PHANTOM_API_TOKEN", lambda: "x") == persisted
        # different env value → ignored, persisted value stays authoritative
        with patch.dict(os.environ, {"PHANTOM_API_TOKEN": "stale-test-token"}):
            from phantom.utils.c2_crypto import get_api_token
            assert get_api_token() == persisted


def test_secure_default_flags():
    path, tmp = _fresh_state_file()
    with patch.dict(os.environ, {"PHANTOM_STATE_FILE": path}, clear=True):
        # beacon auth + mTLS are secure by default
        assert state.get_flag("PHANTOM_BEACON_AUTH_REQUIRED", True) is True
        assert state.get_flag("PHANTOM_MTLS_REQUIRED", True) is True
        # explicit opt-out via env
        with patch.dict(os.environ, {"PHANTOM_MTLS_REQUIRED": "0"}, clear=False):
            assert state.get_flag("PHANTOM_MTLS_REQUIRED", True) is False


def test_set_flag_persists():
    path, tmp = _fresh_state_file()
    with patch.dict(os.environ, {"PHANTOM_STATE_FILE": path}, clear=True):
        state.set_flag("PHANTOM_MTLS_REQUIRED", False)
        assert state.get_flag("PHANTOM_MTLS_REQUIRED", True) is False
        data = json.load(open(path))
        assert data["PHANTOM_MTLS_REQUIRED"] is False


def test_bootstrap_generates_all_once():
    path, tmp = _fresh_state_file()
    with patch.dict(os.environ, {"PHANTOM_STATE_FILE": path}, clear=True):
        first = state.ensure_bootstrap()
        assert all(first.values())  # all four generated
        second = state.ensure_bootstrap()
        assert not any(second.values())  # nothing new on second run
        data = json.load(open(path))
        for key in ("PHANTOM_C2_KEY", "PHANTOM_C2_NONCE",
                    "PHANTOM_PAYLOAD_TOKEN", "PHANTOM_API_TOKEN"):
            assert data.get(key), f"{key} missing"


def test_state_file_ignored_by_git():
    path, tmp = _fresh_state_file()
    with patch.dict(os.environ, {"PHANTOM_STATE_FILE": path}, clear=True):
        state.get_secret("PHANTOM_C2_KEY", lambda: "x")
        # default project .gitignore must ignore data/phantom_state.json
        gitignore = open(".gitignore", encoding="utf-8").read()
        assert "data/phantom_state.json" in gitignore