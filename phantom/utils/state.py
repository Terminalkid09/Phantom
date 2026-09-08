"""Operator-local state with auto-generated secrets.

Phantom generates its own C2 key material, tokens, and certificates on first
use and persists everything to a local, gitignored state file. The operator
never has to hand-edit ``.env`` for secrets.

Environment variables remain supported as overrides for advanced setups.
"""
from __future__ import annotations

import json
import os
import secrets as _secrets
import tempfile
import threading
from typing import Any, Callable, Optional

from phantom.utils.paths import data_dir

_STATE_LOCK = threading.RLock()
_STATE_ENV = "PHANTOM_STATE_FILE"

# ── helpers ─────────────────────────────────────────────────────────────────

def state_file() -> str:
    return os.getenv(_STATE_ENV, "").strip() or os.path.join(data_dir(), "phantom_state.json")


def _secure_file(path: str) -> None:
    if os.name != "nt":
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def _read() -> dict[str, Any]:
    try:
        with open(state_file(), "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write(data: dict[str, Any]) -> None:
    path = state_file()
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".phantom-state-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
        _secure_file(temp_path)
        os.replace(temp_path, path)
        _secure_file(path)
    finally:
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass


def _env(name: str) -> str:
    # Guard against shells that still carry a stale PHANTOM_API_TOKEN from a
    # previous test run: if the persisted state already has a DIFFERENT token,
    # the env value would silently desync the API server and the Electron main
    # process (every renderer fetch → 401). Persisted state is authoritative
    # for the API token; a matching env value is still accepted (no-op), and
    # operators who genuinely need the override can pass --env-state-file.
    value = os.getenv(name, "").strip()
    if name == "PHANTOM_API_TOKEN" and value:
        with _STATE_LOCK:
            persisted = _read().get(name)
        if persisted and str(persisted) != value:
            return ""
    return value


def _falsy(value: str) -> bool:
    return value.lower() in ("0", "false", "no", "off", "n")


# ── public API ──────────────────────────────────────────────────────────────

def get_secret(name: str, factory: Callable[[], str]) -> str:
    """Return secret ``name``.  Order: env override → persisted → generate.

    When a new value is generated it is persisted atomically with ``0600``
    permissions on POSIX.
    """
    value = _env(name)
    if value:
        return value
    with _STATE_LOCK:
        data = _read()
        existing = data.get(name)
        if existing:
            return str(existing)
        value = factory()
        data[name] = value
        _write(data)
        return value


def get_string(name: str, default: str = "") -> str:
    value = _env(name)
    if value:
        return value
    with _STATE_LOCK:
        return str(_read().get(name, default))


def get_flag(name: str, default: bool) -> bool:
    """Return boolean flag.  Env takes precedence over persisted state."""
    value = _env(name)
    if value:
        return not _falsy(value) if value else default
    with _STATE_LOCK:
        data = _read()
        if name in data:
            return bool(data[name])
    return default


def set_flag(name: str, value: bool) -> None:
    with _STATE_LOCK:
        data = _read()
        data[name] = bool(value)
        _write(data)


def regenerate_secret(name: str, factory: Callable[[], str]) -> str:
    """Always generate a fresh value and persist it."""
    with _STATE_LOCK:
        data = _read()
        value = factory()
        data[name] = value
        _write(data)
        return value


def ensure_bootstrap() -> dict[str, bool]:
    """Generate all secrets that are still missing; return what was created."""
    created: dict[str, bool] = {}

    def _gen(env_name: str, factory: Callable[[], str]) -> None:
        existing = bool(_env(env_name))
        if not existing:
            with _STATE_LOCK:
                data = _read()
                existing = env_name in data
        if not existing:
            get_secret(env_name, factory)
            created[env_name] = True
        else:
            created[env_name] = False

    _gen("PHANTOM_C2_KEY", lambda: _secrets.token_hex(16))
    _gen("PHANTOM_C2_NONCE", lambda: _secrets.token_hex(6))
    _gen("PHANTOM_PAYLOAD_TOKEN", lambda: _secrets.token_urlsafe(32))
    _gen("PHANTOM_API_TOKEN", lambda: _secrets.token_urlsafe(32))
    return created


def status() -> dict[str, Any]:
    """Return a human-friendly summary (secret values masked)."""
    data = _read()
    summary: dict[str, Any] = {"_state_file": state_file()}

    def _masked(name: str) -> str:
        value = data.get(name, "")
        if not value:
            return "<not set>"
        if len(str(value)) <= 4:
            return "<set>"
        return str(value)[:4] + "…"

    summary["aes_key"] = _masked("PHANTOM_C2_KEY")
    summary["aes_nonce"] = _masked("PHANTOM_C2_NONCE")
    summary["payload_token"] = _masked("PHANTOM_PAYLOAD_TOKEN")
    summary["api_token"] = _masked("PHANTOM_API_TOKEN")
    for flag in ("PHANTOM_BEACON_AUTH_REQUIRED", "PHANTOM_MTLS_REQUIRED"):
        summary[flag] = get_flag(flag, True)
    summary["mTLS_cert_dir"] = _env("PHANTOM_MTLS_CERT_DIR") or str(
        os.path.join(data_dir(), "certs"))
    return summary


def use_mtls() -> bool:
    """True when the default transport should be HTTPS + client-certificate."""
    return get_flag("PHANTOM_MTLS_REQUIRED", True)


def beacon_auth_required() -> bool:
    """True when beacon HMAC authentication is enforced."""
    return get_flag("PHANTOM_BEACON_AUTH_REQUIRED", True)