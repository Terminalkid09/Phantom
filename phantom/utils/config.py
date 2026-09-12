"""
config.py — zero-config workspace settings.

Phantom keeps its runtime configuration in ``data/config.json``. The file is
auto-created on first use with sensible defaults, so a fresh checkout works
immediately against the local lab / C2 with NO environment setup:

  * everything local (ports, host, paths, flags) ships pre-configured;
  * only per-engagement, external channels (SMTP creds, Telegram token,
    Discord webhook, public tracker URL, SMS carrier) can be missing — those
    features degrade gracefully with a clear reason instead of blocking.

``phantom setup`` enriches the file interactively. Legacy ``PHANTOM_*``
environment variables take precedence over the file when both are present,
so existing .env setups keep working unchanged.
"""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any, Dict, Optional

from phantom.utils.paths import data_dir

_CONFIG_PATH = os.path.join(data_dir(), "config.json")

# Defaults shipped with the tool: everything needed to run the full chain
# against the local lab with zero configuration.
DEFAULTS: Dict[str, Any] = {
    "workspace": {
        "data_dir": None,          # None -> phantom.utils.paths.data_dir()
        "sessions_dir": None,      # None -> data/sessions
        "reports_dir": None,       # None -> data/reports
    },
    "c2": {
        # EMPTY by default: a stored 127.0.0.1 would be embedded in every
        # beacon and every payload URL, so a remote target would dial its
        # OWN loopback (dead beacon, dead dropper link). Empty lets
        # get_c2_endpoint() derive the routable operator address; set an
        # explicit host (public IP or your domain) for real engagements.
        "host": "",
        "port": 8080,
        "mtls": True,
        "listener_auto_start": False,
    },
    "tracker": {
        "host": "0.0.0.0",
        # 8081, NOT 8080: the C2 listener owns 8080, and two servers on the
        # same port make the tracker fail (or, worse on Windows, double-bind
        # silently) while every lure link points at a dead server.
        "port": 8081,
        "skin": "youtube",         # youtube|instagram|tiktok
        "redirect": "",            # empty -> landing page
        "public_url": "",          # set to a public base URL for real lures
    },
    "transports": {
        "smtp": {
            "host": "mail.smtp2go.com",
            "port": 2525,
            "username": "",
            "password": "",
            "tls": True,
        },
        "telegram_bot_token": "",
        "discord_webhook": "",
        "dm_transport": "",        # dotted.path.to.Class for a custom DM sender
        "sms_carrier": "",         # email-to-SMS carrier (verizon, tmobile, ...)
        "sms_phone": "",           # operator phone for SMS receive tests
    },
    "breach": {
        "hibp_api_key": "",
        "custom_api": "",          # alternative breach API endpoint
    },
    "llm": {
        "model_path": "",          # empty -> bundled default (Qwen) when present
        "enabled": False,
    },
    "engagement": {
        "allow_unscoped": False,   # PHANTOM_ALLOW_UNSCOPED equivalent
        "ransom_sim_allow": False, # PHANTOM_RANSOM_SIM_ALLOW equivalent
    },
}

_loaded: Optional[Dict[str, Any]] = None
_load_lock_owner = None


def _defaults() -> Dict[str, Any]:
    return json.loads(json.dumps(DEFAULTS))


def load_config() -> Dict[str, Any]:
    """Return the merged configuration (file + defaults). On first use the
    file does not exist and is CREATED with the defaults, so a fresh
    checkout runs with zero configuration. Cached per-process; call
    ``reload_config`` to re-read after ``phantom setup`` writes it."""
    global _loaded
    if _loaded is not None:
        return _loaded
    cfg = _defaults()
    try:
        if os.path.exists(_CONFIG_PATH):
            with open(_CONFIG_PATH, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            if isinstance(raw, dict):
                _deep_merge(cfg, raw)
        else:
            save_config({})      # first use: materialize the defaults
            return _loaded or cfg
    except (OSError, ValueError):
        pass  # corrupt/missing file -> defaults
    _loaded = cfg
    return cfg


def reload_config() -> Dict[str, Any]:
    """Drop the cached config so the next read picks up on-disk changes."""
    global _loaded
    _loaded = None
    return load_config()


def save_config(patch: Dict[str, Any]) -> None:
    """Deep-merge ``patch`` into the on-disk config and write it atomically."""
    cfg = _defaults()
    if os.path.exists(_CONFIG_PATH):
        try:
            with open(_CONFIG_PATH, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            if isinstance(raw, dict):
                _deep_merge(cfg, raw)
        except (OSError, ValueError):
            pass
    _deep_merge(cfg, patch)
    os.makedirs(os.path.dirname(_CONFIG_PATH), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(_CONFIG_PATH),
                               prefix=".config.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, _CONFIG_PATH)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
    global _loaded
    _loaded = cfg


def config_path() -> str:
    return _CONFIG_PATH


def get(key: str, default: Any = None, env: Optional[str] = None) -> Any:
    """Read ``key`` (dotted path, e.g. ``transports.smtp.host``) from the
    config. When ``env`` is given and set, the environment variable WINS
    (legacy PHANTOM_* overrides the file)."""
    if env:
        val = os.getenv(env)
        if val is not None and str(val).strip() != "":
            return val
    cfg = load_config()
    node: Any = cfg
    for part in key.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return default
    if node is None:
        return default
    return node


def set(key: str, value: Any) -> None:
    """Set a dotted key and persist the file (used by ``phantom setup``)."""
    cfg = load_config()
    node: Dict[str, Any] = cfg
    parts = key.split(".")
    for part in parts[:-1]:
        node = node.setdefault(part, {})
    node[parts[-1]] = value
    save_config(cfg)


def _deep_merge(base: Dict[str, Any], patch: Dict[str, Any]) -> None:
    for k, v in patch.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v