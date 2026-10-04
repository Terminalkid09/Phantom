"""
api_keys.py — the single plane for external-service credentials.

Phantom talks to several optional external services (Shodan, NVD/NIST,
GitHub, HaveIBeenPwned, a self-hosted breach aggregator). Before this module
each one had its own hiding place: some read a bare ``os.getenv`` (NVD,
GitHub), one lived only in the per-session state (Shodan ``set-key``), and
two sat under ``breach.*`` in the config file. That meant a key set in one
place was invisible everywhere else, and the operator had to edit ``.env``
to make a feature work.

Every key is now declared ONCE here: its config path (persisted to
``data/config.json``), its legacy ``PHANTOM_*`` env override (which still
wins, so existing scripts keep working) and its human label. The CLI
(``config keys``), the local HTTP bridge (``/api/config/keys``) and the
Electron settings panel all read this same registry, so a key entered in
any of them is immediately visible to the others and to the code that
consumes it — no ``.env`` editing required.
"""

from __future__ import annotations

import os
from typing import Any, Dict

from phantom.utils import config as cfg


# logical name -> declaration. ``config`` is the dotted path written to
# data/config.json; ``env`` is the legacy override that WINS when set.
KEY_REGISTRY: Dict[str, Dict[str, str]] = {
    "shodan": {
        "config": "api_keys.shodan",
        "env": "PHANTOM_SHODAN_KEY",
        # legacy spelling used before the key plane existed; still honoured
        "alt_env": "SHODAN_API_KEY",
        "label": "Shodan",
        "hint": "Unlocks Shodan search/stats; without it only the keyless "
                "InternetDB host lookup is used.",
    },
    "nvd": {
        "config": "api_keys.nvd",
        "env": "PHANTOM_NVD_API_KEY",
        "label": "NVD (NIST)",
        "hint": "Raises the NVD rate limit from 1 request / 6s to ~50/30s.",
    },
    "github": {
        "config": "api_keys.github",
        "env": "PHANTOM_GITHUB_TOKEN",
        "label": "GitHub token",
        "hint": "Raises the GitHub search API limit (60 -> 5000 req/h) used "
                "for public PoC correlation.",
    },
    "hibp": {
        "config": "breach.hibp_api_key",
        "env": "PHANTOM_HIBP_API_KEY",
        "label": "HaveIBeenPwned",
        "hint": "Breached-account lookups (which breaches an email appears "
                "in). The key is a paid HIBP subscription.",
    },
    "breach_api": {
        "config": "breach.custom_api",
        "env": "PHANTOM_BREACH_API",
        "label": "Breach aggregator API",
        "hint": "Base URL of a self-hosted/aggregator JSON API exposing "
                "plaintext credentials (queried as <base>/lookup?q=...).",
    },
}


def names() -> list:
    """Logical key names in a stable order."""
    return list(KEY_REGISTRY.keys())


def _decl(name: str) -> Dict[str, str]:
    return KEY_REGISTRY.get(name, {}) or {}


def _env_value(decl: Dict[str, str]) -> str:
    """The first non-empty environment override for a key (primary, then
    the legacy spelling)."""
    for env_name in (decl.get("env"), decl.get("alt_env")):
        if not env_name:
            continue
        value = str(os.getenv(env_name) or "").strip()
        if value:
            return value
    return ""


def get(name: str, default: str = "") -> str:
    """Resolve a key's value: env override wins, else the config file.

    Returns ``default`` for an unknown name or an unset value.
    """
    decl = _decl(name)
    if not decl:
        return default
    env_value = _env_value(decl)
    if env_value:
        return env_value
    value = cfg.get(decl["config"], default, env=None)
    return default if value is None else str(value).strip()


def set(name: str, value: str) -> None:
    """Persist a key to data/config.json (empty string clears it)."""
    decl = _decl(name)
    if not decl:
        raise KeyError(f"unknown api key: {name}")
    cfg.set(decl["config"], str(value or "").strip())


def source(name: str) -> str:
    """Where the effective value comes from: 'env', 'config' or 'none'."""
    decl = _decl(name)
    if not decl:
        return "none"
    if _env_value(decl):
        return "env"
    value = cfg.get(decl["config"], "")
    if value is not None and str(value).strip():
        return "config"
    return "none"


def mask(value: str) -> str:
    """Render a secret for display without leaking it."""
    value = str(value or "")
    if not value:
        return ""
    if len(value) <= 8:
        return "•" * len(value)
    return value[:4] + "•" * (len(value) - 8) + value[-4:]


def status() -> Dict[str, Dict[str, Any]]:
    """Every declared key with its configured state — one dict the CLI, the
    HTTP bridge and doctor all render. NO secret is ever emitted raw."""
    out: Dict[str, Dict[str, Any]] = {}
    for name, decl in KEY_REGISTRY.items():
        value = get(name)
        out[name] = {
            "label": decl.get("label", name),
            "hint": decl.get("hint", ""),
            "env": decl.get("env", ""),
            "configured": bool(value),
            "source": source(name),
            "masked": mask(value),
        }
    return out
