"""config.py — the AI plane's settings, read through the config schema.

Modes:

* ``off``         — the default. The deterministic path is untouched.
* ``local``       — llama.cpp server on this box.
* ``cloud``       — an OpenAI-compatible endpoint, credential from an env NAME.
* ``integrated``  — use the promoted per-phase adapter (falls back to local).

Per-phase override wins over the global mode (``ai.osint.mode=off`` while
``ai.mode=local`` is the normal shape: run the advisor on exploit, not on
OSINT).
"""

from __future__ import annotations

import os
from typing import Dict

from phantom.utils import config as cfg

MODES = ("off", "local", "cloud", "integrated")
PHASES = ("exploit", "finding", "osint", "social", "scan_parse", "evolution")

_PHASE_ENV: Dict[str, str] = {
    "exploit": "PHANTOM_AI_EXPLOIT_MODE",
    "finding": "PHANTOM_AI_FINDING_MODE",
    "osint": "PHANTOM_AI_OSINT_MODE",
    "social": "PHANTOM_AI_SOCIAL_MODE",
    "scan_parse": "PHANTOM_AI_SCAN_PARSE_MODE",
    "evolution": "PHANTOM_AI_EVOLUTION_MODE",
}


def normalize(value: str) -> str:
    token = str(value or "").strip().lower()
    return token if token in MODES else "off"


def mode(phase: str = "") -> str:
    """The effective mode for one phase (global when no override is set)."""
    name = str(phase or "").strip()
    if name:
        specific = cfg.get_str(f"ai.{name}.mode", "",
                               env=_PHASE_ENV.get(name, ""))
        if str(specific or "").strip():
            return normalize(specific)
    return normalize(cfg.get_str("ai.mode", "off", env="PHANTOM_AI_MODE"))


def enabled(phase: str = "") -> bool:
    return mode(phase) != "off"


def set_mode(value: str) -> str:
    """Apply a CLI mode for this process (per-phase overrides still win)."""
    token = normalize(value)
    os.environ["PHANTOM_AI_MODE"] = token
    return token


def local_base_url() -> str:
    return cfg.get_str("ai.local.base_url", "http://127.0.0.1:8080",
                       env="PHANTOM_AI_LOCAL_URL")


def local_candidates() -> list:
    """Every local endpoint worth probing, in priority order.

    The configured URL comes first, then the ports a model server commonly
    listens on. This exists because ``8080`` — llama.cpp's own default — is
    also the port another application is most likely to own already, and
    that is exactly what happened on 2026-11-02: every AI call in a lab run
    returned ``http 405`` from an unrelated process, the order never moved,
    and the run looked as if the model had agreed with the deterministic
    plan. A fallback needs a list to fall back ON.
    """
    raw = cfg.get_str("ai.local.urls", "", env="PHANTOM_AI_LOCAL_URLS")
    urls = [u.strip() for u in str(raw or "").split(",") if u.strip()]
    if not urls:
        urls = ["http://127.0.0.1:8080", "http://127.0.0.1:8008",
                "http://127.0.0.1:8009", "http://127.0.0.1:11434",
                "http://127.0.0.1:1234", "http://127.0.0.1:5000"]
    configured = str(local_base_url() or "").strip()
    if configured and configured not in urls:
        urls.insert(0, configured)
    return urls


def authority_override() -> str:
    """``auto`` (evidence decides) or an operator-forced authority level."""
    raw = str(cfg.get_str("ai.authority", "auto",
                          env="PHANTOM_AI_AUTHORITY") or "auto")
    token = raw.strip().lower()
    return token if token in ("auto", "nudge", "decide", "full") else "auto"


def local_model() -> str:
    return cfg.get_str("ai.local.model", "", env="PHANTOM_AI_LOCAL_MODEL")


def cloud_base_url() -> str:
    return cfg.get_str("ai.cloud.base_url", "", env="PHANTOM_AI_CLOUD_URL")


def cloud_model() -> str:
    return cfg.get_str("ai.cloud.model", "", env="PHANTOM_AI_CLOUD_MODEL")


def cloud_api_key_env() -> str:
    """The NAME of the credential variable — never the credential."""
    return cfg.get_str("ai.cloud.api_key_env", "",
                       env="PHANTOM_AI_CLOUD_KEY_ENV")


def timeout_s() -> float:
    return max(1.0, cfg.get_float("ai.timeout_s", 60.0,
                                  env="PHANTOM_AI_TIMEOUT"))


def budget_tokens() -> int:
    return max(256, cfg.get_int("ai.budget_tokens", 8000,
                                env="PHANTOM_AI_BUDGET_TOKENS"))
