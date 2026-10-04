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
        # PUBLIC, DISPOSABLE front the beacons are built against (a
        # redirector / CDN). When set it is embedded as the beacon's
        # endpoint INSTEAD of `host`, so a captured beacon only reveals a
        # hop you can burn and rotate in minutes while the real listener
        # never enters the binary. Accepts "host" or "host:port". Empty =
        # fall back to `host` (the backend is then compiled in) — `doctor`
        # flags that build as leaking the backend.
        "front": "",
        # Certificate the beacon PINS. Empty = the listener's own certificate
        # (the passthrough case). When the front TERMINATES TLS it presents
        # its own certificate, so set this to that file (or drop
        # certs/front.crt, which is picked up automatically) — otherwise the
        # pin never matches and every check-in fails. See `c2.pins` for a
        # per-rung pin list when the ladder's redirectors differ.
        "front_cert": "",
        # PER-ENDPOINT pins, positionally aligned with [host] + `fallback`.
        # One SHA-256 DER digest per rung (empty field = inherit the primary
        # pin); `pubkey_pins` is the same list in libcurl's sha256//SPKI shape
        # for the macOS transport.
        "pins": "",
        "pubkey_pins": "",
        # LAST-RING dead drop: one neutral URL (a paste, a gist, an S3
        # object) holding the CURRENT endpoint as an obfuscated record,
        # consulted after the ladder fails. With `bootstrap_dead_drop` it is
        # also the FIRST source, so the indirection can be rotated without
        # rebuilding the beacon. Declared here because it was read at call
        # sites (dead_drop.configured_url, doctor) but invisible to the
        # config plane.
        "dead_drop": "",
        # Resolve the live endpoint from the dead drop BEFORE the first
        # check-in: the compiled endpoint then only ever acts as a fallback
        # rung. A failed bootstrap costs one request and falls through to
        # the compiled ladder unchanged.
        "bootstrap_dead_drop": True,
        # DATA PLANE implementation: "python" (the in-tree listener, default)
        # or "go" (the `c2d` static binary). With "go", auto-mode does NOT
        # start the Python listener — run c2d so the two do not fight for the
        # port. Same wire protocol either way; the beacon cannot tell.
        "transport_backend": "python",
        # BIND address of the listener (where it LISTENS), distinct from
        # `host` above (what beacons are told to DIAL). 0.0.0.0 by default:
        # the listener accepts on every interface, so a multi-homed
        # operator or a changed VPN address never silently makes the C2
        # unreachable. `host` stays the advertised address — 0.0.0.0 there
        # would make every beacon dial its own loopback.
        "bind": "0.0.0.0",
        "port": 8080,
        "mtls": True,
        # mTLS client-certificate REQUIREMENT. True (default): a client
        # without a certificate cannot complete the handshake at all
        # (CERT_REQUIRED). False keeps CERT_OPTIONAL, where the app-layer
        # HMAC is the only gate — accepted for legacy setups, flagged by
        # `doctor`. Beacons get their certificate at BUILD time, so the
        # required default never blocks a real deploy.
        "mtls_require_client_cert": True,
        # Refuse to run a PLAINTEXT listener on a non-loopback bind: that is
        # a C2 anyone on the path can read and hijack. Set True to override
        # (lab only) — the listener then starts with a loud warning.
        "allow_plaintext": False,
        # True: auto-mode brings its own listener (HTTPS/mTLS, bound to
        # `c2.bind` = every interface by default, dialing the derived
        # beacon-facing address) when none is up. False: never auto-start —
        # the operator starts the listener explicitly (`c2` -> listener
        # start); without one, beacons cannot check in.
        "listener_auto_start": True,
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
    # External-service credentials. Persisted here so the CLI (`config keys`)
    # and the Electron settings panel can set them WITHOUT touching .env;
    # the legacy PHANTOM_* env vars still win (see phantom.utils.api_keys).
    "api_keys": {
        "shodan": "",
        "nvd": "",
        "github": "",
    },
    # Operator-declared tool options for the toolbelt. The built-in catalog
    # ships a fixed set of known implementers; this lets an operator register
    # a tool without a code change, so a superior tool the operator has
    # installed is actually selectable. Shape:
    #   toolbelt.extra = {"<capability>": [ {"name": "myTool", "rank": 10,
    #       "styles": ["default", "stealth"],
    #       "requires_service": ["http"], "note": "..."} ]}
    "toolbelt": {
        "extra": {},
        # Runtime DRIVER discovery: scan the (gitignored) data/drivers and
        # `drivers_dir` directories for declarative tool manifests and turn
        # each valid one into a live, plannable capability. A fresh checkout
        # has no manifests, so this is a no-op until the operator adds one.
        "drivers": True,
        "drivers_dir": "",         # os.pathsep-separated extra dirs
    },
    "osint": {
        # Region used to parse a NATIONAL-format phone number that carries no
        # country code ("02 1234 5678"); international numbers ignore it.
        "default_region": "",
    },
    "llm": {
        "model_path": "",          # empty -> bundled default (Qwen) when present
        "enabled": False,
    },
    "automation": {
        # Cross-engagement EXPERIENCE memory: when true, every run records
        # (situation, technique, outcome, cause, repair) episodes into
        # data/experience_cases.json and the planner reorders already-allowed
        # moves so a wall hit once is not hit the same way again. Privacy:
        # everything stays in the local data dir; `automation.experience:
        # false` (or --no-experience) keeps the memory run-only.
        "experience": True,
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


# ── Declared schema ───────────────────────────────────────────────────────
# Every setting Phantom reads, with its type and the legacy PHANTOM_* env
# override that WINS over the file. This is the single place a new setting
# is declared, so the config plane is auditable instead of scattered across
# call sites. Call sites read through the typed accessors below; the plain
# `get` stays for callers that pass their own default inline.
SCHEMA: Dict[str, Dict[str, Any]] = {
    # C2 listener / beacon transport
    "c2.host": {"type": str, "env": "PHANTOM_C2_HOST"},
    "c2.front": {"type": str, "env": "PHANTOM_C2_FRONT"},
    "c2.front_cert": {"type": str, "env": "PHANTOM_C2_FRONT_CERT"},
    "c2.pins": {"type": str, "env": "PHANTOM_C2_PINS"},
    "c2.pubkey_pins": {"type": str, "env": "PHANTOM_C2_PUBKEY_PINS"},
    "c2.dead_drop": {"type": str, "env": "PHANTOM_C2_DEADDROP"},
    "c2.bootstrap_dead_drop": {"type": bool,
                               "env": "PHANTOM_C2_DEADDROP_BOOTSTRAP"},
    "c2.port": {"type": int, "env": "PHANTOM_C2_PORT"},
    "c2.ssl": {"type": bool, "env": "PHANTOM_C2_SSL"},
    "c2.mtls": {"type": bool, "env": None},
    "c2.listener_auto_start": {"type": bool, "env": None},
    "c2.auto_persist": {"type": bool, "env": "PHANTOM_AUTO_PERSIST"},
    "c2.fallback": {"type": str, "env": "PHANTOM_C2_FALLBACK"},
    "c2.proxy": {"type": str, "env": "PHANTOM_C2_PROXY"},
    "c2.pin": {"type": str, "env": "PHANTOM_BEACON_PIN"},
    "c2.api": {"type": str, "env": None},
    "c2.bind": {"type": str, "env": "PHANTOM_C2_BIND"},
    "c2.transport_backend": {"type": str, "env": "PHANTOM_C2_BACKEND"},
    "c2.mtls_require_client_cert": {
        "type": bool, "env": "PHANTOM_MTLS_REQUIRE_CLIENT_CERT"},
    "c2.allow_plaintext": {"type": bool, "env": "PHANTOM_ALLOW_PLAINTEXT"},
    "c2.remote_session_ttl": {"type": int, "env": "PHANTOM_REMOTE_SESSION_TTL"},
    # Tracking server (lure landing)
    "tracker.host": {"type": str, "env": "PHANTOM_TRACK_HOST"},
    "tracker.port": {"type": int, "env": "PHANTOM_TRACK_PORT"},
    "tracker.skin": {"type": str, "env": "PHANTOM_TRACK_SKIN"},
    "tracker.redirect": {"type": str, "env": "PHANTOM_TRACK_REDIRECT"},
    "tracker.brand": {"type": str, "env": "PHANTOM_TRACK_BRAND"},
    "tracker.otp": {"type": bool, "env": "PHANTOM_TRACK_OTP"},
    "tracker.js_challenge": {"type": bool,
                             "env": "PHANTOM_TRACK_JS_CHALLENGE"},
    "tracker.public_url": {"type": str, "env": None},
    # Outbound transports / breach feeds
    "transports.smtp.host": {"type": str, "env": "PHANTOM_SMTP_HOST"},
    "transports.smtp.port": {"type": int, "env": "PHANTOM_SMTP_PORT"},
    "transports.smtp.username": {"type": str, "env": "PHANTOM_SMTP_USER"},
    "transports.smtp.password": {"type": str, "env": "PHANTOM_SMTP_PASSWORD"},
    "transports.smtp.tls": {"type": bool, "env": "PHANTOM_SMTP_TLS"},
    "transports.telegram_bot_token": {"type": str,
                                      "env": "PHANTOM_TELEGRAM_BOT_TOKEN"},
    "transports.telegram_allowed_users": {"type": str, "env": None},
    "transports.dm_transport": {"type": str, "env": None},
    "transports.phish_from": {"type": str, "env": None},
    "transports.discord_webhook": {"type": str, "env": None},
    "transports.sms_carrier": {"type": str, "env": None},
    "breach.hibp_api_key": {"type": str, "env": "PHANTOM_HIBP_API_KEY"},
    "breach.custom_api": {"type": str, "env": "PHANTOM_BREACH_API"},
    "api_keys.shodan": {"type": str, "env": "PHANTOM_SHODAN_KEY"},
    "api_keys.nvd": {"type": str, "env": "PHANTOM_NVD_API_KEY"},
    "api_keys.github": {"type": str, "env": "PHANTOM_GITHUB_TOKEN"},
    # LLM advisor + engagement governance
    "llm.model_path": {"type": str, "env": "PHANTOM_LLM_MODEL"},
    "llm.enabled": {"type": bool, "env": "PHANTOM_LLM_ENABLED"},
    "automation.experience": {"type": bool, "env": None},
    "toolbelt.extra": {"type": dict, "env": None},
    "toolbelt.drivers": {"type": bool, "env": None},
    "toolbelt.drivers_dir": {"type": str, "env": "PHANTOM_DRIVERS_DIR"},
    "osint.default_region": {"type": str, "env": "PHANTOM_DEFAULT_REGION"},
    "engagement.allow_unscoped": {"type": bool,
                                  "env": "PHANTOM_ALLOW_UNSCOPED"},
    "engagement.ransom_sim_allow": {"type": bool,
                                     "env": "PHANTOM_RANSOM_SIM_ALLOW"},
    "phishing.aitm": {"type": bool, "env": "PHANTOM_AITM"},
}

_TRUTHY = ("1", "true", "yes", "on")
_FALSY = ("0", "false", "no", "off", "")


def declared(key: str) -> Optional[Dict[str, Any]]:
    """The schema entry for ``key`` (None when undeclared)."""
    return SCHEMA.get(key)


def _as_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    token = str(value).strip().lower()
    if token in _TRUTHY:
        return True
    if token in _FALSY:
        return False
    return bool(default)


def get_bool(key: str, default: bool = False,
             env: Optional[str] = None) -> bool:
    """Read ``key`` as a boolean with canonical parsing.

    Accepts 1/true/yes/on (and non-zero numbers) as true, 0/false/no/off/
    empty as false; anything unrecognized falls back to ``default``. This
    replaces the ad-hoc `str(...) not in (...)` / `bool(...) in (...)`
    parsing that treated values inconsistently across call sites."""
    return _as_bool(get(key, default, env=env), default)


def get_int(key: str, default: int = 0,
            env: Optional[str] = None) -> int:
    """Read ``key`` as an int, falling back to ``default`` when unset or
    not parseable (never raises)."""
    try:
        return int(str(get(key, default, env=env)).strip())
    except (TypeError, ValueError):
        return default


def get_str(key: str, default: str = "",
            env: Optional[str] = None) -> str:
    """Read ``key`` as a string (``None`` collapses to ``default``)."""
    value = get(key, default, env=env)
    return default if value is None else str(value)


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