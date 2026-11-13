"""settings.py — the declared schema over the FIVE configuration planes.

Phantom configuration currently lives on five planes with IMPLICIT
precedence scattered across two modules:

  1. param  — a function parameter (``run_auto_mode(llm=True)``)
  2. cli    — a CLI flag (``--stealth``, ``--engine swarm``)
  3. env    — a ``PHANTOM_*`` environment variable
  4. config — ``data/config.json`` (``phantom.utils.config``: env wins over
              the file, decided INSIDE ``config.get``)
  5. state  — ``data/phantom_state.json`` (``phantom.utils.state``: env wins
              over the persisted value, except ``state._env`` vetoes a
              divergent ``PHANTOM_API_TOKEN`` — an ad-hoc fix because the
              implicit order was wrong for that one key)

This module is the NUCLEUS of the fix (proposal + core, not a rewrite):
every setting is declared ONCE with a name, a type, a default and the
planes it is ALLOWED to come from — in explicit resolution order, first hit
wins. The per-setting order is the policy: ``PHANTOM_API_TOKEN`` declares
``sources=("state", "env")`` because the persisted state is authoritative
on divergence, while every other secret keeps the historical env-first
order. Callers can see WHERE a value came from (``resolve``), which implicit
priority can never tell you.

The existing planes keep owning storage; this module only READS them through
small adapters (injectable for tests). Migrating call sites is deliberately
out of scope for the nucleus.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

# The canonical precedence, highest first. A Setting.sources tuple is an
# explicit ORDER (usually a subsequence of this); it may be reordered when
# the policy demands it (see c2.api_token).
PLANES: Tuple[str, ...] = ("param", "cli", "env", "config", "state")

_KINDS = ("str", "bool", "int", "float", "secret")


@dataclass(frozen=True)
class Setting:
    """One declared setting: name, type, default, allowed sources."""
    name: str
    kind: str
    default: Any
    sources: Tuple[str, ...]
    env: Optional[str] = None          # env plane: the PHANTOM_* name
    config_key: Optional[str] = None   # config plane: dotted key
    state_key: Optional[str] = None    # state plane: persisted key
    doc: str = ""

    def key_for(self, plane: str) -> Optional[str]:
        if plane == "env":
            return self.env
        if plane == "config":
            return self.config_key or self.name
        if plane == "state":
            return self.state_key or self.name
        return None


def _s(name: str, kind: str, default: Any, sources: Tuple[str, ...],
       env: Optional[str] = None, config_key: Optional[str] = None,
       state_key: Optional[str] = None, doc: str = "") -> Setting:
    return Setting(name=name, kind=kind, default=default, sources=sources,
                   env=env, config_key=config_key, state_key=state_key,
                   doc=doc)


# ---------------------------------------------------------------------------
# the nucleus: a representative slice of real settings, one entry per policy
# shape. Add call sites / entries incrementally; do not rewrite the planes.
# ---------------------------------------------------------------------------

SETTINGS: Dict[str, Setting] = {s.name: s for s in (
    # -- secrets (state plane persists, env plane overrides) --------------
    _s("c2.key", "secret", "", ("env", "state"), env="PHANTOM_C2_KEY",
       state_key="PHANTOM_C2_KEY",
       doc="AES key of the C2 envelope. Generated on first use."),
    _s("c2.nonce", "secret", "", ("env", "state"), env="PHANTOM_C2_NONCE",
       state_key="PHANTOM_C2_NONCE",
       doc="AES nonce of the C2 envelope. Generated on first use."),
    _s("payload.token", "secret", "", ("env", "state"),
       env="PHANTOM_PAYLOAD_TOKEN", state_key="PHANTOM_PAYLOAD_TOKEN",
       doc="Shared token binding droppers to staged payloads."),
    # -- the divergence policy, declared instead of hacked in state._env --
    _s("c2.api_token", "secret", "", ("state", "env"),
       env="PHANTOM_API_TOKEN", state_key="PHANTOM_API_TOKEN",
       doc="API token for the local API/Electron. State plane FIRST: the "
           "persisted token is authoritative and a stale env copy from a "
           "previous run must not desync the server (the old fix was the "
           "state._env veto; the order IS the policy now)."),
    # -- flags persisted as state -----------------------------------------
    _s("beacon.auth_required", "bool", True, ("env", "state"),
       env="PHANTOM_BEACON_AUTH_REQUIRED",
       state_key="PHANTOM_BEACON_AUTH_REQUIRED",
       doc="Require HMAC authentication on beacon check-ins."),
    _s("c2.mtls_required", "bool", True, ("env", "state"),
       env="PHANTOM_MTLS_REQUIRED", state_key="PHANTOM_MTLS_REQUIRED",
       doc="Default transport is HTTPS + client certificate."),
    # -- config-file settings with their legacy env override ---------------
    _s("c2.transport_backend", "str", "python", ("env", "config"),
       env="PHANTOM_C2_BACKEND", config_key="c2.transport_backend",
       doc='Data plane: "python" listener or "go" (c2d).'),
    _s("c2.listener_auto_start", "bool", True, ("param", "cli", "config"),
       config_key="c2.listener_auto_start",
       doc="Auto-mode brings its own C2 listener before any deploy."),
    _s("automation.experience", "bool", True,
       ("param", "cli", "env", "config"), env="PHANTOM_EXPERIENCE",
       config_key="automation.experience",
       doc="Cross-engagement experience memory (nothing leaves the box)."),
)}


# ---------------------------------------------------------------------------
# plane adapters (read-only; injectable so tests pin RESOLUTION, not I/O)
# ---------------------------------------------------------------------------

def _read_env(s: Setting) -> Any:
    return os.getenv(s.env) if s.env else None


def _read_config(s: Setting) -> Any:
    from phantom.utils import config as cfg
    return cfg.get(s.key_for("config"), None)


def _read_state(s: Setting) -> Any:
    # The state plane is read RAW: state.get_string/get_flag re-implement an
    # env-first order of their own, which is exactly the implicit priority
    # this schema replaces.
    from phantom.utils import state as st
    return st._read().get(s.key_for("state"))


_READERS: Dict[str, Callable[[Setting], Any]] = {
    "env": _read_env,
    "config": _read_config,
    "state": _read_state,
}


def _coerce(kind: str, value: Any) -> Any:
    if value is None:
        return None
    if kind in ("str", "secret"):
        return str(value)
    if kind == "bool":
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        return str(value).strip().lower() not in ("0", "false", "no", "off", "n")
    if kind == "int":
        return int(value)
    if kind == "float":
        return float(value)
    raise ValueError(f"unknown kind: {kind}")


def _validate(s: Setting) -> None:
    assert s.kind in _KINDS, (s.name, s.kind)
    assert s.sources, f"{s.name}: no sources"
    for plane in s.sources:
        assert plane in PLANES, (s.name, plane)
    assert len(set(s.sources)) == len(s.sources), f"{s.name}: dup sources"
    for plane in s.sources:
        if plane in ("env", "config", "state") and not s.key_for(plane):
            raise AssertionError(f"{s.name}: plane {plane} has no key")


for _s_ in SETTINGS.values():
    _validate(_s_)


def resolve(name: str, *, param: Any = None, cli: Any = None,
            readers: Optional[Dict[str, Callable[[Setting], Any]]] = None
            ) -> Tuple[Any, str]:
    """Resolve ``name`` — returns (value, source) where source is the plane
    that won ("default" when no plane holds a value). Explicit order: the
    FIRST plane in ``Setting.sources`` holding a value wins."""
    try:
        s = SETTINGS[name]
    except KeyError:
        raise KeyError(f"undeclared setting: {name}") from None
    for plane in s.sources:
        if plane == "param":
            raw = param
        elif plane == "cli":
            raw = cli
        else:
            table = _READERS if readers is None else readers
            reader = table.get(plane)
            if reader is None:
                continue
            raw = reader(s)
        if raw is None or (isinstance(raw, str) and raw.strip() == ""):
            continue  # a plane that is silent is not a hit
        coerced = _coerce(s.kind, raw)
        return coerced, plane
    return s.default, "default"


def get(name: str, *, param: Any = None, cli: Any = None,
        readers: Optional[Dict[str, Callable[[Setting], Any]]] = None) -> Any:
    """The resolved value only (``resolve`` when the caller wants the plane)."""
    return resolve(name, param=param, cli=cli, readers=readers)[0]


def describe() -> List[Dict[str, Any]]:
    """Audit view for `doctor`/docs: every declared setting with its type,
    default, allowed planes and secret-safe metadata."""
    out = []
    for s in SETTINGS.values():
        out.append({
            "name": s.name,
            "kind": s.kind,
            "default": "<empty>" if s.kind == "secret" and not s.default
            else s.default,
            "sources": list(s.sources),
            "env": s.env,
            "config_key": s.config_key,
            "state_key": s.state_key,
            "doc": s.doc,
        })
    return out
