"""
toolbelt.py — capability → ranked tool selection.

One capability, many implementers. The agent must never hard-code a single
tool per capability: scan, enum, brute and OSINT phases all have several
valid tools whose availability, speed and noise differ per operator box
(Windows native / WSL Kali / Linux) and per run profile (stealth / speed /
aggressive). The toolbelt picks the best AVAILABLE implementer and never
returns a tool that is not on this host.

Design:
    * options are ordered best-first per use-case (opsec + speed + depth)
    * `ToolRegistry` (runtime/toolchain.py) stays the single source of
      truth for "is this binary on this box" (native + WSL resolution)
    * `pick()` returns the winning tool name; adapters that need
      capability-aware flags use `pick_with_reason()` to log WHY
    * every selection is cached per (capability, style, host-class) so the
      hot planner loop does not re-probe the filesystem

This is the seam where new tools plug in: add an entry to _CATALOG, keep
the same output contract, and every capability that declares the generic
tool set instantly uses it when installed.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from phantom.automation.runtime.toolchain import ToolRegistry


@dataclass(frozen=True)
class ToolOption:
    """One implementer of a capability, with its trade-offs."""
    name: str                 # binary the adapter must emit
    rank: int = 50            # lower = preferred (opsec/speed/depth blend)
    styles: Tuple[str, ...] = ("default", "stealth", "speed", "aggressive")
    # styles this option is suitable for; the run profile filters the pool
    note: str = ""            # shown in tool_missing / setup panels


@dataclass
class ToolChoice:
    """The winning selection, with the reasoning attached."""
    capability: str
    tool: Optional[str]           # None when nothing is installed
    alternatives_missing: List[str] = field(default_factory=list)
    reason: str = ""

    @property
    def ok(self) -> bool:
        return self.tool is not None


# ── catalog ────────────────────────────────────────────────────────────────
# capability-id -> ranked options. Ranks blend depth, speed and noise:
#   scan_tcp    : masscan finds MORE ports faster but is loud and often
#                 needs root; nmap is the quiet default; nc sweep is the
#                 zero-dependency floor (bash-only, WSL always has it).
#   version     : nmap -sV is the only game in town today, but amap-style
#                 probes plug in here.
#   os          : nmap -O; xprobe2 could slot in later.
#   ssh_banner  : the fingerprint engine (pure socket, zero deps) is the
#                 FIRST choice when available; nc is the floor. This is the
#                 fix for the "nc at a closed 22 fails" loop — with the
#                 internal engine the capability no longer needs ANY tool.
#   smb_enum    : smbmap (scriptable) > enum4linux (noisy, slow).
#   brute_ssh   : hydra > medusa > ncat scripting (future).
#   http_probe  : curl is universal; httpx adds concurrency when present.
_TOOL_CATALOG: Dict[str, List[ToolOption]] = {
    "scan_tcp": [
        ToolOption("masscan", rank=20,
                   styles=("speed", "aggressive"),
                   note="fastest full-range sweep, loud, needs root"),
        ToolOption("nmap", rank=40, note="default scanner, quiet+precise"),
        ToolOption("nc", rank=80, styles=("default",),
                   note="zero-dependency TCP connect sweep (slow, quiet)"),
    ],
    "version_detect": [
        ToolOption("nmap", rank=40),
    ],
    "os_detect": [
        ToolOption("nmap", rank=40),
    ],
    "ssh_banner": [
        ToolOption("__internal__", rank=10,
                   note="pure-socket fingerprint engine (no binary needed)"),
        ToolOption("nc", rank=80, note="banner grab fallback"),
    ],
    "smb_enum": [
        ToolOption("smbmap", rank=30),
        ToolOption("enum4linux", rank=60),
        ToolOption("nmap", rank=90,
                   note="nmap --script smb-enum-shares fallback"),
    ],
    "http_probe": [
        ToolOption("curl", rank=30),
        ToolOption("httpx", rank=20, note="concurrent prober when installed"),
    ],
    "http_get": [
        ToolOption("curl", rank=30),
        ToolOption("wget", rank=40, note="fallback fetcher when curl is absent"),
    ],
    "redis_info": [
        ToolOption("redis-cli", rank=30),
        ToolOption("nc", rank=80, styles=("default",),
                   note="RESP INFO over raw TCP (zero extra deps)"),
    ],
    "brute_ssh": [
        ToolOption("hydra", rank=30),
        ToolOption("medusa", rank=60),
    ],
}

# capabilities whose options must be re-resolved per run profile
_PROFILE_SENSITIVE = {"scan_tcp"}


class Toolbelt:
    """Picks the best available tool per capability on THIS operator box."""

    def __init__(self, registry: Optional[ToolRegistry] = None) -> None:
        self.registry = registry or ToolRegistry()
        self._cache: Dict[Tuple[str, str], ToolChoice] = {}
        self._lock = threading.Lock()

    # ── public API ─────────────────────────────────────────────────────
    def pick(self, capability: str, style: str = "default") -> ToolChoice:
        """Best installed implementer for a capability, or tool=None."""
        key = (capability, style if capability in _PROFILE_SENSITIVE
               else "default")
        with self._lock:
            cached = self._cache.get(key)
        if cached is not None:
            return cached
        choice = self._resolve(capability, style)
        with self._lock:
            self._cache[key] = choice
        return choice

    def invalidate(self) -> None:
        """Drop the cache (after `phantom setup` installs a tool)."""
        with self._lock:
            self._cache.clear()

    def status(self) -> Dict[str, ToolChoice]:
        """Every catalogued capability with its current selection —
        rendered by `setup status` / the Electron tool panel."""
        out: Dict[str, ToolChoice] = {}
        for cap in _TOOL_CATALOG:
            out[cap] = self.pick(cap)
        return out

    # ── resolution ─────────────────────────────────────────────────────
    def _resolve(self, capability: str, style: str) -> ToolChoice:
        options = _TOOL_CATALOG.get(capability, [])
        if not options:
            return ToolChoice(capability, None, reason="no tool options registered")
        pool = [o for o in options if style in o.styles or "default" in o.styles]
        if not pool:
            pool = options
        ranked = sorted(pool, key=lambda o: o.rank)
        missing: List[str] = []
        for opt in ranked:
            if opt.name == "__internal__":
                # in-process engine: always available, needs no binary
                return ToolChoice(
                    capability, opt.name, missing,
                    reason=opt.note or "in-process engine")
            if self.registry.has(opt.name):
                return ToolChoice(
                    capability, opt.name, missing,
                    reason=opt.note or f"best available (rank {opt.rank})")
            missing.append(opt.name)
        return ToolChoice(
            capability, None, missing,
            reason="not installed — install one of: "
                   + ", ".join(o.name for o in ranked if o.name != "__internal__"))
