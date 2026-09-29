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
    # services the TARGET must expose for this option to be usable at all:
    # ranking an SMB tool for a host with no SMB is how a plan ends up
    # looping a tool against a surface that is not there.
    requires_service: Tuple[str, ...] = ()


@dataclass(frozen=True)
class TargetSurface:
    """What the TARGET actually exposes — the input that turns "best tool
    on MY box" into "tool that fits THIS target". Derived from the
    WorldModel's service/os findings, never from the operator's machine."""
    services: frozenset = frozenset()
    has_web: bool = False
    os: str = ""

    def has(self, name: str) -> bool:
        return (name or "").lower() in self.services


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
        ToolOption("__internal__", rank=10, requires_service=("ssh",),
                   note="pure-socket fingerprint engine (no binary needed)"),
        ToolOption("nc", rank=80, requires_service=("ssh",),
                   note="banner grab fallback"),
    ],
    "smb_enum": [
        ToolOption("smbmap", rank=30, requires_service=("smb",)),
        ToolOption("enum4linux", rank=60, requires_service=("smb",)),
        ToolOption("nmap", rank=90, requires_service=("smb",),
                   note="nmap --script smb-enum-shares fallback"),
    ],
    "http_probe": [
        ToolOption("curl", rank=30, requires_service=("http",)),
        ToolOption("httpx", rank=20, requires_service=("http",),
                   note="concurrent prober when installed"),
    ],
    "http_get": [
        ToolOption("curl", rank=30, requires_service=("http",)),
        ToolOption("wget", rank=40, requires_service=("http",),
                   note="fallback fetcher when curl is absent"),
    ],
    "redis_info": [
        ToolOption("redis-cli", rank=30, requires_service=("redis",)),
        ToolOption("nc", rank=80, styles=("default",),
                   requires_service=("redis",),
                   note="RESP INFO over raw TCP (zero extra deps)"),
    ],
    "brute_ssh": [
        ToolOption("hydra", rank=30, requires_service=("ssh",)),
        ToolOption("medusa", rank=60, requires_service=("ssh",)),
    ],
}

# capabilities whose options must be re-resolved per run profile
_PROFILE_SENSITIVE = {"scan_tcp"}


class Toolbelt:
    """Picks the best available tool per capability on THIS operator box."""

    def __init__(self, registry: Optional[ToolRegistry] = None) -> None:
        self.registry = registry or ToolRegistry()
        self._cache: Dict[Tuple, ToolChoice] = {}
        self._lock = threading.Lock()

    @staticmethod
    def surface_from_wm(wm) -> TargetSurface:
        """Derive the target surface from a WorldModel's findings.

        Only the TARGET's own service/os facts are read — this is the
        difference between "what my box has" and "what the target is",
        which is what the choice should turn on."""
        services = set()
        has_web = False
        os_name = ""
        try:
            for f in wm.find("service"):
                v = f.value if isinstance(f.value, dict) else {}
                svc = str(v.get("service") or "").lower()
                prod = str(v.get("product") or "").lower()
                if "http" in svc or "http" in prod:
                    has_web = True
                    services.add("http")
                if "smb" in svc or "microsoft-ds" in svc or \
                        "netbios" in svc or "netbios" in prod:
                    services.add("smb")
                if "ssh" in svc or "ssh" in prod:
                    services.add("ssh")
                if "redis" in svc or "redis" in prod:
                    services.add("redis")
            for f in wm.find("os"):
                v = f.value if isinstance(f.value, dict) else {}
                os_name = str(v.get("os") or v.get("name") or "")
                break
        except Exception:
            pass
        return TargetSurface(services=frozenset(services),
                             has_web=has_web, os=os_name)

    # ── public API ─────────────────────────────────────────────────────
    def pick(self, capability: str, style: str = "default",
             target: Optional[TargetSurface] = None) -> ToolChoice:
        """Best implementer for a capability ON THIS TARGET, or tool=None.

        ``target`` is the target's surface (services present). When given,
        an option whose ``requires_service`` is absent is dropped before
        ranking — a tool aimed at a surface the target does not expose can
        never be the right answer, however well installed it is.
        """
        style_key = style if capability in _PROFILE_SENSITIVE else "default"
        tkey = None
        if target is not None:
            tkey = (tuple(sorted(target.services)), target.has_web)
        key = (capability, style_key, tkey)
        with self._lock:
            cached = self._cache.get(key)
        if cached is not None:
            return cached
        choice = self._resolve(capability, style, target)
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
    def _resolve(self, capability: str, style: str,
                 target: Optional[TargetSurface] = None) -> ToolChoice:
        options = _TOOL_CATALOG.get(capability, [])
        if not options:
            return ToolChoice(capability, None, reason="no tool options registered")
        pool = [o for o in options if style in o.styles or "default" in o.styles]
        if not pool:
            pool = options
        if target is not None:
            wanted = sorted({s for o in pool for s in o.requires_service})
            viable = [o for o in pool
                      if not o.requires_service
                      or any(target.has(s) for s in o.requires_service)]
            if not viable:
                return ToolChoice(
                    capability, None,
                    reason="target exposes no " + "/".join(wanted) +
                           " surface — tool not applicable")
            pool = viable
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
