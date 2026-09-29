"""
toolchain.py — tool detection and graceful degradation.

The agent uses ANY tool installed on the operator box, not a fixed list.
Each capability declares the tools it needs (`tools=["nmap"]` or
alternates `tools=["nc", "ncat"]`); the ToolRegistry detects what is
actually present (shutil.which works on Windows and Unix) and resolves
the first available alternate.

A missing tool NEVER crashes the agent: the capability fails with a typed
"tool unavailable" reason and is treated as a self-sufficient failure
(no preconditions -> never retried), because installing the tool is an
operator action, not new world knowledge.
"""

from __future__ import annotations

import shutil
from typing import Callable, Dict, List, Optional, Set, Tuple


def _wsl_which(name: str) -> Optional[str]:
    """Resolve a Linux tool through WSL when the Windows host lacks it.

    Phantom runs natively on Windows but the operator toolset (nmap,
    sshpass, hydra, ...) typically lives in the Kali WSL distro. A tool
    absent from Windows PATH but present in WSL is USABLE via
    `wsl -d <distro> -- <tool> ...`: this returns that wrapper so the
    capability is not wrongly marked missing.

    Distros are probed in order (running ones first): the default distro
    via `wsl -e`, then every registered distro via `wsl -d <name>`.
    Results are cached process-wide (WSL probes cost ~1s each).
    """
    import subprocess
    cache = _wsl_which.__dict__.setdefault("_cache", {})
    if name in cache:
        return cache[name]
    result: Optional[str] = None
    # 1. default distro
    try:
        r = subprocess.run(
            ["wsl", "-e", "sh", "-c", f"command -v {name} 2>/dev/null"],
            capture_output=True, text=True, timeout=15)
        out = (r.stdout or "").strip().splitlines()
        if r.returncode == 0 and out and out[0].strip().startswith("/"):
            result = f"wsl -e {name}"
    except Exception:
        pass
    # 2. named distros (wsl --list output is UTF-16 on some builds)
    if result is None:
        distros = _wsl_distro_list()
        for d in distros:
            try:
                r = subprocess.run(
                    ["wsl", "-d", d, "-e", "sh", "-c",
                     f"command -v {name} 2>/dev/null"],
                    capture_output=True, text=True, timeout=20)
                out = (r.stdout or "").strip().splitlines()
                if r.returncode == 0 and out and out[0].strip().startswith("/"):
                    result = f"wsl -d {d} {name}"
                    break
            except Exception:
                continue
    cache[name] = result
    return result


def _wsl_distro_list() -> list:
    """Registered WSL distro names, cached process-wide (a `wsl --list`
    spawn costs seconds and distros never change mid-run)."""
    lst = _wsl_distro_list.__dict__.setdefault("_cache", None)
    if lst is not None:
        return lst
    import subprocess
    out: list = []
    try:
        r = subprocess.run(["wsl", "--list", "--quiet"],
                           capture_output=True, timeout=15)
        names = (r.stdout or b"").decode("utf-16-le", errors="ignore")
        if "\x00" in names:
            names = names.replace("\x00", "")
        out = [d.strip() for d in names.splitlines() if d.strip()
               and d.isprintable()]
    except Exception:
        pass
    _wsl_distro_list._cache = out
    return out


# Logical tool name -> the binaries that can provide it. Modern distros
# install impacket's Windows-side scripts as `impacket-<name>` (pip entry
# points, Debian packaging), so a bare which("secretsdump.py") reports a
# MISSING tool on a fully provisioned box — which silently killed the whole
# AD chain (kerberoast/dcsync/psexec) with a misleading install hint.
_TOOL_ALIASES: Dict[str, Tuple[str, ...]] = {
    "secretsdump.py": ("secretsdump.py", "impacket-secretsdump",
                       "secretsdump"),
    "GetUserSPNs.py": ("GetUserSPNs.py", "impacket-GetUserSPNs",
                       "GetUserSPNs"),
    "GetNPUsers.py": ("GetNPUsers.py", "impacket-GetNPUsers",
                      "GetNPUsers"),
    "psexec.py": ("psexec.py", "impacket-psexec", "psexec"),
    "wmiexec.py": ("wmiexec.py", "impacket-wmiexec", "wmiexec"),
    "smbexec.py": ("smbexec.py", "impacket-smbexec", "smbexec"),
    "atexec.py": ("atexec.py", "impacket-atexec", "atexec"),
    "ntlmrelayx.py": ("ntlmrelayx.py", "impacket-ntlmrelayx",
                      "ntlmrelayx"),
}


def tool_candidates(name: str) -> Tuple[str, ...]:
    """Every binary name that satisfies a logical tool."""
    return _TOOL_ALIASES.get(name, (name,))


def resolve_tool(name: str) -> str:
    """The FIRST installed binary for a logical tool, else the logical name.

    Used by command builders: detection may find `impacket-secretsdump`, so
    the command must be built with THAT name, not the legacy `.py` one.
    """
    for cand in tool_candidates(name):
        if shutil.which(cand):
            return cand
    return name


class ToolRegistry:
    """Detects which offensive tools are installed on the operator box."""

    def __init__(self, installed: Optional[Set[str]] = None,
                 detect: Optional[Callable[[str], bool]] = None) -> None:
        self._installed = installed          # injected in tests
        self._detect = detect or (lambda name: shutil.which(name) is not None)
        self._cache: Dict[str, bool] = {}

    def has(self, name: str) -> bool:
        if name not in self._cache:
            if self._installed is not None:
                # injected toolset (tests / offline planning): authoritative
                found = any(cand in self._installed
                            for cand in tool_candidates(name))
            else:
                found = self._detect(name)
                if not found:
                    # alias-aware: impacket-<name> satisfies the .py names
                    found = any(cand != name and self._detect(cand)
                                for cand in tool_candidates(name))
                if not found and _wsl_which(name):
                    # Windows-native miss -> the tool exists in a WSL distro
                    # (Kali toolbox): usable via the `wsl -d <distro>` wrapper.
                    found = True
            self._cache[name] = found
        return self._cache[name]

    def resolve(self, tools: List[str]) -> Optional[str]:
        """First installed tool among the alternates, or None."""
        for t in tools:
            if self.has(t):
                return t
        return None

    def missing(self, tools: List[str]) -> List[str]:
        return [t for t in tools if not self.has(t)]

    def installed_tools(self) -> List[str]:
        from phantom.automation.guidance.kit import CAPABILITIES
        names: Set[str] = set()
        for cap in CAPABILITIES:
            names.update(cap.tools)
        return sorted(n for n in names if self.has(n))

    def missing_tools(self) -> List[str]:
        from phantom.automation.guidance.kit import CAPABILITIES
        names: Set[str] = set()
        for cap in CAPABILITIES:
            names.update(cap.tools)
        return sorted(n for n in names if not self.has(n))
