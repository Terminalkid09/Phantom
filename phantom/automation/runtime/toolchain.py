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
import time
from typing import Callable, Dict, List, Optional, Set, Tuple

# A WSL probe spawns `wsl.exe`, which on a Windows box with no usable distro
# can BLOCK instead of failing: observed hanging until the timeout, once per
# tool, which turned the first toolbelt scan into ~4 minutes of dead time
# (and made a single misconfigured machine look like a broken build). So
# availability is checked ONCE per process with its own short deadline, and a
# process-wide budget caps the total time the WSL path may ever spend. Failing
# closed costs a "tool missing" on a machine where the probe would have hung
# anyway — the honest degradation this module is for.
_WSL_AVAIL_TIMEOUT = 5.0
_WSL_BUDGET_SECONDS = 20.0


def _wsl_probe(cmd: List[str], timeout: float):
    """Run ONE wsl.exe command and return the CompletedProcess or None.

    Separated out so the budget/availability logic can be verified without a
    real WSL on the box (the whole point of the fix).
    """
    import subprocess
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
    except Exception:
        return None


def _wsl_state() -> Dict[str, float]:
    return _wsl_which.__dict__.setdefault(
        "_state", {"checked": 0.0, "ok": 0.0, "spent": 0.0, "disabled": 0.0})


def _reset_wsl_state() -> None:
    """Forget the memoised WSL facts (tests, and after installing a distro)."""
    _wsl_which.__dict__.pop("_state", None)
    _wsl_which.__dict__.pop("_cache", None)


def wsl_available() -> bool:
    """Is there a USABLE wsl.exe? Checked once per process, bounded."""
    state = _wsl_state()
    if not state["checked"]:
        state["checked"] = 1.0
        started = time.time()
        proc = _wsl_probe(["wsl", "-l", "-q"], _WSL_AVAIL_TIMEOUT)
        state["spent"] += time.time() - started
        state["ok"] = 1.0 if proc is not None else 0.0
    return bool(state["ok"]) and not state["disabled"]


def _wsl_budget_left() -> float:
    return _WSL_BUDGET_SECONDS - _wsl_state()["spent"]


def _wsl_which(name: str) -> Optional[str]:
    """Resolve a Linux tool through WSL when the Windows host lacks it.

    Phantom runs natively on Windows but the operator toolset (nmap,
    sshpass, hydra, ...) typically lives in the Kali WSL distro. A tool
    absent from Windows PATH but present in WSL is USABLE via
    `wsl -d <distro> -- <tool> ...`: this returns that wrapper so the
    capability is not wrongly marked missing.

    Distros are probed in order (running ones first): the default distro
    via `wsl -e`, then every registered distro via `wsl -d <name>`.
    Results are cached process-wide, and the whole WSL path is bounded: no
    availability, or a spent budget, turns it off for the rest of the
    process instead of paying another hang per tool.
    """
    cache = _wsl_which.__dict__.setdefault("_cache", {})
    if name in cache:
        return cache[name]
    if not wsl_available() or _wsl_budget_left() <= 0:
        cache[name] = None
        return None
    result: Optional[str] = None
    # 1. default distro
    started = time.time()
    r = _wsl_probe(["wsl", "-e", "sh", "-c", f"command -v {name} 2>/dev/null"],
                   max(min(15.0, _wsl_budget_left()), 1.0))
    _wsl_state()["spent"] += time.time() - started
    if r is not None:
        out = (r.stdout or "").strip().splitlines()
        if r.returncode == 0 and out and out[0].strip().startswith("/"):
            result = f"wsl -e {name}"
    # 2. named distros (wsl --list output is UTF-16 on some builds)
    if result is None and _wsl_budget_left() > 0:
        try:
            distros = _wsl_distro_list()
        except Exception:
            distros = []
        for d in distros:
            if _wsl_budget_left() <= 0:
                break
            started = time.time()
            r = _wsl_probe(
                ["wsl", "-d", d, "-e", "sh", "-c",
                 f"command -v {name} 2>/dev/null"],
                max(min(20.0, _wsl_budget_left()), 1.0))
            _wsl_state()["spent"] += time.time() - started
            if r is not None:
                out = (r.stdout or "").strip().splitlines()
                if (r.returncode == 0 and out
                        and out[0].strip().startswith("/")):
                    result = f"wsl -d {d} {name}"
                    break
    if result is None and _wsl_budget_left() <= 0:
        # the budget is gone: stop paying for probes this run
        _wsl_state()["disabled"] = 1.0
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
                 detect: Optional[Callable[[str], bool]] = None,
                 wsl: bool = True) -> None:
        self._installed = installed          # injected in tests
        self._detect = detect or (lambda name: shutil.which(name) is not None)
        # WSL fallback resolution costs a subprocess probe per unique tool
        # (seconds each). A caller that must stay fast — the doctor's bulk
        # toolbelt scan — can opt out and report NATIVE availability only.
        self._wsl = wsl
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
                if not found and self._wsl and _wsl_which(name):
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
