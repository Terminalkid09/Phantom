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

import json
import os
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
_WSL_BUDGET_SECONDS = 30.0

# A NEGATIVE availability answer is the dangerous one to memoise. Measured
# 2026-11-07: the first `wsl -l` after a `wsl --shutdown` (and under a heavily
# loaded host) exceeded the 5 s deadline, and the cached "no WSL" then made
# EVERY tool look missing for the rest of the run — `execute_quiet` answered
# `rc=-1, error="tool 'nmap' not installed"` for a distro that printed
# `nmap --version` fine seconds later. Positives stay cached for the process
# (distros do not appear mid-run); a negative is retried, at most
# `_WSL_MAX_PROBES` times and no sooner than `_WSL_RETRY_AFTER` seconds
# apart, so a truly absent WSL still costs one short probe per minute rather
# than one per tool.
_WSL_RETRY_AFTER = 60.0
_WSL_MAX_PROBES = 3


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
        "_state", {"checked": 0.0, "ok": 0.0, "spent": 0.0,
                   "disabled": 0.0, "probes": 0})


def _reset_wsl_state() -> None:
    """Forget the memoised WSL facts (tests, and after installing a distro)."""
    _wsl_which.__dict__.pop("_state", None)
    _wsl_which.__dict__.pop("_cache", None)
    _wsl_which.__dict__.pop("_inventory", None)
    _wsl_distro_list.__dict__.pop("_cache", None)


def wsl_available() -> bool:
    """Is there a USABLE wsl.exe? Bounded, and never permanently wrong.

    A positive answer is cached for the process. A negative one expires after
    `_WSL_RETRY_AFTER` seconds (max `_WSL_MAX_PROBES` attempts), because a
    cold or overloaded VM looks exactly like a missing one for a moment.
    """
    state = _wsl_state()
    if state["ok"]:
        return not state["disabled"]
    if state["disabled"]:
        return False
    now = time.time()
    if state["probes"] and (now - state["checked"] < _WSL_RETRY_AFTER
                             or state["probes"] >= _WSL_MAX_PROBES):
        return False
    state["probes"] += 1
    state["checked"] = now
    started = time.time()
    proc = _wsl_probe(["wsl", "-l", "-q"], _WSL_AVAIL_TIMEOUT)
    state["spent"] += time.time() - started
    if proc is not None:
        state["ok"] = 1.0
    return bool(state["ok"]) and not state["disabled"]


def _wsl_budget_left() -> float:
    return _WSL_BUDGET_SECONDS - _wsl_state()["spent"]


#: WSL2 utility distros that only host Docker's engine. They carry no
#: operator toolset, and probing them is expensive: measured 2026-11-07, one
#: `wsl -d docker-desktop sh -c "command -v nmap"` took 15.6 s of the 20 s
#: process budget, so the Kali hit that came AFTER it was never paid for and
#: auto-mode reported `tool unavailable: nmap, masscan, nc` on a box where
#: `nmap --version` answers in a second. Saltier distros are probed first.
_WSL_SKIP_DISTROS = ("docker-desktop", "docker-desktop-data")
_WSL_PREFERRED_DISTROS = ("kali", "parrot", "blackarch")


def _usable_distros() -> List[str]:
    """Registered distros minus Docker's own, tool-bearing ones first."""
    try:
        names = [d for d in _wsl_distro_list()
                 if not d.lower().startswith(tuple(_WSL_SKIP_DISTROS))]
    except Exception:
        return []
    preferred = [d for d in names
                 if d.lower().startswith(_WSL_PREFERRED_DISTROS)]
    return preferred + [d for d in names if d not in preferred]


#: How long a distro's tool INVENTORY is trusted. A `command -v` per tool cost
#: ~2 s each, so a toolbelt scan of twenty binaries spent the whole WSL budget
#: and the tools asked for last were reported missing (measured 2026-11-07).
#: One directory listing (~2 s, ~2775 entries on Kali) answers every question
#: in the run; the on-disk copy makes the NEXT run instant.
_WSL_INVENTORY_TTL = 6 * 3600.0
_WSL_TOOL_DIRS = "/usr/bin /usr/sbin /bin /sbin /usr/local/bin"


def _inventory_file() -> str:
    try:
        from phantom.utils.paths import data_dir
        return os.path.join(data_dir(), "cache", "wsl_inventory.json")
    except Exception:
        return ""


def _inventory_memory() -> Dict[str, dict]:
    return _wsl_which.__dict__.setdefault("_inventory", {})


def invalidate_wsl_inventory() -> None:
    """Forget the listings (after `install <tool>`, or a distro change)."""
    _wsl_which.__dict__.pop("_inventory", None)
    path = _inventory_file()
    try:
        if path and os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


def _load_inventory_from_disk() -> Dict[str, dict]:
    path = _inventory_file()
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, ValueError):
        return {}
    now = time.time()
    fresh: Dict[str, dict] = {}
    for distro, entry in (raw or {}).items():
        try:
            if now - float(entry.get("ts", 0)) < _WSL_INVENTORY_TTL:
                fresh[distro] = {"ts": entry["ts"],
                                 "tools": set(entry.get("tools") or ())}
        except (TypeError, ValueError, AttributeError):
            continue
    return fresh


def _save_inventory(memory: Dict[str, dict]) -> None:
    path = _inventory_file()
    if not path:
        return
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        payload = {d: {"ts": e["ts"], "tools": sorted(e["tools"])}
                   for d, e in memory.items()}
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(payload, fh)
        os.replace(tmp, path)
    except OSError:
        pass


def _distro_tools(distro: str) -> Optional[Set[str]]:
    """Basenames of every executable the distro knows, or None if unknown.

    One listing per distro per TTL, in memory and on disk — the difference
    between a toolbelt that resolves and one that reports "tool unavailable"
    because the probes ran out of budget halfway.
    """
    memory = _inventory_memory()
    if distro not in memory:
        loaded = _load_inventory_from_disk()
        for name, entry in loaded.items():
            memory.setdefault(name, entry)
    entry = memory.get(distro)
    if entry and time.time() - float(entry["ts"]) < _WSL_INVENTORY_TTL:
        return entry["tools"]
    if _wsl_budget_left() <= 0:
        return None
    started = time.time()
    r = _wsl_probe(["wsl", "-d", distro, "-e", "sh", "-c",
                    f"ls -1 {_WSL_TOOL_DIRS} 2>/dev/null"],
                   max(min(_WSL_BUDGET_SECONDS, _wsl_budget_left()), 1.0))
    _wsl_state()["spent"] += time.time() - started
    if r is None or r.returncode != 0:
        # UNKNOWN, not empty: the caller must not memoise a miss it caused
        _wsl_state()["inventory_unknown"] = 1.0
        return None
    tools = {line.strip().rsplit("/", 1)[-1]
             for line in (r.stdout or "").splitlines() if line.strip()}
    if not tools:
        return None
    memory[distro] = {"ts": time.time(), "tools": tools}
    _save_inventory(memory)
    return tools


def _wsl_which(name: str) -> Optional[str]:
    """Resolve a Linux tool through WSL when the Windows host lacks it.

    Phantom runs natively on Windows but the operator toolset (nmap,
    sshpass, hydra, ...) typically lives in the Kali WSL distro. A tool
    absent from Windows PATH but present in WSL is USABLE via
    `wsl -d <distro> -- <tool> ...`: this returns that wrapper so the
    capability is not wrongly marked missing.

    Distros are probed by NAME, security distros first, and the `wsl -e`
    (default distro) path is only a fallback when the list is unavailable:
    measured 2026-11-07, `wsl -e` from a Stopped Ubuntu paid a >10 s cold
    boot before Kali was ever asked. Results are cached process-wide, and the
    whole WSL path is bounded: no availability, or a spent budget, turns it
    off for the rest of the process instead of paying another hang per tool.
    """
    cache = _wsl_which.__dict__.setdefault("_cache", {})
    if name in cache:
        return cache[name]
    if not wsl_available() or _wsl_budget_left() <= 0:
        # NOT memoised: `wsl_available()` may turn True on its next retry, and
        # a cached None here would outlive that and keep the tool missing.
        # The availability gate is what prevents a hang per tool, not this.
        return None
    result: Optional[str] = None
    distros = _usable_distros()
    if not distros and _wsl_budget_left() > 0:
        # no registered list: the default distro is all there is
        started = time.time()
        r = _wsl_probe(["wsl", "-e", "sh", "-c",
                        f"command -v {name} 2>/dev/null"],
                       max(min(15.0, _wsl_budget_left()), 1.0))
        _wsl_state()["spent"] += time.time() - started
        if r is not None:
            out = (r.stdout or "").strip().splitlines()
            if r.returncode == 0 and out and out[0].strip().startswith("/"):
                result = f"wsl -e {name}"
    # named distros (wsl --list output is UTF-16 on some builds), skipping
    # Docker's utility distros and preferring the security ones. The INVENTORY
    # is listed once per distro, not a `command -v` per tool: at ~2 s a probe a
    # twenty-binary toolbelt exhausted the budget and the tools asked for last
    # were reported missing.
    if result is None:
        for d in distros:
            tools = _distro_tools(d)
            if tools is not None and name in tools:
                result = f"wsl -d {d} {name}"
                break
    if result is None and _wsl_budget_left() <= 0:
        # the budget is gone: stop paying for probes this run
        _wsl_state()["disabled"] = 1.0
    if result is None and _wsl_state().get("inventory_unknown"):
        # a listing failed, so "not found" here means "not looked at": a
        # memoised miss would outlive the outage (same rule as availability)
        return None
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
        # do NOT memoise a failed listing: a cold VM must not pin "no distros"
        # for the rest of the process (same failure mode as `wsl_available`)
        return []
    if out:
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
