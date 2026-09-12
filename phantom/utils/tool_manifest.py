"""tool_manifest.py — the single source of truth for external tool packages.

Maps each offensive tool phantom's capabilities reference to the package
that provides it, per platform family. `phantom setup`, `phantom doctor`
and the Electron preflight panel all consume THIS table — package names
live in reviewable code, never hardcoded at the call site (this is the
structural fix for the class of bug that once produced
`apt-get install deploy-agent`: phantom commands must never reach a
package manager).

Notes:
  * impacket tools (GetNPUsers.py, GetUserSPNs.py, secretsdump.py,
    psexec.py...) all come from the `impacket` pip package / distro
    package `impacket-scripts` or `python3-impacket`;
  * `sudo` and `wget` are treated as BASE (expected present; installed
    with the base group, never individually);
  * entries carry a category so the setup wizard can show a sensible
    grouped list, and `wsl_only` marks tools that on native Windows are
    expected inside the WSL toolbox rather than natively.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass(frozen=True)
class ToolEntry:
    name: str                 # command name phantom looks up (ToolRegistry)
    category: str             # recon | brute | web | ad | msf | base | pip
    apt: str                  # Debian/Kali package ("" = same as name)
    dnf: str = ""             # Fedora/RHEL package ("" = none known)
    pacman: str = ""          # Arch package ("" = none known)
    pip: str = ""             # pip fallback package ("" = no pip source)
    brew: str = ""            # macOS formula ("" = apt-equivalent name)
    base: bool = False        # part of the base system group
    wsl_only: bool = False    # on Windows expected inside the WSL toolbox
    description: str = ""


# ── the manifest ─────────────────────────────────────────────────────────

MANIFEST: Tuple[ToolEntry, ...] = (
    ToolEntry("nmap", "recon", "nmap", "nmap", "nmap",
              description="Port scanner / service detection"),
    ToolEntry("masscan", "recon", "masscan", "masscan", "masscan",
              description="Massive port scanner"),
    ToolEntry("curl", "recon", "curl", "curl", "curl", base=True,
              description="HTTP client"),
    ToolEntry("wget", "recon", "wget", "wget", "wget", base=True,
              description="HTTP downloader"),
    ToolEntry("nc", "recon", "netcat-openbsd", "nmap-ncat", "gnu-netcat",
              description="Netcat (banner grabs / pivots)"),
    ToolEntry("httpx", "web", "httpx-toolkit", "httpx-toolkit", "",
              pip="httpx-toolkit",
              description="HTTP prober (projectdiscovery)"),
    ToolEntry("hydra", "brute", "hydra", "hydra", "hydra",
              description="Login brute-forcer"),
    ToolEntry("medusa", "brute", "medusa", "medusa", "medusa",
              description="Parallel login brute-forcer"),
    ToolEntry("sshpass", "brute", "sshpass", "sshpass", "sshpass",
              description="Non-interactive SSH auth (hydra ssh module)"),
    ToolEntry("john", "brute", "john", "john", "john",
              description="Hash cracker (John the Ripper)"),
    ToolEntry("hashcat", "brute", "hashcat", "hashcat", "hashcat",
              description="GPU hash cracker"),
    ToolEntry("redis-cli", "recon", "redis-tools", "redis", "redis",
              description="Redis client (enum/creds)"),
    ToolEntry("smbmap", "ad", "smbmap", "smbmap", "smbmap",
              pip="smbmap", description="SMB share enumerator"),
    ToolEntry("evil-winrm", "ad", "evil-winrm", "evil-winrm", "evil-winrm",
              description="WinRM shell (gem; package on Kali)"),
    ToolEntry("ldapsearch", "ad", "ldap-utils", "openldap-clients",
              "openldap", description="LDAP query tool"),
    ToolEntry("GetNPUsers.py", "ad", "impacket-scripts", "python3-impacket",
              "impacket", pip="impacket",
              description="AS-REP roasting (impacket)"),
    ToolEntry("GetUserSPNs.py", "ad", "impacket-scripts", "python3-impacket",
              "impacket", pip="impacket",
              description="Kerberoasting (impacket)"),
    ToolEntry("secretsdump.py", "ad", "impacket-scripts", "python3-impacket",
              "impacket", pip="impacket",
              description="NTDS/LSA dump (impacket)"),
    ToolEntry("psexec.py", "ad", "impacket-scripts", "python3-impacket",
              "impacket", pip="impacket",
              description="SMB exec (impacket)"),
    ToolEntry("msfconsole", "msf", "metasploit-framework",
              "", "", wsl_only=True,
              description="Metasploit (heavy — Kali repos recommended)"),
    ToolEntry("sudo", "base", "sudo", "sudo", "sudo", base=True,
              description="Privilege elevation"),
)

_BY_NAME: Dict[str, ToolEntry] = {e.name: e for e in MANIFEST}


def entry(tool: str) -> Optional[ToolEntry]:
    return _BY_NAME.get(tool)


def all_tools() -> List[ToolEntry]:
    return list(MANIFEST)


def capability_tools() -> List[ToolEntry]:
    """Tools the CAPABILITIES actually reference, in manifest order —
    the setup wizard shows exactly these, nothing speculative."""
    from phantom.automation.guidance.kit import CAPABILITIES
    used = set()
    for cap in CAPABILITIES:
        used.update(cap.tools)
    return [e for e in MANIFEST if e.name in used]


# ── per-platform resolution ──────────────────────────────────────────────

def package_for(tool: str, platform: str) -> str:
    """Package name for the platform family ('apt'|'dnf'|'pacman'|'pip'|'brew')."""
    e = entry(tool)
    if e is None:
        return tool
    return {"apt": e.apt, "dnf": e.dnf, "pacman": e.pacman,
            "pip": e.pip, "brew": e.brew or e.apt}.get(platform, "") or e.apt


# ── doctor / install-plan ────────────────────────────────────────────────

def _which(name: str) -> Optional[str]:
    return shutil.which(name)


def check(tools: Optional[List[str]] = None,
          names: Optional[List[str]] = None) -> Dict[str, object]:
    """Snapshot for `phantom doctor` / the Electron panel.

    `names` overrides the tool list (a capability's tools, a module's
    requirement). Returns per-tool state + a summary; never raises.
    """
    entries = (all_tools() if not names
               else [e for e in MANIFEST if e.name in set(names)])
    out: Dict[str, object] = {"tools": [], "missing": [], "installed": 0,
                              "total": len(entries)}
    for e in entries:
        found = bool(_which(e.name))
        out["tools"].append({                      # type: ignore[attr-defined]
            "name": e.name, "category": e.category, "found": found,
            "package": e.apt, "description": e.description,
            "wsl_only": e.wsl_only})
        if found:
            out["installed"] += 1                  # type: ignore[operator]
        else:
            out["missing"].append(e.name)          # type: ignore[operator]
    return out


def install_plan(platform: str, tools: Optional[List[str]] = None) -> List[str]:
    """Ordered package names to install on `platform` for the given tools
    (default: every manifest entry not in the base group). Dedupes
    (impacket tools collapse into one package) — the wizard shows this
    exact list before consenting."""
    entries = all_tools() if not tools else [e for e in MANIFEST
                                             if e.name in set(tools)]
    ordered: List[str] = []
    for e in entries:
        if e.base:
            continue
        pkg = package_for(e.name, platform)
        if pkg and pkg not in ordered:
            ordered.append(pkg)
    return ordered
