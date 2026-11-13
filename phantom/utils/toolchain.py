"""toolchain.py — what this machine is missing, and how Phantom would install it.

Phantom's recon/OSINT surface leans on external binaries (`sherlock`, `amass`,
`subfinder`, `theHarvester`, `dnsrecon`, `nmap`, `hydra`, ...). Until now a
missing binary looked exactly like a clean run: `run_command` returned "" and the
module stored an empty result, so the operator could not tell "the tool found
nothing" from "the tool is not installed". That is the same dishonesty the
status accumulator fixed one layer down — this module fixes it one layer UP, by
answering three questions in ONE place:

  1. WHAT is this machine?  OS, distribution, package manager, whether elevation
     is needed, and whether we are inside WSL (Kali-on-Windows is the setup the
     project is used in: a Kali WSL distro installs with apt, a Windows-native
     run has to fall back to winget/choco).
  2. WHICH of the tools we depend on are missing?
  3. HOW would each one be installed HERE?

It NEVER installs anything on its own. `install()` refuses unless an explicit
`confirm` callback says yes (the CLI/UI asks the operator, the API requires an
explicit `confirm=true`), because a package manager runs as root and changes the
whole machine — a side effect no automated step may take by itself. Detection is
pure (it takes the `/etc/os-release` *content* and the platform name as
arguments), so every branch is testable without touching a real system.
"""

from __future__ import annotations

import os
import platform as _platform
import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, NamedTuple, Optional, Tuple


# ── environment ───────────────────────────────────────────────────────────────

class Env(NamedTuple):
    """The package-manager facts that decide how a tool gets installed."""

    os: str            # linux | macos | windows
    distro: str        # kali | debian | ubuntu | arch | fedora | ... | unknown
    manager: str       # apt | pacman | dnf | zypper | brew | winget | choco | none
    needs_sudo: bool   # apt/pacman/dnf/zypper on Linux as a non-root user
    wsl: bool          # running inside WSL (Kali-on-Windows)

    def label(self) -> str:
        bits = [self.os]
        if self.distro and self.distro != "unknown":
            bits.append(self.distro)
        if self.wsl:
            bits.append("wsl")
        bits.append(f"pkg:{self.manager}")
        bits.append("sudo" if self.needs_sudo else "no-sudo")
        return " ".join(bits)


# distro ID / ID_LIKE -> package manager. First match wins.
_APT_IDS = {"debian", "ubuntu", "kali", "mint", "pop", "raspbian", "parrot",
            "neon", "elementary", "zorin", "devuan"}
_PACMAN_IDS = {"arch", "manjaro", "endeavouros", "garuda", "artix", "cachyos"}
_DNF_IDS = {"fedora", "rhel", "centos", "rocky", "almalinux", "oracle", "amzn"}
_ZYPPER_IDS = {"opensuse", "opensuse-leap", "opensuse-tumbleweed", "sles"}

_MANAGER_FOR_DISTRO: List[Tuple[set, str]] = [
    (_APT_IDS, "apt"),
    (_PACMAN_IDS, "pacman"),
    (_DNF_IDS, "dnf"),
    (_ZYPPER_IDS, "zypper"),
]


def _parse_os_release(text: str) -> Dict[str, str]:
    """Parse `key=value` lines of /etc/os-release (quotes stripped)."""
    out: Dict[str, str] = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip().upper()] = value.strip().strip('"').strip("'")
    return out


def _manager_for_ids(ids: Iterable[str]) -> Optional[str]:
    wanted = {i.strip().lower() for i in ids if i}
    for known, manager in _MANAGER_FOR_DISTRO:
        if wanted & known:
            return manager
    return None


def detect_env(os_release: Optional[str] = None, *, platform_name: str = "",
               wsl_marker: bool = False) -> Env:
    """Decide the environment. Every input is injectable, so it is testable.

    `platform_name` defaults to `sys.platform`; `os_release=None` (the
    default) reads /etc/os-release from the host, which is the only reliable
    way to tell Kali from Debian (they share the apt family but Kali ships the
    recon tools). Pass `""` to say "there is no os-release here" — what the
    injected tests do.

    The bare `detect_env()` must agree with the CLI it feeds. It used to
    answer `distro="unknown", manager="none"` on every Linux host, because the
    file was read by the CALLERS (`report()`, `missing_tools()`) and not here:
    the shell printed `apt-get install -y nmap` while the API — and therefore
    the Electron toolchain panel, which calls this function directly — offered
    no install command for Linux at all.
    """
    if os_release is None:
        os_release = _os_release_text()
    name = (platform_name or _platform.system()).lower()
    # WSL is worth naming: a Kali-on-Windows operator gets apt (the whole recon
    # stack) while a Windows-native run only has winget/choco. `WSL_DISTRO_NAME`
    # / `WSL_INTEROP` are set by WSL itself and are more reliable than grepping
    # the kernel string out of os-release.
    wsl = (bool(wsl_marker)
           or bool(os.environ.get("WSL_DISTRO_NAME")
                   or os.environ.get("WSL_INTEROP"))
           or "microsoft" in (os_release or "").lower())

    if name.startswith("win"):
        manager = "winget" if shutil.which("winget") else "choco"
        return Env("windows", "windows", manager, False, wsl)
    if name == "darwin" or "macos" in name:
        return Env("macos", "macos", "brew", False, False)

    fields = _parse_os_release(os_release)
    ids = [fields.get("ID", ""), *(fields.get("ID_LIKE", "").split())]
    distro = (fields.get("ID", "") or "unknown").lower()
    manager = _manager_for_ids(ids) or "none"
    needs_sudo = manager != "none" and getattr(os, "geteuid", lambda: 1)() != 0
    return Env("linux", distro, manager, needs_sudo, wsl)


# ── the tools Phantom actually shells out to ──────────────────────────────────

class ToolSpec(NamedTuple):
    why: str                       # one line: what breaks without it
    packages: Dict[str, str]       # manager -> package name
    pip: str = ""                  # pip package when there is no distro package


TOOLS: Dict[str, ToolSpec] = {
    "whois": ToolSpec("domain registration / netblock owner",
                      {"apt": "whois", "pacman": "whois", "dnf": "whois",
                       "zypper": "whois", "brew": "whois"}),
    "dig": ToolSpec("DNS records (A/MX/TXT) for a domain",
                    {"apt": "dnsutils", "pacman": "bind", "dnf": "bind-utils",
                     "zypper": "bind-utils", "brew": "bind"}),
    "dnsrecon": ToolSpec("DNS enumeration (zone transfer, SRV, AXFR)",
                         {"apt": "dnsrecon", "pacman": "dnsrecon",
                          "dnf": "dnsrecon", "brew": "dnsrecon"},
                         pip="dnsrecon"),
    "nmap": ToolSpec("port / service discovery (the base of every pivot)",
                     {"apt": "nmap", "pacman": "nmap", "dnf": "nmap",
                      "zypper": "nmap", "brew": "nmap",
                      "winget": "Insecure.Nmap"}),
    "amass": ToolSpec("passive subdomain enumeration",
                      {"apt": "amass", "pacman": "amass", "brew": "amass"}),
    "subfinder": ToolSpec("fast passive subdomain enumeration",
                          {"apt": "subfinder", "pacman": "subfinder",
                           "brew": "subfinder"}, pip="subfinder"),
    "assetfinder": ToolSpec("subdomains from certificate/relation sources",
                            {"apt": "assetfinder", "brew": "assetfinder"},
                            pip="assetfinder"),
    "theHarvester": ToolSpec("emails, hosts and names from public sources",
                             {"apt": "theharvester", "pacman": "theharvester",
                              "dnf": "theharvester", "brew": "theharvester"},
                             pip="theHarvester"),
    "sherlock": ToolSpec("username -> accounts on hundreds of sites",
                         {"apt": "sherlock", "pacman": "sherlock",
                          "brew": "sherlock"}, pip="sherlock-project"),
    "holehe": ToolSpec("which sites an EMAIL is registered on",
                       {"brew": "holehe"}, pip="holehe"),
    "shodan": ToolSpec("Shodan host/dork search (needs a paid API key)",
                       {"brew": "shodan"}, pip="shodan"),
    "gobuster": ToolSpec("web content / vhost brute force",
                         {"apt": "gobuster", "pacman": "gobuster",
                          "dnf": "gobuster", "brew": "gobuster"}),
    "hydra": ToolSpec("credential attacks against network services",
                      {"apt": "hydra", "pacman": "hydra", "dnf": "hydra",
                       "brew": "hydra"}),
    "adb": ToolSpec("USB / network Android device control",
                    {"apt": "android-tools-adb", "pacman": "android-tools",
                     "dnf": "android-tools", "brew": "android-platform-tools"}),
    "arduino-cli": ToolSpec("compile/upload the HID payload sketch",
                            {"brew": "arduino-cli", "winget": "ArduinoSA.CLI"}),

    # ── the manual modules' own dependencies (measured 2026-11-03) ─────────
    # The registry is what `preflight`, the API toolchain endpoint and the
    # Electron installer read. It used to know ~10 of the binaries the manual
    # modules actually invoke, so for the rest a missing tool was INVISIBLE:
    # `scan` offered enum4linux/smbclient/rpcclient/snmpwalk/onesixtyone/
    # sslscan/traceroute, `web` offered ffuf/feroxbuster/nikto/nuclei/sqlmap/
    # wafw00f/whatweb/arjun, `exploit` offered msfconsole, `wifi` offered
    # airmon-ng/airodump-ng/aireplay-ng/reaver and `pivot` offered ssh — and
    # none of them could be named or installed from the toolchain view.
    # A row here is what turns "the module degraded" into "install THIS, here".
    # Only packages that exist for the manager are listed (a wrong package
    # name is worse than an honest "no mapping for this platform"); the
    # offensive half of this list ships in Kali/Debian, which is the distro
    # Phantom is used from, so `apt` carries the ones with no other home.
    "enum4linux": ToolSpec("SMB/NetBIOS enumeration (users, shares, policy)",
                           {"apt": "enum4linux"}),
    "smbclient": ToolSpec("SMB share listing / null sessions / dialect",
                          {"apt": "smbclient", "pacman": "smbclient",
                           "dnf": "samba-client", "brew": "samba"}),
    "rpcclient": ToolSpec("MS-RPC enumeration without a domain account",
                          {"apt": "smbclient", "brew": "samba"}),
    "snmpwalk": ToolSpec("SNMP OID walk from a community string",
                         {"apt": "snmp", "pacman": "net-snmp",
                          "dnf": "net-snmp", "brew": "net-snmp"}),
    "onesixtyone": ToolSpec("fast SNMP community-string sweep",
                            {"apt": "onesixtyone"}),
    "sslscan": ToolSpec("TLS configuration / cipher enumeration",
                        {"apt": "sslscan", "brew": "sslscan"}),
    "nuclei": ToolSpec("template-driven CVE and misconfig checks",
                       {"apt": "nuclei"}),
    "nikto": ToolSpec("web server misconfiguration scan",
                      {"apt": "nikto", "brew": "nikto"}),
    "ffuf": ToolSpec("web content / vhost fuzzing (gobuster alternative)",
                     {"apt": "ffuf", "brew": "ffuf"}),
    "feroxbuster": ToolSpec("recursive web content discovery",
                            {"apt": "feroxbuster"}),
    "wafw00f": ToolSpec("WAF fingerprint before spending requests",
                        {}, pip="wafw00f"),
    "whatweb": ToolSpec("web stack fingerprint (CMS, framework, versions)",
                        {"apt": "whatweb", "brew": "whatweb"}),
    "arjun": ToolSpec("hidden HTTP parameter discovery",
                      {}, pip="arjun"),
    "sqlmap": ToolSpec("SQL injection confirmation and extraction",
                       {"apt": "sqlmap", "brew": "sqlmap"}, pip="sqlmap"),
    "msfconsole": ToolSpec("Metasploit modules used as a fallback engine "
                           "(no Windows-native build)",
                           {"apt": "metasploit-framework"}),
    "nc": ToolSpec("raw TCP/UDP connect: banner grab, listener, probe",
                   {"apt": "netcat-openbsd", "pacman": "gnu-netcat",
                    "dnf": "nmap-ncat", "brew": "netcat"}),
    "ncat": ToolSpec("Nmap's netcat: TLS and --exec (handler, pivot)",
                     {"apt": "ncat", "brew": "nmap"}),
    "traceroute": ToolSpec("path to the target (where a filter sits); on "
                           "Windows the built-in equivalent is tracert",
                           {"apt": "traceroute", "pacman": "traceroute",
                            "dnf": "traceroute", "brew": "traceroute"}),
    "arp-scan": ToolSpec("layer-2 host discovery on the local segment",
                         {"apt": "arp-scan", "brew": "arp-scan"}),
    "host": ToolSpec("DNS A/MX/NS/TXT lookup from the shell",
                     {"apt": "dnsutils", "pacman": "bind",
                      "dnf": "bind-utils", "brew": "bind"}),
    "ssh": ToolSpec("remote shell / port-forward (pivot, brute); Windows "
                    "ships an OpenSSH client, so nothing to install there",
                    {"apt": "openssh-client", "pacman": "openssh",
                     "dnf": "openssh-clients"}),
    "airmon-ng": ToolSpec("put the wireless card into monitor mode",
                          {"apt": "aircrack-ng", "pacman": "aircrack-ng",
                           "brew": "aircrack-ng"}),
    "airodump-ng": ToolSpec("capture 802.11 beacons and handshakes",
                            {"apt": "aircrack-ng", "pacman": "aircrack-ng",
                             "brew": "aircrack-ng"}),
    "aireplay-ng": ToolSpec("deauth / packet injection for handshake capture",
                            {"apt": "aircrack-ng", "pacman": "aircrack-ng",
                             "brew": "aircrack-ng"}),
    "reaver": ToolSpec("WPS PIN attack (loud, last resort)",
                       {"apt": "reaver"}),
    "chisel": ToolSpec("reverse SOCKS tunnel over HTTP (pivot fallback)",
                       {"apt": "chisel"}),
    "searchsploit": ToolSpec("local ExploitDB lookup (CVE -> exploit)",
                             {"apt": "exploitdb"}),
    # Found by the coverage test on a session with live findings: these are
    # invoked by module suggestions the walk only reaches once the session
    # holds evidence, which is exactly why a hand-written list kept missing
    # them.
    "ssh-keyscan": ToolSpec("collect host keys before an SSH attempt (brute, "
                           "known_hosts pre-seed)",
                           {"apt": "openssh-client", "pacman": "openssh",
                            "dnf": "openssh-clients"}),
    "tcpdump": ToolSpec("packet capture for the traffic analyzer",
                        {"apt": "tcpdump", "pacman": "tcpdump",
                         "dnf": "tcpdump", "brew": "tcpdump"}),
    "tshark": ToolSpec("protocol decode for the traffic analyzer (Wireshark "
                       "CLI)",
                       {"apt": "tshark", "brew": "wireshark"}),
}


def _augment_from_manifest(tools: Dict[str, ToolSpec]) -> Dict[str, ToolSpec]:
    """Merge the APPROVED package manifest under this registry, never over it.

    Two tables each claimed to be THE source of tool packages: this one (read
    by `preflight`, the toolchain API endpoint and the Electron installer) and
    :mod:`phantom.utils.tool_manifest` (read by `phantom setup`, `doctor` and
    the Electron preflight panel). Each knew tools the other did not, so
    `httpx`, `medusa`, `smbmap` or `ldapsearch` could be installed by `setup`
    and were STILL invisible to preflight — the operator was told "missing"
    with no way in. Merging removes the drift instead of adding a third list.

    The explicit rows above always win: they carry the one-line `why` and the
    packages measured for this project. A manifest entry with no package for
    any manager and no pip source is skipped rather than registered as a tool
    nobody can install. `base=True` entries (sudo, curl, wget) are skipped on
    purpose: they are expected on every machine and would only add noise to
    `missing()`.
    """
    try:
        from phantom.utils.tool_manifest import MANIFEST
    except Exception:                     # a partially installed tree
        return tools
    merged = dict(tools)
    for entry in MANIFEST:
        name = getattr(entry, "name", "")
        if not name or name in merged or getattr(entry, "base", False):
            continue
        packages: Dict[str, str] = {}
        for manager, package in (("apt", entry.apt), ("dnf", entry.dnf),
                                 ("pacman", entry.pacman),
                                 ("brew", entry.brew)):
            if package:
                packages[manager] = package
        if not packages and not entry.pip:
            continue
        merged[name] = ToolSpec(entry.description or name, packages,
                                pip=entry.pip)
    return merged


TOOLS = _augment_from_manifest(TOOLS)

def package_for(tool: str, env: Env) -> Optional[str]:
    """The package name for `tool` under this manager, or None."""
    spec = TOOLS.get(tool)
    if spec is None:
        return None
    return spec.packages.get(env.manager)


def install_command(tool: str, env: Env) -> Optional[List[str]]:
    """The exact argv Phantom would run to install `tool`. None = not mappable.

    A packaged tool is preferred over the Python distribution: on Debian/Kali
    the recon stack comes from the distro repos and a parallel `pip install`
    would shadow the packaged copy on PATH. Only when THIS manager has no
    package do we fall back to pip (per-user, so no elevation), and only when
    the tool is pip-installable at all.

    Elevation is expressed by prefixing `sudo` on Linux only: `brew` and
    `winget` install per-user and asking for root there breaks them.
    """
    spec = TOOLS.get(tool)
    if spec is None:
        return None

    package = package_for(tool, env)
    if package is None:
        if not spec.pip:
            return None
        return ["python", "-m", "pip", "install", "--user", spec.pip]

    if env.manager == "apt":
        cmd = ["apt-get", "install", "-y", package]
    elif env.manager == "pacman":
        cmd = ["pacman", "-S", "--noconfirm", package]
    elif env.manager == "dnf":
        cmd = ["dnf", "install", "-y", package]
    elif env.manager == "zypper":
        cmd = ["zypper", "--non-interactive", "install", package]
    elif env.manager == "brew":
        cmd = ["brew", "install", package]
    elif env.manager == "winget":
        # Without these flags winget opens an interactive agreement/source
        # prompt, and the subprocess (no TTY) waits until the timeout.
        cmd = ["winget", "install", "--silent", "--accept-package-agreements",
               "--accept-source-agreements", package]
    elif env.manager == "choco":
        cmd = ["choco", "install", "-y", package]
    else:
        return None

    if env.needs_sudo and cmd[0] in ("apt-get", "pacman", "dnf", "zypper"):
        cmd = ["sudo", *cmd]
    return cmd


def missing(tools: Iterable[str] = (),
            which: Optional[Callable[[str], Optional[str]]] = None) -> List[str]:
    """Names of `tools` (default: the whole registry) not usable here.

    With no injected `which`, resolution goes through the agent's
    `ToolRegistry`: on Windows that means a tool present only in the Kali WSL
    distro counts as installed. Probing raw host PATH (the old default) said
    `nmap` was missing on a box where `wsl -d kali-linux nmap` worked, and the
    CLI/API disagreed with the planner. An injected `which` keeps the
    existing unit tests and offline callers on their explicit answer.
    """
    wanted = list(tools) or sorted(TOOLS)
    if which is not None:
        return [t for t in wanted if which(t) is None]
    try:
        from phantom.automation.runtime.toolchain import ToolRegistry
        registry = ToolRegistry()
        return [t for t in wanted if not registry.has(t)]
    except Exception:
        return [t for t in wanted if shutil.which(t) is None]


def report(env: Optional[Env] = None,
           which: Optional[Callable[[str], Optional[str]]] = None) -> str:
    """Human-readable state: the machine, what is missing, and each fix."""
    if env is None:
        env = detect_env(_os_release_text())
    gone = missing(which=which)
    lines = [f"environment: {env.label()}",
             f"tools: {len(TOOLS) - len(gone)}/{len(TOOLS)} present"]
    if not gone:
        return "\n".join(lines + ["nothing missing"])
    lines.append("missing:")
    for name in gone:
        cmd = install_command(name, env)
        how = " ".join(cmd) if cmd else "no package mapping for this platform"
        lines.append(f"  {name:<14} {TOOLS[name].why}")
        lines.append(f"  {'':<14} install: {how}")
    return "\n".join(lines)


def install(tool: str, env: Optional[Env] = None, *,
            confirm: Optional[Callable[[str, List[str]], bool]] = None,
            runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
            which: Callable[[str], Optional[str]] = shutil.which,
            timeout: int = 900) -> Tuple[bool, str]:
    """Install ONE tool, but only after an explicit confirmation.

    `confirm(tool, cmd)` must return True — anything else (including a missing
    callback, i.e. an automated caller) is a REFUSAL, so no code path can install
    software as a side effect of, say, running a scan. Never raises: every
    failure comes back as `(False, why)` so the CLI/UI can report it.
    """
    if tool not in TOOLS:
        return False, f"unknown tool: {tool}"
    if env is None:
        env = detect_env(_os_release_text())
    if which(tool):
        return True, f"{tool} is already installed"

    cmd = install_command(tool, env)
    if not cmd:
        return False, (f"{tool} has no install mapping for {env.label()}; "
                       "install it manually")
    if confirm is None:
        return False, (f"refused: installing {tool} needs an explicit "
                       "confirmation (no confirm callback was given)")
    try:
        if not confirm(tool, list(cmd)):
            return False, f"refused by the operator: {tool} was not installed"
    except Exception as exc:                      # a broken UI must not install
        return False, f"confirmation failed ({type(exc).__name__}): {exc}"

    try:
        result = runner(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception as exc:
        return False, f"could not run {' '.join(cmd)}: {exc}"
    if (result.returncode != 0 and "-m" in cmd and "pip" in cmd):
        # PEP 668 (Kali/Debian/Ubuntu 23.04+): `pip install --user` is refused
        # because the interpreter is externally managed. The operator already
        # confirmed THIS install; retry once with the explicit override instead
        # of dead-ending every pip-only tool on the distro Phantom targets.
        detail = (result.stderr or "") + (result.stdout or "")
        if "externally-managed-environment" in detail:
            retry = list(cmd) + ["--break-system-packages"]
            try:
                result = runner(retry, capture_output=True, text=True,
                                timeout=timeout)
            except Exception as exc:
                return False, f"could not run {' '.join(retry)}: {exc}"
            if result.returncode == 0:
                cmd = retry
    if result.returncode != 0:
        tail = (result.stderr or result.stdout or "").strip().splitlines()
        return False, (f"{' '.join(cmd)} failed (exit {result.returncode})"
                       + (f": {tail[-1]}" if tail else ""))
    return True, f"installed {tool} ({' '.join(cmd)})"


def _os_release_text() -> str:
    """The real /etc/os-release, or "" when it is not there (macOS/Windows)."""
    try:
        with open("/etc/os-release", "r", encoding="utf-8") as handle:
            return handle.read()
    except OSError:
        return ""
