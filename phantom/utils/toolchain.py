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
}

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
    elif env.manager in ("winget", "choco"):
        cmd = [env.manager, "install", package]
    else:
        return None

    if env.needs_sudo and cmd[0] in ("apt-get", "pacman", "dnf", "zypper"):
        cmd = ["sudo", *cmd]
    return cmd


def missing(tools: Iterable[str] = (),
            which: Callable[[str], Optional[str]] = shutil.which) -> List[str]:
    """Names of `tools` (default: the whole registry) not found on PATH."""
    wanted = list(tools) or sorted(TOOLS)
    return [t for t in wanted if which(t) is None]


def report(env: Optional[Env] = None,
           which: Callable[[str], Optional[str]] = shutil.which) -> str:
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
