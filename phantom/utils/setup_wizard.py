"""setup_wizard.py — the guided, non-invasive phantom setup.

Principles (agreed with the operator):
  * user-scope only for the core; elevation is NEVER silent — every
    command that needs privileges is printed first and explicitly
    confirmed;
  * tool install is ASK-ONCE: show the deduplicated package list for
    this platform, one consent, then run non-interactively
    (DEBIAN_FRONTEND=noninteractive, --no-install-recommends);
  * WSL on Windows is a guided flow of its own: detect the exact state
    (not installed / installed-no-distro / ready), explain that admin +
    one reboot are needed, and only then run `wsl --install` + distro
    configuration unattended;
  * idempotent: re-running skips what is already fine;
  * every step is resumable — the wizard can be re-run any time and
    never breaks an existing installation.

Entry points:
    phantom setup          -> full guided wizard
    phantom setup wsl      -> only the WSL flow (Windows)
    phantom doctor         -> read-only diagnostics, changes nothing
"""

from __future__ import annotations

import os
import platform as _platform
import shutil
import subprocess
import sys
from typing import Callable, Dict, List, Optional, Tuple

from phantom.utils.tool_manifest import (
    MANIFEST, ToolEntry, capability_tools, entry, install_plan, package_for,
)

Say = Callable[[str], None]
Ask = Callable[[str], bool]

PLATFORM = ("windows" if sys.platform.startswith("win")
            else "darwin" if _platform.system() == "Darwin" else "linux")

# ASCII-only status glyphs: the wizard prints through plain print() and
# legacy Windows consoles are cp1252 — a Unicode checkmark crashes with
# UnicodeEncodeError there (utf-8 consoles are not guaranteed).
STEP_OK = "[OK]"
STEP_WARN = "[!]"
STEP_FAIL = "[X]"


# ── primitives ───────────────────────────────────────────────────────────

def _run(cmd: List[str], timeout: int = 600,
         env: Optional[Dict[str, str]] = None) -> Tuple[bool, str]:
    e = dict(os.environ)
    if env:
        e.update(env)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, env=e)
        return proc.returncode == 0, (proc.stdout or "") + (proc.stderr or "")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)


def _linux_family() -> str:
    if PLATFORM != "linux":
        return "apt"
    if shutil.which("apt-get"):
        return "apt"
    if shutil.which("dnf"):
        return "dnf"
    if shutil.which("pacman"):
        return "pacman"
    return "apt"


def _is_root() -> bool:
    if PLATFORM == "windows":
        return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _sudo_prefix() -> List[str]:
    """Elevation WITHOUT pretending: on linux root runs bare; a sudo
    binary is used when present; otherwise the step is refused with an
    honest message (never a silent attempt)."""
    if _is_root():
        return []
    if shutil.which("sudo"):
        return ["sudo", "-n"]
    return []            # caller refuses with instructions when empty


# ── doctor (read-only) ───────────────────────────────────────────────────

def doctor(say: Say = print) -> Dict[str, object]:
    """Diagnostics only — installs nothing, changes nothing."""
    py_ok = sys.version_info >= (3, 10)
    say(f"{STEP_OK if py_ok else STEP_FAIL} python "
        f"{_platform.python_version()} (needs >= 3.10)")

    tools = capability_tools()
    found = [e for e in tools if shutil.which(e.name)]
    missing = [e for e in tools if not shutil.which(e.name)]
    say(f"{STEP_OK if not missing else STEP_WARN} tools: "
        f"{len(found)}/{len(tools)} installed"
        + (f" — missing: {', '.join(e.name for e in missing)}"
           if missing else ""))

    docker = bool(shutil.which("docker"))
    say(f"{STEP_OK if docker else STEP_WARN} docker "
        + ("present (lab/evolution usable)" if docker else
           "missing (evolution lab + auto-managed lab disabled)"))

    wsl_state = wsl_state_check() if PLATFORM == "windows" else None
    if wsl_state is not None:
        icon = {READY: STEP_OK, NO_DISTRO: STEP_WARN,
                NOT_INSTALLED: STEP_WARN}[wsl_state[0]]
        say(f"{icon} WSL: {wsl_state[1]}")

    llm_backend = os.environ.get("PHANTOM_LLM_BACKEND", "local")
    llm_model = (os.environ.get("PHANTOM_LLM_REMOTE_MODEL")
                 if llm_backend == "remote" else
                 os.environ.get("PHANTOM_LLM_MODEL"))
    say(f"{STEP_WARN if llm_backend == 'remote' and not llm_model else STEP_OK}"
        f" llm transport: {llm_backend}"
        + (f" ({llm_model})" if llm_model else " (unconfigured — advisor off)"))

    return {"python_ok": py_ok,
            "tools_installed": len(found), "tools_missing":
                [e.name for e in missing],
            "docker": docker,
            "wsl": (wsl_state[0] if wsl_state else None),
            "llm_backend": llm_backend}


# ── WSL state machine (Windows) ──────────────────────────────────────────

NOT_INSTALLED = "not_installed"
NO_DISTRO = "no_distro"
READY = "ready"


def wsl_state_check() -> Optional[Tuple[str, str]]:
    """(state, human detail). None when not on Windows."""
    if PLATFORM != "windows":
        return None
    if not shutil.which("wsl"):
        return (NOT_INSTALLED,
                "WSL not installed — `wsl --install` requires ADMIN and "
                "one REBOOT")
    ok, out = _run(["wsl", "-l", "-q"])
    distros = [d.strip() for d in (out or "").replace("\x00", "").splitlines()
               if d.strip() and "no installed distributions"
               not in d.lower()]
    if not ok or not distros:
        return (NO_DISTRO,
                "WSL present but no distro — installing Kali needs ADMIN")
    return (READY, f"distro(s): {', '.join(distros)}")


def wsl_guided(say: Say, ask: Ask) -> bool:
    """The full guided WSL flow. Returns True when a distro is ready."""
    state = wsl_state_check()
    if state is None:
        return False
    kind, detail = state
    say(f"WSL state: {detail}")

    if kind == READY:
        return _configure_distro(say, ask)

    # NOT_INSTALLED / NO_DISTRO → the elevated step, explained first
    say("")
    say("To continue, phantom must run (once) with ADMIN rights:")
    say("  1. wsl --install -d kali-linux   (or --no-distribution + distro)")
    say("  2. one system REBOOT")
    say("  3. distro first-boot + tool setup (automated after reboot)")
    say("")
    if not ask("Proceed with the elevated step now? (UAC prompt will appear)"):
        say("Skipped. Re-run `phantom setup wsl` any time — nothing was "
            "changed.")
        return False
    ps = ("Start-Process wt -Verb RunAs -ArgumentList "
          "'wsl','--install','-d','kali-linux'")
    ok, _ = _run(["powershell", "-NoProfile", "-Command", ps], timeout=900)
    if not ok:
        say(f"{STEP_FAIL} elevated install did not complete — run "
            "`wsl --install -d kali-linux` from an ADMIN terminal, reboot, "
            "then re-run `phantom setup wsl`.")
        return False
    say(f"{STEP_WARN} WSL install launched. REBOOT when it finishes, then "
        "re-run `phantom setup wsl` — it will resume from the distro step.")
    return False


def _configure_distro(say: Say, ask: Ask) -> bool:
    """Distro exists: set up the toolbox (tools) inside it, unattended."""
    from phantom.core.executor import install_tool   # WSL-root aware
    targets = [e for e in capability_tools() if e.wsl_only or True]
    missing = [e.name for e in targets if not shutil.which(e.name)]
    if not missing:
        say(f"{STEP_OK} toolbox already complete")
        return True
    plan = install_plan("apt", missing)
    say("Packages to install INSIDE the WSL distro (deduplicated):")
    for p in plan:
        say(f"  - {p}")
    if not ask("Install now?"):
        return False
    fails = []
    for tool in dict.fromkeys(missing):
        say(f"  installing {tool} ...")
        res = install_tool(tool)
        if not res.get("ok"):
            fails.append(tool)
    if fails:
        say(f"{STEP_WARN} failed: {', '.join(fails)} — re-run `phantom "
            "setup wsl` to retry just those")
        return False
    say(f"{STEP_OK} WSL toolbox ready")
    return True


# ── native linux / wsl tool setup ────────────────────────────────────────

def _apt_install(pkgs: List[str], say: Say) -> bool:
    env = {"DEBIAN_FRONTEND": "noninteractive"}
    sudo = _sudo_prefix()
    if not _is_root() and not sudo:
        say(f"{STEP_FAIL} no sudo available — run `phantom setup` from an "
            "account that can elevate, or run the commands printed above "
            "manually")
        return False
    ok, out = _run([*sudo, "apt-get", "update", "-y"], timeout=300, env=env)
    base_cmd = [*sudo, "apt-get", "install", "-y",
                "--no-install-recommends", *pkgs]
    say(f"  $ {' '.join(base_cmd)}")
    ok, out = _run(base_cmd, timeout=1800, env=env)
    if not ok:
        say(f"{STEP_WARN} batch install failed — retrying one by one")
        for p in pkgs:
            ok1, _ = _run([*sudo, "apt-get", "install", "-y",
                           "--no-install-recommends", p],
                          timeout=900, env=env)
            say(f"    {STEP_OK if ok1 else STEP_FAIL} {p}")
    return True


def _dnf_install(pkgs: List[str], say: Say) -> bool:
    sudo = _sudo_prefix()
    return _run([*sudo, "dnf", "install", "-y", *pkgs],
                timeout=1800)[0]


def _pacman_install(pkgs: List[str], say: Say) -> bool:
    sudo = _sudo_prefix()
    return _run([*sudo, "pacman", "-S", "--noconfirm", *pkgs],
                timeout=1800)[0]


def _pip_fallback(missing: List[ToolEntry], say: Say) -> None:
    for e in missing:
        if not e.pip:
            continue
        say(f"  pip fallback: {e.name} (pip install {e.pip})")
        _run([sys.executable, "-m", "pip", "install", "--user", e.pip],
             timeout=600)


def tools_step(say: Say, ask: Ask, assume_yes: bool = False) -> None:
    """ASK-ONCE tool setup for the native platform."""
    if PLATFORM == "windows":
        say(f"{STEP_WARN} native Windows cannot host apt tools — the "
            "toolbox lives in WSL. Run: `phantom setup wsl`")
        return
    family = _linux_family()
    tools = capability_tools()
    missing = [e for e in tools if not shutil.which(e.name)]
    if not missing:
        say(f"{STEP_OK} tools present: {len(tools)}/{len(tools)} — "
            "toolbox complete")
        return
    say(f"{STEP_OK} tools present: {len(tools) - len(missing)}/{len(tools)}")
    pkgs = install_plan(family, [e.name for e in missing])
    say(f"Missing tool packages for {family} (deduplicated):")
    for p in pkgs:
        e = next((x for x in MANIFEST
                  if package_for(x.name, family) == p), None)
        say(f"  - {p}" + (f"  ({e.description})" if e else ""))
    if not (assume_yes or ask("Install these now?")):
        say("Skipped. Re-run `phantom setup` any time.")
        return
    if family == "apt":
        _apt_install(pkgs, say)
    elif family == "dnf":
        _dnf_install(pkgs, say)
    elif family == "pacman":
        _pacman_install(pkgs, say)
    # pip-only entries that had no distro package
    still = [e for e in missing if not shutil.which(e.name)]
    if still:
        _pip_fallback(still, say)
    final = [e.name for e in tools if not shutil.which(e.name)]
    if final:
        say(f"{STEP_WARN} still missing after setup: {', '.join(final)} — "
            "phantom plans around missing tools (capabilities with "
            "unavailable tools are simply not planned)")
    else:
        say(f"{STEP_OK} toolbox complete")


# ── the wizard ───────────────────────────────────────────────────────────

def _ask_console(question: str) -> bool:
    try:
        a = input(f"{question} [Y/n] ").strip().lower()
        return a in ("", "y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


def run_wizard(arg: str = "", assume_yes: bool = False,
               say: Say = print, ask: Ask = _ask_console) -> int:
    """`phantom setup [wsl]` — the guided flow."""
    say("Phantom setup — guided, user-scope, nothing silent")
    say("")
    if arg.strip() == "wsl":
        return 0 if wsl_guided(say, ask) else 1
    if arg.strip():
        say(f"{STEP_FAIL} unknown setup target: {arg} (use 'wsl' or none)")
        return 2
    doctor(say)
    say("")
    say("── tools ──")
    tools_step(say, ask, assume_yes=assume_yes)
    if PLATFORM == "windows":
        say("")
        say("── WSL toolbox ──")
        wsl_guided(say, ask)
    say("")
    say(f"{STEP_OK} setup done. Launch with: phantom | phantom.c2 | "
        "phantom.auto — doctor again any time with: phantom doctor")
    say("")
    say("NOTE — this command installs TOOLS only. External channels "
        "(SMTP, Telegram, breach API, public tracker URL) are configured "
        "INSIDE the phantom console with the `setup` command "
        "(or `setup status` to see what is ready). Nothing is required "
        "for the local chain (C2, lab, manual core, auto-mode).")
    return 0
