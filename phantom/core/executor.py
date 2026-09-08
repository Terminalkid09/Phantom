import re
import subprocess
import threading
import sys
import shutil
import os
from rich.console import Console
from phantom.core.session import session
from phantom.core.scope import is_in_scope

console = Console()

TIMEOUT_SECONDS = 300

# termios only on Unix/Linux/Mac
_IS_UNIX = os.name == "posix"
if _IS_UNIX:
    import termios


def _is_safe_target(target: str) -> bool:
    """Return True if target contains no shell metacharacters (allows @ and _ for social handles)."""
    # MODIFICATA: Ora include '@' e '_' per supportare l'OSINT sui profili social
    return bool(re.match(r'^[@a-zA-Z0-9._\-/:]+$', target))


_WSL_REDIRECT_RE = None  # lazy compile


def _wrap_wsl_redirects(cmd: str) -> str:
    """Wrap a `wsl -d <distro> <tool> ...` line in `sh -c "..."` when it
    carries Linux-side shell syntax (redirects to /dev/null, pipes, globs,
    single-quoted argv). Without the wrap, cmd.exe parses `2>/dev/null` on
    the Windows side and the whole command dies with "path not found".
    """
    global _WSL_REDIRECT_RE
    import re as _re
    if _WSL_REDIRECT_RE is None:
        _WSL_REDIRECT_RE = _re.compile(
            r"(?:2?>/?dev/null|\|\s*(?:head|grep|tee|awk|cut|sort|wc|tr)\b|')")
    # already wrapped or nothing Linux-specific to protect
    if "sh -c" in cmd or not _WSL_REDIRECT_RE.search(cmd):
        return cmd
    parts = cmd.split(" ", 3)          # wsl, -d, <distro>, <rest>
    if len(parts) < 4:
        return cmd
    prefix, rest = " ".join(parts[:3]), parts[3]
    # double any double quotes already present, then quote the Linux argv
    escaped = rest.replace('"', '\\"')
    return f'{prefix} sh -c "{escaped}"'


def _rewrite_wsl(cmd: str) -> str:
    """Route a command through the WSL toolbox when the binary is only
    available there (Windows native miss, Kali distro hit).

    `nmap -sV target` -> `wsl -d kali-linux nmap -sV target`
    Paths are translated naively: /mnt/c-style targets keep working inside
    WSL, and the C2 endpoint / scan targets are plain IPs/domains so no
    translation is needed for the tool invocation the agent produces.
    """
    if os.name != "nt":
        return cmd
    tool = cmd.split()[0] if cmd.split() else ""
    # Tools already native on Windows must keep running natively: WSL interop
    # lists Windows exes inside the distro (via /mnt/c), so a naive WSL probe
    # "finds" docker.exe and rewrites it into a Linux invocation that dies
    # with execvpe() failure. Only route through WSL when the tool is NOT on
    # the Windows PATH.
    if tool and shutil.which(tool) is not None:
        return cmd
    # The deploy line chains WSL-side tools with shell syntax:
    #   setsid sshpass ... ssh ... "... </dev/null >/dev/null 2>&1 &"
    # Rewriting only the first token breaks (wrong distro / mangled quoting);
    # route the WHOLE line through the distro shell instead.
    if any(t in cmd for t in ("sshpass", "ssh ", "scp ", "setsid")):
        from phantom.automation.runtime.toolchain import _wsl_distro_list
        # cmd.exe (shell=True) eats double quotes before wsl.exe sees them, so
        # the remote-command quoting is destroyed. base64 is quoting-proof:
        # the Linux side decodes and executes the EXACT original line.
        import base64 as _b64
        payload = _b64.b64encode(cmd.encode()).decode()
        try:
            distros = _wsl_distro_list()
            # prefer a distro that actually has sshpass (kali), else default
            for d in ("kali-linux", "kali", "Ubuntu"):
                if d in distros:
                    return f'wsl -d {d} sh -c "echo {payload} | base64 -d | sh"'
        except Exception:
            pass
        return f'wsl sh -c "echo {payload} | base64 -d | sh"'
    try:
        from phantom.automation.runtime.toolchain import _wsl_which
        wrapper = _wsl_which(tool) if tool else None
        if wrapper:
            # wrapper is "wsl -d <distro> <tool>" or "wsl -e <tool>"
            parts = wrapper.split()
            distro_prefix = " ".join(parts[:3])   # wsl -d <distro>
            rest = cmd.split(" ", 1)[1] if " " in cmd else ""
            return f"{distro_prefix} {cmd.split()[0]} {rest}"
    except Exception:
        pass
    return cmd


def install_tool(tool: str, timeout: int = 420) -> dict:
    """Install a missing tool in the CURRENT backend environment.

    Builds the platform-appropriate install command (apt / brew / choco /
    pip) from `tool_install_hint`, routes apt through the WSL toolbox as
    ROOT when the tool lives there on Windows (WSL root needs no password
    even when the distro default user is not root — without `-u root` a
    non-root default user gets permission denied on /var/lib/dpkg), and
    falls back to an elevated retry for native admin-requiring installers.
    Executes it and returns {ok, command, output}.
    Used by the CLI (`install <tool>`) and the Electron preflight panel.
    """
    # NOTE: platform.system() returns "Windows", not "win32" — comparing it
    # against "win32" (sys.platform) silently routed EVERY Windows install
    # into the Linux branch, which then executed the raw `sudo apt-get ...`
    # candidate. On Windows 11 24H2 a disabled native sudo.exe prints
    # "Sudo è disabilitato in questo computer..." and the install dies.
    import sys as _sys_mod
    if _sys_mod.platform.startswith("win"):
        sys_os = "windows"
    elif _sys_mod.platform == "darwin":
        sys_os = "darwin"
    else:
        sys_os = "linux"

    # `deploy-agent`, `privesc-run`, … are PHANTOM module commands, not
    # system packages — installing them through apt/pip is nonsense and
    # ends in "Unable to locate package deploy-agent". Refuse early with
    # a message pointing at the real command instead of a failed install.
    if tool in _PHANTOM_COMMANDS:
        return {"ok": False, "command": f"install {tool}",
                "output": (f"'{tool}' is a built-in Phantom command, not an "
                           f"external tool — there is nothing to install. "
                           f"Type 'use <module>' + 'help' for how to run it.")}

    hint = tool_install_hint(tool)

    if sys_os == "windows":
        # Windows 11 24H2 ships a native sudo.exe that is DISABLED by default.
        # Any `sudo ...` subprocess spawned with shell=True finds it and dies
        # with "Sudo is disabled on this computer" instead of falling through.
        # Our Windows paths never need sudo (WSL runs as root, choco elevates
        # via UAC), so hide it from PATH for every child process we spawn.
        _hide_windows_sudo()
    parts = [p.strip() for p in hint.split("|") if p.strip()]

    def _pick(needles: tuple) -> str:
        for p in parts:
            if any(n in p.lower() for n in needles):
                return p
        return ""

    def _wsl_distro() -> str:
        try:
            from phantom.automation.runtime.toolchain import _wsl_distro_list
            distros = _wsl_distro_list()
            return next((d for d in ("kali-linux", "kali") if d in distros),
                        (distros[0] if distros else ""))
        except Exception:
            return "kali-linux"

    def _run(cmdline: str, t: int = timeout) -> dict:
        try:
            proc = subprocess.run(cmdline, shell=True, capture_output=True,
                                  text=True, timeout=t)
            return {"ok": proc.returncode == 0, "command": cmdline,
                    "output": ((proc.stdout or "") + (proc.stderr or ""))[-4000:]}
        except subprocess.TimeoutExpired:
            return {"ok": False, "command": cmdline,
                    "output": f"install timed out after {t}s"}
        except Exception as e:
            return {"ok": False, "command": cmdline, "output": str(e)}

    if sys_os == "windows":
        apt = _pick(("apt",))
        if apt:
            # drop the "(WSL)" display annotation before taking the pkg name
            tokens = [t for t in apt.split() if t.upper() != "(WSL)"]
            pkg = tokens[-1] if tokens else tool
            distro = _wsl_distro()
            if distro:
                cmd = (f"wsl -d {distro} -u root apt-get install -y "
                       f"--no-install-recommends {pkg}")
            else:
                cmd = f"{sys.executable} -m pip install --user {pkg}"
            res = _run(_rewrite_wsl(cmd) if os.name == "nt" else cmd)
            # `wsl` may exit 4294967295 / 1 when the distro is not installed
            if not res["ok"] and "no installed distributions" in res["output"].lower():
                res = _run(f"{sys.executable} -m pip install --user {pkg}")
            return res
        pip = _pick(("pip",))
        if pip:
            pkg = pip.replace("pip install", "").strip() or tool
            return _run(f"{sys.executable} -m pip install --user {pkg}")
        choco = _pick(("choco",))
        if choco:
            pkg = choco.replace("choco install", "").strip() or tool
            res = _run(f"choco install -y {pkg}")
            if not res["ok"]:
                # choco writes to ProgramData -> admin required. Retry behind
                # a UAC prompt so the install succeeds instead of failing.
                res2 = _run(
                    'powershell -NoProfile -Command "Start-Process choco '
                    f"-ArgumentList 'install','-y','{pkg}' "
                    '-Verb RunAs -Wait; exit $LASTEXITCODE"')
                if res2["ok"]:
                    res2["output"] = ("(installed elevated)\n" + res2["output"])
                    return res2
                res["output"] += ("\n[elevated retry failed] " +
                                  res2["output"][-800:])
            return res
        # no hint: try a user-scope pip install of the tool name
        return _run(f"{sys.executable} -m pip install --user {tool}")
    elif sys_os == "darwin":
        brew = _pick(("brew",)) or f"brew install {tool}"
        return _run(brew)
    # linux
    apt = _pick(("apt",))
    if apt:
        pkg = apt.replace("apt install", "").replace("apt-get install", "").strip() or tool
        pkg = pkg.split()[-1]
        candidates = []
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            candidates.append(f"DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {pkg}")
        candidates.append(f"sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {pkg}")
        candidates.append(f"sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends {pkg}")
        last = None
        for c in candidates:
            last = _run(c)
            if last["ok"]:
                return last
        return last or {"ok": False, "command": "apt-get", "output": "no install method"}
    pip = _pick(("pip",))
    if pip:
        pkg = pip.replace("pip install", "").strip() or tool
        return _run(f"{sys.executable} -m pip install --user {pkg}")
    return _run(f"sudo -n apt-get install -y {tool}" if "sudo" not in tool else f"{tool}")


def _is_tool_installed(cmd: str) -> bool:
    """Check if the primary tool in the command string is installed."""
    tool = cmd.split()[0] if cmd.split() else ""
    if not tool:
        return True
    if shutil.which(tool) is not None:
        return True
    # Windows-native miss: the tool may live in a WSL distro (Kali toolbox).
    # The agent's ToolRegistry already bridges this — mirror it here so
    # execute_quiet does not reject `wsl -d kali-linux nmap ...` commands
    # (and plain `nmap ...` rewrites) as "tool not installed".
    if os.name == "nt":
        try:
            from phantom.automation.runtime.toolchain import _wsl_which
            return _wsl_which(tool) is not None
        except Exception:
            return False
    return False


# Phantom module subcommands that preflight/install must never treat as
# external packages (keep in sync with the shell's do_* dispatch).
# Includes every module NAME (`use <module>` verbs) and module action words
# from build_commands — e.g. payload's `handler <port>` suggestion must not
# turn into `apt-get install handler`.
_PHANTOM_COMMANDS = frozenset({
    "deploy-agent", "privesc-run", "list-exploits", "msf-search",
    "generate-shellcode", "mem-run", "inject-tl", "inject-eb",
    "beacon-auth", "beacon-help", "autopersist", "interact", "results",
    "back", "payloads", "console", "migrate", "run", "use", "set",
    "fire", "execute", "screenshot", "keylog", "persist",
    # module names — `use <module>` / `run <module>` verbs, never packages
    "scan", "osint", "wifi", "web", "brute", "exploit", "payload",
    "handler", "pivot", "analyzer", "report", "wordlist", "telegram",
    "craft", "map", "install", "agent",
    # payload/handler module action words appearing in suggestion groups
    "generate", "deploy", "privesc", "listen", "start-listener",
})


def _hide_windows_sudo() -> None:
    """Remove the (often disabled) Windows-native sudo.exe from PATH for this
    process so `sudo ...` shell commands fail with 'not recognized' — a clean
    failure our fallbacks handle — instead of the confusing "Sudo is
    disabled on this computer" error. Idempotent, no-op on non-Windows."""
    import os as _os
    if _os.name != "nt" or getattr(_hide_windows_sudo, "_done", False):
        return
    _hide_windows_sudo._done = True
    try:
        parts = _os.environ.get("PATH", "").split(_os.pathsep)
        cleaned = [p for p in parts if p
                   and not _os.path.exists(_os.path.join(p, "sudo.EXE"))
                   and not _os.path.exists(_os.path.join(p, "sudo.exe"))]
        if len(cleaned) != len(parts):
            _os.environ["PATH"] = _os.pathsep.join(cleaned)
    except Exception:
        pass


def tool_install_hint(tool: str) -> str:
    """Cross-platform install hint for a missing tool (apt/brew/pip/choco)."""
    import sys as _sys_mod
    if _sys_mod.platform.startswith("win"):
        sys_os = "windows"
    elif _sys_mod.platform == "darwin":
        sys_os = "darwin"
    else:
        sys_os = "linux"
    hints = {
        "nmap": "sudo apt install nmap | brew install nmap | choco install nmap",
        "traceroute": "sudo apt install traceroute | brew install traceroute",
        "hydra": "sudo apt install hydra | brew install hydra | choco install thc-hydra",
        "john": "sudo apt install john | brew install john-jumbo",
        "hashcat": "sudo apt install hashcat | brew install hashcat",
        "aircrack-ng": "sudo apt install aircrack-ng | brew install aircrack-ng",
        "airodump-ng": "sudo apt install aircrack-ng | brew install aircrack-ng",
        "airmon-ng": "sudo apt install aircrack-ng | brew install aircrack-ng",
        "reaver": "sudo apt install reaver | brew install reaver",
        "hcxdumptool": "sudo apt install hcxtools | brew install hcxtools",
        "hcxpcapngtool": "sudo apt install hcxtools | brew install hcxtools",
        "gobuster": "sudo apt install gobuster | brew install gobuster",
        "ffuf": "sudo apt install ffuf | brew install ffuf",
        "sqlmap": "sudo apt install sqlmap | brew install sqlmap",
        "nikto": "sudo apt install nikto | brew install nikto",
        "msfconsole": "brew install metasploit | curl https://raw.githubusercontent.com/rapid7/metasploit-framework/master/msfupdate | sudo sh",
        "msfvenom": "brew install metasploit | curl https://raw.githubusercontent.com/rapid7/metasploit-framework/master/msfupdate | sudo sh",
        "chisel": "go install github.com/jpillora/chisel@latest | brew install chisel",
        "tshark": "sudo apt install tshark | brew install wireshark",
        "scapy": "pip install scapy",
        "theharvester": "sudo apt install theharvester | pip install theHarvester | brew install theharvester",
        "whatweb": "sudo apt install whatweb | brew install whatweb",
        "whois": "sudo apt install whois | brew install whois",
        "dig": "sudo apt install dnsutils | brew install bind",
        "curl": "sudo apt install curl | brew install curl",
        "wget": "sudo apt install wget | brew install wget",
        "sshpass": "sudo apt install sshpass | brew install hudochenkov/sshpass/sshpass",
        "evil-winrm": "sudo gem install evil-winrm | brew install evil-winrm",
        "secretsdump": "pip install impacket",
        "proxychains": "sudo apt install proxychains4 | brew install proxychains-ng",
        "sshuttle": "sudo apt install sshuttle | pip install sshuttle",
        "socat": "sudo apt install socat | brew install socat",
        "nc": "sudo apt install netcat-openbsd | brew install netcat",
        "ncat": "sudo apt install ncat | brew install nmap",
        "tmux": "sudo apt install tmux | brew install tmux",
    }
    if tool in hints:
        hint = hints[tool]
    elif sys_os == "darwin":
        hint = f"brew install {tool} | pip install {tool}"
    elif sys_os == "windows":
        # apt (WSL) first: that is where the offensive toolchain lives on a
        # Windows operator box; pip/choco as pure-Windows fallbacks.
        hint = (f"apt install {tool} (WSL) | pip install {tool} | "
                f"choco install {tool} | scoop install {tool}")
    else:
        hint = f"sudo apt install {tool} | pip install {tool}"
    if sys_os == "windows":
        # A Windows operator box cannot run the raw `sudo apt ...` variants
        # (and Win11 24H2's disabled sudo.exe turns them into a confusing
        # error). Rewrite every hint: WSL-flavoured apt first, no sudo,
        # no mac-only brew noise.
        parts = [p.strip() for p in hint.split("|") if p.strip()]
        apt_parts: list = []
        rest: list = []
        for p in parts:
            pl = p.lower()
            if "apt" in pl:
                clean = p.replace("sudo ", "").strip()
                if "(wsl)" not in pl:
                    clean += " (WSL)"
                apt_parts.append(clean)
            elif "brew" not in pl:
                rest.append(p)
        hint = " | ".join(apt_parts + rest) or hint
    return hint


def _save_terminal():
    """Save current terminal settings (Unix only)."""
    if _IS_UNIX:
        try:
            return termios.tcgetattr(sys.stdin.fileno())
        except Exception:
            return None
    return None


def _restore_terminal(settings) -> None:
    """Restore terminal settings (Unix only)."""
    if _IS_UNIX and settings is not None:
        try:
            termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, settings)
        except Exception:
            pass


def _safe_input(prompt: str, default: str = "y") -> str:
    """
    Read user input safely after restoring terminal settings.
    Falls back to default on EOF or KeyboardInterrupt.
    """
    try:
        return input(prompt).strip().lower() or default
    except (EOFError, KeyboardInterrupt):
        return "k"


def run_command(cmd: str, target_ip: str = "") -> str:
    """
    Run a shell command with interactive timeout.

    Behavior:
    - Checks scope, safe target, tool installed.
    - Streams output in real time.
    - Saves and restores terminal settings (fixes invisible input bug).
    - After TIMEOUT_SECONDS asks user:
        y = wait another 300s
        n = send to background, buffer output, show at end of all commands
        k = kill definitively
    Returns combined stdout+stderr as string.
    """
    if target_ip and session.scope and not is_in_scope(target_ip, session.scope):
        console.print(f"[red][!] Command blocked: {target_ip} is out of scope.[/]")
        return ""

    if target_ip and not _is_safe_target(target_ip):
        console.print(f"[red][!] Blocked: target '{target_ip}' contains dangerous characters.[/]")
        return ""

    if not _is_tool_installed(cmd):
        tool = cmd.split()[0] if cmd.split() else "Unknown"
        console.print(f"[yellow][!] Tool '{tool}' not installed. Skipping.[/]")
        console.print(f"    [dim]Install with: sudo apt install {tool}[/]")
        return ""

    console.print(f"\n  [dim]$ {cmd}[/]")
    session.add_history(cmd)

    output_lines = []
    terminal_settings = _save_terminal()

    try:
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,  # Prevents child from stealing stdin from parent
            text=True,
            bufsize=1,
        )

        while True:
            lines_in_window = []

            def _read():
                try:
                    for line in process.stdout:
                        lines_in_window.append(line)
                except Exception:
                    pass

            reader = threading.Thread(target=_read, daemon=True)
            reader.start()
            reader.join(timeout=TIMEOUT_SECONDS)

            # Print whatever arrived in this window
            for line in lines_in_window:
                sys.stdout.write(line)
                sys.stdout.flush()
                output_lines.append(line)

            if not reader.is_alive():
                # Reader finished — process ended normally
                break

            if process.poll() is None:
                # Process still running — restore terminal before asking
                _restore_terminal(terminal_settings)

                console.print(
                    f"\n[yellow][!] Command still running after {TIMEOUT_SECONDS}s.[/]\n"
                    "    [y] Wait another 300s  "
                    "[n] Send to background (output shown at end)  "
                    "[k] Kill and skip"
                )
                choice = _safe_input("    Choice [y/n/k]: ", default="y")

                if choice == "y":
                    continue

                elif choice == "n":
                    # Buffer remaining output in background thread
                    background_buffer = []
                    console.print("[yellow]  Running in background. Output will appear at end.[/]")

                    def _collect():
                        try:
                            for line in process.stdout:
                                background_buffer.append(line)
                        except Exception:
                            pass

                    bg_thread = threading.Thread(target=_collect, daemon=True)
                    bg_thread.start()

                    # Store in session for run_commands to display later
                    bg_key = f"_bg_{cmd[:40]}"
                    session.add_result(bg_key, {
                        "cmd": cmd,
                        "thread": bg_thread,
                        "buffer": background_buffer,
                        "process": process,
                    })
                    return "".join(output_lines)

                elif choice == "k":
                    process.kill()
                    process.wait(timeout=5)
                    console.print("[yellow]  Command killed.[/]")
                    break
            else:
                break

        process.wait(timeout=5)

    except FileNotFoundError:
        console.print(f"[red][!] Command not found. Is it installed?[/]")
    except PermissionError:
        console.print(f"[red][!] Permission denied. Try running with sudo.[/]")
    except KeyboardInterrupt:
        try:
            process.kill()
            process.wait(timeout=2)
        except Exception:
            pass
        console.print("\n[yellow][!] Interrupted by user (Ctrl+C). Moving to next command.[/]")

    except Exception as e:
        console.print(f"[red][!] Execution error: {type(e).__name__}: {e}[/]")

    finally:
        # Always restore terminal — fixes invisible input after sudo commands
        _restore_terminal(terminal_settings)

    return "".join(output_lines)


import time
from dataclasses import dataclass, field
from typing import Optional, List as _List


@dataclass
class QuietResult:
    """Result of a non-interactive command execution."""
    cmd: str
    stdout: str = ""
    stderr: str = ""
    returncode: Optional[int] = None
    timed_out: bool = False
    error: Optional[str] = None
    duration: float = 0.0

    @property
    def combined(self) -> str:
        if self.stderr:
            return f"{self.stdout}\n{self.stderr}".strip()
        return self.stdout.strip()

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.error


def execute_quiet(
    cmd: str,
    target_ip: str = "",
    timeout: float = 60.0,
    check_scope: bool = True,
    check_tool: bool = True,
) -> QuietResult:
    """
    Run a shell command NON-interactively (no y/n/k prompts, no streaming).

    Used by the autonomous agent so execution never blocks waiting for user
    input. Applies the same scope / safe-target / tool-availability guards as
    run_command unless explicitly disabled.

    Returns a QuietResult (never raises for command failure).
    """
    started = time.time()
    if check_scope and target_ip and session.scope and not is_in_scope(target_ip, session.scope):
        return QuietResult(cmd=cmd, error=f"out of scope: {target_ip}", returncode=-1)

    if target_ip and not _is_safe_target(target_ip):
        return QuietResult(cmd=cmd, error=f"unsafe target chars: {target_ip}", returncode=-1)

    if check_tool and not _is_tool_installed(cmd):
        tool = cmd.split()[0] if cmd.split() else "Unknown"
        return QuietResult(cmd=cmd, error=f"tool '{tool}' not installed", returncode=-1)

    # WSL toolbox: run through the distro when the binary is Windows-missing
    cmd = _rewrite_wsl(cmd)
    # WSL exec line: `wsl -d <distro> <tool> ... 'x' 2>/dev/null` — the
    # trailing shell redirection is interpreted by WINDOWS cmd.exe (which
    # has no /dev/null) and fails with "path not found" before wsl ever
    # runs. Wrap the Linux part in `sh -c` so redirects/pipes/quotes are
    # evaluated by the Linux shell they were written for.
    if os.name == "nt" and cmd.startswith("wsl "):
        cmd = _wrap_wsl_redirects(cmd)
    session.add_history(cmd)

    try:
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=True,
        )
    except OSError as e:
        return QuietResult(cmd=cmd, error=f"spawn failed: {e}", returncode=-1)

    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        # SALVAGE: a killed long scan still holds minutes of completed work
        # in its pipe buffers (an 85%-done full sweep knows most open
        # ports). Drain the buffers after the kill instead of discarding
        # everything, and flag the result as timed_out so the caller can
        # interpret the partial output.
        stdout = ""
        try:
            process.kill()
        except OSError:
            pass
        try:
            stdout, stderr = process.communicate(timeout=8)
        except Exception:
            stdout = ""
        return QuietResult(cmd=cmd, timed_out=True,
                           stdout=stdout or "", stderr="", returncode=None)

    return QuietResult(
        cmd=cmd,
        stdout=stdout or "",
        stderr=stderr or "",
        returncode=process.returncode,
        duration=time.time() - started,
    )


def execute_quiet_bg(cmd: str, target_ip: str = "") -> "BackgroundProcess":
    """
    Spawn a command in the background with readable stdout.

    Returns a BackgroundProcess handle with poll()/wait()/kill()/read().
    No prompts, no streaming, survives as long as the parent does not exit.
    """
    if target_ip and session.scope and not is_in_scope(target_ip, session.scope):
        raise PermissionError(f"out of scope target: {target_ip}")
    if not _is_tool_installed(cmd):
        raise FileNotFoundError(f"tool '{cmd.split()[0] if cmd.split() else '?'}' not installed")

    session.add_history(cmd)
    process = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    return BackgroundProcess(cmd, process)


class BackgroundProcess:
    """Handle for a background process with readable, non-blocking output."""

    def __init__(self, cmd: str, proc: subprocess.Popen):
        self.cmd = cmd
        self._proc = proc
        self._lines: _List[str] = []
        self._buffer_lock = threading.Lock()
        self._reader: Optional[threading.Thread] = None
        self._start_reader()

    def _start_reader(self):
        def _read():
            try:
                for line in self._proc.stdout:
                    with self._buffer_lock:
                        self._lines.append(line)
            except Exception:
                pass

        self._reader = threading.Thread(target=_read, daemon=True)
        self._reader.start()

    def is_alive(self) -> bool:
        return self._proc.poll() is None

    def poll(self) -> Optional[int]:
        return self._proc.poll()

    def write(self, data: str) -> None:
        if self._proc.stdin:
            try:
                self._proc.stdin.write(data)
                self._proc.stdin.flush()
            except (OSError, ValueError):
                pass

    def read(self, timeout: float = 0.1) -> str:
        """Return all output captured in the last window (non-blocking)."""
        with self._buffer_lock:
            lines = self._lines
            self._lines = []
        return "".join(lines)

    def read_line(self, timeout: float = 1.0) -> str:
        """Wait up to `timeout` seconds for at least one new line."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._buffer_lock:
                if self._lines:
                    return self._lines.pop(0)
            time.sleep(0.05)
        return ""

    def wait(self, timeout: Optional[float] = None) -> Optional[int]:
        try:
            return self._proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def terminate(self) -> None:
        try:
            self._proc.terminate()
        except OSError:
            pass

    def kill(self) -> None:
        try:
            self._proc.kill()
        except OSError:
            pass


def run_commands(commands: list, target_ip: str = "") -> dict:
    """
    Run a list of commands sequentially.
    After all commands complete, shows buffered output
    from any commands sent to background with 'n'.
    Returns dict {command: output}.
    """
    results = {}
    for cmd in commands:
        clean_cmd = cmd.replace(" AGGRESSIVE", "").strip()
        results[clean_cmd] = run_command(clean_cmd, target_ip)

    # Show background command output at the end
    bg_keys = [k for k in session.results.keys() if k.startswith("_bg_")]
    if bg_keys:
        console.print("\n[bold cyan]── BACKGROUND OUTPUT ───────────────────────────────[/]")
        for key in bg_keys:
            data = session.results[key]
            cmd_label = data.get("cmd", key)
            buffer = data.get("buffer", [])
            thread = data.get("thread")
            process = data.get("process")

            # Wait max 5s for thread to finish collecting
            if thread and thread.is_alive():
                thread.join(timeout=5)
            
            # Ensure process is finished
            if process and process.poll() is None:
                try:
                    process.wait(timeout=1)
                except (subprocess.TimeoutExpired, OSError):
                    pass

            terminal_settings = _save_terminal()
            _restore_terminal(terminal_settings)

            choice = _safe_input(
                f"\n  Finished: [dim]{cmd_label[:60]}[/]\n"
                f"  Show output now? [y/N]: ",
                default="n"
            )

            if choice == "y" and buffer:
                console.print()
                for line in buffer:
                    sys.stdout.write(line)
                sys.stdout.flush()
            elif not buffer:
                console.print(f"  [dim]No output captured.[/]")

            # Remove from session after showing
            del session.results[key]

    return results