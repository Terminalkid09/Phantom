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


def quote_arg(arg: str) -> str:
    """Quote ONE argument for a command LINE that runs under `shell=True`.

    The shell is not the same everywhere: on Windows it is cmd.exe, which has
    NO single-quote quotes. `curl -A 'Mozilla/5.0 (X11)' 'https://x/'` reached
    curl as four arguments and died with rc=3 "URL malformed", so every social
    fetch returned "" and every profile was duly reported `missing` — live
    evidence (2026-10-16): an existing Instagram account was declared absent
    while a direct fetch of the same URL returned 586 KB containing the handle.

    POSIX gets `shlex.quote`; Windows gets the CommandLineToArgvW quoting
    cmd.exe hands to the program. Callers that build a shell LINE around
    interpolated values must use this, not hand-written quotes.
    """
    if os.name == "nt":
        from phantom.utils.service_units import quote_windows_arg
        return quote_windows_arg(str(arg))
    import shlex
    return shlex.quote(str(arg))


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
    # prefix = `wsl` plus ITS OWN options (`-d <distro>`, `-u root`, `-e`).
    # Slicing a fixed three tokens silently pushed `-u root` INSIDE the quoted
    # command on `wsl -d <distro> -u root <tool>` lines — the elevation became
    # an argument to the tool instead of to wsl.
    parts = cmd.split()
    i = 1
    while i < len(parts) and parts[i].startswith("-"):
        flag = parts[i]
        i += 1
        if flag in ("-d", "--distribution", "-u", "--user"):
            i += 1                      # the option's value
    if i >= len(parts):
        return cmd
    prefix, rest = " ".join(parts[:i]), " ".join(parts[i:])
    # double any double quotes already present, then quote the Linux argv
    escaped = rest.replace('"', '\\"')
    return f'{prefix} sh -c "{escaped}"'


# Privilege/wrapper prefixes a command may START with: `sudo nmap -sV x` runs
# nmap, through sudo. Resolving the wrapper as "the tool" answers a question
# nobody asked — and on Windows 11, which ships a (disabled) sudo.exe, it
# answers it WRONGLY: `sudo ...` looked like a native binary, so the WSL
# bridge declined to touch it and cmd.exe ran Windows' own sudo, which prints
# "Sudo is disabled on this computer" instead of scanning anything.
_WRAPPER_PREFIXES = frozenset({"sudo", "doas", "env", "nohup", "time",
                               "command", "stdbuf", "nice", "ionice"})

# The subset that means "run this with more privilege". On the WSL side the
# bridge expresses it as `-u root` instead of keeping the word: see
# `_rewrite_wsl`.
_PRIVILEGE_PREFIXES = frozenset({"sudo", "doas"})


def is_comment(cmd: str) -> bool:
    """True when the line is a shell COMMENT — a documented no-op.

    Adapters use `# <reason>` to say "this step does not apply here"
    instead of inventing a command that would fail (see
    `guidance/kit.py:_version_adapter`). Running it as a program made the
    reason itself the failure ("tool '#' not installed"), so both the
    tool check and the executor treat it as nothing to do.
    """
    return str(cmd or "").lstrip().startswith("#")


def _command_head(cmd: str) -> tuple:
    """``(prefix, tool, rest)`` for a shell command line.

    ``prefix`` holds the wrapper words (`"sudo"`, `"sudo env"`, otherwise
    `""`), ``tool`` the real binary, ``rest`` everything after it. Spelling
    of `rest` is preserved because only split indices are used — quoting and
    redirections reach the child exactly as written.
    """
    tokens = cmd.split()
    idx = 0
    while idx < len(tokens):
        if tokens[idx] in _WRAPPER_PREFIXES:
            idx += 1
            continue
        # a flag that FOLLOWS a wrapper belongs to it (`sudo -n nmap ...`),
        # not to the command being wrapped
        if idx > 0 and tokens[idx].startswith("-"):
            idx += 1
            continue
        break
    if idx >= len(tokens):
        return "", "", ""
    prefix = " ".join(tokens[:idx])
    tool = tokens[idx]
    parts = cmd.split(None, idx + 1)
    rest = parts[idx + 1] if len(parts) > idx + 1 else ""
    return prefix, tool, rest


def _win_paths_to_wsl(cmd: str) -> str:
    """`C:\\dir\\file` -> `/mnt/c/dir/file` for a line about to run in WSL.

    WSL reaches the Windows filesystem through `/mnt/<drive>`. A Linux tool
    handed a Windows path does not fail loudly: it writes a file whose NAME
    is that literal string, and the Windows side then parses an `-oX` output
    that is not where it asked. Only absolute drive paths are touched —
    `host:port`, `http://` and CLI flags have no separator after the colon.
    """
    def _sub(m: "re.Match") -> str:
        return f"/mnt/{m.group(1).lower()}/{m.group(2).replace(chr(92), '/')}"

    return re.sub(r"(?<![\w/])([A-Za-z]):[\\/]([^\s'\"]*)", _sub, cmd)


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
    prefix, tool, rest = _command_head(cmd)
    if not tool:
        return cmd
    # Tools already native on Windows must keep running natively: WSL interop
    # lists Windows exes inside the distro (via /mnt/c), so a naive WSL probe
    # "finds" docker.exe and rewrites it into a Linux invocation that dies
    # with execvpe() failure. Only route through WSL when the tool is NOT on
    # the Windows PATH.
    if shutil.which(tool) is not None:
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
            # wrapper is "wsl -e <tool>" or "wsl -d <distro> <tool>": only the
            # DISTRO part is reusable. Re-appending the tool the wrapper
            # already names produced `wsl -e nmap nmap -sV ...`.
            wparts = wrapper.split()
            if wparts[:2] == ["wsl", "-d"] and len(wparts) >= 3:
                distro, distro_prefix = wparts[2], f"wsl -d {wparts[2]}"
            else:
                distro, distro_prefix = "", "wsl -e"
            if any(w in _PRIVILEGE_PREFIXES for w in prefix.split()):
                # `sudo` is a Linux habit that dies twice on this host: the
                # native sudo.exe is disabled (Windows 11) and the distro's
                # sudo wants a PASSWORD the child process has no tty to ask
                # for (default user is uid 1000). WSL can run a command as
                # root directly — the same elevation `install_tool` already
                # uses — so the intent survives and nothing prompts.
                distro_prefix = (f"wsl -d {distro} -u root" if distro
                                 else "wsl -u root -e")
                prefix = ""
            # the wrapper words stay in FRONT of the tool: inside the distro
            # `env`/`nohup`/`time` mean exactly what the command says
            line = " ".join(p for p in (distro_prefix, prefix, tool, rest) if p)
            return _win_paths_to_wsl(line)
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
                                  text=True, encoding="utf-8",
                                  errors="replace", timeout=t)
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
    """Check if the primary tool in the command string is installed.

    "Primary tool" means the real binary, not a privilege wrapper: on a
    Windows box `sudo nmap ...` used to resolve `sudo` (Windows ships a
    disabled sudo.exe), report "installed", and then hand the raw line to
    cmd.exe — the scan never ran. `_command_head` skips the wrappers.

    A shell COMMENT is not a missing tool: some adapters degrade to
    `# …` as a documented no-op when the step cannot apply (e.g.
    `version_detect` with no known open port). Reading `#` as the binary
    name turned that no-op into "refused: tool '#' not installed".
    """
    if is_comment(cmd):
        return True
    _prefix, tool, _rest = _command_head(cmd)
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
    "msf-fire", "msf-status", "msf-interact", "remote-deploy",
    "chain", "poc-sync", "remote-view", "remote-open",
    "generate-shellcode", "mem-run", "inject-tl", "inject-eb",
    "beacon-auth", "beacon-help", "autopersist", "interact", "results",
    "back", "payloads", "console", "migrate", "run", "use", "set",
    "fire", "execute", "screenshot", "keylog", "persist",
    "unpersist",
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


# `_WRAPPER_PREFIXES` (defined with `_command_head` above) is the single list
# of privilege/wrapper words: `sudo nmap ...` needs nmap, not sudo — checking
# the wrapper would report a false positive (or miss the real dependency).
def _tools_from_commands(commands) -> set:
    """Binary names invoked by a flat list of command strings."""
    tools = set()
    for cmd in (commands or []):
        # ONE unwrapping rule for the whole module: the wrapper words are not
        # the binary here either (see `_command_head`).
        _prefix, first, _rest = _command_head(str(cmd))
        if first and not first.startswith(("#", "$")) and first != "echo":
            tools.add(first)
    return tools


def module_tools(instance) -> set:
    """Binary names a module's own commands invoke (build + suggest)."""
    tools = set()
    try:
        for source in (instance.build_commands(),
                       instance.suggest_commands()):
            for group in (source or {}).values():
                tools |= _tools_from_commands(group or [])
    except Exception:
        pass
    return tools


def module_missing_tools(instance, commands=None) -> list:
    """``[(tool, install_hint)]`` a module instance needs but cannot find.

    ONE gate shared by `preflight` and by a module's own `run`: the tools
    are derived from the module's own commands (build + suggest), so a
    module that only calls a tool conditionally does not block. Resolution
    goes through ToolRegistry, so `impacket-secretsdump` counts as the
    legacy `secretsdump.py` being installed.

    ``commands`` restricts the check to those command strings — quiet mode
    executes only the TOP suggestion, so it must not be refused for a tool
    a different suggestion would need.
    """
    try:
        from phantom.automation.runtime.toolchain import ToolRegistry
        reg = ToolRegistry()
    except Exception:
        return []
    tools = (_tools_from_commands(commands) if commands is not None
             else module_tools(instance))
    return [(t, tool_install_hint(t)) for t in sorted(tools)
            if not reg.has(t)]


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


class RunStatus:
    """Outcome accumulator for a command batch (G16).

    `run_command` returns "" for a missing tool, for an out-of-scope target
    and for a command that genuinely printed nothing -- three different facts
    that modules then stored as their whole module result. Nothing downstream
    could tell a BROKEN run from a CLEAN one: "nmap is not installed" and
    "nmap found nothing" and "the target is unreachable" all arrived as an
    empty value. This accumulator carries the reason next to the output.
    """

    __slots__ = ("errors", "refused", "commands", "output_chars", "with_output")

    def __init__(self):
        self.errors: list = []
        self.refused: list = []
        self.commands: int = 0
        self.output_chars: int = 0
        self.with_output: list = []

    def refused_command(self, cmd: str, reason: str) -> None:
        self.errors.append(reason)
        self.refused.append(cmd)

    def ran(self, cmd: str, output: str) -> None:
        self.commands += 1
        self.output_chars += len(output or "")
        if output and output.strip():
            self.with_output.append(cmd)

    @property
    def error(self):
        return self.errors[0] if self.errors else None

    @property
    def outcome(self) -> str:
        """error / empty / ok -- never inferred from the output text."""
        if self.errors and not self.output_chars:
            return "error"
        if not self.commands:
            return "empty"
        return "ok" if self.output_chars else "empty"

    def as_dict(self) -> dict:
        return {
            "outcome": self.outcome,
            "error": self.error,
            "errors": list(self.errors),
            "refused": list(self.refused),
            "commands": self.commands,
            "output_chars": self.output_chars,
            "with_output": list(self.with_output),
        }


def _to_cmd_redirects(cmd: str) -> str:
    """Translate POSIX `/dev/null` redirects for cmd.exe (no-op elsewhere).

    Not cosmetic: cmd.exe parses `2>/dev/null` as a redirect to the path
    ``\\dev\\null``, fails with "path not found" and runs NOTHING. Verified on
    this host: ``cmd /c "echo hi 2>/dev/null"`` exits 1 with no output. Every
    template carrying a POSIX redirect was therefore silently skipped on
    Windows — the yt-dlp video picker, theHarvester, the suggested
    `ssh-keyscan ... 2>/dev/null`, `searchsploit ... 2>/dev/null`.
    `ssh -o UserKnownHostsFile=/dev/null` is an ARGUMENT, not a redirect, and
    is deliberately left intact by the anchor on `>`.
    """
    if os.name != "nt":
        return cmd
    for posix, win in (("&>/dev/null", ">NUL 2>&1"),
                       ("2>/dev/null", "2>NUL"),
                       ("1>/dev/null", "1>NUL"),
                       (">/dev/null", ">NUL")):
        cmd = cmd.replace(posix, win)
    return cmd


def run_command(cmd: str, target_ip: str = "", status=None) -> str:
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
    if is_comment(cmd):
        console.print(f"[dim]{cmd.strip()}[/]")
        return ""

    if target_ip and session.scope and not is_in_scope(target_ip, session.scope):
        console.print(f"[red][!] Command blocked: {target_ip} is out of scope.[/]")
        if status is not None:
            status.refused_command(cmd, f"out of scope: {target_ip}")
        return ""

    if target_ip and not _is_safe_target(target_ip):
        console.print(f"[red][!] Blocked: target '{target_ip}' contains dangerous characters.[/]")
        if status is not None:
            status.refused_command(cmd, f"unsafe target: {target_ip}")
        return ""

    if not _is_tool_installed(cmd):
        _p, _tool, _r = _command_head(cmd)
        tool = _tool or "Unknown"
        console.print(f"[yellow][!] Tool '{tool}' not installed. Skipping.[/]")
        console.print(f"    [dim]Install with: sudo apt install {tool}[/]")
        if status is not None:
            status.refused_command(cmd, f"tool '{tool}' not installed")
        return ""

    # WSL toolbox: this manual path used to hand the line straight to cmd.exe,
    # so on Windows `sudo nmap -sV ...` resolved the (disabled) native
    # sudo.exe and every module-powered scan died with "Sudo is disabled on
    # this computer" — the quiet/agent path and the network mapper already
    # bridged through the distro, the interactive one never did.
    _hide_windows_sudo()
    cmd = _rewrite_wsl(cmd)
    if os.name == "nt" and cmd.startswith("wsl "):
        cmd = _wrap_wsl_redirects(cmd)
    cmd = _to_cmd_redirects(cmd)

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
            # DECODE, do not die: `text=True` alone picks the LOCALE codec
            # (cp1252 here), and any UTF-8 byte in a tool's output killed the
            # reader thread with UnicodeDecodeError — the line vanished and a
            # traceback landed in the operator's console. Live evidence
            # (2026-10-16): five of them during one `social graph --run`, each
            # one a page-body chunk the recon never saw.
            encoding="utf-8",
            errors="replace",
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
                    if status is not None:
                        status.ran(cmd, "".join(output_lines))
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

    if status is not None:
        status.ran(cmd, "".join(output_lines))
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


def _kill_process_tree(process: "subprocess.Popen") -> None:
    """Kill the child AND its descendants (P0 negative-test item). The
    timeout path previously killed only the direct child (the shell),
    leaving grandchildren — nmap helpers, wsl children — running.
    POSIX: SIGKILL the whole process group (execute_quiet starts the
    child in its own session). Windows: taskkill /T walks the tree."""
    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                capture_output=True, timeout=10)
            return
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        try:
            import signal
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            return
        except (ProcessLookupError, PermissionError, OSError):
            pass
    try:
        process.kill()
    except OSError:
        pass


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

    `shell=True` is intentional and load-bearing: module commands are shell
    LINES (pipes, redirections, `wsl -d <distro> ...`, `&&` chains) produced
    by the planner's templates and the CLI, not argv lists. The injection
    boundary is therefore the interpolated TARGET, validated by
    `_is_safe_target` above (and by shlex.quote in the ssh/remote wrappers);
    a new adapter that interpolates other untrusted text MUST quote it.

    Returns a QuietResult (never raises for command failure).
    """
    started = time.time()
    if check_scope and target_ip and session.scope and not is_in_scope(target_ip, session.scope):
        return QuietResult(cmd=cmd, error=f"out of scope: {target_ip}", returncode=-1)

    if target_ip and not _is_safe_target(target_ip):
        return QuietResult(cmd=cmd, error=f"unsafe target chars: {target_ip}", returncode=-1)

    if is_comment(cmd):
        # a documented no-op: nothing to run, nothing to fail. Reported as
        # a successful command with the reason as its output so the step's
        # postcondition check stays honest (it will simply observe nothing).
        return QuietResult(cmd=cmd, stdout=cmd.lstrip().lstrip("#").strip(),
                           returncode=0)

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
    cmd = _to_cmd_redirects(cmd)
    session.add_history(cmd)

    try:
        # P0-negative "timeout kills the process group": start_new_session
        # (POSIX) / CREATE_NEW_PROCESS_GROUP (Windows) detaches the child
        # into its own group so the timeout kill takes the WHOLE tree with
        # it — nmap's helper processes, wsl bash children, etc. included.
        if os.name == "nt":
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                # locale codec (cp1252) on Windows makes every UTF-8 byte in a
                # tool's output a UnicodeDecodeError in the reader thread: the
                # output disappears and the operator gets a traceback. Decode
                # with replacement and keep the bytes that do decode.
                encoding="utf-8",
                errors="replace",
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
            )
        else:
            process = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                errors="replace",
                start_new_session=True,
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
            _kill_process_tree(process)
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
    # Parity with run_command/execute_quiet: an unsafe target (shell
    # metacharacters) must never reach the shell=True child here either.
    if target_ip and not _is_safe_target(target_ip):
        raise ValueError(f"unsafe target chars: {target_ip}")
    if not _is_tool_installed(cmd):
        raise FileNotFoundError(f"tool '{cmd.split()[0] if cmd.split() else '?'}' not installed")

    # same bridge as run_command/execute_quiet: the background spawner used to
    # hand POSIX lines (`sudo nmap ...`, `... 2>/dev/null`) straight to cmd.exe
    _hide_windows_sudo()
    cmd = _rewrite_wsl(cmd)
    if os.name == "nt" and cmd.startswith("wsl "):
        cmd = _wrap_wsl_redirects(cmd)
    cmd = _to_cmd_redirects(cmd)

    session.add_history(cmd)
    process = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",   # a locale codec turns any UTF-8 byte into a
                            # UnicodeDecodeError and the output is lost
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


def run_commands(commands: list, target_ip: str = "", status=None,
                 checkpoint=None) -> dict:
    """
    Run a list of commands sequentially.
    After all commands complete, shows buffered output
    from any commands sent to background with 'n'.
    Returns dict {command: output}.

    `status`, when given a `RunStatus`, accumulates WHY each command did
    or did not produce output (missing tool / out of scope / genuinely
    empty), so the caller can store that next to the raw output instead
    of collapsing every case into an empty dict.

    `checkpoint`, when given a `ManualCheckpoint`, makes the batch
    RESUMABLE: a command already recorded as completed is not run again,
    and each result is persisted as soon as it is produced — so a run
    interrupted at minute 39 of 40 resumes instead of starting over.
    """
    results = {}
    done = checkpoint.completed() if checkpoint is not None else {}
    for cmd in commands:
        clean_cmd = cmd.replace(" AGGRESSIVE", "").strip()
        if checkpoint is not None and clean_cmd in done:
            results[clean_cmd] = done[clean_cmd]
            console.print(f"  [dim]resume: skipping completed "
                          f"'{clean_cmd[:60]}'[/]")
            if status is not None:
                status.ran(clean_cmd, done[clean_cmd])
            continue
        # The call SHAPE is unchanged when no status is requested: wrappers
        # and test doubles that predate the outcome channel keep working
        # (they only need to accept the extra kwarg when they ask for one).
        if status is None:
            results[clean_cmd] = run_command(clean_cmd, target_ip)
        else:
            results[clean_cmd] = run_command(clean_cmd, target_ip, status=status)
        if checkpoint is not None:
            checkpoint.mark(clean_cmd, results[clean_cmd])

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

    if checkpoint is not None:
        checkpoint.finish()
    return results