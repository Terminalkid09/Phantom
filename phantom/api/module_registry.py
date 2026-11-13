"""Module registry and the API command allowlist.

Extracted from the HTTP composition root: module discovery, command-group
metadata and the per-segment execution gate are policy, not transport.  The
server re-exports these names because they are part of the tested API surface.
"""

from __future__ import annotations

import contextlib
import re
import shlex
import threading
from typing import List, Optional

from phantom.core.session import session

_MODULES = {
    "scan": ("phantom.modules.scan", "ScanModule"),
    "osint": ("phantom.modules.osint", "OsintModule"),
    "wifi": ("phantom.modules.wifi", "WifiModule"),
    "web": ("phantom.modules.web", "WebModule"),
    "brute": ("phantom.modules.brute", "BruteModule"),
    "exploit": ("phantom.modules.exploit", "ExploitModule"),
    "payload": ("phantom.modules.payload", "PayloadModule"),
    "handler": ("phantom.modules.handler", "HandlerModule"),
    "pivot": ("phantom.modules.pivot", "PivotModule"),
    "analyzer": ("phantom.modules.analyzer", "AnalyzerModule"),
    "wordlist": ("phantom.modules.wordlist", "WordlistModule"),
}




def _module_instance(name: str):
    import importlib
    spec = _MODULES.get(name)
    if not spec:
        return None
    module = importlib.import_module(spec[0])
    return getattr(module, spec[1])()


def _module_groups(instance, method: str) -> dict[str, list[str]]:
    try:
        value = getattr(instance, method)()
    except (NotImplementedError, TypeError, AttributeError):
        return {}
    return {str(key): [str(command) for command in (commands or [])]
            for key, commands in (value or {}).items()}


_suggest_lock = threading.Lock()  # serializes scoped suggest generation


_TARGET_RE = re.compile(r"^[@+a-zA-Z0-9._\s\-:/]+$")


def _query_target(request) -> str:
    """Explicit ?target= override, validated like the shell's set target
    (garbage/Mock noise never reaches the session)."""
    try:
        raw = str(request.rel_url.query.get("target", "") or "").strip()
    except Exception:
        return ""
    if not raw or raw == session.target:
        return ""
    if not _TARGET_RE.match(raw) or ".." in raw:
        return ""
    return raw


@contextlib.contextmanager
def _scoped_suggest_target(target: str):
    """Generate suggestions for an explicit target without moving the
    operator's global session.target.
    INTERIM (documented): modules read the global session; until they
    take an explicit target parameter, generation runs serialized under
    a lock with a temporary override. Suggest generation is pure string
    building (no I/O), so the critical section is microseconds-wide and
    never blocks execution paths (which already carry explicit targets).
    """
    if not target:
        yield
        return
    with _suggest_lock:
        prev = session.target
        session.target = target
        try:
            yield
        finally:
            session.target = prev


def _module_group_status(name: str, instance, method: str,
                         ) -> dict[str, list[dict]]:
    """Same groups, but every command tagged with the REAL execution
    verdict (the same gate module_run enforces): the UI disables what
    cannot run instead of showing a button that 403s. Phantom-internal
    shell commands (do_* like `run`/`fire`) are flagged CLI-only."""
    out: dict[str, list[dict]] = {}
    for group, cmds in _module_groups(instance, method).items():
        items = []
        for cmd in cmds:
            gate = _validate_backend_command(name, cmd)
            items.append({"command": cmd,
                          "runnable": gate is None,
                          "reason": "" if gate is None else gate})
        out[group] = items
    return out


# ── Command allowlist (API execution gate) ─────────────────────────────────
# The module endpoints execute shell commands in the operator backend. The
# frontend is NOT a security boundary: a request body can carry anything, so
# every command is validated against the set of leading binaries the modules
# themselves generate (extracted at import time) plus a curated global tool
# set. Phantom-internal shell commands (do_* methods like `fire`, `run`,
# `deploy-agent`, `ssh [user:pass]`) are NOT backend-executable: they run in
# the CLI shell, and the API rejects them with a clear message instead of
# handing them to the OS (where "run" would just fail or worse).

_GLOBAL_TOOLS = {
    # core recon / discovery
    "nmap", "masscan", "nc", "ncat", "netcat", "traceroute", "arp-scan",
    "ping", "fping", "arp", "nbtscan", "wakeonlan", "arping",
    # service enumeration
    "sslscan", "openssl", "smbclient", "enum4linux", "enum4linux-ng",
    "rpcclient", "snmpwalk", "snmpbulkwalk", "onesixtyone", "smbmap",
    "ike-scan", "crackmapexec", "netexec", "evil-winrm", "rdesktop",
    "ldapsearch", "wbinfo",
    # web
    "curl", "wget", "whatweb", "wafw00f", "nuclei", "gobuster",
    "feroxbuster", "dirb", "nikto", "wfuzz", "ffuf", "wpscan",
    "dnsrecon", "sublist3r", "amass", "httpx", "hakrawler", "katana",
    "jsbeautifier", "xsstrike", "arjun",
    # dns
    "dig", "host", "nslookup", "whois", "dnsenum", "fierce",
    # creds / brute force
    "hydra", "medusa", "patator", "john", "hashcat", "cewl", "crunch",
    "sshpass", "ssh", "scp", "wpscan",
    # osint
    "theHarvester", "sherlock", "shodan", "exiftool", "steghide",
    "binwalk", "strings", "file", "unzip", "tar", "7z", "rar",
    "gzip", "zip", "base64",
    # exploit frameworks / tools
    "msfconsole", "msfvenom", "searchsploit", "sqlmap", "responder",
    "impacket-secretsdump", "secretsdump.py", "impacket-GetNPUsers",
    "GetNPUsers.py", "impacket-GetUserSPNs", "GetUserSPNs.py",
    "impacket-psexec", "psexec.py", "impacket-smbexec", "smbexec.py",
    "impacket-wmiexec", "wmiexec.py", "impacket-ntlmrelayx",
    "ntlmrelayx.py", "impacket-mssqlclient", "mssqlclient.py",
    "kerbrute", "bloodhound-python", "bloodhound", "cyberchef",
    # wifi
    "airmon-ng", "airodump-ng", "aireplay-ng", "reaver", "wash",
    "wifite", "bully",
    # pivot / tunneling / shells
    "proxychains", "proxychains4", "socat", "chisel", "sshuttle",
    "nc.traditional", "busybox",
    # generic utilities (interpreters are intentionally EXCLUDED: a leading
    # `bash`/`python` would be arbitrary code execution, not a module action)
    "git", "ls", "cat", "grep", "sed", "awk", "sort", "uniq", "head",
    "tail", "wc", "date", "id", "hostname", "uname", "whoami", "ps",
    "kill",
}

_MODULE_INTERNAL: dict[str, set[str]] = {}
_MODULE_TOOLS: dict[str, set[str]] = {}
_ALLOWED_TOOLS: set[str] = set(_GLOBAL_TOOLS)


def _strip_comment(cmd: str) -> str:
    """Module commands carry `  # reason` comments — drop them before
    parsing so the comment never becomes part of the token stream."""
    return re.sub(r"\s+#.*$", "", cmd).strip()


def _leading_token(cmd: str) -> str:
    """First binary of a shell command, `sudo` peeled off:
    'sudo nmap -sV {t}' -> 'nmap'; 'msfconsole -q -x "..."' -> 'msfconsole'."""
    try:
        tokens = shlex.split(_strip_comment(cmd))
    except ValueError:
        # unbalanced quotes: not a valid shell command, refuse it
        return ""
    if not tokens:
        return ""
    tok = tokens[0]
    if tok == "sudo" and len(tokens) > 1:
        tok = tokens[1]
    return tok


def _build_allowlists() -> None:
    """Extract per-module internal commands (do_*) and leading binaries from
    the same command groups the frontend receives, so anything the UI can
    legitimately send is allowed and everything else is refused."""
    global _ALLOWED_TOOLS
    for name in _MODULES:
        instance = _module_instance(name)
        internal = {m[3:] for m in dir(instance)
                    if m.startswith("do_") and m != "do_"}
        _MODULE_INTERNAL[name] = internal
        tools: set[str] = set()
        for group, cmds in {**_module_groups(instance, "build_commands"),
                            **_module_groups(instance, "suggest_commands")}.items():
            for c in cmds:
                tok = _leading_token(c)
                if not tok:
                    continue
                # Phantom pseudo-commands advertised in the module panels
                # ("run", "fire <cve>", "deploy-agent"...) are NOT shell
                # binaries: keep them out of the tool set so they cannot be
                # mistaken for a real executable by the validation gate.
                if tok.replace("-", "_") in internal:
                    continue
                tools.add(tok)
        _MODULE_TOOLS[name] = tools
        _ALLOWED_TOOLS |= tools


_build_allowlists()


def _split_shell_segments(cmd: str) -> List[str]:
    """Split on control operators that appear OUTSIDE quotes (`;`, `&&`,
    `||`, `|`, newline). Thin wrapper over the SHARED parser in
    `phantom.core.safe_exec` so validation and execution can never
    disagree about what the command means."""
    from phantom.core.safe_exec import split_operators
    segs, _seps = split_operators(cmd)
    return [s for s in segs if s.strip()]


def _check_segment_token(module: Optional[str], tok: str) -> Optional[str]:
    """Allowlist check for ONE command segment's leading binary."""
    if module is not None:
        # real shell binaries win (a do_* method may share its name with a
        # tool the module also invokes as a command, e.g. whatweb)
        if tok in _MODULE_TOOLS.get(module, set()) or tok in _ALLOWED_TOOLS:
            return None
        internal = _MODULE_INTERNAL.get(module, set())
        if tok in internal or tok.replace("-", "_") in internal:
            return (f"'{tok}' is a Phantom shell command (CLI-only) — run it "
                    f"in the Phantom shell with 'use {module}', not through "
                    f"the API backend")
        return f"command '{tok}' is not allowed for module '{module}'"
    if tok in _ALLOWED_TOOLS:
        return None
    return f"command '{tok}' is not in the API allowlist"


def _validate_backend_command(module: Optional[str],
                              command: str) -> Optional[str]:
    """Return an error string when the command must NOT execute, else None.
    module=None applies the GLOBAL allowlist only (generic /api/backend/run).

    EVERY shell segment is validated, not just the first: `nmap x; rm -rf ~`
    and `nmap x && curl evil` previously passed because only the leading
    binary was checked, while the string ran under `shell=True`."""
    cmd = (command or "").strip()
    if not cmd:
        return "empty command"
    # `curl ... | sh` / `... | python -` is arbitrary code execution even
    # when the leading binary is allowlisted — reject pipes into
    # interpreters outright (modules never generate those).
    if re.search(r"\|\s*(?:sh|bash|zsh|dash|python|python3|perl|ruby|node|php)\b",
                 cmd):
        return ("command pipes into an interpreter (arbitrary execution) "
                "— not allowed")
    # Nested execution the allowlist would never see. Modules generano
    # quoted `;` arguments (msfconsole -x "...; exit") but never `$()`,
    # `${}` or backticks.
    if "`" in cmd or "$(" in cmd or "${" in cmd:
        return "command substitution is not allowed"
    segments = _split_shell_segments(cmd)
    if not segments:
        return "unparseable command (check quotes)"
    for seg in segments:
        tok = _leading_token(seg)
        if not tok:
            return "unparseable command (check quotes)"
        err = _check_segment_token(module, tok)
        if err:
            return err
    return None
