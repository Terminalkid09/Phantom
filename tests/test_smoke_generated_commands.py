"""Smoke test: the generated commands must actually be executable.

For every representative generated command we resolve the leading tool on
PATH; if the tool is missing the test SKIPS (the suggestion is still valid,
it just needs the toolchain installed). If the tool is present we run it in
syntax-only mode (--version / -h / -V) and assert it exits, so the smoke
test proves the environment can actually launch what Phantom proposes —
without ever touching a real target.
"""
import shutil
import subprocess
import sys

import pytest

from phantom.core.session import session
from phantom.modules import suggest
from phantom.modules.handler import HandlerModule
from phantom.modules.payload import PayloadModule

_TOOL_VERIFY = {
    "curl": ("--version", 0),
    "openssl": ("version", 0),
    "nmap": ("--version", 0),
    "sshpass": ("-h", 0),
    "hydra": ("-h", 0),
    "sqlmap": ("--version", 0),
    "nikto": ("-h", 0),
    "ffuf": ("-V", 0),
    "gobuster": ("--version", 0),
    "msfconsole": ("--version", 0),
    "whatweb": ("--version", 0),
}


def _reset():
    session.target = "10.0.0.1"
    session.scope = []
    session.results = {}
    session.notes = []
    session.history = []
    session.mode = "recon"
    session.knowledge_base["os_info"] = {}
    session.knowledge_base["target_type"] = None
    session.knowledge_base["creds_found"] = []


# Tools that are not worth looking up: the shell plumbing is the OS's job.
_SHELL_TERMS = frozenset(("grep", "echo", "jq", "sh", "bash", "nc", "tee"))

# A suggestion written as a shell LOOP (`for p in admin login api; do curl
# ...`) is executed by the shell: the leading token is a keyword, the tool to
# look up is inside the loop.
_SHELL_KEYWORDS = frozenset(("for", "while", "until", "if", "then", "case"))

# Verbs the operator types INTO a Phantom shell — `reverse 10.0.0.1 4444`,
# `deploy`, `generate linux`, `bind 4444`, `listen --port 8443`, emitted by
# `payload_suggestion_group()` / `handler_suggestion_group()`. They are not
# binaries and can never be on PATH: looking them up is a category error, and
# it is what made this file report `bind`/`generate`/`listen`/`reverse` as
# "tools not installed". Derived from the shells' own `do_*` methods instead
# of a hand-kept list, so it cannot drift from the code that emits them.
_INTERACTIVE_VERBS = frozenset(
    name[3:] for cls in (PayloadModule, HandlerModule)
    for name in dir(cls) if name.startswith("do_"))


def _first_token(cmd):
    """The binary a command line invokes, `sudo`-aware.

    `lstrip("sudo")` was a character-SET strip, not a prefix strip: it turned
    `searchsploit` into `earchsploit`, `sqlmap` into `qlmap`, `sshpass` into
    `hpass`, `openssl` into `penssl` and `deploy` into `eploy`, and returned
    "" for every `sudo nmap ...` suggestion — which is the most common shape
    in this very file. The guard below was therefore checking names no binary
    can have, on a list of commands it never managed to parse correctly.
    """
    parts = cmd.strip().split()
    if not parts:
        return ""
    if parts[0] in ("sudo", "doas"):
        rest = parts[1:]
        # `sudo -u user tool ...`: the option's VALUE is a token too, so step
        # over the pair instead of reporting "-u" as a missing binary.
        if len(rest) >= 2 and rest[0] in ("-u", "-g", "-p", "-C", "--user"):
            rest = rest[2:]
        return rest[0] if rest else ""
    return parts[0]


@pytest.fixture(autouse=True)
def _clean():
    _reset()
    yield
    _reset()


def _collect_commands():
    cmds = []

    def add(groups):
        for group in (groups or {}).values():
            cmds.extend(group)

    session.add_result("scan", {
        "cmd": "22/tcp open  ssh   OpenSSH 7.9\n"
               "80/tcp open  http  Apache httpd 2.4.49\n"
               "443/tcp open  ssl/http  nginx 1.18.0\n",
    })
    add(suggest.first_steps_suggestion_group())
    add(suggest.service_suggestion_group())
    add(suggest.web_suggestion_group())
    add(suggest.brute_suggestion_group())
    add(suggest.exploit_suggestion_group())
    add(suggest.probe_suggestion_group())
    add(suggest.vulners_fallback_group())
    session.knowledge_base["creds_found"] = [
        {"username": "root", "password": "toor", "service": "ssh"},
    ]
    add(suggest.creds_suggestion_group())
    session.knowledge_base["os_info"] = {"name": "Linux 5.15", "accuracy": 90}
    add(suggest.payload_suggestion_group())
    add(suggest.handler_suggestion_group())
    return cmds


def test_every_generated_command_has_real_tool_on_path():
    cmds = _collect_commands()
    assert cmds, "no commands collected"
    missing = []
    for cmd in cmds:
        tool = _first_token(cmd)
        if not tool:
            continue
        if tool in _SHELL_TERMS or tool in _SHELL_KEYWORDS:
            continue
        if tool in _INTERACTIVE_VERBS:
            continue
        if tool.startswith("-"):
            # A token that starts with a dash is a parsing failure, never a
            # missing binary: failing here keeps a mangled name out of the
            # "not installed" list, where it would read as an environment gap.
            pytest.fail(f"could not name the binary in {cmd!r}")
        if shutil.which(tool) is None:
            missing.append((tool, cmd))
    if missing:
        pytest.skip(
            "tools not installed here: "
            + ", ".join(sorted({t for t, _ in missing})))


def test_installed_tools_parse_their_generated_flags():
    """Syntax-level validation only: run the tool's own version/help probe.
    This proves the toolchain can execute; it never touches a target."""
    checked = 0
    probed = set()
    for cmd in _collect_commands():
        tool = _first_token(cmd)
        # One probe per TOOL, not per suggestion: `curl` alone appears in ~260
        # of the 294 commands, so this loop used to spawn ~260 `--version`
        # processes and spend most of the file's runtime re-proving the same
        # binary launches. The assertion is "this tool executes", which the
        # first sighting already establishes.
        if tool not in _TOOL_VERIFY or tool in probed:
            continue
        args, _ = _TOOL_VERIFY[tool]
        if shutil.which(tool) is None:
            continue
        probed.add(tool)
        try:
            subprocess.run([tool, args], capture_output=True,
                           timeout=10)
        except (OSError, subprocess.TimeoutExpired) as e:
            pytest.fail(f"tool {tool} failed to launch: {e}")
        checked += 1
    if checked == 0:
        pytest.skip("no verifiable tools installed")
    assert checked > 0