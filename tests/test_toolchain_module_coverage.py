"""Tests: every binary a manual module invokes is a tool Phantom can NAME.

The manual modules are orchestrators — `scan` shells out to nmap, enum4linux,
smbclient, rpcclient, snmpwalk, onesixtyone, sslscan and traceroute, `web` to
ffuf, feroxbuster, nikto, nuclei, sqlmap, wafw00f, whatweb and arjun, `exploit`
to msfconsole, `wifi` to airmon-ng/airodump-ng/aireplay-ng/reaver, `pivot` to
ssh. That orchestration was the module layer's documented weakness: with the
binary missing, the module simply degraded, and nothing said WHICH dependency
was absent or how to add it.

``phantom.utils.toolchain.TOOLS`` is the ONE place that answers both questions,
and it is what ``preflight``, the API toolchain endpoint and the Electron
installer read. Measured 2026-11-03: it knew ~10 of those binaries, so for the
rest the toolchain view had nothing to offer — "install the missing tool" was
advice with no command behind it.

This test is the invariant that keeps that fixed: a module may not invoke a
binary the registry cannot name. It discovers the binaries from the modules
themselves (never from a list copied here), so adding a command to a module
fails this test until its tool is a known dependency — the exact drift that
made the registry incomplete in the first place.

Deliberately skipped: modules whose ``build_commands()`` needs arguments
(``brute``) or is a stub (``analyzer``, ``report``). Instantiating them here
would test the stub, not the dependency.
"""
from __future__ import annotations

import importlib
import pkgutil

import phantom.modules as modules_pkg
from phantom.core.executor import (_PHANTOM_COMMANDS, _command_head,
                                  tool_install_hint)
from phantom.core.session import session
from phantom.utils import toolchain as tc

# Interpreters and shell builtins a module may legitimately put at the head of
# a command. They ship with every OS Phantom runs on, so there is nothing to
# install and a registry row would be a lie about a dependency.
_NO_INSTALL = frozenset({
    "powershell", "powershell.exe", "cmd", "cmd.exe", "bash", "sh",
    "python", "python3", "echo", "curl", "wget", "start", "open", "xdg-open",
    # Shell keywords: a module may emit a `for p in …; do …; done` loop, and
    # its head is a keyword, not something an operator could install.
    "for", "if", "while", "until", "case", "do", "done", "then", "fi",
    "esac", "elif", "else",
})

# The managers `detect_env` can report; a package mapped to anything else would
# never be reachable.
_MANAGERS = frozenset({"apt", "pacman", "dnf", "zypper", "brew",
                       "winget", "choco"})


def _module_instances():
    """``[(file_name, instance)]`` for every real module class."""
    out = []
    for info in pkgutil.iter_modules(modules_pkg.__path__):
        if info.name == "base_module":
            continue
        try:
            module = importlib.import_module(f"phantom.modules.{info.name}")
        except Exception:                     # optional dependency missing
            continue
        for attr, obj in vars(module).items():
            if (not isinstance(obj, type) or not attr.endswith("Module")
                    or not getattr(obj, "module_name", None)
                    or obj.__module__ != module.__name__):
                continue
            try:
                out.append((info.name, obj()))
            except Exception:                 # stub that refuses construction
                continue
    return out


def _binaries(instance) -> set:
    """Binary names the module's own plans invoke (build + suggest)."""
    found = set()
    for builder in ("build_commands", "suggest_commands"):
        try:
            groups = getattr(instance, builder)() or {}
        except Exception:                     # needs arguments, or a stub
            continue
        for commands in groups.values():
            for command in commands or []:
                _prefix, first, _rest = _command_head(str(command))
                if first:
                    found.add(first)
    return found


def _is_dependency(binary: str) -> bool:
    """Is this token a binary that has to be installed somewhere?"""
    if not binary or binary.startswith(("#", "$", "-")):
        return False
    return binary not in _PHANTOM_COMMANDS and binary not in _NO_INSTALL


def test_every_module_binary_is_a_known_tool(monkeypatch):
    # A module's plan is target-dependent; give it one so the state-aware
    # groups are produced instead of silently empty.
    monkeypatch.setattr(session, "target", "10.0.0.5", raising=False)
    # …and give it no RESULTS: another test in the same session may have left
    # services behind, which changed which suggestion groups are emitted and
    # made this test order-dependent (it passed alone, failed in the suite).
    monkeypatch.setattr(session, "results", {}, raising=False)
    unknown = {}
    for name, instance in _module_instances():
        for binary in _binaries(instance):
            if _is_dependency(binary) and binary not in tc.TOOLS:
                unknown.setdefault(binary, set()).add(name)

    assert not unknown, (
        "these binaries are invoked by a manual module but absent from "
        "phantom.utils.toolchain.TOOLS, so preflight and the Electron "
        "toolchain view can neither name them nor say how to install them: "
        + ", ".join(f"{binary} ({', '.join(sorted(mods))})"
                    for binary, mods in sorted(unknown.items())))


def test_every_package_maps_to_a_manager_that_can_use_it():
    bad = [(name, manager)
           for name, spec in tc.TOOLS.items()
           for manager in spec.packages
           if manager not in _MANAGERS]
    assert not bad, f"unreachable package mappings: {bad}"


def test_the_hint_for_a_module_only_tool_names_its_package():
    # enum4linux is invoked by `scan` and was absent from the registry, so the
    # hint was the generic "apt install <tool>" guess. The package row is what
    # makes the advice real on a Debian/Kali box.
    kali = tc.Env("linux", "kali", "apt", False, False)
    assert tc.package_for("enum4linux", kali) == "enum4linux"
    assert "enum4linux" in tool_install_hint("enum4linux")


def test_the_approved_manifest_is_reachable_from_preflight(monkeypatch):
    # `phantom setup`/`doctor` install from tool_manifest; preflight reads
    # TOOLS. A tool in one and not the other is a "missing" with no way in,
    # which is exactly what happened to httpx and medusa.
    monkeypatch.delitem(tc.TOOLS, "httpx", raising=False)
    merged = tc._augment_from_manifest(dict(tc.TOOLS))
    assert "httpx" in merged
    assert merged["httpx"].pip == "httpx-toolkit"


def test_a_tool_the_registry_does_not_know_still_gets_a_hint():
    # The literal dict in executor.py remains the fallback; a future tool
    # nobody mapped must still produce advice instead of an empty string.
    assert tool_install_hint("some-unmapped-tool")
