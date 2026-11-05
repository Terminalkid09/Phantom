"""Tests: the tool manifest covers every phase, and the bridge limit is stated.

Measured 2026-11-05: `phantom --doctor` reported `tools: 3/20 installed`. Twenty
entries was a recon-and-brute list: the web, AD, lateral-movement and wireless
phases had no installable tool at all, so an operator could read "all tools
present" while half of Phantom could not run. The same session found a second,
different failure: `nmap` resolves through the WSL/Kali bridge, and that distro
has no route to Docker Desktop's bridge networks, so a container serving HTTP
looked like "no open services".

These tests pin the two answers: every manifest row is a real, installable tool
in a named phase, and the WSL<->Docker caveat is emitted only when a tool is
actually bridged.
"""
from __future__ import annotations

import pytest

from phantom.core import doctor
from phantom.utils import tool_manifest as tm
from phantom.utils import toolchain as tc

#: The phases the framework must be able to run. A manifest row that belongs to
#: none of these is a tool nobody can reach from a capability.
PHASES = {"recon", "web", "brute", "ad", "lateral", "post", "c2", "wireless",
          "build", "msf", "base", "pip"}

#: Phases that must not be empty: each one is a kill-chain stage, not a nicety.
REQUIRED_PHASES = ("recon", "web", "ad", "lateral", "wireless", "build")


def test_every_entry_has_a_phase_a_package_and_a_reason():
    for entry in tm.MANIFEST:
        assert entry.category in PHASES, f"{entry.name}: unknown phase"
        packages = [entry.apt, entry.dnf, entry.pacman, entry.brew, entry.pip]
        assert any(packages), f"{entry.name}: no installable package at all"
        assert entry.description.strip(), f"{entry.name}: no description"


def test_every_kill_chain_phase_has_at_least_one_tool():
    present = {e.category for e in tm.MANIFEST}
    missing = [p for p in REQUIRED_PHASES if p not in present]
    assert not missing, f"phases with no installable tool: {missing}"


def test_the_manifest_is_not_a_recon_only_list():
    installable = tm.setup_tools()
    assert len(installable) >= 45, (
        f"only {len(installable)} installable tools: the manifest still "
        "describes a scanner, not a framework"
    )


def test_setup_tools_excludes_only_the_base_group():
    installable = tm.setup_tools()
    assert all(not e.base for e in installable)
    assert len(installable) + sum(1 for e in tm.MANIFEST if e.base) == len(tm.MANIFEST)


def test_the_apt_plan_has_no_duplicates_and_no_blank_package():
    plan = tm.install_plan("apt")
    assert len(plan) == len(set(plan)), "the install plan repeats a package"
    assert all(p.strip() for p in plan), "the plan carries an empty package name"
    # impacket tools share one package: the dedupe is the contract, not a bug.
    assert plan.count("impacket-scripts") == 1


def test_a_host_tool_emits_no_bridge_note():
    rows = [("nmap", "host"), ("hydra", "missing")]
    assert doctor.bridge_network_note(rows) == ""


def test_a_bridged_tool_emits_the_docker_reachability_note():
    rows = [("nmap", "wsl"), ("hydra", "host")]
    note = doctor.bridge_network_note(rows)
    assert note, "a bridged tool must carry its Docker reachability caveat"
    assert "172" in note
    assert "published" in note.lower()


def test_the_bridge_note_is_absent_when_nothing_is_installable():
    assert doctor.bridge_network_note([]) == ""


def test_the_summary_counts_add_up_with_a_bridged_row():
    rows = [("nmap", "wsl"), ("curl", "host"), ("hydra", "missing")]
    line = doctor.tools_summary_from(rows)
    assert "2/3 installed" in line
    assert "host 1, wsl 1" in line
    assert "missing: hydra" in line


def test_the_bridge_probe_is_not_consulted_when_everything_is_native():
    """No WSL probe on a host that has everything: the check must stay cheap."""
    def explode(_name):                      # pragma: no cover - must not run
        raise AssertionError("the bridge was probed although nothing was missing")

    rows = doctor.tool_sources(["nmap"], native=lambda name: "/usr/bin/" + name,
                               bridged=explode)
    assert rows == [("nmap", "host")]


def test_the_registry_still_names_the_new_manifest_entries():
    """The manifest feeds the toolchain registry: a row there must be nameable."""
    for name in ("ffuf", "nuclei", "netexec", "chisel", "x86_64-w64-mingw32-g++"):
        assert name in tc.TOOLS, f"{name} missing from toolchain.TOOLS"
        assert tc.TOOLS[name].packages, f"{name} has no package in the registry"
