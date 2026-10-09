"""Section D4 — the parity rule, as a check that fails on drift.

Two surfaces diverged because nothing compared them:

* the module list: `phantom/api/server.py::_MODULES` is the single source, and
  `electron/src/components/Sidebar.tsx` repeats it by hand — adding a module to
  one and not the other is a silent gap (and the sidebar FILTERS entries by
  capability, so a missing entry looks like a feature flag, not a mistake);
* the AutoShell command set: `auto_shell.py` grew `context` and `workspace`
  (both authored recently) with no Electron equivalent, and nobody noticed
  because "which commands have a UI" lived in nobody's head.

The rule, kept as small as possible:

  1. every module in `_MODULES` appears in the Sidebar's MODULES section and
     nothing else does;
  2. every AutoShell `do_*` command is CLASSIFIED — either with the Electron
     surface that covers it, or by name as CLI-only WITH the reason.

Both are mechanical, need no Electron toolchain, run in the existing pytest
job, and fail the moment a new command or module appears unclassified. The
allowlist in `electron/electron/endpoint_allowlist.ts` already applies exactly
this convention to endpoints ("add a rule only when a panel actually calls
it"); this extends the same idea to the two lists that were drifting.
"""
import pathlib
import re

import pytest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SIDEBAR = _ROOT / "electron" / "src" / "components" / "Sidebar.tsx"

# Every AutoShell command and where the SAME function lives in the desktop
# app. `do_*` with nothing here is CLI-only, and has to say why.
ELECTRON_SURFACES = {
    "targets": "AutoModePanel: target list",
    "scope": "AutoModePanel: scope field",
    "flags": "AutoModePanel: goal / profile / agents / flags",
    "plan": "AutoModePanel: Plan -> POST /api/automode/plan",
    "launch": "AutoModePanel: Start -> POST /api/automode/run "
              "(same engine/force_network payload)",
    "status": "TimelinePanel: per-target events (partial: the panel shows the "
              "engagement timeline, the command the last run's events)",
    "export": "BundlesPanel: export session",
    "import": "BundlesPanel: import session",
    "manual": "the module tabs are the manual surface",
    "c2": "C2Dashboard + AutoModePanel handoff card -> setActiveTab('c2')",
    "handoff": "AutoModePanel: handoff card",
    "guardrails": "SettingsPanel: guardrails section (GET/POST /api/guardrails)",
    "review": "LearningPanel: evolution summary (partial: the panel shows "
              "learned patterns, not the PR/gate budgets)",
    "help": "CommandPalette: search across modules and commands",
    "back": "navigation: the tab switch itself",
    "exit": "navigation: closing the window",
    "quit": "navigation: closing the window",
    "run": "TODO: remove the alias (patch B1 in the report) — today it "
           "aliases `launch` while `run` means one module in the manual shell",
}

# Commands with no desktop surface, and the reason (an omission has to be a
# decision, so it is written down).
CLI_ONLY = {
    "resume": "no panel resumes a checkpoint: /api/automode/resume does not "
              "exist and BundlesPanel only IMPORTS a .pm (it restores state "
              "for the next run, it does not resume the interrupted one)",
    "context": "GAP: the author added `context` to the CLI only "
               "(target/scope/flags/run state/pending beacons — the data is "
               "already in the store, a StatusBar summary would do)",
    "workspace": "GAP: same omission — the surfaces of the engagement and how "
                 "to reach them; the Sidebar IS that list, so a badge/legend "
                 "would cover it",
}


def _sidebar_module_ids() -> set:
    text = _SIDEBAR.read_text(encoding="utf-8")
    start = text.index("label: 'MODULES'")
    block = text[start:]
    block = block[block.index("items: ["):]
    block = block[:block.index("]")]
    return set(re.findall(r"id: '([a-z_]+)'", block))


class TestModulesAreInParity:
    def test_the_module_registry_is_the_eleven_the_api_serves(self):
        from phantom.api.server import _MODULES
        assert set(_MODULES) == {
            "analyzer", "brute", "exploit", "handler", "osint", "payload",
            "pivot", "scan", "web", "wifi", "wordlist"}

    def test_the_sidebar_lists_exactly_those(self):
        from phantom.api.server import _MODULES
        assert _sidebar_module_ids() == set(_MODULES), (
            "a module exists on one surface only: add it to both "
            "(Sidebar.tsx MODULES section vs server.py _MODULES)")

    @pytest.mark.parametrize("name", ["craft", "telegram", "report"])
    def test_the_cli_only_modules_are_NOT_in_the_registry(self, name):
        # Their ABSENCE is deliberate and each one has a surface of its own:
        # `craft` and `report` are reached through dedicated endpoints
        # (/api/craft, /api/reports/*) and `telegram` has no endpoint at all.
        # If one of them ever joins _MODULES, this test is the reminder that
        # the two other surfaces have to follow.
        from phantom.api.server import _MODULES
        assert name not in _MODULES


class TestEveryAutoShellCommandIsClassified:
    def _commands(self) -> set:
        from phantom.core.auto_shell import AutoShell
        return {name[3:] for name in dir(AutoShell)
                if name.startswith("do_") and name != "do_"}

    def test_nothing_is_unclassified(self):
        commands = self._commands()
        classified = set(ELECTRON_SURFACES) | set(CLI_ONLY)
        assert commands - classified == set(), (
            "a new AutoShell command with no Electron surface: classify it "
            "here (either the panel that covers it, or CLI-only + reason)")

    def test_nothing_is_classified_that_no_longer_exists(self):
        commands = self._commands()
        classified = set(ELECTRON_SURFACES) | set(CLI_ONLY)
        assert classified - commands == set(), (
            "the table names commands that are gone: drop them")

    def test_every_cli_only_command_states_a_reason(self):
        for command, reason in CLI_ONLY.items():
            assert len(reason) > 30, command

    def test_the_cli_only_gaps_are_the_two_the_report_names(self):
        assert {c for c, why in CLI_ONLY.items() if why.startswith("GAP")} == {
            "context", "workspace"}


class TestTheConventionHasAHome:
    def test_the_endpoint_allowlist_states_the_same_convention(self):
        path = (_ROOT / "electron" / "electron" /
                "endpoint_allowlist.ts")
        text = path.read_text(encoding="utf-8")
        # the rule this file implements already exists for endpoints: a rule
        # is added when a PANEL calls the route, not speculatively.
        assert "DELIBERATELY NOT BRIDGED" in text
        assert "when a panel actually calls" in text
