"""The renderer must be usable without a mouse and readable by a screen reader.

The audit found ZERO `aria-*` attributes and ONE `role=` in all of
`electron/src` — for a tool whose pitch is "better than the CLI", accessibility
was the weakest UX axis. The fixes are attribute-level (no behaviour change),
so the contract is enforced the same way this repo enforces the Electron IPC
allowlist: by scanning the sources, with the *rule* spelled out so the next
component cannot quietly skip it.

What is checked, and why each one matters:

* landmarks — `status` and `alert`/`status` live regions mean the two places
  the app speaks on its own (the status bar, the toast stack) are announced
  instead of visible-only;
* `role="dialog"` + `aria-modal` on overlays — otherwise a modal is a div that
  a screen reader reads straight through;
* `aria-current` on navigation — tells which panel is open;
* a labelled icon-only button — a lucide icon has no accessible name;
* `role="log"` on the auto-mode stream — the run's live output is announced as
  it grows;
* `scope="col"` on table headers — data tables need header association;
* every custom `role="button"` also has `tabIndex` — a role without keyboard
  reachability is worse than no role at all.

Run it with `python -m pytest tests/test_electron_a11y.py`.
"""
import os
import re

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO_ROOT, "electron", "src")


def _sources(suffixes=(".tsx", ".ts")):
    out = {}
    for root, _dirs, files in os.walk(SRC):
        for name in files:
            if name.endswith(suffixes):
                path = os.path.join(root, name)
                with open(path, encoding="utf-8") as handle:
                    out[os.path.relpath(path, SRC).replace("\\", "/")] = \
                        handle.read()
    return out


#: file → attributes that must appear in it
REQUIRED = {
    # the app's own voice: five-second polls change this text
    "components/StatusBar.tsx": ["aria-live"],
    "components/Toast.tsx": ["role=\"status\"", "aria-live"],
    # the nav landmark and which panel is current (`<nav>` IS the landmark)
    "components/Sidebar.tsx": ["<nav", "aria-current"],
    # the command palette is a modal dialog
    "components/CommandPalette.tsx": ["role=\"dialog\"", "aria-modal"],
    # the run's live log, the handoff card, and a safe progress read-out
    "components/AutoModePanel.tsx": ["role=\"log\"", "aria-live",
                                     "aria-label"],
    # the app shell: a skip link and one <main>
    "App.tsx": ["<main", "aria-label"],
}

#: lucide icons have no accessible name — the button around one needs a label
ICON_FILES = [
    "components/AdGraphPanel.tsx", "components/AuditViewer.tsx",
    "components/AutoModePanel.tsx", "components/BundlesPanel.tsx",
    "components/C2Dashboard.tsx", "components/CommandPalette.tsx",
    "components/ExternalTools.tsx", "components/LearningPanel.tsx",
    "components/LlmProposals.tsx", "components/ModulePanel.tsx",
    "components/NetworkMap.tsx", "components/RecordingsPanel.tsx",
    "components/RemoteCanvas.tsx", "components/ReportsPanel.tsx",
    "components/SessionPanel.tsx", "components/SettingsPanel.tsx",
    "components/Sidebar.tsx", "components/SocialGraphPanel.tsx",
    "components/StatusBar.tsx", "components/TimelinePanel.tsx",
]


@pytest.fixture(scope="module")
def sources():
    return _sources()


@pytest.mark.parametrize("relative,attributes", sorted(REQUIRED.items()))
def test_the_required_attributes_are_present(sources, relative, attributes):
    text = sources.get(relative)
    assert text is not None, f"{relative} does not exist any more"
    missing = [a for a in attributes if a not in text]
    assert not missing, (
        f"{relative} is missing {missing}: these are the affordances a screen "
        f"reader (or a keyboard) needs, and they are one attribute each")


def test_the_components_that_render_tables_associate_their_headers(sources):
    """A data table without `scope` is a grid of anonymous cells."""
    offenders = []
    for relative, text in sources.items():
        if not relative.endswith(".tsx") or "<table" not in text:
            continue
        headers = re.findall(r"<th\b[^>]*>", text)
        if headers and not all("scope=" in h for h in headers):
            offenders.append(relative)
    assert not offenders, f"tables without `scope=` on headers: {offenders}"


def test_every_icon_button_file_labels_at_least_one_control(sources):
    """`aria-label` is how an icon-only control gets a name."""
    offenders = [f for f in ICON_FILES
                 if f in sources and "aria-label" not in sources[f]]
    assert not offenders, (
        f"these files render lucide icon buttons but never label one: "
        f"{offenders}")


def test_a_custom_button_role_is_keyboard_reachable(sources):
    """`role=\"button\"` on a div must come with `tabIndex` (and a key handler)."""
    offenders = []
    for relative, text in sources.items():
        for match in re.finditer(r"<[A-Za-z][^>]*role=\"button\"[^>]*>", text):
            tag = match.group(0)
            if "tabIndex" not in tag:
                offenders.append(f"{relative}: {tag[:60]}")
    assert not offenders, (
        "role=button without tabIndex is a mouse-only affordance dressed up "
        f"as a button: {offenders}")


def test_every_overlay_is_an_announced_dialog(sources):
    """A full-screen overlay that is not a dialog is read straight through."""
    offenders = []
    for relative, text in sources.items():
        if not relative.endswith(".tsx"):
            continue
        if "fixed inset-0" in text and "role=\"dialog\"" not in text:
            offenders.append(relative)
    assert not offenders, f"overlays without role=\"dialog\": {offenders}"
