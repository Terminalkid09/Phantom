"""Electron module panels must react to a target set after they are mounted.

All panels stay mounted so switching tabs cannot lose scan/auto-mode state.
That means the first module load happens before the session target is
hydrated; without a target dependency the panel kept saying "No commands
available" until the operator found the refresh icon.

There is no JS unit-test runner in this repo, so this pins the React effect
the same way the other Electron contract tests do: by reading the component.
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PANEL = os.path.join(ROOT, "electron", "src", "components", "ModulePanel.tsx")
C2 = os.path.join(ROOT, "electron", "src", "components", "C2Dashboard.tsx")
TUNNEL = os.path.join(ROOT, "electron", "src", "components", "TunnelHidCard.tsx")


def _src(path: str = PANEL) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def test_module_panel_reloads_commands_when_session_target_changes():
    src = _src()
    assert "}, [moduleId, session.target])" in src
    assert "load()" in src
    # The reset must happen with the reload, not only on a tab switch.
    effect = src[src.index("useEffect(() => {"):]
    effect = effect[:effect.index("}, [moduleId, session.target])")]
    assert "setModule(null)" in effect
    assert "setSelected('')" in effect
    assert "load()" in effect


def test_tunnel_card_refreshes_when_the_listener_starts_or_stops():
    tunnel = _src(TUNNEL)
    c2 = _src(C2)
    assert "listenerActive: boolean" in tunnel
    assert "}, [listenerActive]) // eslint-disable-line" in tunnel
    assert "<TunnelHidCard api={api} listenerActive={listener.active} />" in c2
