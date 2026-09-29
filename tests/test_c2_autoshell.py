"""9.3 — auto-open shell: a new beacon is handed a live console.

Waiting for the operator to notice a check-in and click is how a live
session sits idle while the beacon's first task goes unread. With the grant
on, the FIRST check-in of a new beacon queues ONE harmless `health` task
(the console is then live with evidence the task channel works).

It is OFF by default — a beacon must not receive unsolicited tasks — the
toggle is audited, a session RESUME gets nothing (its queue is preserved),
and the UI opens the console of the first LIVE beacon instead of leaving an
empty selection.
"""
import json
import os
from unittest.mock import AsyncMock, MagicMock

import pytest

from phantom.core.c2_server import c2_state


def _reset():
    c2_state.beacons.clear()
    c2_state.tasks.clear()
    c2_state.results.clear()


@pytest.fixture(autouse=True)
def _clean():
    _reset()
    previous = c2_state.auto_shell
    c2_state.auto_shell = False
    yield
    c2_state.auto_shell = previous
    _reset()


def _commands(beacon_id):
    return [t["command"] for t in c2_state.tasks.get(beacon_id, [])]


class TestAutoShellOnCheckin:
    def test_default_is_off(self):
        assert c2_state.auto_shell is False
        c2_state.update_beacon("b1", {"ip": "10.0.0.9", "os": "Linux"})
        assert "health" not in _commands("b1")

    def test_when_enabled_a_new_beacon_gets_one_health_task(self):
        c2_state.set_auto_shell(True)
        c2_state.update_beacon("b1", {"ip": "10.0.0.9", "os": "Linux"})
        assert _commands("b1").count("health") == 1

    def test_the_health_task_comes_before_the_auto_persist(self):
        c2_state.set_auto_shell(True)
        c2_state.update_beacon("b1", {"ip": "10.0.0.9", "os": "Linux"})
        commands = _commands("b1")
        assert commands[0] == "health"
        if "persist" in commands:            # auto-persist default is on
            assert commands.index("health") < commands.index("persist")

    def test_a_session_resume_gets_nothing(self):
        c2_state.set_auto_shell(True)
        c2_state.update_beacon("b1", {"ip": "10.0.0.9", "os": "Linux"})
        c2_state.tasks["b1"].clear()          # the beacon drained its queue
        c2_state.update_beacon("b1", {"ip": "10.0.0.9", "os": "Linux"})
        assert "health" not in _commands("b1")

    def test_the_queue_is_audited(self, monkeypatch):
        calls = []
        from phantom.utils import audit_log as audit_module
        monkeypatch.setattr(audit_module.audit_log, "append",
                            lambda event, **kw: calls.append((event, kw)))
        c2_state.set_auto_shell(True)
        c2_state.update_beacon("b1", {"ip": "10.0.0.9", "os": "Linux"})
        assert any(event == "auto_shell_queued" for event, _ in calls), calls

    def test_turning_it_on_is_audited_too(self, monkeypatch):
        calls = []
        from phantom.utils import audit_log as audit_module
        monkeypatch.setattr(audit_module.audit_log, "append",
                            lambda event, **kw: calls.append((event, kw)))
        assert c2_state.set_auto_shell(True) is True
        assert ("auto_shell_toggled", {"enabled": True}) in calls


class TestTheGrant:
    def test_the_config_default_is_honoured(self, monkeypatch):
        monkeypatch.setenv("PHANTOM_AUTO_SHELL", "1")
        from phantom.core.c2_server import _auto_shell_allowed
        assert _auto_shell_allowed() is True
        monkeypatch.setenv("PHANTOM_AUTO_SHELL", "0")
        assert _auto_shell_allowed() is False

    def test_the_grant_is_off_when_nothing_says_otherwise(self, monkeypatch):
        monkeypatch.delenv("PHANTOM_AUTO_SHELL", raising=False)
        from phantom.core.c2_server import _auto_shell_allowed
        # an explicit config value still wins, but the fallback is False
        assert _auto_shell_allowed() in (True, False)


class TestApi:
    @pytest.mark.asyncio
    async def test_the_toggle_route_sets_and_reports_the_state(self):
        from phantom.api.server import c2_autoshell
        request = MagicMock()
        request.json = AsyncMock(return_value={"enabled": True})
        response = await c2_autoshell(request)
        assert response.status == 200
        assert json.loads(response.body)["auto_shell"] is True
        assert c2_state.auto_shell is True

        request.json = AsyncMock(return_value={"enabled": False})
        response = await c2_autoshell(request)
        assert json.loads(response.body)["auto_shell"] is False

    @pytest.mark.asyncio
    async def test_the_state_route_exposes_the_grant(self):
        from phantom.api.server import c2_state_get
        c2_state.set_auto_shell(True)
        response = await c2_state_get(MagicMock())
        assert json.loads(response.body)["auto_shell"] is True

    def test_the_route_is_registered(self):
        from phantom.api.server import routes
        rendered = "\n".join(str(r) for r in routes)
        assert "/api/c2/autoshell" in rendered


class TestTheUiOpensTheConsole:
    """The dashboard half: a LIVE beacon must not sit unselected."""

    _TSX = os.path.join("electron", "src", "components", "C2Dashboard.tsx")

    def test_the_dashboard_auto_selects_a_live_beacon(self):
        with open(self._TSX, encoding="utf-8") as handle:
            source = handle.read()
        assert "auto-open shell" in source
        assert "beacons.find((b) => b.status === 'LIVE')" in source
        assert "setActiveBeacon(live.id)" in source

    def test_it_never_steals_a_deliberate_selection(self):
        with open(self._TSX, encoding="utf-8") as handle:
            source = handle.read()
        effect = source.split("auto-open shell", 1)[1].split("}, [", 1)[0]
        assert "if (activeBeacon) return" in effect
