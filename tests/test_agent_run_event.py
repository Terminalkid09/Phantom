"""Tests for the enriched auto-mode live stream: every `run` event now
carries the REAL command, the planner's WHY and the stealth badge, so the
CLI and Electron render the action instead of just its name."""
import unittest
from unittest.mock import patch, MagicMock

from phantom.automation import agent as agent_mod


def _step(cap_id="scan_tcp", reason="port 80 open -> fingerprint web"):
    cap = MagicMock()
    cap.id = cap_id
    cap.banner = "port scan"
    cap.category = "scan"
    cap.opsec_cost = 1.0
    cap.stealth_level = "active"
    cap.detection_risk = 0.3
    cap.preconditions = []
    cap.tools = []
    step = MagicMock()
    step.capability = cap
    step.slot_values = {}
    step.reason = reason
    return step


class TestRunEventEnriched(unittest.TestCase):
    def _agent(self, capsys=None):
        ag = agent_mod.AutonomousAgent.__new__(agent_mod.AutonomousAgent)
        ag.wm = MagicMock()
        ag.wm.find.return_value = []
        ag.wm.has_any.return_value = False
        ag.wm.record_failure = MagicMock()
        ag.wm.record_noise = MagicMock()
        ag.target = "10.0.0.5"
        ag.target_type = "ip"
        ag.scope_list = []
        ag.sink = MagicMock()
        ag.sink.emit = MagicMock()
        ag._on_event = None
        ag._mark_failed = MagicMock()
        ag._account_noise = MagicMock()
        ag.aggressive = False
        ag.stealth_engine = MagicMock()
        ag.stealth_engine.online_brute_allowed.return_value = False
        ag.toolchain = MagicMock()
        ag.toolchain.missing.return_value = []
        ag._autofill_slots = MagicMock(side_effect=lambda c, s: s)
        ag._dyn = MagicMock()
        ag._dyn.shape = MagicMock(side_effect=lambda c, wm: c)
        ag._preflight = MagicMock()
        ag._preflight.return_value = MagicMock(approved=True)
        ag._ad_checked = True
        ag.hunt_delay = None
        ag.runtime = MagicMock()
        ag.runtime.run.return_value = MagicMock(
            success=True, output="80/open", findings=[])
        ag.wm.add_finding = MagicMock()
        ag.session_wm = MagicMock()
        ag._fallback = MagicMock()
        ag._fallback.record = MagicMock()
        return ag

    def test_run_emits_real_command_and_reason(self):
        ag = self._agent()
        cap = MagicMock()
        cap.id = "scan_tcp"
        cap.category = "scan"
        cap.opsec_cost = 1.0
        cap.stealth_level = "active"
        cap.detection_risk = 0.3
        cap.tools = []
        cap.preconditions = []
        cap.make_command = MagicMock(
            return_value="nmap -sV -sC -p- 10.0.0.5")
        step = _step()
        step.capability = cap
        with patch.object(ag, "_scope_ok", return_value=True):
            ag._execute_capability(step)
        first = ag.sink.emit.call_args_list[0]
        self.assertEqual(first.args[0], "run")
        kw = first.kwargs
        self.assertEqual(kw["command"], "nmap -sV -sC -p- 10.0.0.5")
        self.assertEqual(kw["reason"], "port 80 open -> fingerprint web")
        self.assertEqual(kw["stealth_level"], "active")
        self.assertEqual(kw["detection_risk"], 0.3)


if __name__ == "__main__":
    unittest.main()