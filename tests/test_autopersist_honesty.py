"""`autopersist` must queue an artifact the supported undo can remove —
and name a persistence method only when the beacon reported an OS.

LIVE DEFECT 2026-10-17 (A6 live session, this host). Two problems walked in
together on the auto-persist path:

1. `C2Shell.do_autopersist` queued `persist {method}` (`persist systemd` /
   `persist runkey`). The beacon's `persist` argument is the ARTIFACT NAME,
   not the method (default `PhantomBeacon`; see main.cpp), so the automated
   path installed a unit / Run value literally named "systemd"/"runkey".
   The C2 server's own auto-persist comment already warned about this exact
   mis-naming — the shell task had not gotten the memo. Worse, the mis-named
   artifact broke the G2 round-trip contract: bare `unpersist` removes the
   default name and could never remove what `autopersist` wrote.

2. For a beacon that never reported an OS (empty `os` — any check-in whose
   telemetry has no `OS:` line, e.g. the transport harness used in the same
   session), both `do_autopersist` and `C2Server.update_beacon` claimed
   `systemd`. The server-side queued command was bare `persist` (safe: the
   beacon resolves its own platform), but the operator log and the
   immutable audit chain recorded a method the data did not support.
"""
import os
import re
import unittest
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SRC = os.path.join(_ROOT, "phantom", "payloads", "beacon", "src")


class TestShellQueuesTheUndoableName(unittest.TestCase):

    def _run(self, os_str):
        from phantom.core.c2_shell import C2Shell
        shell = C2Shell()
        shell.active_beacon = "B-AUTO"
        state = mock.MagicMock()
        state.get_beacons.return_value = {"B-AUTO": {"os": os_str}}
        state.queue_task.return_value = "task-1"
        with mock.patch("phantom.core.c2_shell.c2_state", state), \
             mock.patch("phantom.core.c2_shell.notifier") as nt:
            shell.do_autopersist("")
        return state, nt

    def test_windows_beacon_queues_bare_persist(self):
        state, nt = self._run("Windows 11 Pro 22631")
        state.queue_task.assert_called_once_with("B-AUTO", "persist")
        texts = " ".join(str(c) for c in nt.info.call_args_list)
        self.assertIn("runkey", texts)

    def test_linux_beacon_queues_bare_persist(self):
        state, nt = self._run("Linux 6.8.0-31-generic")
        state.queue_task.assert_called_once_with("B-AUTO", "persist")
        texts = " ".join(str(c) for c in nt.info.call_args_list)
        self.assertIn("systemd", texts)

    def test_unknown_os_queues_bare_persist_and_claims_no_method(self):
        state, nt = self._run("")
        state.queue_task.assert_called_once_with("B-AUTO", "persist")
        texts = " ".join(str(c) for c in nt.info.call_args_list)
        self.assertNotIn("systemd", texts,
                         "no OS was reported — systemd is a guess, not a fact")
        self.assertNotIn("runkey", texts)
        self.assertIn("native default", texts)


class TestServerAuditNamesTheMethodHonestly(unittest.TestCase):

    def _update(self, beacon_id, info):
        from phantom.core.c2_server import c2_state
        from phantom.utils.audit_log import audit_log
        c2_state.update_beacon(beacon_id, info)
        cmds = [t["command"] for t in c2_state.tasks.get(beacon_id, [])]
        method = None
        for event in audit_log.tail(300):
            if (event.get("event") == "auto_persist_queued"
                    and event.get("beacon_id") == beacon_id):
                method = event.get("method")
        c2_state.beacons.pop(beacon_id, None)
        c2_state.tasks.pop(beacon_id, None)
        c2_state.results.pop(beacon_id, None)
        return cmds, method

    def test_unknown_os_is_recorded_as_unknown_not_systemd(self):
        cmds, method = self._update("B-AUTO-UNK", {"ip": "10.9.0.1"})
        self.assertIn("persist", cmds)
        self.assertEqual(method, "unknown")

    def test_windows_os_is_recorded_as_runkey(self):
        cmds, method = self._update("B-AUTO-WIN",
                                    {"ip": "10.9.0.2", "os": "Windows 11"})
        self.assertIn("persist", cmds)
        self.assertEqual(method, "runkey")

    def test_linux_os_is_recorded_as_systemd(self):
        cmds, method = self._update("B-AUTO-NIX",
                                    {"ip": "10.9.0.3", "os": "Linux 6.8"})
        self.assertIn("persist", cmds)
        self.assertEqual(method, "systemd")


class TestTheBeaconArgumentIsAnArtifactName(unittest.TestCase):
    """Static contract behind the fix: `persist`/`unpersist` default the
    name to PhantomBeacon, which is what makes bare `persist` the only form
    that round-trips with bare `unpersist`."""

    @classmethod
    def setUpClass(cls):
        with open(os.path.join(_SRC, "main.cpp"), encoding="utf-8") as fh:
            cls.main = fh.read()

    def test_persist_and_unpersist_share_the_default_name(self):
        self.assertRegex(
            self.main,
            r'action\s*==\s*XOR_DEC\(XOR_STR\("persist"\)\)')
        self.assertRegex(
            self.main,
            r'action\s*==\s*XOR_DEC\(XOR_STR\("unpersist"\)\)')
        defaults = re.findall(
            r'name\s*=\s*XOR_DEC\(XOR_STR\("PhantomBeacon"\)\)', self.main)
        self.assertGreaterEqual(
            len(defaults), 2,
            "both persist and unpersist must default to the same artifact name")


if __name__ == "__main__":
    unittest.main()
