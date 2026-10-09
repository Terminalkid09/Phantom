"""G2 — persistence must have a supported way back out.

The beacon could install persistence (`persist` / `autopersist`) but had no
command that removed it, while the report told the client to clean up the
IOCs. `unpersist` must reuse the IDENTICAL paths `persist` wrote, so the
client's cleanup removes the framework's artifacts and nothing else.

G3 — the anti-analysis refusal must not be silent.

`beacon_main` used to `stalling_delay(50); return;` when it detected a
debugger or a VM: the operator saw "no check-in", indistinguishable from a
failed exploit. The gate now emits a best-effort abort event naming the
reason, so the C2 timeline says WHY the beacon never started.
"""
import os
import re
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SRC = os.path.join(_ROOT, "phantom", "payloads", "beacon", "src")


def _read(name: str) -> str:
    with open(os.path.join(_SRC, name), encoding="utf-8") as fh:
        return fh.read()


def _fn_body(src: str, signature: str) -> str:
    """The brace-matched body of a function whose definition starts at
    `signature`. Returns the text between the outermost braces."""
    start = src.index(signature)
    brace = src.index("{", start)
    depth = 0
    for j in range(brace, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[brace:j + 1]
    raise AssertionError(f"unterminated body for {signature!r}")


class TestUnpersistContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = _read("main.cpp")
        cls.persist = _read("persistence.h")

    def test_the_verb_is_in_the_python_allow_list(self):
        from phantom.core.task_policy import BEACON_VERBS
        self.assertIn("unpersist", BEACON_VERBS)

    def test_the_beacon_dispatches_the_verb(self):
        # Same dispatch form the verb-contract test parses.
        self.assertRegex(
            self.main,
            r'action\s*==\s*XOR_DEC\(XOR_STR\("unpersist"\)\)')

    def test_removal_functions_exist_for_both_platforms(self):
        self.assertIn("remove_windows(", self.persist)
        self.assertIn("remove_posix(", self.persist)

    def test_windows_removal_uses_the_same_paths_as_establish(self):
        est = _fn_body(self.persist, "inline std::string establish_windows(")
        rem = _fn_body(self.persist, "inline std::string remove_windows(")
        # the Run key location both write/delete
        run_key = 'Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run'
        self.assertIn(run_key, est)
        self.assertIn(run_key, rem)
        # the on-disk directory
        self.assertIn('"\\\\Microsoft\\\\Phantom"', est)
        self.assertIn('"\\\\Microsoft\\\\Phantom"', rem)

    def test_posix_removal_uses_the_same_paths_as_establish(self):
        est = self.persist
        rem = _fn_body(self.persist, "inline std::string remove_posix(")
        for needle in (".config/systemd/user/", ".config/autostart/",
                       "/Library/LaunchAgents/com.", ".local/bin/"):
            self.assertIn(needle, est, f"establish no longer uses {needle}")
            self.assertIn(needle, rem, f"removal does not clean {needle}")

    def test_windows_removal_drops_the_runkey_value_and_on_disk_copy(self):
        rem = _fn_body(self.persist, "inline std::string remove_windows(")
        self.assertIn("RegDeleteValueA", rem)
        self.assertIn("DeleteFileA", rem)

    def test_posix_removal_does_not_delete_unrelated_cron_jobs(self):
        rem = _fn_body(self.persist, "inline std::string remove_posix(")
        # filter by the installed path, not by a blanket crontab -r
        self.assertIn("grep -v -F", rem)
        self.assertNotIn("crontab -r", rem)

    def test_help_registers_a_reachable_handler(self):
        from phantom.core.c2_help import BY_NAME
        from phantom.core.c2_shell import C2Shell
        self.assertIn("unpersist", BY_NAME)
        spec = BY_NAME["unpersist"]
        self.assertTrue(hasattr(C2Shell(), f"do_{spec.handler}"))


class TestStartupAbortIsNotSilent(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.main = _read("main.cpp")

    def test_no_silent_isvm_exit(self):
        self.assertNotRegex(
            self.main,
            r"if\s*\(anti::is_debugger_present\(\)\s*\|\|\s*anti::is_vm\(\)\)"
            r"\s*\{\s*anti::stalling_delay\(50\);\s*return;\s*\}")

    def test_abort_gate_emits_an_event_with_a_reason(self):
        self.assertIn("BEACON_ABORT: ", self.main)
        self.assertIn("abort_reason", self.main)
        # the reason must distinguish the two detections
        self.assertIn('"debugger present"', self.main)
        self.assertIn('"virtualised/sandbox environment"', self.main)
        # and it must be an actual event on the wire, not a printf
        self.assertRegex(
            self.main,
            r"net::send_result\(cfg,\s*XOR_DEC\(XOR_STR\(\"beacon-startup\"\)\)")

    def test_abort_gate_runs_after_the_config_exists(self):
        # the gate must sit after cfg is populated, otherwise it cannot send
        gate = self.main.index("BEACON_ABORT: ")
        cfg_created = self.main.index("auto cfg_owner")
        self.assertGreater(gate, cfg_created)
        # still refuses to enter the task loop
        self.assertIn("the beacon refused to start", self.main)

    def test_abort_registers_with_the_c2_before_it_reports(self):
        # handle_result() answers 404 for a result from a beacon the C2 has
        # NOT seen check in yet, and this gate runs BEFORE the loop's first
        # check-in — so without the registration ping the abort report is
        # refused and the operator is back to the silence this fix removes.
        send = self.main.index(
            'net::send_result(cfg, XOR_DEC(XOR_STR("beacon-startup"))')
        stall = self.main.rindex("anti::stalling_delay(50)", 0, send)
        checkin = self.main.rindex("net::checkin(cfg)", 0, send)
        self.assertLess(stall, checkin,
                        "the abort gate must ping the C2 before reporting")
        self.assertLess(checkin, send,
                        "the registration ping must precede the abort report")


class TestAbortResultNeedsRegistration(unittest.TestCase):
    """The registration ping is load-bearing, not decoration.

    Drives the REAL ``handle_result`` handler: a result from a beacon the C2
    has not seen check in is refused (404), so the ping the gate now sends is
    what makes the abort event visible on the operator's C2 timeline. If the
    server ever stops dropping unknown-beacon results, this test says so.
    """

    def _post(self, beacon_id, registered):
        import asyncio
        import json
        from unittest.mock import patch
        from aiohttp import web
        from aiohttp.test_utils import TestClient, TestServer
        from phantom.utils.c2_crypto import encrypt_for_beacon
        from phantom.core import c2_server as mod

        async def run():
            app = web.Application()
            app.router.add_post("/api/v1/result", mod.handle_result)
            body = encrypt_for_beacon(json.dumps({
                "task_id": "beacon-startup",
                "output": "BEACON_ABORT: virtualised/sandbox environment"}),
                beacon_id)
            with patch.object(mod.c2_state, "authenticate_beacon",
                              return_value=True):
                async with TestClient(TestServer(app)) as client:
                    if registered:
                        mod.c2_state.update_beacon(beacon_id,
                                                   {"ip": "127.0.0.1"})
                    resp = await client.post(
                        "/api/v1/result", data=body,
                        headers={"X-Beacon-Id": beacon_id})
                    return resp.status

        return asyncio.run(run())

    def test_a_result_from_an_unregistered_beacon_is_refused(self):
        self.assertEqual(
            self._post("ABORT-PROBE-UNREGISTERED", registered=False), 404)

    def test_the_abort_result_lands_once_the_beacon_has_checked_in(self):
        self.assertEqual(
            self._post("ABORT-PROBE-REGISTERED", registered=True), 200)


if __name__ == "__main__":
    unittest.main()
