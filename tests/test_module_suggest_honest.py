"""Tests: honest suggestions (UI-1/UI-2).

Every suggestion the backend lists carries the REAL execution verdict
(same gate module_run enforces): CLI-only pseudo-commands are flagged,
not silently 403'd at click time. run-group skips them per-command
instead of aborting the batch.
"""
import unittest

from phantom.core import session as session_mod


def _with_target(target="10.0.0.5"):
    """Module suggestions are state-aware: they need a target, like the UI."""
    session_mod.session.target = target


class TestRunnableFlags(unittest.TestCase):
    def test_pseudo_commands_flagged_not_runnable(self):
        from phantom.api.server import _module_group_status, _module_instance
        found_cli_only = []
        for name in ("exploit", "payload", "brute"):
            inst = _module_instance(name)
            groups = _module_group_status(name, inst, "suggest_commands")
            groups.update(_module_group_status(name, inst, "build_commands"))
            for _group, items in groups.items():
                for it in items:
                    self.assertIn("command", it)
                    self.assertIn("runnable", it)
                    self.assertIn("reason", it)
                    if not it["runnable"]:
                        found_cli_only.append(it["command"])
        # the catalogue is known to advertise CLI-only verbs: at least
        # one must be flagged (otherwise the flag is vacuous)
        self.assertTrue(found_cli_only,
                        "no CLI-only suggestion flagged anywhere")

    def test_real_tool_commands_runnable(self):
        _with_target()
        try:
            from phantom.api.server import _module_group_status, _module_instance
            inst = _module_instance("scan")
            groups = _module_group_status(inst and "scan", inst,
                                          "suggest_commands")
            runnable = [it["command"] for items in groups.values()
                        for it in items if it["runnable"]]
            # nmap-family suggestions exist and pass the gate on any box
            # (the gate checks the allowlist, not installation; some
            # are sudo-prefixed)
            self.assertTrue(any("nmap" in cmd for cmd in runnable),
                            [it for items in groups.values() for it in items])
        finally:
            session_mod.session.target = ""

    def test_module_detail_shape(self):
        import asyncio
        from phantom.api.server import module_detail
        _with_target()

        class _Req:
            match_info = {"module_name": "scan"}

        async def scenario():
            try:
                resp = await module_detail(_Req())
                self.assertEqual(resp.status, 200)
                import json
                data = json.loads(resp.text)
                self.assertIn("target", data)
                self.assertEqual(data["target"], "10.0.0.5")
                first = next(iter(data["suggestions"].values()))[0]
                self.assertIn("runnable", first)
            finally:
                session_mod.session.target = ""

        asyncio.run(scenario())


class TestRunGroupSkip(unittest.TestCase):
    def test_group_skips_cli_only_per_command(self):
        import asyncio
        from phantom.api.server import module_run_group

        class _Req:
            match_info = {"module_name": "scan"}

            async def json(self):
                # curl exists on every box (the gate checks the
                # allowlist, installation is a runtime concern), the
                # other two are CLI-only / unknown verbs -> skipped
                return {"commands": ["curl -sI http://127.0.0.1 "
                                     "--max-time 2",
                                     "run scan", "fire CVE-2021-1"],
                        "target": "10.0.0.5", "timeout": 30}

        async def scenario():
            # scope must cover the target or the backend refuses
            # everything with a fatal (-1) break before the gate runs
            session_mod.session.scope = ["10.0.0.0/8"]
            try:
                resp = await module_run_group(_Req())
                self.assertEqual(resp.status, 200)
                import json
                return json.loads(resp.text)
            finally:
                session_mod.session.scope = []

        data = asyncio.run(scenario())
        self.assertEqual(data["total"], 3)
        skipped = [r for r in data["results"] if r["returncode"] is None]
        self.assertEqual(len(skipped), 2)
        self.assertTrue(all(r["error"].startswith("skipped:")
                            for r in skipped))
        self.assertEqual(data.get("skipped"), 2)
        # the runnable one really executed (attempted, whatever nmap says)
        ran = [r for r in data["results"] if r["returncode"] is not None]
        self.assertEqual(len(ran), 1)


if __name__ == "__main__":
    unittest.main()
