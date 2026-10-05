"""Runtime tool drivers — declarative manifests become live capabilities.

A driver is how a tool Phantom has never shipped becomes plannable without a
code change: its JSON template IS the synthesized adapter and its markers ARE
the interpreter. These tests pin validation, the manifest→capability build,
directory discovery (dedupe + malformed skip), the registry collision guard,
and the planner fallback that makes a discovered capability reachable.
"""
import json
import os
import tempfile
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.runtime import drivers as drv


_MINIMAL = {
    "id": "dnscan_subdomains",
    "tool": "dnscan",
    "category": "recon",
    "description": "Passive subdomain discovery",
    "effects": ["hostname"],
    "command": "dnscan -d {target} -o -",
    "requires": ["target"],
    "markers": [{"prefix": "DNSCAN:", "kind": "hostname",
                 "key": "hostname:{name}", "fields": ["name"]}],
}


class TestParse(unittest.TestCase):
    def test_minimal_manifest(self):
        d = drv.parse_driver(dict(_MINIMAL))
        self.assertIsNotNone(d)
        self.assertEqual(d.id, "dnscan_subdomains")
        self.assertEqual(d.tool, "dnscan")
        self.assertIn("hostname", d.effects)
        self.assertEqual(len(d.markers), 1)

    def test_rejects_missing_required_fields(self):
        for bad in ({"id": "x"}, {"id": "x", "tool": "y"},
                    {"id": "x", "tool": "y", "category": "bogus",
                     "command": "y {target}", "effects": ["f"]},
                    {"id": "x", "tool": "y", "category": "recon",
                     "command": "y", "effects": ["f"]}):   # no {field}
            self.assertIsNone(drv.parse_driver(bad), bad)

    def test_rejects_empty_effects(self):
        m = dict(_MINIMAL, effects=[])
        self.assertIsNone(drv.parse_driver(m))

    def test_rejects_binary_that_is_not_the_declared_tool(self):
        # command mode: the tool must appear as a token
        self.assertIsNone(drv.parse_driver(dict(_MINIMAL, command="evil {target}")))
        # argv mode: argv[0] must be the tool
        self.assertIsNone(drv.parse_driver(
            dict(_MINIMAL, command="", argv=["evil", "{target}"])))
        # but `sudo <tool>` / `wsl ... <tool>` still match in command mode
        self.assertIsNotNone(
            drv.parse_driver(dict(_MINIMAL, command="sudo dnscan {target}")))


class TestCapabilityBuild(unittest.TestCase):
    def _cap(self):
        return drv.driver_capability(drv.parse_driver(dict(_MINIMAL)))

    def test_marks_discovered(self):
        self.assertTrue(getattr(self._cap(), "discovered", False))

    def test_command_fills_target(self):
        wm = WorldModel(target="example.com", target_type="domain")
        cmd = self._cap().make_command(wm, {})
        self.assertEqual(cmd, "dnscan -d example.com -o -")

    def test_missing_field_is_a_clear_error(self):
        # the binary must still be the declared tool, so keep `dnscan` and
        # only the SLOT is unknown
        m = dict(_MINIMAL, command="dnscan {nonexistent} {target}")
        cap = drv.driver_capability(drv.parse_driver(m))
        wm = WorldModel(target="example.com")
        with self.assertRaises(ValueError):
            cap.make_command(wm, {})

    def test_argv_form_is_shell_quoted(self):
        import shlex
        m = dict(_MINIMAL, command="",
                 argv=["dnscan", "-d", "{target}", "-o", "-"])
        d = drv.parse_driver(m)
        self.assertIsNotNone(d)
        cap = drv.driver_capability(d)
        # a target with a space must survive as ONE argv token, not split
        wm = WorldModel(target="a b.example")
        self.assertEqual(shlex.split(cap.make_command(wm, {})),
                         ["dnscan", "-d", "a b.example", "-o", "-"])

    def test_interpreter_parses_markers(self):
        wm = WorldModel(target="example.com", target_type="domain")
        cap = self._cap()
        fs = cap.interpret("DNSCAN: name=www.example.com\n"
                           "DNSCAN: name=mail.example.com", wm, {})
        self.assertEqual(len(fs), 2)
        self.assertEqual(fs[0].kind, "hostname")
        self.assertEqual(fs[0].key, "hostname:www.example.com")
        self.assertEqual(fs[0].source, "dnscan_subdomains")

    def test_requires_target_maps_to_a_real_predicate(self):
        cap = self._cap()
        self.assertTrue(all(p(WorldModel(target="example.com"))
                            for p in cap.preconditions))
        self.assertFalse(cap.preconditions[0](WorldModel(target="")))


class TestDiscovery(unittest.TestCase):
    def _write(self, d, name, data):
        with open(os.path.join(d, name), "w", encoding="utf-8") as fh:
            json.dump(data, fh)

    def test_loads_valid_and_skips_malformed(self):
        with tempfile.TemporaryDirectory() as d:
            self._write(d, "a.json", {"driver": _MINIMAL})
            self._write(d, "b.json", {"id": "bad"})          # malformed
            with open(os.path.join(d, "c.json"), "w") as fh:
                fh.write("{ not json")                        # unreadable
            saved = drv.driver_dirs
            drv.driver_dirs = lambda: [d]
            try:
                found = drv.load_drivers()
            finally:
                drv.driver_dirs = saved
        self.assertEqual([x.id for x in found], ["dnscan_subdomains"])

    def test_first_directory_wins_on_duplicate_id(self):
        with tempfile.TemporaryDirectory() as d1, \
                tempfile.TemporaryDirectory() as d2:
            self._write(d1, "a.json", dict(_MINIMAL, description="first"))
            self._write(d2, "a.json", dict(_MINIMAL, description="second"))
            saved = drv.driver_dirs
            drv.driver_dirs = lambda: [d1, d2]
            try:
                found = drv.load_drivers()
            finally:
                drv.driver_dirs = saved
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].description, "first")

    def test_packaged_dir_present_by_default(self):
        # the default scan set exists even with no config/env
        self.assertIn(drv._PACKAGED_DIR, drv.driver_dirs())


class TestApprovalGate(unittest.TestCase):
    def test_found_driver_is_inert_until_approved(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "a.json"), "w", encoding="utf-8") as fh:
                json.dump(dict(_MINIMAL), fh)
            saved_dirs = drv.driver_dirs
            saved_approved = drv.approved_ids
            drv.driver_dirs = lambda: [d]
            drv.approved_ids = lambda: set()
            try:
                # found, but NOT plannable
                self.assertEqual(drv.load_driver_capabilities(), [])
                # and still surfaced as a candidate
                summary = drv.driver_summary()
                self.assertEqual([r["id"] for r in summary], ["dnscan_subdomains"])
                self.assertFalse(summary[0]["approved"])
                drv.approved_ids = lambda: {"dnscan_subdomains"}
                ids = [c.id for c in drv.load_driver_capabilities()]
            finally:
                drv.driver_dirs = saved_dirs
                drv.approved_ids = saved_approved
        self.assertEqual(ids, ["dnscan_subdomains"])


class TestRegistryWiring(unittest.TestCase):
    def test_collision_with_builtin_is_refused(self):
        # a driver whose id shadows a built-in must NOT replace it
        colliding = dict(_MINIMAL, id="scan_tcp", category="recon")
        cap = drv.driver_capability(drv.parse_driver(colliding))
        saved = drv.load_driver_capabilities
        drv.load_driver_capabilities = lambda: [cap]
        try:
            from phantom.automation.guidance.commands import make_registry
            reg = make_registry()
        finally:
            drv.load_driver_capabilities = saved
        builtin = reg.get("scan_tcp")
        self.assertIsNotNone(builtin)
        self.assertFalse(getattr(builtin, "discovered", False))

    def test_discovered_capability_is_registered(self):
        cap = drv.driver_capability(drv.parse_driver(dict(_MINIMAL)))
        saved = drv.load_driver_capabilities
        drv.load_driver_capabilities = lambda: [cap]
        try:
            from phantom.automation.guidance.commands import make_registry
            reg = make_registry()
        finally:
            drv.load_driver_capabilities = saved
        self.assertIsNotNone(reg.get("dnscan_subdomains"))


class TestPlannerFallback(unittest.TestCase):
    def test_discovered_source_is_reachable(self):
        from phantom.automation.guidance.commands import make_registry
        from phantom.automation.guidance.stealth import StealthEngine
        from phantom.automation.planner import Planner
        cap = drv.driver_capability(drv.parse_driver(dict(_MINIMAL)))
        saved = drv.load_driver_capabilities
        drv.load_driver_capabilities = lambda: [cap]
        try:
            reg = make_registry()
        finally:
            drv.load_driver_capabilities = saved
        wm = WorldModel(target="example.com", target_type="domain")
        planner = Planner(reg, StealthEngine(wm))
        # static sources for `hostname` exhausted -> fall to the driver
        picked = planner._pick_source("hostname", used={"external_recon"}, wm=wm)
        self.assertIsNotNone(picked)
        self.assertEqual(picked.id, "dnscan_subdomains")


if __name__ == "__main__":
    unittest.main()
