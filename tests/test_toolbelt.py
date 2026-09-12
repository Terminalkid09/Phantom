"""Tests for the brain.toolbelt multi-tool selection and the unified
scan-output parsing (nmap / nc -zv floor sweep / masscan)."""
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.brain.toolbelt import Toolbelt, ToolChoice
from phantom.automation.perception import parse_nmap_ports
from phantom.automation.runtime.toolchain import ToolRegistry


class TestToolbelt(unittest.TestCase):
    def test_prefers_ranked_best(self):
        # default style: masscan is speed/aggressive-only, so nmap wins
        tb = Toolbelt(ToolRegistry(installed={"nmap", "masscan", "nc"}))
        self.assertEqual(tb.pick("scan_tcp").tool, "nmap")

    def test_style_filters_pool(self):
        tb = Toolbelt(ToolRegistry(installed={"nmap", "masscan", "nc"}))
        self.assertEqual(tb.pick("scan_tcp", style="stealth").tool, "nmap")
        self.assertEqual(tb.pick("scan_tcp", style="speed").tool, "masscan")

    def test_missing_records_alternatives(self):
        tb = Toolbelt(ToolRegistry(installed={"nmap"}))
        ch = tb.pick("smb_enum")
        self.assertEqual(ch.tool, "nmap")           # nmap fallback option
        self.assertEqual(ch.alternatives_missing, ["smbmap", "enum4linux"])

    def test_bare_box_scan_has_no_tool(self):
        tb = Toolbelt(ToolRegistry(installed=set()))
        ch = tb.pick("scan_tcp")
        self.assertIsNone(ch.tool)
        self.assertFalse(ch.ok)
        self.assertIn("nmap", ch.reason)

    def test_internal_engine_needs_no_binary(self):
        tb = Toolbelt(ToolRegistry(installed=set()))
        self.assertEqual(tb.pick("ssh_banner").tool, "__internal__")

    def test_status_covers_catalog(self):
        tb = Toolbelt(ToolRegistry(installed={"nmap"}))
        st = tb.status()
        self.assertIn("scan_tcp", st)
        self.assertIn("ssh_banner", st)
        self.assertTrue(all(isinstance(v, ToolChoice) for v in st.values()))

    def test_cache_and_invalidate(self):
        tb = Toolbelt(ToolRegistry(installed={"nmap"}))
        a = tb.pick("scan_tcp")
        b = tb.pick("scan_tcp")
        self.assertIs(a, b)          # cached instance
        tb.invalidate()
        c = tb.pick("scan_tcp")
        self.assertIsNot(a, c)
        self.assertEqual(c.tool, a.tool)


class TestAdaptersUseChosenTool(unittest.TestCase):
    def _wm(self):
        return WorldModel(target="10.0.0.9")

    def test_masscan_command(self):
        from phantom.automation.guidance.kit import _port_scan_adapter
        wm = self._wm()
        wm.chosen_tool = {"capability": "scan_tcp", "tool": "masscan"}
        cmd = _port_scan_adapter(wm, {})
        self.assertTrue(cmd.startswith("masscan 10.0.0.9"))
        self.assertIn("--rate", cmd)

    def test_nc_floor_command_is_allowlist_safe(self):
        from phantom.automation.guidance.kit import _port_scan_adapter
        wm = self._wm()
        wm.chosen_tool = {"capability": "scan_tcp", "tool": "nc"}
        cmd = _port_scan_adapter(wm, {})
        self.assertTrue(cmd.startswith("nc -zv"))
        self.assertNotIn("bash -c", cmd)   # API allowlist compatibility

    def test_legacy_default_without_stamp(self):
        from phantom.automation.guidance.kit import _port_scan_adapter
        cmd = _port_scan_adapter(self._wm(), {})
        self.assertTrue(cmd.startswith("nmap -Pn -sT"))

    def test_smb_enum_nmap_fallback(self):
        from phantom.automation.guidance.kit import _smb_enum_adapter
        wm = self._wm()
        wm.chosen_tool = {"capability": "smb_enum", "tool": "nmap"}
        cmd = _smb_enum_adapter(wm, {})
        self.assertIn("smb-enum-shares", cmd)

    def test_ssh_banner_internal_markers(self):
        from phantom.automation.guidance.kit import _ssh_banner_adapter
        wm = self._wm()
        wm.chosen_tool = {"capability": "ssh_banner", "tool": "__internal__"}
        out = _ssh_banner_adapter(wm, {"port": "1"})   # nothing listens on 1
        self.assertTrue(out.startswith("#") or out.startswith("FINGERPRINT:"))

    def test_http_probe_httpx_command(self):
        from phantom.automation.guidance.kit import _http_probe_adapter
        wm = self._wm()
        wm.chosen_tool = {"capability": "http_probe", "tool": "httpx"}
        cmd = _http_probe_adapter(wm, {})
        self.assertTrue(cmd.startswith("httpx"))
        self.assertIn("-silent", cmd)

    def test_http_probe_curl_default(self):
        from phantom.automation.guidance.kit import _http_probe_adapter
        cmd = _http_probe_adapter(self._wm(), {})
        self.assertTrue(cmd.startswith("curl -s -I"))

    def test_http_get_wget_command(self):
        from phantom.automation.guidance.kit import _http_get_adapter
        wm = self._wm()
        wm.chosen_tool = {"capability": "http_get", "tool": "wget"}
        cmd = _http_get_adapter(wm, {})
        self.assertTrue(cmd.startswith("wget -q"))

    def test_redis_info_nc_floor(self):
        from phantom.automation.guidance.kit import _redis_info_adapter
        wm = self._wm()
        wm.chosen_tool = {"capability": "redis_info", "tool": "nc"}
        cmd = _redis_info_adapter(wm, {})
        self.assertIn("printf 'INFO", cmd)
        self.assertIn("nc -w 5", cmd)

    def test_toolbelt_catalog_covers_new_adapters(self):
        from phantom.automation.brain.toolbelt import _TOOL_CATALOG
        self.assertIn("http_get", _TOOL_CATALOG)
        self.assertIn("redis_info", _TOOL_CATALOG)
        self.assertIn("wget", {o.name for o in _TOOL_CATALOG["http_get"]})


class TestUnifiedScanParsing(unittest.TestCase):
    def test_nc_floor_output_parses(self):
        out = ("Connection to 10.0.0.9 22 port [tcp/ssh] succeeded!\n"
               "Connection to 10.0.0.9 80 port [tcp/http] succeeded!\n"
               "Connection to 10.0.0.9 445 port [tcp/microsoft-ds] succeeded!")
        f = parse_nmap_ports(out, "nc")
        keys = {x["key"] for x in f}
        self.assertEqual(keys, {"tcp/22", "tcp/80", "tcp/445"})

    def test_masscan_output_parses(self):
        out = ("Discovered open port 80/tcp on 10.0.0.9\n"
               "Discovered open port 3306/tcp on 10.0.0.9")
        f = parse_nmap_ports(out, "masscan")
        services = {x["value"].get("service") for x in f}
        self.assertEqual({x["key"] for x in f}, {"tcp/80", "tcp/3306"})
        self.assertIn("http", services)
        self.assertIn("mysql", services)

    def test_nmap_still_primary(self):
        out = "22/tcp   open  ssh     OpenSSH 8.9p1"
        f = parse_nmap_ports(out, "nmap")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["value"]["service"], "ssh")
        self.assertEqual(f[0]["value"]["version"], "OpenSSH 8.9p1")

    def test_no_false_positives_from_refused(self):
        out = "connect to 10.0.0.9 22 port 22 tcp: Connection refused"
        self.assertEqual(parse_nmap_ports(out, "nc"), [])


# ---------------------------------------------------------------------------
# brute_ssh: multi-tool cracker (hydra > medusa) + capability wiring
# ---------------------------------------------------------------------------


class TestBruteSshMultiTool(unittest.TestCase):
    """The aggressive-only online brute picks the best installed cracker."""

    def _pick(self, installed):
        from phantom.automation.brain.toolbelt import Toolbelt, ToolRegistry
        tb = Toolbelt.__new__(Toolbelt)
        tb._reg = ToolRegistry
        return tb

    def test_registry_has_brute_ssh(self):
        from phantom.automation.brain.toolbelt import _TOOL_CATALOG
        self.assertIn("brute_ssh", _TOOL_CATALOG)
        tools = [o.name for o in _TOOL_CATALOG["brute_ssh"]]
        self.assertIn("hydra", tools)
        self.assertIn("medusa", tools)
        # hydra ranked better (lower rank = preferred)
        self.assertEqual(_TOOL_CATALOG["brute_ssh"][0].name, "hydra")

    def test_capability_registered_and_gated(self):
        from phantom.automation.guidance.kit import CAPABILITIES
        cap = {c.id: c for c in CAPABILITIES}["brute_ssh"]
        self.assertEqual(cap.category, "brute")
        self.assertTrue(cap.forceful)
        self.assertIn("creds", cap.effects)
        self.assertIn("hydra", cap.tools)

    def test_adapter_emits_chosen_tool(self):
        from phantom.automation.guidance.kit import _brute_ssh_adapter
        from phantom.automation.belief import WorldModel
        wm = WorldModel("10.0.0.9")
        wm.add_finding(kind="service", key="tcp/22",
                       value={"port": 22, "service": "ssh"}, source="t")
        wm.chosen_tool = {"capability": "brute_ssh", "tool": "hydra"}
        cmd = _brute_ssh_adapter(wm, {})
        self.assertTrue(cmd.startswith("hydra"))
        self.assertIn("-f", cmd)  # stop on first hit
        wm.chosen_tool = {"capability": "brute_ssh", "tool": "medusa"}
        cmd2 = _brute_ssh_adapter(wm, {})
        self.assertTrue(cmd2.startswith("medusa"))

    def test_interpreter_hydra_and_medusa(self):
        from phantom.automation.guidance.kit import _brute_ssh_interp
        from phantom.automation.belief import WorldModel
        wm = WorldModel("10.0.0.9")
        wm.add_finding(kind="service", key="tcp/22",
                       value={"port": 22, "service": "ssh"}, source="t")
        fs = _brute_ssh_interp(
            "[22][ssh] host: 10.0.0.9   login: root   password: toor", wm, {})
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0].kind, "creds")
        self.assertEqual(fs[0].value["username"], "root")
        fs2 = _brute_ssh_interp(
            "ACCOUNT CHECK: [ssh] Host: 10.0.0.9 User: admin "
            "Password: admin [SUCCESS]", wm, {})
        self.assertEqual(len(fs2), 1)
        self.assertEqual(fs2[0].value["password"], "admin")
        self.assertEqual(_brute_ssh_interp("hydra: no hits", wm, {}), [])

    def test_agent_gates_brute_outside_aggressive(self):
        """Category 'brute' capabilities are hard-gated behind --aggressive."""
        import inspect
        from phantom.automation import agent as agent_mod
        src = inspect.getsource(agent_mod.AutonomousAgent)
        self.assertIn('cap.category == "brute"', src)
        self.assertIn("online_brute_allowed", src)


if __name__ == "__main__":
    unittest.main()
