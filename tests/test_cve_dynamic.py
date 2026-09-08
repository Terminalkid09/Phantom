"""Tests for the dynamic CVE/exploit pipeline:

* registry product aliases (banner "Apache" -> canonical "apache")
* newly added curated modules match their affected ranges
* service_exploit falls back to live-NVD correlation + msf search discovery
* CVE_NOTE findings are knowledge-only (never weaponized)"""

import unittest
from unittest.mock import Mock, patch

from phantom.automation.belief import WorldModel
from phantom.automation.exploit.modules import build_registry
from phantom.automation.exploit.modules.registry import normalize_product
from phantom.automation.runtime import msf as msf_mod


class TestRegistryAliases(unittest.TestCase):

    def test_banner_product_aliases(self):
        self.assertEqual(normalize_product("Apache"), "apache")
        self.assertEqual(normalize_product("Apache httpd"), "apache")
        self.assertEqual(normalize_product("OpenSSH"), "openssh")
        self.assertEqual(normalize_product("GitLab"), "gitlab")
        self.assertEqual(normalize_product("Elasticsearch"), "elasticsearch")
        self.assertEqual(normalize_product("unknown_product"), "unknown_product")

    def test_curated_modules_match_via_alias(self):
        reg = build_registry()
        # banner reports "Apache 2.4.49" -> alias -> apache module
        m = reg.match("Apache", "2.4.49")
        self.assertIsNotNone(m)
        self.assertEqual(m.cve_id, "CVE-2021-41773")
        # GitLab 13.3 -> the curated gitlab module
        m = reg.match("GitLab", "13.3.2")
        self.assertIsNotNone(m)
        self.assertEqual(m.cve_id, "CVE-2021-22205")
        # out of range -> no match
        self.assertIsNone(reg.match("Apache", "2.4.55"))
        self.assertIsNone(reg.match("OpenSSH", "9.6"))


class TestDynamicWeaponization(unittest.TestCase):

    def _wm_with_service(self, product="Apache", version="2.4.49"):
        wm = WorldModel(target="10.0.0.5", target_type="ip")
        wm.add_finding("service", "tcp/80",
                       {"port": "80", "protocol": "tcp", "service": "http",
                        "product": product, "version": version},
                       confidence=0.9, source="scan")
        return wm

    def test_static_path_wins(self):
        from phantom.automation.guidance.kit import _service_exploit_adapter
        wm = self._wm_with_service()
        cmd = _service_exploit_adapter(wm, {})
        self.assertIn("apache_normalize_path_rce", cmd)
        self.assertIn("EXPLOIT: cve=CVE-2021-41773", cmd)

    @patch("phantom.automation.guidance.kit._dynamic_cve_hit",
           return_value=("CVE-2024-23897", "jenkins", "2.440", 9.8, "8080"))
    @patch("phantom.automation.runtime.msf.search_module_for_cve",
           return_value="exploit/multi/http/jenkins_script_console")
    def test_dynamic_path_discovers_module(self, _msf, _hit):
        from phantom.automation.guidance.kit import _service_exploit_adapter
        # no static module for jenkins banner -> dynamic tier
        wm = self._wm_with_service(product="jenkins", version="2.440")
        cmd = _service_exploit_adapter(wm, {})
        self.assertIn("jenkins_script_console", cmd)
        self.assertIn("EXPLOIT: cve=CVE-2024-23897", cmd)
        _msf.assert_called_once_with("CVE-2024-23897")

    @patch("phantom.automation.guidance.kit._dynamic_cve_hit",
           return_value=("CVE-2024-23897", "jenkins", "2.440", 9.8, "8080"))
    @patch("phantom.automation.runtime.msf.search_module_for_cve",
           return_value=None)
    def test_dynamic_path_without_module_emits_cve_note(self, _msf, _hit):
        from phantom.automation.guidance.kit import _service_exploit_adapter
        wm = self._wm_with_service(product="jenkins", version="2.440")
        cmd = _service_exploit_adapter(wm, {})
        self.assertIn("CVE_NOTE: cve=CVE-2024-23897", cmd)
        self.assertNotIn("msfconsole", cmd)

    def test_no_match_raises(self):
        from phantom.automation.guidance.kit import _service_exploit_adapter
        wm = self._wm_with_service(product="madeup", version="1.0")
        with patch("phantom.automation.guidance.kit._dynamic_cve_hit",
                   return_value=None):
            with self.assertRaises(ValueError):
                _service_exploit_adapter(wm, {})

    def test_cve_note_interp_is_knowledge_only(self):
        from phantom.automation.guidance.kit import _service_exploit_interp
        wm = WorldModel(target="10.0.0.5", target_type="ip")
        findings = _service_exploit_interp(
            "CVE_NOTE: cve=CVE-2024-23897 software=jenkins "
            "version=2.440 severity=9.8 port=8080", wm, {})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "exploit_plan")
        self.assertEqual(findings[0].value["kind"], "note")
        self.assertEqual(findings[0].value["msf_module"], "")


class TestMsfSearchParsing(unittest.TestCase):

    def test_parses_modules_preferring_exploit(self):
        fake_proc = Mock()
        fake_proc.wait = Mock()
        fake_proc.stdout = (
            "Matching Modules\n"
            "================\n\n"
            "   #  Name                                     Disclosure Date  Rank       Check  Description\n"
            "   -  ----                                     ---------------  ----       -----  -----------\n"
            "   0  auxiliary/gather/jenkins_read_file        2024-01-24       normal     No     Jenkins ...\n"
            "   1  exploit/multi/http/jenkins_script_console 2024-01-24       excellent  Yes    Jenkins ...\n"
        )
        with patch.object(msf_mod.tool_runner, "spawn",
                          return_value=fake_proc), \
             patch.object(msf_mod, "_require_tool", return_value="msfconsole"):
            mod = msf_mod.search_module_for_cve("CVE-2024-23897")
        self.assertEqual(mod, "exploit/multi/http/jenkins_script_console")

    def test_no_modules_returns_none(self):
        fake_proc = Mock()
        fake_proc.wait = Mock()
        fake_proc.stdout = "No results found\n"
        with patch.object(msf_mod.tool_runner, "spawn",
                          return_value=fake_proc), \
             patch.object(msf_mod, "_require_tool", return_value="msfconsole"):
            self.assertIsNone(msf_mod.search_module_for_cve("CVE-2024-99999"))

    def test_missing_msf_returns_none(self):
        from phantom.automation.runtime.toolrunner import ToolMissingError
        with patch.object(msf_mod, "_require_tool",
                          side_effect=ToolMissingError("nope")):
            self.assertIsNone(msf_mod.search_module_for_cve("CVE-2024-23897"))


if __name__ == "__main__":
    unittest.main()
