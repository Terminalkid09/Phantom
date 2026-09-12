"""Tests: dynamic manual-module UX (state-aware suggestions)."""
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from phantom.core.session import session
from phantom.core.preview import PreviewSession
from phantom.modules.base_module import BaseModule
from phantom.modules.scan import ScanModule
from phantom.modules.exploit import ExploitModule
from phantom.modules import suggest


def _reset(target="10.0.0.1"):
    session.target = target
    session.scope = []
    session.results = {}
    session.notes = []
    session.history = []
    session.mode = "recon"
    session.knowledge_base["os_info"] = {}
    session.knowledge_base["target_type"] = None
    from phantom.automation.exploit.resolver import get_resolver
    from phantom.automation.exploit.hunter import get_lag
    get_resolver().clear()
    get_lag().clear()


class TestBaseModuleSuggest:

    def test_default_suggestions_empty_without_target(self):
        _reset(target="")
        assert BaseModule().suggest_commands() == {}

    def test_default_suggestions_empty(self):
        _reset(target="10.0.0.1")
        assert BaseModule().suggest_commands() == {}

    def test_scan_proposes_first_steps_with_target(self):
        _reset(target="10.0.0.1")
        groups = ScanModule().suggest_commands()
        assert "SUGGESTED (First Steps)" in groups
        assert any("nmap" in c for c in groups["SUGGESTED (First Steps)"])

    def test_scan_follow_up_without_probes_when_services_known(self):
        _reset(target="10.0.0.1")
        session.add_result("scan", {
            "cmd": "22/tcp open  ssh     OpenSSH 7.9\n"
                   "80/tcp open  http    Apache httpd 2.4.49\n",
        })
        groups = ScanModule().suggest_commands()
        assert "SUGGESTED (Follow-up)" in groups
        blob = " ".join(sum(groups.values(), []))
        assert "-p 22,80" in blob
        assert "probe:" not in blob
        assert "grep -m1 -q" not in blob
        assert "VULN-" not in blob

    def test_probe_group_exploit_phase_only(self):
        _reset(target="10.0.0.1")
        session.add_result("scan", {
            "cmd": "80/tcp open  http    Apache httpd 2.4.49\n",
        })
        groups = suggest.exploit_suggestion_group()
        assert "SUGGESTED (probe:CVE-2021-41773)" in groups
        cmd = groups["SUGGESTED (probe:CVE-2021-41773)"][0]
        assert cmd.startswith("curl -sk --max-time 10")
        assert "/cgi-bin/" in cmd
        assert "grep -m1 -q" in cmd
        assert "VULN-CVE-2021-41773" in cmd
        assert "-o " not in cmd.replace("-o /dev/null", "")

    def test_probe_tls_heartbeat(self):
        _reset(target="10.0.0.1")
        session.add_result("scan", {
            "cmd": "443/tcp open  ssl/http  OpenSSL 1.0.1f\n",
        })
        groups = suggest.exploit_suggestion_group()
        assert "SUGGESTED (probe:CVE-2014-0160)" in groups
        cmd = groups["SUGGESTED (probe:CVE-2014-0160)"][0]
        assert cmd.startswith("openssl s_client -connect 10.0.0.1:443")
        assert "heartbeat (id=15)" in cmd

    def test_no_probe_without_version(self):
        _reset(target="10.0.0.1")
        session.add_result("scan", {"cmd": "80/tcp open  http\n"})
        assert suggest.probe_suggestion_group() == {}

    def test_rate_limits_on_noisy_commands(self):
        _reset(target="10.0.0.1")
        session.add_result("scan", {
            "cmd": "22/tcp open  ssh   OpenSSH 7.9\n"
                   "80/tcp open  http  Apache httpd 2.4.49\n",
        })
        brute = suggest.brute_suggestion_group()
        assert any("-W 3" in c for c in brute["SUGGESTED (brute:ssh)"])
        web = suggest.web_suggestion_group()
        assert any("-Delay 2" in c for c in web["SUGGESTED (web:80)"])
        from phantom.modules.web import WebModule
        cmds = " ".join(sum(WebModule().build_commands().values(), []))
        assert "--delay 2" in cmds and "--threads 1" in cmds

    def test_creds_reuse_group_ssh(self):
        _reset(target="10.0.0.1")
        session.knowledge_base["creds_found"] = [
            {"username": "root", "password": "toor", "service": "ssh"},
        ]
        groups = suggest.creds_suggestion_group()
        assert "SUGGESTED (creds reuse)" in groups
        cmd = groups["SUGGESTED (creds reuse)"][0]
        assert cmd.startswith("sshpass -p 'toor' ssh")
        assert "UserKnownHostsFile=/dev/null" in cmd
        assert "root@10.0.0.1" in cmd

    def test_creds_reuse_group_mysql(self):
        _reset(target="10.0.0.1")
        session.knowledge_base["creds_found"] = [
            {"username": "admin", "password": "s3cret", "service": "mysql",
             "port": 3306},
        ]
        cmd = suggest.creds_suggestion_group()["SUGGESTED (creds reuse)"][0]
        assert cmd.startswith("mysql -h 10.0.0.1 -P 3306 -u admin -p's3cret'")

    def test_creds_reuse_merged_into_brute(self):
        _reset(target="10.0.0.1")
        session.add_result("scan", {"cmd": "22/tcp open  ssh\n"})
        session.knowledge_base["creds_found"] = [
            {"username": "root", "password": "toor", "service": "ssh"},
        ]
        groups = suggest.brute_suggestion_group()
        assert "SUGGESTED (creds reuse)" in groups

    def test_creds_reuse_empty_without_creds(self):
        _reset(target="10.0.0.1")
        session.knowledge_base["creds_found"] = []
        assert suggest.creds_suggestion_group() == {}

    def test_cve_lookup_group_for_unmatched_service(self):
        _reset(target="10.0.0.1")
        session.add_result("scan", {
            "cmd": "443/tcp open  ssl/http  nginx 1.18.0\n",
        })
        hits = [{"cve": "CVE-2024-9999",
                 "description": "nginx 1.18.0 issue", "score": 8.5,
                 "source": "nvd"}]
        with patch("phantom.automation.exploit.resolver.CveResolver._fetch",
                   return_value=hits):
            groups = suggest.exploit_suggestion_group()
        assert "SUGGESTED (cve-lookup:CVE-2024-9999)" in groups
        cmd = groups["SUGGESTED (cve-lookup:CVE-2024-9999)"][0]
        assert "nvd.nist.gov/vuln/detail/CVE-2024-9999" in cmd

    def test_cve_lookup_skips_catalog_covered_service(self):
        _reset(target="10.0.0.1")
        session.add_result("scan", {
            "cmd": "80/tcp open  http  Apache httpd 2.4.49\n",
        })
        with patch("phantom.automation.exploit.resolver.CveResolver._fetch",
                   return_value=[{"cve": "CVE-X", "description": "x",
                                  "score": 9.0, "source": "nvd"}]):
            groups = suggest.exploit_suggestion_group()
        assert "SUGGESTED (cve-lookup:CVE-X)" not in groups
        assert "SUGGESTED (probe:CVE-2021-41773)" in groups

    def test_cve_lookup_offline_is_empty(self):
        _reset(target="10.0.0.1")
        session.add_result("scan", {
            "cmd": "443/tcp open  ssl/http  nginx 1.18.0\n",
        })
        from phantom.automation.exploit.resolver import get_resolver
        get_resolver().clear()

        def boom(self, product, version):
            raise OSError("offline")
        with patch("phantom.automation.exploit.resolver.CveResolver._fetch",
                   boom):
            groups = suggest.exploit_suggestion_group()
        assert not any("cve-lookup" in k for k in groups)

    def test_vulners_fallback_for_unmatched_services(self):
        _reset(target="10.0.0.1")
        session.add_result("scan", {
            "cmd": "443/tcp open  ssl/http  nginx 1.18.0\n",
        })
        from phantom.automation.exploit.hunter import (
            vuln_hunt_suggestion_group)
        groups = vuln_hunt_suggestion_group()
        assert "SUGGESTED (hunt:stealth-vuln-scan)" in groups
        cmd = groups["SUGGESTED (hunt:stealth-vuln-scan)"][0]
        assert "--script vulners" not in cmd
        assert "-sS -Pn -T2" in cmd
        assert "--version-light" in cmd
        assert "-p 443" in cmd
        assert "searchsploit" in groups["SUGGESTED (hunt:stealth-vuln-scan)"][1]

    def test_vulners_script_gated_behind_aggressive(self):
        _reset(target="10.0.0.1")
        session.add_result("scan", {
            "cmd": "443/tcp open  ssl/http  nginx 1.18.0\n",
        })
        from phantom.automation.exploit.hunter import (
            vuln_hunt_suggestion_group)
        groups = vuln_hunt_suggestion_group()
        assert not any("vulners" in k and "AGGRESSIVE" not in k
                       for k in groups)
        session.knowledge_base["aggressive"] = True
        try:
            groups = vuln_hunt_suggestion_group()
        finally:
            session.knowledge_base["aggressive"] = False
        assert any("AGGRESSIVE" in k and "vulners" in k for k in groups)

    def test_vulners_absent_when_catalog_covers_everything(self):
        _reset(target="10.0.0.1")
        session.add_result("scan", {
            "cmd": "80/tcp open  http  Apache httpd 2.4.49\n",
        })
        from phantom.automation.exploit.hunter import (
            vuln_hunt_suggestion_group)
        assert vuln_hunt_suggestion_group() == {}

    def test_misconfig_probes_no_auth_services(self):
        _reset(target="10.0.0.1")
        session.add_result("scan", {
            "cmd": "6379/tcp open  redis\n"
                   "139/tcp open  netbios-ssn\n"
                   "21/tcp open  ftp\n",
        })
        from phantom.automation.exploit.hunter import (
            misconfig_suggestion_group)
        groups = misconfig_suggestion_group()
        assert "SUGGESTED (hunt:no-auth:redis)" in groups
        assert groups["SUGGESTED (hunt:no-auth:redis)"][0].startswith(
            "redis-cli -h 10.0.0.1 -p 6379")
        assert "SUGGESTED (hunt:no-auth:smb)" in groups
        assert "SUGGESTED (hunt:no-auth:ftp)" in groups

    def test_scan_wires_hunt_and_misconfig(self):
        _reset(target="10.0.0.1")
        session.add_result("scan", {
            "cmd": "443/tcp open  ssl/http  nginx 1.18.0\n"
                   "6379/tcp open  redis\n",
        })
        groups = ScanModule().suggest_commands()
        assert "SUGGESTED (hunt:stealth-vuln-scan)" in groups
        assert "SUGGESTED (hunt:no-auth:redis)" in groups

    def test_behavioural_probes_on_web_services(self):
        _reset(target="10.0.0.1")
        session.add_result("scan", {
            "cmd": "80/tcp open  http  Apache httpd 2.4.49\n",
        })
        from phantom.automation.exploit.hunter import (
            behavioural_hunt_suggestion_group)
        groups = behavioural_hunt_suggestion_group()
        assert "SUGGESTED (hunt:traversal:80)" in groups
        assert "SUGGESTED (hunt:sqli:80)" in groups
        blob = " ".join(sum(groups.values(), []))
        assert "%2e%2e/%2e%2e" in blob
        assert "SLEEP(3)" in blob
        assert "--max-time 8" in blob

    def test_with_suggestions_orders_suggestions_first(self):
        merged = BaseModule()._with_suggestions(
            {"A": ["a1"]}, {"SUGGESTED (X)": ["s1"]})
        assert list(merged) == ["SUGGESTED (X)", "A"]
        assert merged["A"] == ["a1"]

    def test_show_enter_hint_no_output_without_target(self, capsys):
        _reset(target="")
        BaseModule().show_enter_hint()
        assert capsys.readouterr().out == ""


class TestSessionServices:

    def test_parses_scan_output(self):
        _reset()
        session.add_result("scan", {
            "nmap -sV 10.0.0.1": "22/tcp open  ssh     OpenSSH 7.9p1\n"
                                 "80/tcp open  http    Apache httpd 2.4.49\n",
        })
        services = suggest.session_services()
        assert len(services) == 2
        by_port = {s["port"]: s for s in services}
        assert by_port["80"]["product"] == "apache"
        assert by_port["80"]["version"] == "Apache httpd 2.4.49"

    def test_service_summary_used(self):
        _reset()
        session.add_result("service_summary", [
            {"port": "445", "service": "Microsoft-ds", "version": ""},
        ])
        services = suggest.session_services()
        assert services[0]["service"] == "microsoft-ds"

    def test_dedupes_across_sources(self):
        _reset()
        session.add_result("service_summary", [
            {"port": "22", "service": "ssh", "version": "OpenSSH 7.4"},
        ])
        session.add_result("scan", {
            "cmd": "22/tcp open  ssh  OpenSSH 7.4\n",
        })
        assert len(suggest.session_services()) == 1

    def test_exploit_ranked_services(self):
        _reset()
        svc = SimpleNamespace(port="80", protocol="tcp", service="http",
                              product="Apache", version="2.4.49")
        session.add_result("exploit", {"ranked": [{"service": svc}]})
        services = suggest.session_services()
        assert services[0]["product"] == "apache"

    def test_infer_product_from_version(self):
        assert suggest._infer_product("Apache httpd 2.4.49") == "apache"
        assert suggest._infer_product("") == ""


class TestServiceSuggestionGroup:

    def test_targeted_commands_per_service(self):
        _reset()
        session.add_result("service_summary", [
            {"port": "445", "service": "smb", "version": ""},
            {"port": "80", "service": "http", "version": "nginx/1.18"},
        ])
        groups = suggest.service_suggestion_group()
        flat = [c for cmds in groups.values() for c in cmds]
        assert any("enum4linux -a 10.0.0.1" in c for c in flat)
        assert any("whatweb 10.0.0.1" in c for c in flat)
        assert any("curl -sI http://10.0.0.1:80" in c for c in flat)

    def test_empty_without_target(self):
        _reset(target="")
        assert suggest.service_suggestion_group() == {}


class TestExploitSuggestionGroup:

    def test_version_matched_msfconsole(self):
        _reset()
        session.add_result("service_summary", [
            {"port": "80", "service": "http",
             "version": "Apache httpd 2.4.49"},
        ])
        groups = suggest.exploit_suggestion_group()
        assert "SUGGESTED EXPLOIT (CVE-2021-41773)" in groups
        cmds = groups["SUGGESTED EXPLOIT (CVE-2021-41773)"]
        assert any("apache_normalize_path_rce" in c and "10.0.0.1" in c
                   for c in cmds)
        assert any("searchsploit --cve CVE-2021-41773" in c for c in cmds)

    def test_patched_version_no_suggestion(self):
        _reset()
        session.add_result("service_summary", [
            {"port": "80", "service": "http", "version": "Apache httpd 2.4.52"},
        ])
        groups = suggest.exploit_suggestion_group()
        assert not any("EXPLOIT" in k or "probe:" in k
                       or "cve-lookup" in k for k in groups)
        assert "SUGGESTED (hunt:traversal:80)" in groups

    def test_no_services_empty(self):
        _reset()
        assert suggest.exploit_suggestion_group() == {}


class TestScanModuleDynamic:

    def test_build_commands_regression(self):
        _reset()
        scan = ScanModule()
        commands = scan.build_commands()
        assert "NMAP (Basic)" in commands
        assert any("oX" in c for c in commands["NMAP (Basic)"])

    def test_build_commands_empty_without_target(self):
        _reset(target="")
        assert ScanModule().build_commands() == {}

    def test_suggestions_injected_first(self):
        _reset()
        session.add_result("service_summary", [
            {"port": "445", "service": "smb", "version": ""},
        ])
        commands = ScanModule().build_commands()
        assert list(commands)[0].startswith("SUGGESTED")
        assert any("enum4linux" in c
                   for cmds in commands.values() for c in cmds)


class TestExploitModuleDynamic:

    def test_build_commands_has_core_msf(self):
        _reset()
        commands = ExploitModule().build_commands()
        assert "CORE" in commands
        assert "MSF" in commands

    def test_build_commands_injects_exploit_suggestions(self):
        _reset()
        session.add_result("service_summary", [
            {"port": "80", "service": "http",
             "version": "Apache httpd 2.4.49"},
        ])
        commands = ExploitModule().build_commands()
        assert any(k.startswith("SUGGESTED EXPLOIT") for k in commands)

    def test_preview_early_exit_without_suggestions(self):
        _reset()
        with patch("phantom.modules.exploit.notifier") as n:
            ExploitModule()._execute_flow("")
        assert n.warn.called

    def test_preview_runs_selected_commands(self):
        _reset()
        session.add_result("service_summary", [
            {"port": "80", "service": "http",
             "version": "Apache httpd 2.4.49"},
        ])
        selected = ["msfconsole -q -x 'x' && echo y"]
        with patch.object(PreviewSession, "interactive",
                          return_value=selected), \
             patch("phantom.core.executor.run_commands",
                   return_value={selected[0]: "out"}):
            ExploitModule()._execute_flow("")
        assert session.get_result("exploit_manual") is not None


class TestPreviewSuggestedStyling:

    def test_suggested_commands_in_flat_run(self):
        preview = PreviewSession({
            "SUGGESTED (web:80)": ["whatweb 10.0.0.1"],
            "NMAP": ["nmap -sV 10.0.0.1"],
        })
        assert preview.run_all() == ["whatweb 10.0.0.1", "nmap -sV 10.0.0.1"]

    def test_display_does_not_crash_with_suggestions(self, capsys):
        preview = PreviewSession({
            "SUGGESTED (First Steps)": ["sudo nmap -O 10.0.0.1"],
            "NMAP": ["sudo nmap -sS 10.0.0.1"],
        })
        preview._display()
        out = capsys.readouterr().out
        assert "SUGGESTED" in out


class TestAllModulesDynamic:
    """Every manual module exposes state-aware commands."""

    def test_osint_identity_target(self):
        _reset(target="john.doe@example.com")
        groups = suggest.osint_suggestion_group()
        assert "SUGGESTED (Identity)" in groups
        assert any("sherlock john.doe" in c for c in
                   groups["SUGGESTED (Identity)"])

    def test_osint_domain_target(self):
        _reset(target="example.com")
        groups = suggest.osint_suggestion_group()
        assert "SUGGESTED (Domain)" in groups
        assert any("crt.sh" in c for c in groups["SUGGESTED (Domain)"])

    def test_osint_ip_target(self):
        _reset(target="10.0.0.1")
        groups = suggest.osint_suggestion_group()
        assert "SUGGESTED (IP)" in groups
        assert any("shodan host 10.0.0.1" in c for c in groups["SUGGESTED (IP)"])

    def test_osint_module_wired(self):
        _reset(target="example.com")
        from phantom.modules.osint import OsintModule
        cmds = OsintModule().build_commands()
        assert "SUGGESTED (Domain)" in cmds
        assert "WHOIS / DNS" in cmds

    def test_web_suggestions_targeted_at_open_web_service(self):
        _reset()
        session.add_result("scan", {
            "cmd": "80/tcp open  http  Apache httpd 2.4.49\n"
                   "22/tcp open  ssh   OpenSSH 7.9\n",
        })
        groups = suggest.web_suggestion_group()
        assert "SUGGESTED (web:80)" in groups
        assert any("whatweb http://10.0.0.1:80" in c
                   for c in groups["SUGGESTED (web:80)"])

    def test_web_no_suggestions_without_web_service(self):
        _reset()
        session.add_result("scan", {"cmd": "22/tcp open  ssh\n"})
        assert suggest.web_suggestion_group() == {}

    def test_web_module_wired(self):
        _reset()
        session.add_result("scan", {"cmd": "80/tcp open  http\n"})
        from phantom.modules.web import WebModule
        cmds = WebModule().build_commands()
        assert "SCANNING & VULN" in cmds
        assert any(k.startswith("SUGGESTED") for k in cmds)

    def test_brute_suggestions_for_auth_services(self):
        _reset()
        session.add_result("scan", {
            "cmd": "22/tcp open  ssh   OpenSSH 7.9\n"
                   "3306/tcp open  mysql MySQL 5.7\n",
        })
        groups = suggest.brute_suggestion_group()
        assert "SUGGESTED (brute:ssh)" in groups
        assert "SUGGESTED (brute:mysql)" in groups
        assert any("hydra" in c for c in groups["SUGGESTED (brute:ssh)"])

    def test_brute_no_suggestions_without_auth_service(self):
        _reset()
        session.add_result("scan", {"cmd": "80/tcp open  http\n"})
        assert "SUGGESTED (brute:http)" in suggest.brute_suggestion_group()

    def test_payload_suggestions_match_detected_os(self):
        _reset()
        session.knowledge_base["os_info"] = {"name": "Windows Server 2022",
                                             "accuracy": 95}
        groups = suggest.payload_suggestion_group()
        cmds = groups["SUGGESTED (payload)"]
        # engine-backed reverse first, then the classic wizard
        assert any("reverse" in c for c in cmds)
        assert any("generate windows" in c for c in cmds)
        # classic msfvenom stays available in its own group
        msf = groups.get("MSF (classic)", [])
        assert any("windows/x64" in c for c in msf)

    def test_payload_no_suggestions_without_os(self):
        _reset()
        assert suggest.payload_suggestion_group() == {}

    def test_handler_suggestions_match_platform(self):
        _reset()
        session.knowledge_base["os_info"] = {"name": "Linux 5.15",
                                             "accuracy": 90}
        groups = suggest.handler_suggestion_group()
        assert any("linux/x64/shell_reverse_tcp" in c
                   for c in groups["SUGGESTED (handler)"])

    def test_pivot_suggestions_when_beacon_registered(self):
        from phantom.core.c2_server import c2_state
        c2_state.beacons.clear()
        _reset()
        assert suggest.pivot_suggestion_group() == {}
        c2_state.beacons["beacon-x"] = {"ip": "10.0.0.1", "os": "Linux"}
        try:
            groups = suggest.pivot_suggestion_group()
            assert "SUGGESTED (pivot)" in groups
            assert any("socks" in c for c in groups["SUGGESTED (pivot)"])
        finally:
            c2_state.beacons.clear()

    def test_report_suggestions_when_results_exist(self):
        _reset()
        assert suggest.report_suggestion_group() == {}
        session.add_result("scan", {"cmd": "out"})
        groups = suggest.report_suggestion_group()
        assert "SUGGESTED (report)" in groups
        assert any("export json" in c for c in groups["SUGGESTED (report)"])

    def test_wordlist_suggestions_seeded_by_target(self):
        _reset(target="example.com")
        groups = suggest.wordlist_suggestion_group()
        assert "SUGGESTED (wordlist)" in groups
        assert any("--name example" in c for c in groups["SUGGESTED (wordlist)"])

    def test_all_modules_have_suggest_command(self):
        _reset(target="10.0.0.1")
        from phantom.core.shell import PhantomShell
        from phantom.modules.wordlist import WordlistModule
        shell = PhantomShell()
        for name in ("scan", "osint", "web", "brute", "exploit", "payload",
                     "handler", "pivot", "analyzer", "report", "wifi"):
            instance = shell._instantiate_module(name)
            assert instance is not None
            assert hasattr(instance, "do_suggest")
            assert callable(instance.suggest_commands)
        assert hasattr(WordlistModule(), "do_suggest")
        assert callable(WordlistModule().suggest_commands)
