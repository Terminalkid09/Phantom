"""
scan.py – Network reconnaissance module.
Orchestrates Nmap and network tools with conditional suggestions.
"""
import os
from phantom.utils.scan_history import save_scan_history
from phantom.modules.base_module import BaseModule
from phantom.core.preview import PreviewSession
from phantom.core.executor import run_commands
from phantom.core.session import session
from rich.console import Console
from rich.table import Table
from phantom.utils.aggressive import filter_aggressive_commands

from phantom.utils.notifier import notifier

console = Console()


class ScanModule(BaseModule):
    module_name = "scan"

    def build_commands(self) -> dict:
        """Return the command groups for network scanning."""
        t = session.target
        if not t:
            return {}

        return {
            "NMAP": [
                f"sudo nmap -sS -p- --min-rate 5000 -T4 {t}",
                f"sudo nmap -sV -sC -p- {t}",
                f"sudo nmap -sV -sC -p- -oX data/sessions/scan_{t}.xml {t}  # REQUIRED FOR EXPLOIT MODULE",
                f"sudo nmap -sU --top-ports 200 {t}",
                f"sudo nmap -sS --top-ports 1000 {t}",
                f"sudo nmap -O {t}",
                f"sudo nmap --script vuln {t}",
                f"sudo nmap --script exploit {t}  AGGRESSIVE",
                f"sudo nmap -f {t}",
                f"sudo nmap -D RND:10 {t}",
                f"sudo nmap -sN {t}",
                f"sudo nmap -sF {t}",
                f"sudo nmap -sX {t}",
                f"sudo nmap -sA {t}",
            ],
            "NETWORK": [
                f"traceroute {t}",
                f"sudo traceroute -I {t}",
                f"ping -c 4 {t}",
                f"sudo arp-scan --localnet",
                f"sudo netdiscover -r {t}/24",
                f"fping -a -g {t}/24",
            ],
            "SERVICE ENUM": [
                f"nc -nv {t} 22",
                f"sslscan {t}:443",
                f"openssl s_client -connect {t}:443",
                f"enum4linux -a {t}",
                f"smbclient -L //{t}",
                f"rpcclient -U '' {t}",
                f"snmpwalk -c public -v1 {t}",
                f"snmpwalk -c public -v2c {t}",
                f"onesixtyone {t} public",
                f"smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t {t}",
            ],
        }

    def do_preview(self, _):
        """Show preview, let user edit, then execute selected commands."""
        if not session.target:
            notifier.error("No target set. Use 'set target <ip>' first.")
            return

        groups = self.build_commands()
        if not groups:
            return

        preview = PreviewSession(groups)
        chosen_commands = preview.interactive()
        if chosen_commands is None:
            notifier.warn("Scan cancelled.")
            return

        # Check for aggressive commands and ask for confirmation
        chosen_commands = filter_aggressive_commands(chosen_commands)

        notifier.status(f"Starting scan sequence for {session.target}...")
        results = run_commands(chosen_commands, session.target)
        session.add_result("scan", results)
        
        # Trigger Smart Intelligence: CVE Analysis
        self._analyze_vulnerabilities(results)

        xml_path = f"data/sessions/scan_{session.target}.xml"
        if os.path.exists(xml_path):
            save_scan_history(session.target, xml_path)
            notifier.success(f"Scan results saved to history.")
        
        self._conditional_suggestions(results)

    def _analyze_vulnerabilities(self, results):
        """Automatically correlate scan results with CVEs."""
        from phantom.utils.api import nvd_lookup, exploitdb_lookup
        import re
        
        console.print("\n[bold cyan]── SMART INTELLIGENCE: CVE CORRELATION ─────────────[/]")
        services = []
        for output in results.values():
            matches = re.findall(r"(\d+)/(tcp|udp)\s+open\s+([\w-]+)\s+(.*)", output)
            for port, proto, service, version in matches:
                services.append({"service": service, "version": version.strip()})
        
        if not services:
            console.print("[dim]    No versioned services found for CVE analysis.[/]")
            return

        vulns = []
        for svc in services:
            cves = nvd_lookup(svc['service'], svc['version'])
            for cve in cves:
                score = cve['cvss']
                if exploitdb_lookup(cve['id']):
                    score += 2.0
                    cve['has_exploit'] = True
                cve['final_score'] = min(score, 10.0)
                vulns.append(cve)
        
        if vulns:
            vulns.sort(key=lambda x: x['final_score'], reverse=True)
            table = Table(title="Vulnerability Insights")
            table.add_column("CVE ID", style="bold red")
            table.add_column("Score", style="bold magenta")
            table.add_column("Exploit", style="green")
            table.add_column("Description")
            
            for v in vulns[:5]:
                table.add_row(v['id'], f"{v['final_score']:.1f}", "YES" if v.get('has_exploit') else "no", v['description'][:60]+"...")
            console.print(table)
            session.add_result("cve_analysis", vulns)
            console.print(f"[dim]    Run 'use exploit' to search for found CVEs.[/]")
        else:
            console.print("[dim]    No critical CVEs matched for these versions.[/]")

    def do_run(self, _):
        """Alias for do_preview."""
        self.do_preview(_)

    def _conditional_suggestions(self, results: dict):
        all_output = " ".join(results.values()).lower()

        # SMB
        if "445/tcp open" in all_output or "microsoft-ds" in all_output:
            console.print("\n[yellow][!] Port 445 / SMB detected.[/]")
            console.print("    Consider running: enum4linux -a, smbclient, rpcclient")
            if input("    Add these commands now? [y/N] ").strip().lower() == "y":
                console.print("    [dim]Run: use scan, then run-group \"SERVICE ENUM\"[/]")

        # HTTPS
        if "443/tcp open" in all_output:
            console.print("\n[yellow][!] Port 443 (HTTPS) detected.[/]")
            console.print("    Consider: sslscan, openssl s_client, whatweb")

        # SNMP
        if "161/udp open" in all_output:
            console.print("\n[yellow][!] Port 161 (SNMP) detected.[/]")
            console.print("    Consider: snmpwalk, onesixtyone")

        # Nessuna porta aperta
        if "open" not in all_output:
            console.print("\n[yellow][!] No open ports found with standard scans.[/]")
            console.print("    Consider: UDP scan, stealth scans (NULL, FIN, Xmas), or decoy scans.")