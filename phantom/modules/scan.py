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

    def suggest_commands(self) -> dict:
        """Targeted enumeration for the services already found, or first scans."""
        from phantom.modules.suggest import (
            service_suggestion_group, first_steps_suggestion_group)
        from phantom.automation.exploit.hunter import (
            vuln_hunt_suggestion_group, misconfig_suggestion_group)
        groups = {}
        groups.update(service_suggestion_group())
        groups.update(first_steps_suggestion_group())
        groups.update(vuln_hunt_suggestion_group())
        groups.update(misconfig_suggestion_group())
        return groups

    def build_commands(self) -> dict:
        """Return the command groups for network scanning (static + state)."""
        from phantom.utils.paths import scan_xml_path, sessions_dir
        from phantom.modules.suggest import target_host

        t = target_host()
        if not t:
            return {}

        os.makedirs(sessions_dir(), exist_ok=True)
        xml_out = scan_xml_path(t)

        groups = {
            # `-Pn` on every basic row: without it nmap's host discovery
            # answers "Host seems down" for any box that drops ICMP, and the
            # operator reads that as "no services" on a host that has some
            # (measured live: the docker lab on 127.0.0.1, 2026-10-27).
            "NMAP (Basic)": [
                f"sudo nmap -Pn -sS -p- --min-rate 5000 -T4 {t}",
                f"sudo nmap -Pn -sV -sC -p- {t}",
                f"sudo nmap -Pn -sV -sC -p- -oX {xml_out} {t}  # REQUIRED FOR EXPLOIT MODULE",
                f"sudo nmap -Pn -O {t}",
                # The connect scan is the row that still WORKS when a SYN
                # probe comes back filtered: measured on a target published
                # through a port forwarder / WSL loopback, `-sS` reported
                # 6379+8081 filtered while `-sT` opened them (2026-10-27).
                # Same port space and same XML, so it feeds the exploit
                # module exactly like the SYN row above.
                f"sudo nmap -Pn -sT -sV -sC -p- -oX {xml_out} {t}  # connect scan: use when SYN is filtered",
            ],
            "NMAP (Stealth & Evasion)": [
                f"sudo nmap -sS -f --mtu 24 {t}  # Fragmented packets",
                f"sudo nmap -sS --spoof-mac 0 {t}  # Random MAC Address",
                f"sudo nmap -sS -D RND:10 {t}  # Use 10 Random Decoys",
                f"sudo nmap -sS --source-port 53 {t}  # Spoof source port (DNS)",
                f"sudo nmap -sS --data-length 24 {t}  # Append random data to packets",
                f"sudo nmap -sS --badsum {t}  # Check for firewall/IDS response",
                f"sudo nmap -sN {t}  # NULL Scan",
                f"sudo nmap -sF {t}  # FIN Scan",
                f"sudo nmap -sX {t}  # Xmas Scan",
            ],
            "NETWORK & DISCOVERY": [
                f"traceroute {t}",
                f"sudo nmap -sn -PR {t}/24  # ARP Ping sweep",
                f"sudo nmap -sn -PE {t}/24  # ICMP Echo sweep",
                f"sudo arp-scan --localnet 2>/dev/null || sudo nmap -sn -PR {t}/24",
                f"sudo nmap -sn -PR {t}/24  # Host discovery via ARP",
                f"nmap -sn -PE {t}/24  # ICMP ping sweep (replaces fping)",
            ],
            "SERVICE ENUM": [
                f"nc -nv {t} 22",
                f"sslscan {t}:443",
                f"enum4linux -a {t}",
                f"smbclient -L //{t}",
                f"rpcclient -U '' {t}",
                f"snmpwalk -c public -v2c {t}",
                f"onesixtyone {t} public",
            ],
            "DEEP SCAN (Metasploit)": [
                f'msfconsole -q -x "use auxiliary/scanner/smb/smb_version; set RHOSTS {t}; run; exit"',
                f'msfconsole -q -x "use auxiliary/scanner/smb/smb_enumshares; set RHOSTS {t}; run; exit"',
                f'msfconsole -q -x "use auxiliary/scanner/http/title; set RHOSTS {t}; run; exit"',
                f'msfconsole -q -x "use auxiliary/scanner/ssh/ssh_version; set RHOSTS {t}; run; exit"',
                f'msfconsole -q -x "use auxiliary/scanner/snmp/snmp_login; set RHOSTS {t}; run; exit"',
                f'msfconsole -q -x "use auxiliary/scanner/ftp/ftp_version; set RHOSTS {t}; run; exit"',
                f'msfconsole -q -x "use auxiliary/scanner/ftp/anonymous; set RHOSTS {t}; run; exit"',
                f'msfconsole -q -x "use auxiliary/scanner/mssql/mssql_ping; set RHOSTS {t}; run; exit"',
            ],
        }
        return self._with_suggestions(groups, self.suggest_commands())

    # A full-port sweep is 65535 probes, and against a host whose firewall
    # DROPs instead of REJECTs nmap retries every one of them. MEASURED on
    # this LAN (2026-10-16/17): `nmap -sV -sC -p- 192.168.1.18` against a
    # fully firewalled host COMPLETED in 13 552 s (~3 h 46 m) with all 65535
    # ports filtered. The scan writes the XML host entry only when the host
    # finishes, so a kill mid-sweep yields an EMPTY file, not a partial one:
    # the flat 120 s --quiet budget used to kill exactly that scan and the
    # run then reported "0 services" on a host that has some. The ceiling is
    # a safety net, not a target — a completed scan returns immediately —
    # so it sits 60% above the worst measurement on purpose.
    FULL_SWEEP_QUIET_TIMEOUT = 21600

    def quiet_timeout_seconds(self, cmd: str) -> int:
        """Give a full-port sweep its own budget, everything else the default.

        `-p-` and `--top-ports` are whole-port-space scans; a single-port
        probe or a version query keeps the short leash so a hung command
        cannot stall a scripted run.
        """
        if "-p-" in cmd or "--top-ports" in cmd or "-p 1-" in cmd:
            return self.FULL_SWEEP_QUIET_TIMEOUT
        return self.quiet_timeout_default

    def _execute_flow(self, arg=""):
        """Show preview, let user edit, then execute selected commands."""
        if not session.target:
            notifier.error("No target set. Use 'set target <ip>' first.")
            return

        groups = self.build_commands()
        if not groups:
            return

        preview = PreviewSession(groups)
        # `choose`: the menu when a terminal is attached, the module's first
        # group when stdin is a pipe (a scripted `use scan` + `run` used to
        # die here with "EOF when reading a line").
        chosen_commands = preview.choose(self._group_from_arg(arg))
        if chosen_commands is None:
            notifier.warn("Scan cancelled.")
            return

        # Check for aggressive commands and ask for confirmation
        chosen_commands = filter_aggressive_commands(chosen_commands)

        # Answer the `-p-` question BEFORE handing a 4-hour nmap the job.
        self._fast_full_sweep(chosen_commands)

        notifier.status(f"Starting scan sequence for {session.target}...")
        from phantom.core.executor import RunStatus
        status = RunStatus()
        results = run_commands(chosen_commands, session.target, status=status)
        session.add_result("scan", results, status=status)
        
        # Trigger Smart Intelligence: CVE Analysis
        self._analyze_vulnerabilities(results)

        from phantom.utils.paths import scan_xml_path
        xml_path = scan_xml_path(session.target)
        if os.path.exists(xml_path):
            save_scan_history(session.target, xml_path)
            notifier.success(f"Scan results saved to history.")
        
        self._conditional_suggestions(results)

    #: Time the internal full-range sweep may spend before it reports a
    #: PARTIAL result. Big enough for a DROP-everything host on a /24 (measured
    #: 199 s for 65 535 ports with 500 workers), small enough to be waited on.
    FAST_SWEEP_BUDGET = 420.0

    def _fast_full_sweep(self, commands) -> None:
        """Find the open ports of a full-range request without nmap.

        The defect (2026-10-30): `nmap -sV -sC -p-` against a Windows host that
        DROPs instead of REJECTs took 3 h 46 m for 65 535 filtered ports, so a
        scripted run either waited an afternoon or was killed with an empty
        XML and reported "no services" — while a plain TCP connect sweep found
        two open ports in three minutes. The sweep runs only when the chosen
        rows actually ask for full coverage (`-p-`), because that is the intent
        it answers; a quick top-1000 scan stays quick.

        Never raises: a failed sweep leaves the nmap rows to do their job.
        """
        import ipaddress

        if not any("-p-" in str(c) for c in commands or []):
            return
        target = str(session.target or "").strip()
        try:
            ipaddress.IPv4Address(target)
        except ValueError:
            return                      # hostname: not a connect-sweep target
        try:
            from phantom.core.netmap import sweep_all_ports
        except Exception:
            return
        notifier.status(f"Fast full-range connect sweep on {target} "
                        f"(no nmap, no root)...")
        try:
            ports, stats = sweep_all_ports(target, budget=self.FAST_SWEEP_BUDGET)
        except Exception as exc:        # a sweep must never break the scan
            console.print(f"[yellow][!] fast sweep failed: {exc}[/]")
            return
        if ports:
            try:
                from phantom.automation.fingerprint.probes import PORT_SERVICE_MAP
            except Exception:
                PORT_SERVICE_MAP = {}
            found = [(str(port), PORT_SERVICE_MAP.get(int(port), ""))
                     for port in ports]
            table = Table(title=f"Fast sweep: {len(found)} open TCP port(s) on {target}")
            table.add_column("Port", style="cyan")
            table.add_column("Service", style="green")
            for port, service in found:
                table.add_row(port, service or "?")
            console.print(table)
            from phantom.core.knowledge import add_service
            for port, service in found:
                add_service(port, service or "tcp", product="",
                            version="", confidence=0.6, source="fast_sweep")
        else:
            console.print(f"[dim]    Fast sweep: no open TCP port in the range.[/]")
        # A partial sweep is reported as partial: "nothing else is open" and
        # "we stopped looking" are different answers and only one is a fact.
        if not stats.get("complete", True):
            console.print(
                f"[yellow][!] sweep incomplete: {stats.get('scanned')} of "
                f"65535 port(s) probed in {stats.get('elapsed')}s "
                f"(budget {int(self.FAST_SWEEP_BUDGET)}s) — "
                f"{stats.get('filtered')} filtered, {stats.get('refused')} "
                f"refused. Raise scan.fast_sweep_budget to finish.[/]")
        else:
            console.print(
                f"[dim]    sweep complete in {stats.get('elapsed')}s: "
                f"{stats.get('refused')} refused, {stats.get('filtered')} "
                f"filtered (a DROP-everything firewall shows up as filtered).[/]")

    def _analyze_vulnerabilities(self, results):
        """Light post-scan summary — full CVE analysis deferred to exploit module."""
        import re

        console.print("\n[bold cyan]── SMART INTELLIGENCE: SERVICE SUMMARY ─────────────[/]")
        services = []
        for output in results.values():
            matches = re.findall(r"(\d+)/(tcp|udp)\s+open\s+([\w-]+)\s*(.*)", output)
            for port, proto, service, version in matches:
                services.append({"port": port, "service": service, "version": version.strip()})

        if not services:
            console.print("[dim]    No open services detected for analysis.[/]")
            return

        table = Table(title="Detected Services (CVE analysis deferred)")
        table.add_column("Port", style="cyan")
        table.add_column("Service", style="green")
        table.add_column("Version", style="yellow")
        for svc in services[:15]:
            table.add_row(svc["port"], svc["service"], svc["version"] or "—")
        console.print(table)
        session.add_result("service_summary", services)

        # Write every service to the shared WorldModel so exploit/brute/web
        # read them and the reasoning engine builds live hypotheses on them.
        from phantom.core.knowledge import add_service, session_wm
        for svc in services:
            add_service(svc.get("port"), svc.get("service"),
                        product="", version=svc.get("version") or "",
                        confidence=0.7, source="scan")
        wm = session_wm()
        wm.target = session.target or wm.target

        # Feed the enterprise knowledge base for the professional report and
        # the sequence engine (workflow.py): services, OS, AD hints, WAF.
        kb = session.knowledge_base
        kb["services"] = services
        kb["status"]["scan_done"] = True
        if services:
            kb["status"]["classified"] = True
        kb["status"]["scan_stealth_done"] = kb["status"].get("scan_stealth_done", False)

        all_output = "\n".join(results.values()).lower()
        kb["os_info"] = kb.get("os_info") or {}
        os_m = re.search(r"os details[^\n]*\n?\s*([^\n]+)", all_output, re.I)
        if os_m:
            kb["os_info"]["os"] = os_m.group(1).strip()[:120]
            kb["status"]["os_detected"] = True
        running_m = re.search(r"running:\s*([^\n]+)", all_output, re.I)
        if running_m:
            kb["os_info"].setdefault("os", running_m.group(1).strip()[:120])
            kb["status"]["os_detected"] = True

        svc_names = " ".join(s.get("service", "") for s in services).lower()
        if any(k in svc_names for k in ("microsoft-ds", "netbios", "kerberos", "ldap", "kpasswd")):
            kb["domain_environment"] = True
        if "http" in svc_names or "https" in svc_names:
            kb["status"]["web_recon_done"] = kb["status"].get("web_recon_done", False)
        console.print("[dim]    Run 'use exploit' → 'run' for full CVE correlation (cached NVD).[/]")

    def _conditional_suggestions(self, results: dict):
        all_output = " ".join(results.values()).lower()

        # SMB
        if "445/tcp open" in all_output or "microsoft-ds" in all_output:
            console.print("\n[yellow][!] Port 445 / SMB detected.[/]")
            console.print("    Consider running: enum4linux -a, smbclient, rpcclient")
            # No prompt here: this runs at the END of EVERY scan, so a piped
            # session died with EOFError on an SMB host — or, worse, ate the
            # next scripted line as the answer (measured 2026-10-28). The
            # question never did anything either way: a "y" only printed the
            # line below, and nothing was ever added to the plan.
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