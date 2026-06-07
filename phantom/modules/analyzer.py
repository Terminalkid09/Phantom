import os
import subprocess
import threading
import signal
from phantom.modules.base_module import BaseModule
from phantom.core.executor import run_command
from phantom.core.session import session
from phantom.utils.notifier import notifier
from rich.console import Console
from rich.table import Table

console = Console()


class AnalyzerModule(BaseModule):
    module_name = "analyzer"

    def __init__(self):
        super().__init__()
        self.process = None
        self.stop_event = threading.Event()

    def do_start(self, interface="eth0"):
        """start <interface> — Start background TShark sniffing for credentials."""
        if self.process:
            notifier.warn("Sniffer already running.")
            return
        
        notifier.status(f"Starting background sniffer on {interface}...")
        cmd = ["sudo", "tshark", "-i", interface, "-l", "-V"]
        
        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                preexec_fn=os.setsid if os.name == 'posix' else None
            )
            session.results["_sniffer_active"] = True
            self.stop_event.clear()
            threading.Thread(target=self._live_parse, daemon=True).start()
            notifier.success(f"Sniffer started on {interface}.")
        except FileNotFoundError:
            notifier.error("tshark not found. Install with: sudo apt install tshark")
        except PermissionError:
            notifier.error("Permission denied. Run Phantom with sudo for sniffing.")
        except Exception as e:
            notifier.error(f"Error starting sniffer: {e}")

    def _live_parse(self):
        """Parse TShark output in real-time for sensitive info."""
        for line in iter(self.process.stdout.readline, ""):
            if self.stop_event.is_set(): break
            
            # Extract basic credentials
            if any(p in line for p in ["USER ", "PASS ", "Authorization: Basic"]):
                notifier.success(f"Sensitive data detected: {line.strip()}")
                session.add_note(f"Live Sniffer: Found potential creds - {line.strip()}")

    def do_stop(self, _) -> None:
        """stop — Stop the background sniffer."""
        if not self.process:
            notifier.warn("Sniffer not running.")
            return
        
        self.stop_event.set()
        try:
            if os.name == 'posix':
                try:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                except (ProcessLookupError, PermissionError) as e:
                    notifier.warn(f"Could not send SIGTERM to process group: {e}")
            else:
                self.process.terminate()
            
            # Give process time to exit gracefully
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                notifier.warn("Sniffer killed forcefully (did not stop within 5s).")
        except Exception as e:
            notifier.error(f"Error stopping sniffer: {e}")
        finally:
            self.process = None
            session.results.pop("_sniffer_active", None)
        notifier.success("Sniffer stopped.")

    def postcmd(self, stop: bool, line: str) -> bool:
        """Warn user if leaving with active sniffer."""
        if stop and self.process:
            notifier.warn("Sniffer is still running! Use 'stop' first or it will become a zombie.")
        return stop

    def do_capture(self, args):
        """capture --interface eth0 --duration 60 --output file.pcap"""
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument("--interface", default="eth0")
        parser.add_argument("--duration", type=int, default=60)
        parser.add_argument("--output", default="capture.pcap")
        try:
            parsed = parser.parse_args(args.split())
        except SystemExit:
            return
        cmd = f"sudo tshark -i {parsed.interface} -a duration:{parsed.duration} -w {parsed.output}"
        notifier.status(f"Capturing on {parsed.interface} for {parsed.duration}s → {parsed.output}")
        run_command(cmd, session.target)

    def do_load(self, pcap_path: str):
        """load <file.pcap> — analyze an existing pcap file."""
        pcap_path = pcap_path.strip()
        if not pcap_path or not os.path.exists(pcap_path):
            notifier.error("File not found. Usage: load <file.pcap>")
            return
        try:
            from scapy.all import rdpcap
        except ImportError:
            notifier.error("scapy not installed. Run: pip install scapy")
            return

        # Tentativo di lettura con gestione errori
        try:
            packets = rdpcap(pcap_path)
        except Exception as e:
            notifier.error(f"Error reading PCAP: {e}")
            return

        # Controllo se il file contiene pacchetti
        if len(packets) == 0:
            notifier.warn("PCAP file contains no packets.")
            return

        # Analisi dei pacchetti
        self._analyze_packets(packets, pcap_path)

    def _analyze_packets(self, packets, pcap_path: str):
        """Perform analysis on a list of packets."""
        from scapy.all import ARP, DNS, Raw
        findings = []

        for pkt in packets:
            # Credenziali in chiaro
            if pkt.haslayer(Raw):
                try:
                    raw = pkt[Raw].load.decode('utf-8', errors='ignore')
                    if "Authorization: Basic" in raw:
                        findings.append(("CRITICAL", "HTTP Basic Auth in clear text", raw[:100]))
                    if "USER " in raw or "PASS " in raw:
                        findings.append(("CRITICAL", "FTP/Telnet credentials in clear text", raw[:100]))
                except (UnicodeDecodeError, IndexError, AttributeError):
                    pass

            # ARP poisoning
            if pkt.haslayer(ARP) and pkt[ARP].op == 2:
                findings.append(("HIGH", "ARP reply – possible ARP poisoning", str(pkt.summary())))

            # DNS tunneling (lunghezza anomala)
            if pkt.haslayer(DNS) and pkt[DNS].qd:
                query = str(pkt[DNS].qd.qname)
                if len(query) > 50:  # euristica, può essere regolata
                    findings.append(("MEDIUM", "Long DNS query – possible tunneling", query[:80]))

        if not findings:
            notifier.success("No anomalies found in the PCAP.")
            session.add_result("analyzer", {"status": "clean"})
            return

        # Ordina per severità: CRITICAL, HIGH, MEDIUM
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
        findings.sort(key=lambda x: severity_order.get(x[0], 3))

        table = Table(title=f"PCAP Analysis – {pcap_path}")
        table.add_column("Severity", style="bold")
        table.add_column("Type")
        table.add_column("Detail")
        for sev, typ, detail in findings:
            color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue"}.get(sev, "white")
            table.add_row(f"[{color}]{sev}[/]", typ, detail[:80])
        console.print(table)

        # Salva i risultati nella sessione
        session.add_result("analyzer", {"findings": findings, "file": pcap_path})

    def do_privesc(self, arg):
        """privesc — Analyze session data for potential privilege escalation vectors."""
        beacons = getattr(session, "beacons", {})
        # If we are in C2 shell, we might have active beacons in c2_state
        from phantom.core.c2_server import c2_state
        beacons = c2_state.get_beacons()

        if not beacons:
            notifier.warn("No active beacons to analyze. Collect 'sysinfo' first.")
            return

        table = Table(title="Privilege Escalation Analysis", border_style="bold magenta")
        table.add_column("Beacon ID", style="cyan")
        table.add_column("OS", style="blue")
        table.add_column("Potential Vectors", style="yellow")
        table.add_column("Suggested Action", style="green")

        found = False
        for bid, info in beacons.items():
            os_info = info.get("os", "").lower()
            sysinfo = info.get("sysinfo", "").lower()
            
            vectors = []
            actions = []

            if "windows" in os_info:
                # Windows Kernel Exploit detection (Build-based)
                if "10.0.10240" in os_info: 
                    vectors.append("MS16-032 (Secondary Logon)")
                    actions.append("Use MS16-032 PowerShell PoC")
                if "10.0.14393" in os_info:
                    vectors.append("CVE-2017-0213 (COM Aggregate)")
                    actions.append("Execute CVE-2017-0213 binary")
                if "10.0.19041" in os_info or "10.0.19042" in os_info:
                    vectors.append("CVE-2021-36934 (HiveNightmare)")
                    actions.append("Read SAM/SYSTEM hives from VSS")
                
                # UAC Bypass check
                if "admin" not in info.get("user", "").lower():
                    vectors.append("UAC Bypass potential")
                    actions.append("Try Fodhelper or ComputerDefaults bypass")

            elif "linux" in os_info or "unix" in os_info:
                # Linux Kernel Exploit detection
                if " 4.4.0" in os_info:
                    vectors.append("CVE-2016-5195 (DirtyCow)")
                    actions.append("Run DirtyCow C exploit")
                if " 5.10" in os_info or " 5.15" in os_info:
                    vectors.append("CVE-2022-0847 (DirtyPipe)")
                    actions.append("Run DirtyPipe PoC")
                
                # Common misconfigs
                vectors.append("SUID/Sudo checks")
                actions.append("Run 'find / -perm -u=s -type f' or 'sudo -l'")

            if vectors:
                table.add_row(bid, os_info[:30], "\n".join(vectors), "\n".join(actions))
                found = True

        if found:
            console.print(table)
            notifier.success("Analysis complete. Review the table for escalation paths.")
        else:
            notifier.info("No obvious escalation vectors found automatically. Manual recon recommended.")

    def do_run(self, _):
        """Interactive: ask for pcap path and analyze."""
        path = input("  Path to pcap file: ").strip()
        self.do_load(path)

    def do_preview(self, _):
        self.do_run(_)
