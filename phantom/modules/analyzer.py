import os
import subprocess
from phantom.modules.base_module import BaseModule
from phantom.core.executor import run_command
from phantom.core.session import session
from rich.console import Console
from rich.table import Table

console = Console()


class AnalyzerModule(BaseModule):
    module_name = "analyzer"

    def do_capture(self, args):
        """
        capture --interface <iface> --duration <seconds> [--output <file.pcap>]
        Live capture using tshark.
        """
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument("--interface", "-i", required=True)
        parser.add_argument("--duration", "-d", type=int, default=60)
        parser.add_argument("--output", "-o", default="capture.pcap")
        try:
            parsed = parser.parse_args(args.split())
        except SystemExit:
            return

        cmd = f"sudo tshark -i {parsed.interface} -a duration:{parsed.duration} -w {parsed.output}"
        console.print(f"[cyan][*] Starting capture on {parsed.interface} for {parsed.duration}s → {parsed.output}[/]")
        run_command(cmd)
        console.print(f"[green][+] Capture saved to {parsed.output}[/]")
        # Optionally auto-analyze
        if input("  Analyze now? [y/N] ").lower() == "y":
            self._analyze_pcap(parsed.output)

    def do_load(self, path: str):
        """load <file.pcap> — analyze an existing pcap file."""
        path = path.strip()
        if not path or not os.path.exists(path):
            console.print(f"[red]File not found: {path}[/]")
            return
        self._analyze_pcap(path)

    def _analyze_pcap(self, pcap_path: str):
        """Core analysis using scapy."""
        try:
            from scapy.all import rdpcap, ARP, DNS, Raw, IP, TCP
        except ImportError:
            console.print("[red]scapy not installed. Run: pip install scapy[/]")
            return

        console.print(f"\n[cyan][*] Analyzing {pcap_path}...[/]")
        packets = rdpcap(pcap_path)
        findings = []

        for pkt in packets:
            # Credentials in clear (HTTP Basic Auth, FTP, Telnet)
            if pkt.haslayer(Raw):
                raw = pkt[Raw].load.decode("utf-8", errors="ignore")
                if "Authorization: Basic" in raw:
                    findings.append(("CRITICAL", "HTTP Basic Auth credentials in clear", raw[:100]))
                if "USER " in raw or "PASS " in raw:
                    findings.append(("CRITICAL", "FTP/Telnet credentials in clear", raw[:100]))

            # ARP anomalies (poisoning)
            if pkt.haslayer(ARP) and pkt[ARP].op == 2:
                findings.append(("HIGH", "ARP reply (possible spoofing)", f"{pkt[ARP].psrc} → {pkt[ARP].pdst}"))

            # DNS tunneling (long queries)
            if pkt.haslayer(DNS) and pkt[DNS].qd:
                qname = pkt[DNS].qd.qname.decode("utf-8", errors="ignore")
                if len(qname) > 50:
                    findings.append(("MEDIUM", "Long DNS query (possible tunneling)", qname[:80]))

            # Unusual ports (non-standard)
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                dport = pkt[TCP].dport
                if dport not in [21,22,23,25,80,443,445,3306,3389,8080]:
                    findings.append(("LOW", f"Unusual port {dport}", f"src {pkt[IP].src} → dst {pkt[IP].dst}"))

        if not findings:
            console.print("[green][+] No critical anomalies found.[/]")
            return

        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        findings.sort(key=lambda x: severity_order.get(x[0], 4))

        table = Table(title=f"pcap analysis – {pcap_path}")
        table.add_column("Severity", style="bold")
        table.add_column("Type")
        table.add_column("Details")
        for sev, typ, details in findings:
            color = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "blue", "LOW": "white"}.get(sev, "white")
            table.add_row(f"[{color}]{sev}[/]", typ, details[:100])
        console.print(table)

        # Store results in session
        session.add_result("analyzer", findings)

    def do_run(self, _):
        path = input("  Path to pcap file (or leave empty for live capture): ").strip()
        if path:
            self.do_load(path)
        else:
            iface = input("  Network interface (e.g., eth0): ").strip()
            if not iface:
                console.print("[red]Interface required.[/]")
                return
            dur = input("  Duration (seconds) [60]: ").strip() or "60"
            self.do_capture(f"--interface {iface} --duration {dur}")

    def do_preview(self, _):
        self.do_run(_)