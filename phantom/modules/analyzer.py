import os
from phantom.modules.base_module import BaseModule
from phantom.core.executor import run_command
from phantom.core.session import session
from rich.console import Console
from rich.table import Table

console = Console()


class AnalyzerModule(BaseModule):
    module_name = "analyzer"

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
        console.print(f"[cyan][*] Capturing on {parsed.interface} for {parsed.duration}s → {parsed.output}[/]")
        run_command(cmd, session.target)

    def do_load(self, pcap_path: str):
        """load <file.pcap> — analyze an existing pcap file."""
        pcap_path = pcap_path.strip()
        if not pcap_path or not os.path.exists(pcap_path):
            console.print("[red]File not found. Usage: load <file.pcap>[/]")
            return
        try:
            from scapy.all import rdpcap
        except ImportError:
            console.print("[red]scapy not installed. Run: pip install scapy[/]")
            return

        # Tentativo di lettura con gestione errori
        try:
            packets = rdpcap(pcap_path)
        except Exception as e:
            console.print(f"[red]Error reading PCAP: {e}[/]")
            return

        # Controllo se il file contiene pacchetti
        if len(packets) == 0:
            console.print("[yellow]PCAP file contains no packets.[/]")
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
                raw = pkt[Raw].load.decode('utf-8', errors='ignore')
                if "Authorization: Basic" in raw:
                    findings.append(("CRITICAL", "HTTP Basic Auth in clear text", raw[:100]))
                if "USER " in raw or "PASS " in raw:
                    findings.append(("CRITICAL", "FTP/Telnet credentials in clear text", raw[:100]))

            # ARP poisoning
            if pkt.haslayer(ARP) and pkt[ARP].op == 2:
                findings.append(("HIGH", "ARP reply – possible ARP poisoning", str(pkt.summary())))

            # DNS tunneling (lunghezza anomala)
            if pkt.haslayer(DNS) and pkt[DNS].qd:
                query = str(pkt[DNS].qd.qname)
                if len(query) > 50:  # euristica, può essere regolata
                    findings.append(("MEDIUM", "Long DNS query – possible tunneling", query[:80]))

        if not findings:
            console.print("[green][+] No anomalies found in the PCAP.[/]")
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

    def do_run(self, _):
        """Interactive: ask for pcap path and analyze."""
        path = input("  Path to pcap file: ").strip()
        self.do_load(path)

    def do_preview(self, _):
        self.do_run(_)