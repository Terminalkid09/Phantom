"""
pivot.py — Port forwarding, pivoting, and tunnel management.
SSH tunnels, Chisel, Ligolo-ng, and SOCKS proxy helpers.
"""

from phantom.modules.base_module import BaseModule
from phantom.core.session import session
from phantom.core.executor import run_command
from phantom.utils.notifier import notifier
from rich.console import Console
from rich.table import Table
import subprocess
import os
import signal

console = Console()

TUNNEL_TYPES = {
    "1": "SSH local forward (expose remote port locally)",
    "2": "SSH remote forward (expose local port to remote)",
    "3": "SSH dynamic (SOCKS proxy via proxychains)",
    "4": "Chisel (HTTP tunnel, no SSH needed)",
    "5": "Ligolo-ng (layer 3 VPN-like tunnel)",
}

PIVOT_PARAMS = {
    "target": ("Target IP/hostname", session.target or ""),
    "user": ("SSH username (for SSH tunnels)", "root"),
    "local_port": ("Local port", "8080"),
    "remote_port": ("Remote port (on target)", "80"),
    "socks_port": ("SOCKS proxy port", "1080"),
    "chisel_port": ("Chisel server port", "8000"),
}


class PivotModule(BaseModule):
    module_name = "pivot"

    def __init__(self):
        super().__init__()
        self._tunnels: dict[str, subprocess.Popen] = {}

    def _ask(self, prompt: str, default: str = "") -> str:
        d = f" [{default}]" if default else ""
        return input(f"  {prompt}{d}: ").strip() or default

    def do_setup(self, _):
        """Interactive tunnel setup wizard."""
        console.print("\n[bold]-- PIVOT / PORT FORWARDING --[/]\n")
        for k, desc in TUNNEL_TYPES.items():
            console.print(f"  [{k}] {desc}")
        choice = input("\n  Tunnel type: ").strip()
        if choice not in TUNNEL_TYPES:
            return notifier.error("Invalid choice.")

        target = self._ask("Target IP/hostname", session.target or "")
        user = self._ask("SSH username", "root")
        local_port = self._ask("Local port", "8080")
        remote_port = self._ask("Remote port", "80")
        socks_port = self._ask("SOCKS port", "1080")
        chisel_port = self._ask("Chisel server port", "8000")

        cmd = ""
        desc = ""

        if choice == "1":
            cmd = f"ssh -L {local_port}:{target}:{remote_port} {user}@{target} -N -o StrictHostKeyChecking=no"
            desc = f"SSH local: {target}:{remote_port} → localhost:{local_port}"
        elif choice == "2":
            cmd = f"ssh -R {remote_port}:localhost:{local_port} {user}@{target} -N -o StrictHostKeyChecking=no"
            desc = f"SSH remote: localhost:{local_port} → {target}:{remote_port}"
        elif choice == "3":
            cmd = f"ssh -D {socks_port} {user}@{target} -N -o StrictHostKeyChecking=no"
            desc = f"SOCKS proxy on localhost:{socks_port} — use: proxychains <cmd>"
        elif choice == "4":
            console.print(f"\n  [bold]On your Kali (server):[/]")
            console.print(f"      [yellow]chisel server -p {chisel_port} --reverse[/]")
            console.print(f"\n  [bold]On the target (client):[/]")
            t_port = self._ask("Target's open port (e.g., 22)", "22")
            console.print(f"      [yellow]chisel client {target}:{chisel_port} R:{local_port}:127.0.0.1:{t_port}[/]")
            console.print("\n  [dim]Run the server FIRST, then the client on the target[/]")
            return
        elif choice == "5":
            ligo_port = self._ask("Ligolo-ng relay port", "11601")
            console.print(f"\n  [bold]On your Kali (server — as root):[/]")
            console.print(f"      [yellow]sudo ip tuntap add dev ligolo mode tun && sudo ip link set ligolo up[/]")
            console.print(f"      [yellow]sudo ip route add 0.0.0.0/0 dev ligolo[/]")
            console.print(f"      [yellow]ligolo-ng proxy -selfcert -laddr 0.0.0.0:{ligo_port}[/]")
            console.print(f"\n  [bold]On the target (client):[/]")
            console.print(f"      [yellow]ligolo-ng-agent -connect {target}:{ligo_port} -ignore-cert[/]")
            console.print("\n  [dim]After connection, use 'session' and 'ifconfig' in ligolo proxy[/]")
            return

        if cmd:
            notifier.success(desc)
            console.print(f"  [yellow]{cmd}[/]\n")
            bg = input("  Run in background now? [y/N]: ").strip().lower() == "y"
            if bg:
                tunnel_id = f"{choice}-{local_port}"
                proc = subprocess.Popen(cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                         preexec_fn=os.setsid if hasattr(os, 'setsid') else None)
                self._tunnels[tunnel_id] = proc
                notifier.success(f"Tunnel {tunnel_id} started (PID {proc.pid}).")
            else:
                notifier.info("Copy and run in another terminal.")

    def do_list(self, _):
        """list — show active tunnels."""
        if not self._tunnels:
            notifier.info("No active tunnels.")
            return
        alive = {}
        for tid, proc in list(self._tunnels.items()):
            if proc.poll() is None:
                alive[tid] = proc
            else:
                del self._tunnels[tid]
        if not alive:
            notifier.info("No active tunnels.")
            return
        table = Table(title="Active Tunnels")
        table.add_column("ID", style="cyan")
        table.add_column("PID", style="yellow")
        table.add_column("Status", style="green")
        for tid, proc in alive.items():
            table.add_row(tid, str(proc.pid), "RUNNING")
        console.print(table)

    def do_kill(self, args):
        """kill <id> — stop a tunnel by ID."""
        tid = args.strip()
        if not tid:
            notifier.error("Usage: kill <tunnel_id>")
            return
        proc = self._tunnels.pop(tid, None)
        if proc and proc.poll() is None:
            if hasattr(os, 'setsid'):
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            else:
                proc.terminate()
            notifier.success(f"Tunnel {tid} stopped.")
        else:
            notifier.warn(f"No active tunnel: {tid}")

    def do_socks(self, args):
        """socks <port> — quick SOCKS proxy via SSH dynamic forwarding."""
        port = args.strip() or "1080"
        target = session.target
        if not target:
            return notifier.error("Set target first.")
        user = input("  SSH user [root]: ").strip() or "root"
        cmd = f"ssh -D {port} {user}@{target} -N -o StrictHostKeyChecking=no"
        notifier.status(f"Starting SOCKS on {port} via {target}...")
        proc = subprocess.Popen(cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 preexec_fn=os.setsid if hasattr(os, 'setsid') else None)
        self._tunnels[f"socks-{port}"] = proc
        notifier.success(f"SOCKS proxy on localhost:{port} (PID {proc.pid}).")
        console.print(f"  [yellow]proxychains <cmd>[/]")

    def build_commands(self) -> dict:
        return {
            "SSH TUNNELS": [
                f"setup  # SSH local forward",
                f"setup  # SSH remote forward",
                f"setup  # SOCKS proxy",
            ],
            "PROXY & TUNNEL": [
                f"socks 1080",
                f"setup  # Chisel",
                f"setup  # Ligolo-ng",
            ],
        }

    def do_run(self, _):
        self.do_setup(_)

    def do_preview(self, _):
        self.do_setup(_)
