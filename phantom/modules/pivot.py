"""
pivot.py – Port forwarding and pivoting helper.
Generates SSH tunnels and Chisel commands.
"""

from phantom.modules.base_module import BaseModule
from phantom.core.session import session
from rich.console import Console

console = Console()

TUNNEL_TYPES = {
    "1": "SSH local forward (expose remote port locally)",
    "2": "SSH remote forward (expose local port to remote)",
    "3": "SSH dynamic (SOCKS proxy)",
    "4": "Chisel (when SSH is not available)",
}


class PivotModule(BaseModule):
    module_name = "pivot"

    def do_setup(self, _):
        """Interactive wizard to generate tunnel commands."""
        console.print("\n[bold]-- PIVOT / PORT FORWARDING --[/]\n")
        for k, desc in TUNNEL_TYPES.items():
            console.print(f"  [{k}] {desc}")

        choice = input("\n  Tunnel type: ").strip()
        if choice not in TUNNEL_TYPES:
            console.print("[red]Invalid choice.[/]")
            return

        # Common parameters
        target = session.target
        if not target:
            target = input("  Target IP/hostname: ").strip()
        user = input("  SSH username (for SSH tunnels): ").strip() or "root"
        local_port = input("  Local port: ").strip() or "8080"
        remote_port = input("  Remote port: ").strip() or "80"

        if choice == "1":
            # ssh -L local_port:target:remote_port user@target -N
            cmd = f"ssh -L {local_port}:{target}:{remote_port} {user}@{target} -N"
            desc = f"Port {target}:{remote_port} accessible on localhost:{local_port}"
        elif choice == "2":
            # ssh -R remote_port:localhost:local_port user@target -N
            cmd = f"ssh -R {remote_port}:localhost:{local_port} {user}@{target} -N"
            desc = f"Local port {local_port} exposed on {target}:{remote_port}"
        elif choice == "3":
            # ssh -D local_port user@target -N
            cmd = f"ssh -D {local_port} {user}@{target} -N"
            desc = f"SOCKS proxy on localhost:{local_port} — configure proxychains"
        elif choice == "4":
            console.print("\n[cyan]Chisel setup:[/]")
            server_port = input("  Server port (on your Kali machine): ").strip() or "8000"
            console.print(f"\n  [bold]On your Kali (server):[/]")
            console.print(f"      [yellow]chisel server -p {server_port} --reverse[/]")
            console.print(f"\n  [bold]On the target (client):[/]")
            target_port = input("  Target's open port (e.g., 22 for SSH): ").strip() or "22"
            console.print(f"      [yellow]chisel client {target}:{server_port} R:{local_port}:127.0.0.1:{target_port}[/]")
            return
        else:
            return

        console.print(f"\n  [green]{desc}[/]")
        console.print(f"  [yellow]{cmd}[/]\n")
        console.print("  [dim]Copy and run in another terminal.[/]")

    def do_run(self, _):
        self.do_setup(_)

    def do_preview(self, _):
        self.do_setup(_)