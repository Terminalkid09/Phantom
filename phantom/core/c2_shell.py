import cmd
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from phantom.core.c2_server import ALLOWED_TASKS, c2_state, expected_token, server_instance
from phantom.utils.notifier import notifier

console = Console()


def build_c2_banner() -> str:
    return """
[bold purple]
  PHANTOM C2 LAB
[/bold purple]
  [dim]------------------------------------------------------------[/dim]
  [bold purple]Operations Center Simulator[/bold purple]  [dim]v1.0.0[/dim]
  [dim]Safe lab tasking only: no stealth, no evasion, no remote shell.[/dim]
"""


class C2Shell(cmd.Cmd):
    intro = ""
    prompt = "C2 > "

    def __init__(self):
        super().__init__()
        self.active_beacon: str | None = None

    def preloop(self):
        console.print(build_c2_banner())
        console.print(
            Panel(
                "This interface is intentionally limited to lab simulators and "
                "allowlisted tasks. Set PHANTOM_C2_TOKEN to change the API token.",
                title="[bold purple]Safety Mode[/bold purple]",
                border_style="purple",
            )
        )
        notifier.status("C2 lab shell initialized. Type 'help' for commands.")

    def postcmd(self, stop, line):
        if self.active_beacon:
            self.prompt = f"C2({self.active_beacon}) > "
        else:
            self.prompt = "C2 > "
        return stop

    def do_listeners(self, arg):
        """listeners [start [port] [host] | stop | status]"""
        parts = arg.split()
        action = parts[0].lower() if parts else "status"

        if action == "status":
            active = bool(server_instance.thread and server_instance.thread.is_alive())
            status = "[green]ACTIVE[/green]" if active else "[red]INACTIVE[/red]"
            console.print(
                f"[*] Lab listener {status} on "
                f"{server_instance.host}:{server_instance.port}"
            )
            if active:
                console.print(f"    [dim]Token: {expected_token()}[/dim]")
            return

        if action == "start":
            try:
                port = int(parts[1]) if len(parts) > 1 else server_instance.port
            except ValueError:
                notifier.error("Port must be a number.")
                return
            host = parts[2] if len(parts) > 2 else server_instance.host
            server_instance.start(host=host, port=port)
            notifier.success(f"Started lab listener on {host}:{port}")
            return

        if action == "stop":
            server_instance.stop()
            notifier.success("Stopped lab listener.")
            return

        notifier.error("Usage: listeners [start [port] [host] | stop | status]")

    def do_beacons(self, arg):
        """beacons - list registered lab simulators"""
        beacons = c2_state.get_beacons()
        if not beacons:
            notifier.warn("No lab simulators registered.")
            return

        table = Table(title="Registered Lab Simulators", border_style="purple")
        table.add_column("ID", style="cyan")
        table.add_column("Kind", style="magenta")
        table.add_column("IP", style="green")
        table.add_column("Host")
        table.add_column("OS")
        table.add_column("Last Seen", style="yellow")

        for beacon_id, info in sorted(beacons.items()):
            table.add_row(
                beacon_id,
                info.get("kind", "unknown"),
                info.get("ip", "unknown"),
                info.get("hostname", "unknown"),
                info.get("os", "unknown"),
                info.get("last_seen", "never"),
            )

        console.print(table)

    def do_interact(self, arg):
        """interact <simulator_id> - select a registered lab simulator"""
        beacon_id = arg.strip()
        if not beacon_id:
            notifier.error("Usage: interact <simulator_id>")
            return
        if beacon_id not in c2_state.get_beacons():
            notifier.error("Unknown simulator id. Use 'beacons' first.")
            return

        self.active_beacon = beacon_id
        notifier.success(f"Selected lab simulator {beacon_id}")

    def do_back(self, arg):
        """back - return to the global C2 lab context"""
        if self.active_beacon:
            self.active_beacon = None
            notifier.success("Returned to global C2 lab context.")
        else:
            notifier.warn("Already in global context.")

    def do_tasks(self, arg):
        """tasks - show allowlisted lab task types"""
        table = Table(title="Allowlisted Lab Tasks", border_style="purple")
        table.add_column("Task", style="cyan")
        table.add_column("Description")
        for task, description in sorted(ALLOWED_TASKS.items()):
            table.add_row(task, description)
        console.print(table)

    def do_task(self, arg):
        """task <ping|status|inventory|note> [args] - queue a safe lab task"""
        if not self.active_beacon:
            notifier.error("No active simulator. Use 'interact <simulator_id>' first.")
            return
        if not arg.strip():
            notifier.error("Usage: task <ping|status|inventory|note> [args]")
            return

        try:
            task = c2_state.queue_task(self.active_beacon, arg)
        except ValueError as exc:
            notifier.error(str(exc))
            return

        notifier.info(f"Queued lab task {task['name']} with id {task['task_id']}")

    def default(self, line):
        """Shortcut: queue an allowlisted task when interacting."""
        if not self.active_beacon:
            notifier.error("Unknown command. Type 'help' for available commands.")
            return
        self.do_task(line)

    def do_results(self, arg):
        """results - show stored results for the active simulator"""
        if not self.active_beacon:
            notifier.error("No active simulator. Use 'interact <simulator_id>' first.")
            return

        results = c2_state.get_results(self.active_beacon)
        if not results:
            notifier.warn("No results available for this simulator.")
            return

        for result in results:
            console.print(f"\n[bold cyan]--- Result: {result['task_id']} ---[/]")
            console.print(f"[dim]{result.get('time', '')}[/dim]")
            console.print(result["output"])

    def do_simulate(self, arg):
        """simulate [id] - register a local lab simulator for UI testing"""
        beacon_id = arg.strip() or f"lab-{datetime.now().strftime('%H%M%S')}"
        c2_state.register_simulator(beacon_id)
        notifier.success(f"Registered local lab simulator: {beacon_id}")

    def do_generate(self, arg):
        """generate - explain why real beacon generation is not available"""
        console.print(
            Panel(
                "Real stealth beacon generation is not available in this build. "
                "Use 'simulate' to exercise the C2 workflow with safe lab data, "
                "or connect an explicitly benign simulator that only implements "
                "the allowlisted task protocol.",
                title="[bold purple]Payload Generation Disabled[/bold purple]",
                border_style="purple",
            )
        )

    def do_exit(self, arg):
        """exit - close the C2 lab shell"""
        console.print("[dim]Stopping lab listener...[/]")
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
