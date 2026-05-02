import cmd
from rich.console import Console
from phantom.core.session import session
from phantom.core.preview import PrewiewSession
from phantom.core.executor import run_commands

console = Console()

class BaseModule(cmd.Cmd):
    """
    Class for all interactive modules.
    Common commands: back, exit, show, note.
    """
    module_name = "base"

    def __init__(self):
        super().__init__()
        target = session.target if session.target else "no-target"
        self.prompt = f"[{self.module_name}:{target}] > "

    def do_back(self, _):
        """Return to the main shell"""
        return True

    def do_exit(self, _):
        """Exit Phantom"""
        raise SystemExit

    def do_show(self, arg):
        """Show session - current session"""
        if arg.strip() == "session":
            console.print(f"  Target: {session.target or 'None'}")
            console.print(f"  Mode: {session.mode}")
            console.print(f"  Scope: {', '.join(session.scope) if session.scope else 'none'}")
            console.print(f"  Active wordlist: {session.active_wordlist or 'default'}")
        else:
            console.print("[red]Usage: show session[/]")

        def do_note(self, arg):
            text = arg.strip().strip('"').strip('"')
            if text:
                session.add_note(text)
                console.print("[green][+] Note added.[/]")
            else:
                console.print("[red]Usage: note \"your note here\"[/]")


        # Methods to be implemented by child classes
        def build_commands(self) -> dict:
            """
            return a dictionary of command groups:
            {
            "NMAP": ["nmap -sV target", ...],
            "NETWORK": ["ping target", ...]
            }
            """
            raise NotImplementedError("Each module must implement build_commands()")

        def do_prewiew(self, _):
            raise NotImplementedError("Each module must implement do_prewiew()")

        def do_run(self, _):
            raise NotImplementedError("Each module must implement do_run()")