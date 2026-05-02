from phantom.modules.base_module import BaseModule
from phantom.core.preview import PreviewSession
from phantom.core.executor import run_commands
from phantom.core.session import session
from rich.console import Console
from phantom.utils.aggressive import filter_aggressive_commands

console = Console()


class WebModule(BaseModule):
    module_name = "web"

    def build_commands(self) -> dict:
        """Return the command groups for web enumeration."""
        t = session.target
        if not t:
            return {}

        # Use active wordlist if set, otherwise fallback to common.txt
        wl = session.active_wordlist if session.active_wordlist else "/usr/share/wordlists/dirb/common.txt"

        return {
            "GOBUSTER": [
                f"gobuster dir -u http://{t} -w /usr/share/wordlists/dirb/common.txt",
                f"gobuster dir -u http://{t} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
                f"gobuster dir -u http://{t} -w {wl} -x php,html,txt,js,bak",
                f"gobuster dir -u https://{t} -w /usr/share/wordlists/dirb/common.txt",
                f"gobuster dns -d {t} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                f"gobuster vhost -u http://{t} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                f"feroxbuster -u http://{t} -w {wl}",
                f"dirb http://{t}",
            ],
            "NIKTO": [
                f"nikto -h {t}",
                f"nikto -h {t} -ssl",
            ],
            "FUZZING": [
                f"wfuzz -c -w {wl} http://{t}/FUZZ",
                f"ffuf -w {wl} -u http://{t}/FUZZ",
            ],
            "MANUAL RECON": [
                f"curl -I http://{t}",
                f"curl -L http://{t}",
                f"curl -X OPTIONS http://{t}",
                f"wget --spider http://{t}",
            ],
            "SQL INJECTION": [
                f"sqlmap -u http://{t} --forms --batch  AGGRESSIVE",
                f"sqlmap -u http://{t} --dbs --batch  AGGRESSIVE",
            ],
        }

    def do_preview(self, _):
        """Show preview, let user edit, then execute selected commands."""
        if not session.target:
            console.print("[red][!] No target set. Use 'set target <ip/domain>' first.[/]")
            return

        groups = self.build_commands()
        if not groups:
            return

        preview = PreviewSession(groups)
        chosen_commands = preview.interactive()
        if chosen_commands is None:
            console.print("[yellow]Web enumeration cancelled.[/]")
            return

        # Check for aggressive commands (SQLmap)
        chosen_commands = filter_aggressive_commands(chosen_commands)

        results = run_commands(chosen_commands, session.target)
        session.add_result("web", results)

        # Optional: post-processing suggestion for SQLmap findings could be added here

    def do_run(self, _):
        """Alias for do_preview."""
        self.do_preview(_)