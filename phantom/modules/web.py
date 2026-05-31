from phantom.modules.base_module import BaseModule
from phantom.core.preview import PreviewSession
from phantom.core.executor import run_commands, run_command
from phantom.core.session import session
from rich.console import Console
from phantom.utils.aggressive import filter_aggressive_commands
from phantom.utils.notifier import notifier

console = Console()


class WebModule(BaseModule):
    module_name = "web"

    def do_sqlmap(self, args):
        """sqlmap <target_url> [options] — Smarter SQLmap wrapper with --batch."""
        target = args.strip() or f"http://{session.target}"
        notifier.status(f"Launching SQLmap on {target}...")
        
        # Force --batch for non-interactive use within framework
        cmd = f"sqlmap -u {target} --batch --random-agent --level 1 --risk 1"
        if "--forms" in args: cmd += " --forms"
        
        output = run_command(cmd)
        if "is vulnerable" in output.lower() or "sql injection" in output.lower():
            notifier.success(f"VULNERABILITY FOUND: SQL Injection detected on {target}")
            session.add_note(f"Web: SQLMap found vulnerability on {target}")
        else:
            notifier.info("SQLmap scan complete. No obvious vulnerabilities found.")

    def do_nikto(self, _):
        """nikto — Smarter Nikto wrapper."""
        t = session.target
        if not t:
            notifier.error("No target set.")
            return
        
        notifier.status(f"Starting Nikto scan on {t}...")
        output = run_command(f"nikto -h {t} -Tuning 123b -nointeractive")
        
        if "+ 0 items" not in output:
            notifier.success(f"Nikto found potential issues on {t}")
            session.add_note(f"Web: Nikto found findings on {t}")

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
            notifier.error("No target set. Use 'set target <ip/domain>' first.")
            return

        groups = self.build_commands()
        if not groups:
            return

        preview = PreviewSession(groups)
        chosen_commands = preview.interactive()
        if chosen_commands is None:
            notifier.warn("Web enumeration cancelled.")
            return

        # Check for aggressive commands (SQLmap)
        chosen_commands = filter_aggressive_commands(chosen_commands)

        notifier.status(f"Starting Web enumeration for {session.target}...")
        results = run_commands(chosen_commands, session.target)
        session.add_result("web", results)

        # Optional: post-processing suggestion for SQLmap findings could be added here

    def do_run(self, _):
        """Alias for do_preview."""
        self.do_preview(_)