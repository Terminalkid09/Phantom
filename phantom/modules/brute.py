"""
brute.py – Controlled brute force module.
Hydra, Medusa for network services; John and Hashcat for hash cracking.
"""

from phantom.modules.base_module import BaseModule
from phantom.core.preview import PreviewSession
from phantom.core.executor import run_commands
from phantom.core.session import session
from phantom.utils.notifier import notifier
from rich.console import Console

console = Console()

SERVICES = ["ssh", "ftp", "rdp", "smb", "mysql", "postgresql", "telnet", "http-post-form"]


class BruteModule(BaseModule):
    module_name = "brute"

    def build_commands(self, service: str, user: str, wordlist: str) -> dict:
        """Return command groups for the selected service."""
        t = session.target
        if not t:
            return {}

        if service == "http-post-form":
            path = input("  Login path (e.g., /login.php): ").strip()
            params = input("  POST params (e.g., user=^USER^&pass=^PASS^): ").strip()
            fail = input("  Fail string (e.g., 'Login failed'): ").strip()
            hydra_cmd = f"hydra -l {user} -P {wordlist} {t} http-post-form \"{path}:{params}:{fail}\" AGGRESSIVE"
            return {"HYDRA": [hydra_cmd]}

        hydra_cmd = f"hydra -l {user} -P {wordlist} {t} {service} AGGRESSIVE"
        hydra_cmd_stealth = f"hydra -t 4 -l {user} -P {wordlist} {t} {service} AGGRESSIVE"
        medusa_cmd = f"medusa -h {t} -u {user} -P {wordlist} -M {service} AGGRESSIVE"

        return {
            "HYDRA": [hydra_cmd, hydra_cmd_stealth],
            "MEDUSA": [medusa_cmd],
        }

    def do_run(self, _):
        """Interactive wizard for network brute force."""
        if not session.target:
            notifier.error("No target set. Use 'set target <ip>' first.")
            return

        console.print("\n[bold]--- Brute Force Wizard (Network Services) ---[/]\n")
        console.print(f"Available services: {', '.join(SERVICES)}")
        service = input("  Service target: ").strip().lower()
        if service not in SERVICES:
            notifier.error(f"Unsupported service. Choose from: {', '.join(SERVICES)}")
            return

        user = input("  Username (single): ").strip() or "admin"

        if session.active_wordlist:
            notifier.info(f"Using active wordlist: {session.active_wordlist}")
            wl = session.active_wordlist
        else:
            default_wl = "/usr/share/wordlists/rockyou.txt"
            notifier.info(f"No active wordlist. Using default: {default_wl}")
            wl = default_wl

        notifier.warn("Brute force is noisy and may trigger IDS/IPS.")
        confirm = input("  Proceed? [y/N] ").strip().lower()
        if confirm != "y":
            notifier.warn("Cancelled.")
            return

        groups = self.build_commands(service, user, wl)
        preview = PreviewSession(groups)
        chosen = preview.interactive()
        if chosen is None:
            notifier.warn("Cancelled.")
            return

        notifier.status(f"Starting brute force sequence for {session.target}...")
        results = run_commands(chosen, session.target)
        session.add_result("brute", results)

    def do_crack(self, _):
        """Crack password hashes with John the Ripper or Hashcat."""
        console.print("\n[bold]--- Password Cracking ---[/]\n")
        console.print("[1] John the Ripper")
        console.print("[2] Hashcat")
        choice = input("  Choose tool: ").strip()
        hash_file = input("  Path to hash file: ").strip()
        if not hash_file:
            notifier.error("Hash file required.")
            return

        if session.active_wordlist:
            wl = session.active_wordlist
        else:
            wl = "/usr/share/wordlists/rockyou.txt"
            notifier.info(f"Using default wordlist: {wl}")

        if choice == "1":
            cmd = f"john --wordlist={wl} {hash_file}"
        elif choice == "2":
            mode = input("  Hash mode (e.g., 0 for MD5, 1000 for NTLM): ").strip()
            if not mode:
                notifier.error("Hash mode required.")
                return
            cmd = f"hashcat -m {mode} {hash_file} {wl}"
        else:
            notifier.error("Invalid choice.")
            return

        console.print(f"\n  Preview: [yellow]{cmd}[/]")
        confirm = input("  Execute? [y/N] ").strip().lower()
        if confirm == "y":
            notifier.status("Starting crack sequence...")
            run_commands([cmd], session.target)  # target not relevant, but pass anyway
        else:
            notifier.warn("Cancelled.")

    def do_preview(self, _):
        """Alias for do_run."""
        self.do_run(_)
