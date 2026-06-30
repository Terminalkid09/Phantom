from phantom.modules.base_module import BaseModule
from phantom.core.preview import PreviewSession
from phantom.core.executor import run_commands, run_command
from phantom.core.session import session
from rich.console import Console
from rich.table import Table
from phantom.utils.aggressive import filter_aggressive_commands
from phantom.utils.notifier import notifier
import re

console = Console()


class WebModule(BaseModule):
    module_name = "web"

    def do_sqlmap(self, args):
        """sqlmap <target_url> — Smarter SQLmap wrapper with --batch."""
        target = args.strip() or f"http://{session.target}"
        notifier.status(f"Launching SQLmap on {target}...")
        cmd = f"sqlmap -u {target} --batch --random-agent --level 1 --risk 1"
        if "--forms" in args: cmd += " --forms"
        output = run_command(cmd)
        if "is vulnerable" in output.lower() or "sql injection" in output.lower():
            notifier.success(f"VULNERABILITY FOUND: SQL Injection detected on {target}")
            session.add_note(f"Web: SQLMap found vulnerability on {target}")
        else:
            notifier.info("SQLmap scan complete. No obvious vulnerabilities found.")

    def do_nikto(self, _):
        """nikto — Smarter Nikto wrapper with result parsing."""
        t = session.target
        if not t:
            notifier.error("No target set.")
            return
        notifier.status(f"Starting Nikto scan on {t}...")
        output = run_command(f"nikto -h {t} -Tuning 123b -nointeractive")
        findings = self._extract_nikto_findings(output)
        if findings:
            table = Table(title="Nikto Findings", border_style="red")
            table.add_column("Type", style="yellow")
            table.add_column("Description")
            for f in findings:
                table.add_row(f[0], f[1])
            console.print(table)
            session.add_note(f"Web: Nikto found {len(findings)} issues on {t}")
        else:
            notifier.info("Nikto found no obvious issues.")

    def do_whatweb(self, _):
        """whatweb — Fingerprint web technologies."""
        t = session.target
        if not t:
            notifier.error("No target set.")
            return
        output = run_command(f"whatweb http://{t} --aggression 1")
        notifier.info(f"Web fingerprint:\n{output[:2000]}")
        session.add_note(f"Web: whatweb fingerprint of {t}")

    def do_dirsearch(self, args):
        """dirsearch <wordlist> — Fast directory brute-force."""
        t = session.target
        if not t: return notifier.error("No target set.")
        wl = args.strip() or session.active_wordlist or "/usr/share/wordlists/dirb/common.txt"
        output = run_command(f"dirsearch -u http://{t} -w {wl} --format plain")
        urls = re.findall(r'(?m)^\d{3}\s+.*?(http\S+)', output)
        if urls:
            for u in urls: console.print(f"  [green]{u}[/]")
            session.add_note(f"Web: dirsearch found {len(urls)} paths on {t}")
        else:
            notifier.info("No interesting paths found.")

    def build_commands(self) -> dict:
        t = session.target
        if not t:
            return {}
        wl = session.active_wordlist if session.active_wordlist else "/usr/share/wordlists/dirb/common.txt"
        return {
            "SCANNING & VULN": [
                f"nuclei -u http://{t} -severity critical,high",
                f"nikto -h {t} -Tuning 123b",
                f"whatweb http://{t}",
                f"wafw00f http://{t}",
            ],
            "FUZZING (Dir/File)": [
                f"ffuf -w {wl} -u http://{t}/FUZZ -mc 200,301,302 -t 50",
                f"gobuster dir -u http://{t} -w {wl} -x php,html,txt,js,bak -k",
                f"feroxbuster -u http://{t} -w {wl} --silent",
            ],
            "FUZZING (VHost/DNS)": [
                f"ffuf -w {wl} -u http://{t} -H 'Host: FUZZ.{t}' -fs 0",
                f"gobuster vhost -u http://{t} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            ],
            "API & PARAMETERS": [
                f"ffuf -w {wl} -u http://{t}/api/FUZZ",
                f"arjun -u http://{t} -m GET",
            ],
            "SQL INJECTION": [
                f"sqlmap -u http://{t} --forms --batch --random-agent --level 2 --risk 2  AGGRESSIVE",
                f"sqlmap -u http://{t} --dbs --batch --random-agent  AGGRESSIVE",
            ],
        }

    def _extract_nikto_findings(self, output: str):
        findings = []
        for line in output.split("\n"):
            line = line.strip()
            if not line.startswith("+"):
                continue
            line = line[1:].strip()
            colon = line.find(": ")
            if colon > 0:
                findings.append((line[:colon], line[colon+2:].strip()))
        return findings

    def _analyze_web_results(self, results: dict):
        vulns = 0
        for cmd, output in results.items():
            lo = output.lower()
            if "vulnerable" in lo or "sql injection" in lo:
                vulns += 1
                notifier.warn(f"SQLi likely in: {cmd}")
            if "+ 0 items" not in output and "nikto" in cmd:
                nf = self._extract_nikto_findings(output)
                if nf:
                    vulns += len(nf)
        session.add_note(f"Web: scan complete — {vulns} potential issues logged")

    def do_preview(self, _):
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
        chosen_commands = filter_aggressive_commands(chosen_commands)
        notifier.status(f"Starting Web enumeration for {session.target}...")
        results = run_commands(chosen_commands, session.target)
        session.add_result("web", results)
        self._analyze_web_results(results)

    def do_run(self, _):
        self.do_preview(_)
