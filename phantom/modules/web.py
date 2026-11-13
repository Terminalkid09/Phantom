from phantom.modules.base_module import BaseModule
from phantom.core.preview import PreviewSession
from phantom.core.executor import quote_arg, run_commands, run_command
from phantom.core.session import session
from rich.console import Console
from rich.table import Table
from phantom.utils.aggressive import filter_aggressive_commands
from phantom.utils.notifier import notifier
import re
from urllib.parse import urlsplit

console = Console()


def _web_url(value: str, fallback: str = "") -> tuple[str, str]:
    """A URL plus the host the scope check must see.

    `run_command`'s target guard accepts host characters only, so a full URL
    with a query string (`?id=1&x=2`) is refused before the scan and never
    reaches the shell. Split it: the URL is quoted as ONE argv for the tool,
    and the host is what scope/safe-target validation looks at.
    """
    raw = (value or fallback).strip()
    if not raw:
        raise ValueError("no target")
    if "://" not in raw:
        raw = "http://" + raw
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"not an http(s) URL: {raw}")
    host = parts.hostname
    from phantom.core.executor import _is_safe_target
    if not _is_safe_target(host):
        raise ValueError(f"unsafe host: {host}")
    return raw, host


class WebModule(BaseModule):
    module_name = "web"

    def do_sqlmap(self, args):
        """sqlmap <target_url> — Smarter SQLmap wrapper with --batch."""
        try:
            target, host = _web_url(args.strip(), f"http://{session.target}")
        except ValueError as exc:
            notifier.error(str(exc))
            return
        notifier.status(f"Launching SQLmap on {target}...")
        cmd = (f"sqlmap -u {quote_arg(target)} --batch --random-agent "
               f"--threads 1 --delay 2 --level 1 --risk 1")
        if "--forms" in args: cmd += " --forms"
        # target_ip enforces scope; the URL is quoted, so `?a=1&b=2` is one
        # argument and `&` never becomes a shell operator.
        output = run_command(cmd, target_ip=host)
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
        try:
            url, host = _web_url(t)
        except ValueError as exc:
            notifier.error(str(exc))
            return
        notifier.status(f"Starting Nikto scan on {url}...")
        output = run_command(
            f"nikto -h {quote_arg(url)} -Tuning 123b -Delay 2 -nointeractive",
            target_ip=host)
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
        try:
            url, host = _web_url(t)
        except ValueError as exc:
            notifier.error(str(exc))
            return
        output = run_command(f"whatweb {quote_arg(url)} --aggression 1",
                             target_ip=host)
        notifier.info(f"Web fingerprint:\n{output[:2000]}")
        session.add_note(f"Web: whatweb fingerprint of {url}")

    def do_hunt(self, arg):
        """hunt — behavioural bug-class hunting (baseline + statistical
        anomaly scoring + validation pass): the SAME anomaly engine the
        auto-mode agent runs, executed interactively with real requests.
        Confirmed candidates are written to the shared WorldModel, where
        the reasoning engine can turn them into rce_foothold hypotheses."""
        from phantom.core.knowledge import session_wm
        from phantom.automation.exploit.anomaly import hunt_target, curl_runner
        wm = session_wm()
        services = [f.value for f in wm.find("service")
                    if isinstance(f.value, dict)]
        if not services:
            notifier.error("No services in shared knowledge. Run 'use scan' first.")
            return
        if not any("http" in str(s.get("service", "")) for s in services):
            notifier.warn("No HTTP(S) service in knowledge — the hunt needs a web port.")
            return
        port = arg.strip() or ""
        target = wm.target or session.target
        if port:
            services = [s for s in services if str(s.get("port")) == port]
            if not services:
                notifier.error(f"No service on port {port} in knowledge.")
                return
        notifier.status(f"Behavioural hunt on {target} "
                        "(endpoints, baseline, scoring, validation)...")
        try:
            anomalies = hunt_target(target, services, runner=curl_runner)
        except Exception as e:
            notifier.error(f"Hunt failed: {e}")
            return
        if not anomalies:
            notifier.info("No anomaly candidates — clean surface.")
            return
        table = Table(title="Behavioural Hunt Results")
        table.add_column("Class", style="cyan")
        table.add_column("Endpoint", style="yellow")
        table.add_column("Signals")
        table.add_column("Score", justify="right")
        table.add_column("Status", style="green")
        confirmed = 0
        for a in anomalies:
            status = "CONFIRMED" if a.confirmed else "candidate"
            table.add_row(a.cls, a.endpoint, "|".join(a.signals),
                          f"{a.score:.2f}", status)
            if a.confirmed:
                confirmed += 1
            wm.add_finding(
                "hunt_anomaly", f"{a.cls}:{a.endpoint}",
                {"cls": a.cls, "endpoint": a.endpoint,
                 "signals": "|".join(a.signals), "score": a.score,
                 "confirmed": a.confirmed, "severity": a.severity(),
                 "evidence": a.evidence},
                confidence=0.8 if a.confirmed else 0.5, source="web_hunt")
        console.print(table)
        notifier.info(
            f"{len(anomalies)} candidate(s), {confirmed} confirmed — "
            "written to shared knowledge ('show knowledge'; 'suggest' for "
            "next steps).")

    def do_dirsearch(self, args):
        """dirsearch <wordlist> — Fast directory brute-force."""
        t = session.target
        if not t: return notifier.error("No target set.")
        try:
            url, host = _web_url(t)
        except ValueError as exc:
            notifier.error(str(exc))
            return
        wl = args.strip() or session.active_wordlist or "/usr/share/wordlists/dirb/common.txt"
        output = run_command(
            f"dirsearch -u {quote_arg(url)} -w {quote_arg(wl)} "
            f"--format plain", target_ip=host)
        urls = re.findall(r'(?m)^\d{3}\s+.*?(http\S+)', output)
        if urls:
            for u in urls: console.print(f"  [green]{u}[/]")
            session.add_note(f"Web: dirsearch found {len(urls)} paths on {t}")
        else:
            notifier.info("No interesting paths found.")

    def do_creds(self, _):
        """creds — extract credentials from web services (SSRF → credential
        files, SQLi auth-bypass + UNION dump + MD5 hash-crack). The SAME
        deterministic engine the auto-mode agent uses, run interactively.
        Found pairs are written to the shared WorldModel where the exploit
        / pivot modules can reuse them."""
        from phantom.core.knowledge import session_wm, add_creds
        from phantom.automation.exploit.webcreds import run_web_creds_dump
        wm = session_wm()
        target = wm.target or session.target
        if not target:
            notifier.error("No target set. Use 'set target <ip>' first.")
            return
        services = [f.value for f in wm.find("service")
                    if isinstance(f.value, dict)]
        if not services:
            notifier.error(
                "No services in shared knowledge — run 'use scan' first "
                "so we know which web ports to probe.")
            return
        notifier.status(f"Probing web services on {target} for leaked "
                        "credentials (SSRF + SQLi + hash-crack)...")
        try:
            creds = run_web_creds_dump(wm, target, timeout=60)
        except Exception as e:
            notifier.error(f"Credential extraction failed: {e}")
            return
        if not creds:
            notifier.info("No credentials leaked by the web services.")
            return
        table = Table(title="Extracted Web Credentials")
        table.add_column("Username", style="cyan")
        table.add_column("Password", style="yellow")
        table.add_column("Method", style="green")
        table.add_column("Confidence")
        seen = set()
        for c in creds:
            if c.username.lower() in seen:
                continue
            seen.add(c.username.lower())
            table.add_row(c.username, c.password, c.method,
                          f"{c.confidence:.2f}")
            add_creds(c.username, c.password, service="web",
                      valid=True, source=f"web_{c.method}",
                      port=self._web_port(wm))
        console.print(table)
        notifier.success(
            f"{len(seen)} credential set(s) written to shared knowledge — "
            "reuse with 'use exploit' (ssh login) / 'use payload' / 'use pivot'.")

    @staticmethod
    def _web_port(wm) -> str:
        for f in wm.find("service"):
            v = f.value if isinstance(f.value, dict) else {}
            if "http" in str(v.get("service", "")):
                return str(v.get("port", ""))
        return "8080"

    def build_commands(self) -> dict:
        t = session.target
        if not t:
            return {}
        try:
            url, host = _web_url(t)
        except ValueError:
            return {}
        base = url.rstrip("/")
        wl = session.active_wordlist if session.active_wordlist else "/usr/share/wordlists/dirb/common.txt"
        return self._with_suggestions({
            "SCANNING & VULN": [
                f"creds  # extract leaked creds (SSRF + SQLi + hash-crack)",
                f"nuclei -u {quote_arg(url)} -severity critical,high",
                f"nikto -h {quote_arg(url)} -Tuning 123b -Delay 2",
                f"whatweb {quote_arg(url)}",
                f"wafw00f {quote_arg(url)}",
            ],
            "FUZZING (Dir/File)": [
                f"ffuf -w {quote_arg(wl)} -u {quote_arg(base + '/FUZZ')} "
                f"-mc 200,301,302 -t 50",
                f"gobuster dir -u {quote_arg(url)} -w {quote_arg(wl)} "
                f"-x php,html,txt,js,bak -k",
                f"feroxbuster -u {quote_arg(url)} -w {quote_arg(wl)} "
                f"--silent",
            ],
            "FUZZING (VHost/DNS)": [
                f"ffuf -w {quote_arg(wl)} -u {quote_arg(url)} "
                f"-H 'Host: FUZZ.{host}' -fs 0",
                f"gobuster vhost -u {quote_arg(url)} -w "
                f"/usr/share/seclists/Discovery/DNS/"
                f"subdomains-top1million-5000.txt",
            ],
            "API & PARAMETERS": [
                f"ffuf -w {quote_arg(wl)} -u {quote_arg(base + '/api/FUZZ')}",
                f"arjun -u {quote_arg(url)} -m GET",
            ],
            "SQL INJECTION": [
                f"sqlmap -u {quote_arg(url)} --forms --batch "
                f"--random-agent --threads 1 --delay 2 --level 2 --risk 2  "
                f"AGGRESSIVE",
                f"sqlmap -u {quote_arg(url)} --dbs --batch "
                f"--random-agent --threads 1 --delay 2  AGGRESSIVE",
            ],
        }, self.suggest_commands())

    def suggest_commands(self) -> dict:
        """Web commands targeted at the web services already found open."""
        from phantom.modules.suggest import web_suggestion_group
        return web_suggestion_group()

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
        cms_detected = set()
        for cmd, output in results.items():
            lo = output.lower()
            if "vulnerable" in lo or "sql injection" in lo:
                vulns += 1
                notifier.warn(f"SQLi likely in: {cmd}")
            if "+ 0 items" not in output and "nikto" in cmd:
                nf = self._extract_nikto_findings(output)
                if nf:
                    vulns += len(nf)
            if "whatweb" in cmd or "whatweb" in lo:
                from phantom.core.knowledge import add_web_app
                for cms in ("wordpress", "joomla", "drupal", "prestashop"):
                    if cms in lo:
                        cms_detected.add(cms)
                        add_web_app(cms, url=f"http://{session.target}/",
                                    source="web")
        if cms_detected:
            notifier.success(
                f"CMS detected: {', '.join(sorted(cms_detected))} — "
                "written to shared knowledge.")
        session.add_note(f"Web: scan complete — {vulns} potential issues logged")

    def _execute_flow(self, _):
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
        from phantom.core.executor import RunStatus
        status = RunStatus()
        results = run_commands(chosen_commands, session.target, status=status)
        session.add_result("web", results, status=status)
        self._analyze_web_results(results)
        notifier.info("Tip: 'hunt' runs the behavioural anomaly engine on "
                      "the web services (confirmed candidates -> reasoning).")

