import dns.resolver
import re
from phantom.modules.base_module import BaseModule
from phantom.core.preview import PreviewSession
from phantom.core.executor import run_commands, run_command
from phantom.core.session import session
from phantom.utils.api import crtsh_lookup, shodan_lookup, bgp_lookup, with_backoff
from rich.console import Console
from rich.table import Table
import requests

from phantom.utils.notifier import notifier

console = Console()


class OsintModule(BaseModule):
    module_name = "osint"

    # Critical Dorks (Passive Intelligence)
    DORKS = [
        "port:502",          # Modbus
        "\"default password\"",
        "product:\"MongoDB\" port:27017",
        "\"X-Powered-By: PHP/5.2\"",
    ]

    def build_commands(self) -> dict:
        """Return the command groups for OSINT enumeration."""
        t = session.target
        if not t:
            return {}

        groups = {}

        # CONTROLLO CONTESTO: Se contiene '_' o '@', è un handle social, non un dominio/IP
        is_social_target = "_" in t or "@" in t

        if not is_social_target:
            # Popola i comandi infrastrutturali SOLO se è un vero dominio o IP
            groups["WHOIS / DNS"] = [
                f"whois {t}",
                f"host {t}",
                f"dig {t} ANY +short",
                f"dig {t} MX +short",
                f"dig {t} TXT +short",
                f"dnsrecon -d {t} -t std",
            ]
            groups["SUBDOMAIN ENUM"] = [
                f"amass enum -d {t} -passive",
                f"subfinder -d {t} -silent",
                f"assetfinder --subs-only {t}",
                f"theHarvester -d {t} -l 500 -b all",
            ]
            groups["DORKING (Shodan)"] = [
                f"shodan search \"net:{t}\"",
                f"shodan search \"org:'{t}'\"",
                f"shodan stats \"net:{t}\"",
            ] + [f"shodan search \"{dork} net:{t}\"" for dork in self.DORKS]
            groups["VULNERABILITY SEARCH"] = [
                f"shodan search \"vuln:CVE-2024- net:{t}\"",
                f"shodan search \"has_vuln:true net:{t}\"",
            ]

        # Add Sherlock se il target è un candidato username valido
        username = self._get_username(t)
        if username:
            groups["USERNAME SEARCH"] = [
                f"sherlock {username} --timeout 5 --print-found"
            ]

        return groups

    def _get_username(self, target: str) -> str:
        """Extract a potential username from the target string without breaking social handles."""
        if not target: 
            return ""
        
        import ipaddress
        try:
            ipaddress.ip_address(target)
            return "" # Un IP non è un username
        except ValueError:
            # Se contiene caratteri tipici dei social, l'username è l'intero target (pulito da eventuali @)
            if "_" in target or "@" in target:
                return target.lstrip("@")
            
            # Se è un dominio classico (es. azienda.com), prendiamo solo la prima parte
            return target.split('.')[0] if '.' in target else target

    def do_sherlock(self, args):
        """sherlock [username] - Search social media for a username."""
        username = args.strip() or self._get_username(session.target)
        if not username:
            notifier.error("No username provided and target is not a valid username candidate.")
            return
        
        notifier.status(f"Running Sherlock for username: {username}...")
        cmd = f"sherlock {username} --timeout 5 --print-found"
        output = run_command(cmd)
        
        # Parse output for found social links
        links = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', output)
        if links:
            notifier.success(f"Found {len(links)} social profiles!")
            existing = session.get_result("osint") or {}
            existing["social_profiles"] = links
            session.add_result("osint", existing)
            for link in links[:10]:
                console.print(f"  [cyan]{link}[/]")
            if len(links) > 10:
                notifier.info(f"... and {len(links)-10} more.")
        else:
            notifier.info("No social profiles found with Sherlock.")

    def do_shodan(self, query):
        """shodan <query> - Execute a Shodan search (Key required in session config)."""
        api_key = session.results.get("config", {}).get("shodan_key", "")
        if not api_key:
            notifier.warn("Shodan API key not found. Run 'set-key <key>' or use free InternetDB lookups.")
            return

        def _call():
            url = "https://api.shodan.io/shodan/host/search"
            return requests.get(url, params={"key": api_key, "query": query}, timeout=15)

        try:
            resp = with_backoff(_call)()
            if resp:
                data = resp.json()
                self._display_shodan_results(data)
                session.add_result("shodan_dork", data)
        except Exception as e:
            notifier.error(f"Shodan error: {e}")

    def do_set_key(self, key):
        """set-key <key> - Save Shodan API key for the session."""
        config = session.results.get("config", {})
        config["shodan_key"] = key.strip()
        session.add_result("config", config)
        notifier.success("Shodan key saved.")

    def _display_shodan_results(self, data):
        table = Table(title="Shodan Insights")
        table.add_column("IP", style="bold")
        table.add_column("Port", style="green")
        table.add_column("Data")
        for m in data.get("matches", [])[:10]:
            table.add_row(m.get("ip_str"), str(m.get("port")), m.get("data", "")[:50].replace("\n", " "))
        console.print(table)

    def do_preview(self, _):
        """Show preview, let user edit, then execute selected commands."""
        if not session.target:
            notifier.error("No target set. Use 'set target <domain/ip/username>' first.")
            return

        groups = self.build_commands()
        if not groups:
            return

        preview = PreviewSession(groups)
        chosen_commands = preview.interactive()
        if chosen_commands is None:
            notifier.warn("OSINT cancelled.")
            return

        notifier.status(f"Starting OSINT sequence for {session.target}...")
        results = run_commands(chosen_commands, session.target)
        session.add_result("osint", results)

        # Esegue l'estrazione automatica via API solo se NON siamo in un contesto puramente social
        if not ("_" in session.target or "@" in session.target):
            self._extract_dns_intel(session.target)
            self._run_api_lookups()
        else:
            notifier.info("Social handle detected. Automated DNS/Network lookups skipped.")

    def do_run(self, _):
        """Alias for do_preview."""
        self.do_preview(_)

    def _extract_dns_intel(self, domain):
        """Extract emails/phones/intel from TXT and MX records using dnspython."""
        notifier.status(f"Extracting DNS intelligence for {domain}...")
        intel = {"emails": set(), "phones": set(), "notes": []}
        
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt = str(rdata)
                emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', txt)
                for e in emails: intel["emails"].add(e)
                phones = re.findall(r'\+?[0-9]{7,15}', txt)
                for p in phones: intel["phones"].add(p)
                if "v=spf1" in txt:
                    intel["notes"].append(f"SPF record found: {txt[:50]}...")
        except Exception:
            pass

        try:
            answers = dns.resolver.resolve(domain, 'MX')
            for rdata in answers:
                mx_host = str(rdata.exchange)
                intel["notes"].append(f"MX host: {mx_host}")
        except Exception:
            pass

        if intel["emails"] or intel["phones"] or intel["notes"]:
            table = Table(title="DNS Intelligence Results")
            table.add_column("Type", style="bold magenta")
            table.add_column("Value", style="white")
            for e in intel["emails"]: table.add_row("Email", e)
            for p in intel["phones"]: table.add_row("Phone", p)
            for n in intel["notes"]: table.add_row("Note", n)
            console.print(table)
            
            existing = session.get_result("osint") or {}
            existing["dns_intel"] = {
                "emails": list(intel["emails"]),
                "phones": list(intel["phones"]),
                "notes": intel["notes"]
            }
            session.add_result("osint", existing)
        else:
            notifier.info("No specific intel found in DNS records.")

    def _run_api_lookups(self):
        """Perform crt.sh, Shodan, BGP lookups and store results."""
        t = session.target
        notifier.status("Running API-based lookups (crt.sh, Shodan, BGP)...")

        # crt.sh
        subdomains = crtsh_lookup(t)
        if subdomains:
            notifier.success(f"crt.sh found {len(subdomains)} subdomains.")
            existing = session.get_result("osint") or {}
            existing["crt_sh_subdomains"] = subdomains
            session.add_result("osint", existing)
            
            table = Table(title="Subdomains from crt.sh")
            table.add_column("Subdomain", style="cyan")
            for sd in subdomains[:10]:
                table.add_row(sd)
            console.print(table)
            if len(subdomains) > 10:
                notifier.info(f"... and {len(subdomains)-10} more")

        # Shodan lookup (if target is IP)
        try:
            import ipaddress
            ipaddress.ip_address(t)
            shodan_data = shodan_lookup(t)
            if shodan_data:
                notifier.success("Shodan data retrieved.")
                existing = session.get_result("osint") or {}
                existing["shodan"] = shodan_data
                session.add_result("osint", existing)
                ports = shodan_data.get("ports", [])
                if ports:
                    notifier.info(f"Open ports: {', '.join(map(str, ports[:10]))}")
        except ValueError:
            pass

        # BGP lookup
        bgp_data = bgp_lookup(t)
        if bgp_data:
            notifier.success("BGP info retrieved.")
            existing = session.get_result("osint") or {}
            existing["bgp"] = bgp_data
            session.add_result("osint", existing)
            if "asn" in bgp_data:
                notifier.info(f"ASN: {bgp_data['asn']} - {bgp_data.get('name', '')}")

    def do_crtsh(self, _):
        """crtsh — manual lookup of subdomains via crt.sh."""
        t = session.target
        if not t:
            notifier.error("No target set.")
            return
        if "_" in t or "@" in t:
            notifier.error("crt.sh lookup is only available for domains.")
            return
        subdomains = crtsh_lookup(t)
        if subdomains:
            for sd in subdomains:
                console.print(f"  [cyan]{sd}[/]")
        else:
            notifier.warn("No subdomains found or API error.")

    def do_diff(self, args):
        """diff <session1> <session2> - Compare OSINT results between two saved sessions."""
        parts = args.split()
        if len(parts) < 2:
            notifier.error("Usage: diff <session_old> <session_new>")
            return

        s1_name, s2_name = parts[0], parts[1]
        raw1 = session.load_raw(s1_name)
        raw2 = session.load_raw(s2_name)

        if not raw1 or not raw2:
            raw1_status = "Loaded" if raw1 else "Failed"
            raw2_status = "Loaded" if raw2 else "Failed"
            notifier.error(f"Session loading issue. Session 1: {raw1_status}, Session 2: {raw2_status}")
            return

        res1 = raw1.get("results", {}).get("osint", {})
        res2 = raw2.get("results", {}).get("osint", {})

        if not res1 and not res2:
            notifier.warn("No OSINT results found in either session.")
            return

        console.print(f"\n[bold cyan]OSINT Diff: {s1_name} → {s2_name}[/]\n")

        # 1. Subdomains
        sd1 = set(res1.get("crt_sh_subdomains", []))
        sd2 = set(res2.get("crt_sh_subdomains", []))
        self._print_diff_table("Subdomains", sd1, sd2)

        # 2. Social Profiles
        sp1 = set(res1.get("social_profiles", []))
        sp2 = set(res2.get("social_profiles", []))
        self._print_diff_table("Social Profiles", sp1, sp2)

        # 3. DNS Intel (Emails)
        em1 = set(res1.get("dns_intel", {}).get("emails", []))
        em2 = set(res2.get("dns_intel", {}).get("emails", []))
        self._print_diff_table("DNS: Emails", em1, em2)

        # 4. DNS Intel (Phones)
        ph1 = set(res1.get("dns_intel", {}).get("phones", []))
        ph2 = set(res2.get("dns_intel", {}).get("phones", []))
        self._print_diff_table("DNS: Phones", ph1, ph2)

    def _print_diff_table(self, title, old_set, new_set):
        """Helper to print added/removed items in a table."""
        added = new_set - old_set
        removed = old_set - new_set

        if not added and not removed:
            return

        table = Table(title=f"Diff: {title}")
        table.add_column("Status", style="bold")
        table.add_column("Value")

        for item in added:
            table.add_row("[green][+][/]", item)
        for item in removed:
            table.add_row("[red][-][/]", item)

        console.print(table)