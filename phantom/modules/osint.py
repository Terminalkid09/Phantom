from phantom.modules.base_module import BaseModule
from phantom.core.preview import PreviewSession
from phantom.core.executor import run_commands
from phantom.core.session import session
from phantom.utils.api import crtsh_lookup, shodan_lookup, bgp_lookup
from rich.console import Console
from rich.table import Table

console = Console()


class OsintModule(BaseModule):
    module_name = "osint"

    def build_commands(self) -> dict:
        """Return the command groups for OSINT enumeration."""
        t = session.target
        if not t:
            return {}

        return {
            "WHOIS / DNS": [
                f"whois {t}",
                f"host {t}",
                f"dig {t} ANY",
                f"dig {t} MX",
                f"dig {t} TXT",
                f"dig {t} NS",
                f"dig -x {t}",
                f"nslookup {t}",
            ],
            "SUBDOMAIN ENUM": [
                f"amass enum -d {t}",
                f"subfinder -d {t}",
                f"assetfinder {t}",
                f"dnsenum {t}",
                f"dnsrecon -d {t}",
                f"fierce --domain {t}",
            ],
            "WEB FINGERPRINT": [
                f"curl -I http://{t}",
                f"curl -I https://{t}",
                f"whatweb {t}",
                f"wafw00f {t}",
                f"nikto -h {t}",
            ],
            "CERTIFICATE": [
                f"openssl s_client -connect {t}:443 2>/dev/null | openssl x509 -noout -text",
            ],
        }

    def do_preview(self, _):
        """Show preview, let user edit, then execute selected commands."""
        if not session.target:
            console.print("[red][!] No target set. Use 'set target <domain/ip>' first.[/]")
            return

        groups = self.build_commands()
        if not groups:
            return

        preview = PreviewSession(groups)
        chosen_commands = preview.interactive()
        if chosen_commands is None:
            console.print("[yellow]OSINT cancelled.[/]")
            return

        # No aggressive commands in base OSINT, but execute anyway
        results = run_commands(chosen_commands, session.target)
        session.add_result("osint", results)

        # Additionally, run APIbased lookups automatically (unless user cancelled)
        self._run_api_lookups()

    def do_run(self, _):
        """Alias for do_preview."""
        self.do_preview(_)

    def _run_api_lookups(self):
        """Perform crt.sh, Shodan, BGP lookups and store results."""
        t = session.target
        console.print("\n[cyan][*] Running API-based lookups (crt.sh, Shodan, BGP)...[/]")

        # crt.sh
        subdomains = crtsh_lookup(t)
        if subdomains:
            console.print(f"[green][+] crt.sh found {len(subdomains)} subdomains.[/]")
            # Store as part of osint results
            existing = session.get_result("osint") or {}
            existing["crt_sh_subdomains"] = subdomains
            session.add_result("osint", existing)
            # Show first 10 in table
            table = Table(title="Subdomains from crt.sh")
            table.add_column("Subdomain", style="cyan")
            for sd in subdomains[:10]:
                table.add_row(sd)
            console.print(table)
            if len(subdomains) > 10:
                console.print(f"[dim]... and {len(subdomains)-10} more[/]")

        # Shodan lookup (if target is IP)
        try:
            import ipaddress
            ipaddress.ip_address(t)  # will raise if domain
            shodan_data = shodan_lookup(t)
            if shodan_data:
                console.print("[green][+] Shodan data retrieved.[/]")
                # Store minimal info
                existing = session.get_result("osint") or {}
                existing["shodan"] = shodan_data
                session.add_result("osint", existing)
                # Brief summary
                ports = shodan_data.get("ports", [])
                if ports:
                    console.print(f"    Open ports: {', '.join(map(str, ports[:10]))}")
        except ValueError:
            # domain name, skip Shodan
            pass

        # BGP lookup for IP or ASN
        bgp_data = bgp_lookup(t)
        if bgp_data:
            console.print("[green][+] BGP info retrieved.[/]")
            existing = session.get_result("osint") or {}
            existing["bgp"] = bgp_data
            session.add_result("osint", existing)
            if "asn" in bgp_data:
                console.print(f"    ASN: {bgp_data['asn']} - {bgp_data.get('name', '')}")

    def do_crtsh(self, _):
        """crtsh — manual lookup of subdomains via crt.sh."""
        t = session.target
        if not t:
            console.print("[red]No target set.[/]")
            return
        subdomains = crtsh_lookup(t)
        if subdomains:
            for sd in subdomains:
                console.print(f"  [cyan]{sd}[/]")
        else:
            console.print("[yellow]No subdomains found or API error.[/]")

    def do_diff(self, args):
        """
        diff <session1> <session2>
        Compare OSINT results between two saved sessions (stub).
        """
        console.print("[yellow]OSINT diff not yet implemented.[/]")
        # To be implemented: load two session JSONs, compare notes/ results