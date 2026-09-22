"""System commands: help, config, setup, back, exit, quit."""
from __future__ import annotations

import sys

from phantom.core.session import session
import phantom.core.shell as _sh  # live console: _sh.console resolves the package attr at call time (test patch point)
from phantom.core.shell.ui import (
    _engagement_elapsed,
    print_sandbox_status,
    print_toolbelt_status,
    print_transport_status,
)
from phantom.utils.notifier import notifier


def cmd_help(shell, arg: str):
    """help [command] — Show the help panel or details about a specific command."""
    from rich.table import Table
    from rich.panel import Panel

    if arg.strip():
        # Show help for a specific command
        func = getattr(shell, f"do_{arg.strip().replace('-', '_')}", None)
        if func and func.__doc__:
            from rich.markup import escape
            _sh.console.print(Panel(escape(func.__doc__.strip()), title=f"[bold cyan]Help: {arg}[/]", border_style="cyan"))
        else:
            notifier.error(f"No help available for '{arg}'.")
        return

    # ── Session & Config ────────────────────────────────────────────
    t1 = Table(title="[bold white]Session & Config[/]", border_style="blue", show_lines=False)
    t1.add_column("Command", style="cyan", no_wrap=True)
    t1.add_column("Description", style="white")
    t1.add_row("set target <ip>", "Define the testing target")
    t1.add_row("set mode <mode>", "Select workflow: recon, osint, web, exploit, full, deliver")
    t1.add_row("set scope <cidr,...>", "Define authorized testing boundaries")
    t1.add_row("set lhost <ip>", "Set local host IP for callbacks")
    t1.add_row("set lport <port>", "Set local port for callbacks")
    t1.add_row("show session", "Display current session info")
    t1.add_row("config [status|rotate-api-token]", "Auto-generated C2 secrets & mTLS status")
    t1.add_row("setup [status|auto]", "Zero-config wizard: detect transports, write data/config.json")
    t1.add_row("note \"text\"", "Add a timestamped note")
    t1.add_row("notes", "Display all session notes")
    t1.add_row("history", "Show command history")

    # ── Execution ───────────────────────────────────────────────────
    t2 = Table(title="[bold white]Execution[/]", border_style="green", show_lines=False)
    t2.add_column("Command", style="cyan", no_wrap=True)
    t2.add_column("Description", style="white")
    t2.add_row("run", "Adaptive next step (reads target type + findings + reasoning)")
    t2.add_row("run <module>", "Run a specific module directly (e.g. run scan)")
    t2.add_row("suggest", "Evidence-tagged next steps (why + trust + preflight)")
    t2.add_row("plan <goal>", "Lay out the reasoning chain to a goal (beacon/creds/ad/...)")
    t2.add_row("preflight [module]", "Check required tools + install hints")
    t2.add_row("auto <target...>", "Full autonomous kill chain (enumeration -> exploit -> beacon -> persistence)")
    t2.add_row("agent", "Dedicated AUTO-MODE shell (multi-target, flags, plan/resume, .pm)")
    t2.add_row("use <module>", "Enter a module — aliases: s o w e b p h v a r wl (tab-complete)")
    t2.add_row("plugins", "List all loaded external plugins")
    t2.add_row("c2", "Enter the C2 Operations Center")

    # ── Tooling ─────────────────────────────────────────────────
    t2b = Table(title="[bold white]Tooling & Craft[/]", border_style="cyan", show_lines=False)
    t2b.add_column("Command", style="cyan", no_wrap=True)
    t2b.add_column("Description", style="white")
    t2b.add_row("craft ipgrab|reel|image|pixel|beacon|hits|wait", "Build social-engineering lures (IP grabber, zero-click pixel, disguised beacon link)")
    t2b.add_row("map [cidr]", "Discover live hosts on the network and feed the WorldModel")
    t2b.add_row("install <tool>", "Install a missing tool (apt/brew/choco/pip, auto-selected)")
    t2b.add_row("wordlists list|use|search|info", "Manage attack dictionaries (rockyou, seclists, custom)")
    t2b.add_row("ad tree|paths|add-user|add-dc|add-edge|reset", "BloodHound-style AD graph: ingest auto-mode data + manual nodes, shortest paths to Domain Admin")

    # ── Persistence ─────────────────────────────────────────────────
    t3 = Table(title="[bold white]Persistence & Reporting[/]", border_style="yellow", show_lines=False)
    t3.add_column("Command", style="cyan", no_wrap=True)
    t3.add_column("Description", style="white")
    t3.add_row("save-session <name>", "Save current session to disk")
    t3.add_row("load-session <name>", "Load a previously saved session")
    t3.add_row("list-sessions", "List all saved sessions")
    t3.add_row("export-session [<file.pm>]", "Bundle the engagement into one portable .pm file")
    t3.add_row("import-session <file.pm>", "Open a .pm bundle from another operator/machine")
    t3.add_row("save-profile <name>", "Save settings as a reusable profile")
    t3.add_row("load-profile <name>", "Load a profile")
    t3.add_row("export <json|pdf|html>", "Generate a professional report")
    t3.add_row("scan-diff <target>", "Compare scan results over time")

    # ── Modules ─────────────────────────────────────────────────────
    t4 = Table(title="[bold white]Available Modules[/]", border_style="magenta", show_lines=False)
    t4.add_column("Module", style="bold magenta", no_wrap=True)
    t4.add_column("Purpose", style="white")
    t4.add_row("scan", "Active Reconnaissance (nmap, traceroute)")
    t4.add_row("osint", "Passive Intelligence (crt.sh, Shodan, Whois)")
    t4.add_row("wifi", "Wireless Attacks (aircrack-ng, reaver, PMKID)")
    t4.add_row("web", "Web Application Pentest (gobuster, sqlmap, nikto)")
    t4.add_row("brute", "Credential Auditing (hydra, john, hashcat)")
    t4.add_row("exploit", "CVE Correlation & C2 Beacon Deployment")
    t4.add_row("payload", "Payload Generation (msfvenom)")
    t4.add_row("analyzer", "Traffic Analysis (scapy, tshark)")
    t4.add_row("pivot", "Post-Exploitation (SSH tunneling, chisel)")
    t4.add_row("craft", "Social-Engineering Lures (IP grabber, pixel, disguised links)")
    t4.add_row("handler", "Multi/Handler Bridge (Metasploit payload sessions)")
    t4.add_row("telegram", "Telegram C2 channel (bot control plane)")
    t4.add_row("wordlist", "Wordlist Generator & Manager (see: wordlists list)")
    t4.add_row("report", "Report Generation (JSON, PDF, HTML)")
    t4.add_row("c2", "Command & Control Operations Center")
    _sh.console.print()
    _sh.console.print(t1)
    _sh.console.print()
    _sh.console.print(t2)
    _sh.console.print()
    _sh.console.print(t2b)
    _sh.console.print()
    _sh.console.print(t3)
    _sh.console.print()
    _sh.console.print(t4)
    _sh.console.print()
    _sh.console.print("[dim]  Type 'help <command>' for details on a specific command.[/]")
    _sh.console.print("[dim]  Type 'ad paths' for Domain Admin attack paths — 'help ad' for the full AD syntax.[/]")
    _sh.console.print("[dim]  Type 'wordlists list' to manage attack dictionaries.[/]")
    _sh.console.print()
    try:
        from phantom.core.c2_server import c2_state
        n_beacons = len(c2_state.get_beacons())
        _sh.console.print(f"[dim]Phantom v3.0.0 — beacons: {n_beacons} — "
                      f"{_engagement_elapsed()} since session start[/]")
    except Exception:
        _sh.console.print("[dim]Phantom v3.0.0[/]")
    _sh.console.print()


def cmd_config(shell, arg: str):
    """config (status|regenerate-api-token) - Show auto-generated secrets status."""
    from rich.table import Table
    from phantom.utils.state import status as state_status, regenerate_secret
    action = arg.strip().lower()
    if action in ("regenerate", "rotate", "rotate-api-token", "regenerate-api-token"):
        try:
            import secrets as _secrets
            from phantom.utils.c2_crypto import regenerate_api_token
            token = regenerate_api_token()
            notifier.success(f"API token rotated. New value: {token}")
            notifier.warn("Update any external client (Telegram bot, scripts) that holds the old token.")
        except Exception as e:
            notifier.error(f"Rotation failed: {e}")
        return
    if action in ("mtls-on", "mtls off", "mtls-on=true"):
        from phantom.utils.state import set_flag
        set_flag("PHANTOM_MTLS_REQUIRED", True)
        notifier.success("mTLS enabled (secure default). Listener will require HTTPS + client certs.")
        return
    if action in ("mtls-off", "mtls off", "mtls-off=true"):
        from phantom.utils.state import set_flag
        set_flag("PHANTOM_MTLS_REQUIRED", False)
        notifier.warn("mTLS disabled — beacon channel no longer requires client certificates.")
        return
    # default: status
    info = state_status()
    table = Table(title="[bold]Phantom Operator State[/]", border_style="magenta")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="white")
    for key, value in info.items():
        table.add_row(str(key), str(value))
    _sh.console.print(table)
    notifier.info("Secrets live in data/phantom_state.json (gitignored). "
                  "Env vars override persisted values.")


def cmd_setup(shell, arg: str):
    """setup [status|auto] - Detect transports, configure optional channels
    interactively and write data/config.json (no .env editing needed).

    'status'  -> just print which channels are usable right now
    'auto'    -> create data/config.json with defaults, no prompts
    (no arg)  -> interactive wizard for the channels that are missing
    """
    from phantom.automation.social.transports import transport_status
    from phantom.utils import config as cfg

    action = arg.strip().lower()
    if action == "auto":
        cfg.save_config({})
        notifier.success(f"Config defaults written to {cfg.config_path()} "
                         "— zero-config mode ready (local lab + C2).")
        print_transport_status(transport_status())
        return
    if action == "status":
        print_transport_status(transport_status())
        _sh.console.print()
        print_sandbox_status()
        _sh.console.print()
        print_toolbelt_status()
        notifier.info("Run 'setup' to configure the missing channels, "
                      "or 'setup auto' for defaults only.")
        return

    status = transport_status()
    print_transport_status(status)
    _sh.console.print()
    notifier.info("Configure the optional external channels "
                  "(leave blank to keep current / skip).")

    def _ask(key: str, label: str, env: str, default: str = "") -> str:
        cur = str(cfg.get(key, "", env=env) or "")
        shown = cur or default          # detected suggestion, editable
        try:
            v = input(f"  {label} [{shown}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return cur
        if not v:
            if not cur and default:
                cfg.set(key, default)   # accept the detected value
                return default
            return cur
        cfg.set(key, v)
        return v

    def _yn(prompt: str) -> bool:
        try:
            v = input(f"  {prompt} [y/N]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        return v in ("y", "yes")

    _sh.console.print("[bold cyan]-- Email (phishing / email-to-SMS) --[/]")
    _ask("transports.smtp.host", "SMTP host", "PHANTOM_SMTP_HOST")
    _ask("transports.smtp.port", "SMTP port", "PHANTOM_SMTP_PORT")
    _ask("transports.smtp.username", "SMTP username", "PHANTOM_SMTP_USER")
    _ask("transports.smtp.password", "SMTP password", "PHANTOM_SMTP_PASSWORD")
    _sh.console.print("[bold cyan]-- SMS (email-to-SMS carrier) --[/]")
    _ask("transports.sms_carrier", "Carrier (verizon|att|tmobile|...)",
         "PHANTOM_SMS_CARRIER")
    _sh.console.print("[bold cyan]-- DM (Telegram / Discord / custom) --[/]")
    _ask("transports.telegram_bot_token", "Telegram bot token",
         "PHANTOM_TELEGRAM_BOT_TOKEN")
    _ask("transports.discord_webhook", "Discord webhook URL",
         "PHANTOM_DISCORD_WEBHOOK")
    _sh.console.print("[bold cyan]-- C2 callback address --[/]")
    # This is the address embedded in the BEACON and in the dropper's
    # payload URL: it must be reachable BY THE TARGET, never loopback.
    notifier.info("Address the beacon calls back to (public IP or your "
                  "domain). Leave blank to auto-detect; set it whenever "
                  "the target is not on your LAN — with 127.0.0.1 the "
                  "beacon dials itself and the dropper link is dead.")
    _ask("c2.host", "C2 host for the beacon (public IP or domain)",
         "PHANTOM_C2_HOST")
    _sh.console.print("[bold cyan]-- Tracker / lure delivery --[/]")
    # OPSEC: this is the URL a VICTIM and any SOC analyst will read in
    # the lure. A raw IP (LAN or public) exposes the operator's box and
    # screams "attack" — a DOMAIN with TLS is the only real answer.
    notifier.info("This URL ends up in the victim's mail headers. Prefer "
                  "a lookalike DOMAIN with TLS (the domain IS the "
                  "camouflage for a reel/short link); a bare IP is "
                  "readable and looks like an attack. Leave blank for "
                  "lab-only (real lure delivery stays blocked).")
    _ask("tracker.public_url",
         "Public tracker URL (e.g. https://ig-video-cdn.net)",
         "PHANTOM_TRACK_URL")
    try:
        from phantom.automation.social.tracker import (
            tracker_opsec_warnings,
        )
        for _w in tracker_opsec_warnings():
            notifier.warn(_w)
    except Exception:
        pass
    _sh.console.print("[bold cyan]-- Breach lookup --[/]")
    _ask("breach.hibp_api_key", "HIBP API key (optional)",
         "PHANTOM_HIBP_API_KEY")
    _ask("breach.custom_api", "Custom breach API base URL (optional)",
         "PHANTOM_BREACH_API")
    _sh.console.print("[bold cyan]-- Payload sandbox / AV validation --[/]")
    notifier.info("Optional: multi-engine + VM detonation makes the payload "
                 "gate stronger (ClamAV/YARA run when installed).")
    _ask("sandbox.yara_rules", "YARA rules file or directory",
         "PHANTOM_YARA_RULES")
    _ask("sandbox.vm_exec", "VM exec wrapper (e.g. ssh user@vm)",
         "PHANTOM_SANDBOX_VM_EXEC")
    _ask("sandbox.vm_copy", "VM copy command (e.g. scp -i key {local} {remote})",
         "PHANTOM_SANDBOX_VM_COPY")
    _ask("sandbox.vm_edr", "EDR/AV running in the VM (label, e.g. CrowdStrike)",
         "PHANTOM_SANDBOX_VM_EDR")
    _sh.console.print("[bold cyan]-- Engagement gates --[/]")
    if _yn("Allow unscoped commands (lab/CTF only)"):
        cfg.set("engagement.allow_unscoped", True)
    if _yn("Allow ransomware simulation (scratch dirs only)"):
        cfg.set("engagement.ransom_sim_allow", True)

    cfg.reload_config()
    _sh.console.print()
    notifier.success(f"Config saved to {cfg.config_path()}")
    print_transport_status(transport_status())
    _sh.console.print()
    print_sandbox_status()


def cmd_back(shell, arg: str):
    """Return to main shell (already here)"""
    notifier.warn("Already at main shell.")


def cmd_exit(shell, arg: str):
    """exit - Exit Phantom, optionally save current session and generate professional report"""
    if session.target:
        note = input("\n[?] Add a final manual note for the report? (empty to skip): ").strip()
        if note:
            session.add_note(note)

        confirm = input("[?] Save session and generate professional report? [y/N]: ").strip().lower()
        if confirm == "y":
            name = input("[?] Report/Session name (default: auto): ").strip() or "auto"
            session.save(name)
            # Generate professional markdown report with full context
            from phantom.modules.report import ReportModule
            rm = ReportModule()
            rm.export("json", f"{name}.json")
            session.export_markdown(f"{name}.md")
            notifier.success(f"Professional report saved: {name}.md")

    notifier.status("Exiting Phantom...")
    sys.exit(0)


def cmd_quit(shell, arg: str):
    return cmd_exit(shell, arg)


# `quit` has no own docstring in the original shell (it delegates to exit);
# expose the exit help text so `help quit` stays useful.
cmd_quit.__doc__ = cmd_exit.__doc__


COMMANDS = {
    "help": cmd_help,
    "config": cmd_config,
    "setup": cmd_setup,
    "back": cmd_back,
    "exit": cmd_exit,
    "quit": cmd_quit,
}
