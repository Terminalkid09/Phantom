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
    t1.add_row("config dead-drop <url>", "Beacon last-ring endpoint source (survives a dead C2 forever)")
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
    t2.add_row("why [capability] [--trace <cp>]", "Why did the agent do/veto that move? Decision trace, live or from a checkpoint")
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
    t2b.add_row("tool list|import <binary>|approve <id>|enable <id>|disable <id>", "Runtime tool drivers: discover a new tool (probe --help/--version only), review, approve, enable")
    t2b.add_row("wordlists list|use|search|info", "Manage attack dictionaries (rockyou, seclists, custom)")
    t2b.add_row("ad tree|paths|add-user|add-dc|add-edge|reset", "BloodHound-style AD graph: ingest auto-mode data + manual nodes, shortest paths to Domain Admin")
    t2b.add_row("coverage [profile]", "Audit that every declared capability/goal/phase actually resolves (catches silent plan dead-ends)")
    t2b.add_row("doctor [--net]", "Environmental self-check: toolchain, config, data dir, learning store (offline; --net probes C2/msf/dead-drop)")
    t2b.add_row("experience [list|forget]", "Inspect the learning memory: episodes, causes, repairs — forget what should not persist")

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
    t3.add_row("run-diff <cpA> <cpB>", "Structured diff of two run checkpoints: findings gained/lost, walls resolved/new, verdict")

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
    # NB: the legacy Telegram C2 module/channel is NOT listed here on
    # purpose — it is currently UNMAINTAINED (see README, "Telegram C2
    # (unmaintained)"). The code stays importable for whoever needs it;
    # it is just not part of the documented surface anymore.
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


def _cmd_config_dead_drop(parts) -> None:
    """Operate the last-ring dead drop (see phantom.utils.dead_drop).

    `config dead-drop`              -> what is configured + the live record
    `config dead-drop <url>`        -> set the record URL
    `config dead-drop publish [<host> <port> [http]]`
                                    -> write the record at that URL; with no
                                       host/port it publishes the endpoint a
                                       beacon would dial NOW (`c2.front` when
                                       set), so rotating the indirection is
                                       one command and needs no rebuild
    """
    from phantom.utils import config as cfg
    from phantom.utils import dead_drop as dd

    sub = parts[1].lower() if len(parts) > 1 else ""
    if sub == "publish":
        url = dd.configured_url()
        if not url:
            notifier.error("No dead-drop URL configured.",
                           hint="run 'config dead-drop <url>' first")
            return
        rest = parts[2:]
        use_ssl = not (len(rest) > 2 and rest[2].lower() in ("http", "no-tls"))
        if len(rest) >= 2:
            host = rest[0]
            try:
                port = int(rest[1])
            except ValueError:
                notifier.error(f"Invalid port: '{rest[1]}'.",
                               hint="the port must be a number, 1-65535")
                return
        elif not rest:
            from phantom.utils.network import get_c2_endpoint
            host, port = get_c2_endpoint()
            use_ssl = cfg.get_bool("c2.ssl", True)
            if not host:
                notifier.error("No C2 endpoint to publish.",
                               hint="set c2.front (or c2.host), or pass "
                                    "'publish <host> <port>'")
                return
        else:
            notifier.usage("config dead-drop publish",
                           "[<host> <port> [http]]",
                           "with no arguments it publishes the endpoint a "
                           "beacon would dial now (c2.front when set)")
            return
        if dd.publish(url, host, port, use_ssl):
            notifier.success(
                f"Dead drop updated: beacon '{host}:{port}' "
                f"({'https' if use_ssl else 'http'}) at {url}")
        else:
            notifier.error(f"Publish failed for {url}.",
                           hint="the dead drop is not live, so the beacon's "
                                "last ring would never rotate — check the "
                                "URL and its credentials")
        return
    if len(parts) > 1:
        url = parts[1]
        if not url.lower().startswith(("http://", "https://")):
            notifier.error(f"Not a URL: '{url}'.",
                           hint="an http(s) URL (a paste endpoint, an S3 "
                                "presigned PUT, any object you control)")
            return
        cfg.set("c2.dead_drop", url)
        cfg.reload_config()
        notifier.success(f"Dead drop set to {url}.")
        notifier.info("It is embedded in the beacon at BUILD time: "
                      "rebuild the beacon for it to take effect.")
        return
    url = dd.configured_url()
    if not url:
        notifier.warn("No dead drop configured.")
        notifier.info("Set one with 'config dead-drop <url>': the beacon "
                      "consults it ONLY after the whole C2 ladder failed, "
                      "to fetch a fresh endpoint.")
        return
    notifier.info(f"Dead drop: {url}")
    live = dd.fetch(url)
    if live:
        notifier.success(f"Live record: beacon {live['host']}:{live['port']} "
                         f"({'https' if live['use_ssl'] else 'http'})")
    else:
        notifier.warn("No readable record at that URL — the beacon would "
                      "have no endpoint to rotate to.")
        notifier.info("Publish one with: config dead-drop publish "
                      "<host> <port>")


def _cmd_config_keys(parts) -> None:
    """`config keys` sub-handler — manage external-service credentials.

    config keys                     -> list every declared key + its state
    config keys set <name> <value>  -> persist a key to data/config.json
    config keys clear <name>        -> remove a persisted key

    Values are written to data/config.json (never .env); the legacy
    PHANTOM_* env var, when set, still wins over the file.
    """
    from rich.table import Table
    from phantom.utils import api_keys

    if not parts or parts[0].lower() in ("list", "ls", "status"):
        st = api_keys.status()
        table = Table(title="[bold]External service keys[/]",
                      border_style="magenta")
        table.add_column("Name", style="cyan")
        table.add_column("Service", style="white")
        table.add_column("State", style="white")
        table.add_column("Value", style="dim")
        table.add_column("Env override", style="dim")
        for name, info in st.items():
            state = "set" if info["configured"] else "—"
            if info["source"] == "env":
                state = "set (env)"
            table.add_row(name, info["label"], state,
                          info["masked"] or "", info["env"])
        _sh.console.print(table)
        notifier.info("Set one with: config keys set <name> <value>. "
                      "Keys persist in data/config.json (no .env editing).")
        return

    verb = parts[0].lower()
    if verb in ("set", "add"):
        if len(parts) < 3:
            notifier.error("Usage: config keys set <name> <value>")
            return
        name, value = parts[1].lower(), " ".join(parts[2:])
        if name not in api_keys.KEY_REGISTRY:
            notifier.error(f"Unknown key '{name}'. Known: "
                           f"{', '.join(api_keys.names())}")
            return
        try:
            api_keys.set(name, value)
        except Exception as e:
            notifier.error(f"Could not save '{name}': {e}")
            return
        notifier.success(f"{api_keys.KEY_REGISTRY[name]['label']} key saved "
                         f"to data/config.json ({api_keys.mask(value)}).")
        return
    if verb in ("clear", "unset", "remove", "rm"):
        if len(parts) < 2:
            notifier.error("Usage: config keys clear <name>")
            return
        name = parts[1].lower()
        if name not in api_keys.KEY_REGISTRY:
            notifier.error(f"Unknown key '{name}'. Known: "
                           f"{', '.join(api_keys.names())}")
            return
        api_keys.set(name, "")
        notifier.warn(f"{name} cleared from data/config.json "
                      "(env override, if any, still applies).")
        return
    notifier.error("Usage: config keys [list|set <name> <value>|clear <name>]")


def _cmd_config_drivers(parts) -> None:
    """`config drivers` — inspect the runtime-discovered tool drivers.

    config drivers        -> every manifest found + the dirs that were scanned

    A driver is a JSON manifest that turns a tool Phantom has never shipped
    into a live capability: it declares the binary, the command template and
    the output markers. Drop one in data/drivers/ (gitignored) and it is
    planned like any built-in move.
    """
    from rich.table import Table
    from phantom.automation.runtime import drivers as drv

    rows = drv.driver_summary()
    if not rows:
        notifier.info("No tool drivers found. Drop a JSON manifest in "
                      "data/drivers/ (or toolbelt.drivers_dir) to register "
                      "a tool Phantom has never seen.")
    else:
        table = Table(title="[bold]Discovered tool drivers[/]",
                      border_style="magenta")
        table.add_column("Capability", style="cyan")
        table.add_column("Tool", style="white")
        table.add_column("Category", style="white")
        table.add_column("Approved", style="white")
        table.add_column("Effects", style="dim")
        table.add_column("Manifest", style="dim")
        for row in rows:
            table.add_row(row["id"], row["tool"], row["category"],
                          "yes" if row.get("approved") else "no",
                          ", ".join(row["effects"]),
                          row["source"] or "-")
        _sh.console.print(table)
        unapproved = [r["id"] for r in rows if not r.get("approved")]
        if unapproved:
            notifier.warn(
                "Not approved (inert — the planner will not run them): "
                + ", ".join(unapproved)
                + "\nApprove by adding the id to toolbelt.approved in "
                  "data/config.json (or via PHANTOM_APPROVED_DRIVERS).")
    notifier.info("Scanned: " + ", ".join(drv.driver_dirs()))


def cmd_config(shell, arg: str):
    """config [status|rotate-api-token|keys|dead-drop <url>|dead-drop publish <host> <port>] - Operator state.

    'keys' manages external-service credentials (Shodan, NVD, GitHub, HIBP,
    breach aggregator) in data/config.json, so no .env editing is needed.

    'dead-drop' manages the beacon's endpoint indirection: one neutral URL
    holding the current C2 endpoint, consulted BEFORE the first check-in when
    `c2.bootstrap_dead_drop` is on (and after every ladder rung has failed
    otherwise), so the indirection can be rotated without a rebuild. The URL
    itself is baked into the beacon at build time.
    """
    from rich.table import Table
    from phantom.utils.state import status as state_status, regenerate_secret
    action = arg.strip().lower()
    _parts = arg.strip().split()
    if _parts and _parts[0].lower() in ("dead-drop", "dead_drop", "deaddrop"):
        _cmd_config_dead_drop(_parts)
        return
    if _parts and _parts[0].lower() in ("keys", "key", "apikeys", "api-keys"):
        _cmd_config_keys(_parts[1:])
        return
    if _parts and _parts[0].lower() in ("drivers", "driver", "tools"):
        _cmd_config_drivers(_parts[1:])
        return
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


def cmd_coverage(shell, arg: str):
    """coverage [profile] - Capability coverage audit.

    Checks that every DECLARATIVE name still refers to a working path:
    the planner's fact->capability index, the thin-surface policy, the
    swarm chain facts and every engagement profile's phases. These are
    plain strings, so a rename or a dropped fact silently turns a real
    plan into "no affordable path to goal" — this command makes that
    class of failure visible instead of quiet.

    With no argument it audits every profile; `coverage mobile` shows one.
    """
    from phantom.automation.swarm.coverage import (
        audit,
        coverage_for_profile,
        format_report,
    )

    target = arg.strip().lower()
    try:
        if target:
            row = coverage_for_profile(target)
            if not row.chain:
                from phantom.automation.swarm.profile_policy import POLICY
                notifier.unknown("profile", target, sorted(POLICY.keys()),
                                 hint="run 'coverage' for every profile")
                return
            report = format_report(audit())
            state = "ok" if row.ok else "GAP"
            _sh.console.print(
                f"coverage[{target}]: {state} chain={row.chain} "
                f"thin={row.thin_surface or '-'}", markup=False)
            if row.unreachable:
                _sh.console.print(
                    f"  unreachable phases: {list(row.unreachable)}",
                    markup=False)
            if row.thin_caps_missing:
                _sh.console.print(
                    "  thin-surface caps missing: "
                    f"{list(row.thin_caps_missing)}", markup=False)
            _sh.console.print(report, markup=False)
            if not row.ok:
                notifier.warn("Profile gap: the plan cannot reach every "
                              "phase this class declares.")
            return
        report = format_report(audit())
        _sh.console.print(report, markup=False)
        if report.ok:
            notifier.success("All declared paths resolve.")
        else:
            notifier.warn("Declaration gaps found — see the report above.")
    except Exception as exc:
        notifier.error(f"Coverage audit failed: {exc}")


def cmd_experience(shell, arg: str):
    """experience [list [N] | forget <N> | forget all] - Learning memory.

    The case-based EXPERIENCE memory is what makes Phantom improve with
    use: every run records (situation, technique, outcome, cause, repair)
    episodes and the planner reorders already-allowed moves so a wall hit
    once is not hit the same way again. Cross-engagement persistence is
    ON by default (automation.experience / --no-experience on a run),
    stored in data/experience_cases.json — local disk only.

      experience            status: totals, top causes, top repairs
      experience list [N]   the last N episodes (default 15)
      experience forget N   drop episode #N from `experience list`
      experience forget all wipe the whole memory (starts from zero)
    """
    from phantom.automation.brain.experience import Experience
    from phantom.automation.brain.experience.cases import experience_path

    parts = arg.split()
    sub = parts[0].lower() if parts else ""
    if sub == "forget":
        if len(parts) < 2 or (parts[1].lower() != "all"
                              and not parts[1].isdigit()):
            notifier.usage("experience forget", "<N | all>",
                           hint="N is the row number from 'experience list'")
            return
        store = Experience(enabled=True, path=experience_path())
        cs = store.store          # the CaseStore underneath
        eps = cs.episodes
        if not eps:
            notifier.info("Memory already empty — nothing to forget.")
            return
        if parts[1].lower() == "all":
            cs.clear()
            notifier.success(f"Memory wiped: {len(eps)} episode(s) dropped.")
            return
        idx = int(parts[1])
        if not (1 <= idx <= len(eps)):
            notifier.unknown("episode", str(idx),
                             [f"1..{len(eps)} (oldest first)"],
                             hint="run 'experience list' to see the rows")
            return
        dropped = eps[idx - 1]
        with cs._lock:
            cs._episodes = [e for j, e in enumerate(eps) if j != idx - 1]
        cs.save()
        notifier.success(f"Forgot episode #{idx}: {dropped.technique} "
                         f"({'ok' if dropped.ok else dropped.cause}).")
        return
    if sub == "list":
        n = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 15
        store = Experience(enabled=True, path=experience_path())
        rows = store.recent(n)
        if not rows:
            notifier.info("No episodes yet — run an auto/agent engagement "
                          "and this fills up.")
            return
        from rich.table import Table
        t = Table(title=f"[bold white]Last {len(rows)} episode(s)[/]",
                  border_style="blue", show_lines=False)
        t.add_column("#", style="dim", no_wrap=True)
        t.add_column("Phase", style="cyan", no_wrap=True)
        t.add_column("Technique", style="white", no_wrap=True)
        t.add_column("Outcome", no_wrap=True)
        t.add_column("Repair", style="green")
        t.add_column("Detail")
        base = max(1, len(store.store.episodes) - len(rows) + 1)
        for i, r in enumerate(rows):
            t.add_row(str(base + i), r.get("phase") or "-",
                      r.get("technique") or "-",
                      "[green]ok[/]" if r.get("ok")
                      else f"[red]{r.get('cause') or 'fail'}[/]",
                      r.get("repair") or "-",
                      (r.get("detail") or "")[:60])
        _sh.console.print(t)
        return
    if sub and sub not in ("list", "forget"):
        notifier.unknown("subcommand", sub, ["list", "forget"],
                         hint="bare 'experience' shows the status")
        return
    store = Experience(enabled=True, path=experience_path())
    stats = store.stats()
    if not stats.get("episodes"):
        notifier.info("Learning memory empty. It fills up as you run "
                      "auto/agent engagements (on by default: "
                      "automation.experience).")
        return
    from rich.table import Table
    t = Table(title="[bold white]Learning memory[/]", border_style="blue",
              show_lines=False)
    t.add_column("", style="cyan", no_wrap=True)
    t.add_column("Value", style="white")
    t.add_row("episodes", str(stats.get("episodes")))
    t.add_row("learnable", str(stats.get("learnable")))
    t.add_row("successes / failures",
              f"{stats.get('successes')} / {stats.get('failures')}")
    t.add_row("top causes", ", ".join(
        f"{k}={v}" for k, v in list((stats.get("by_cause") or {}).items())[:5]
    ) if stats.get("by_cause") else "-")
    t.add_row("top repairs", ", ".join(
        f"{k}={v}" for k, v in list((stats.get("top_repairs") or {}).items())[:5]
    ) if stats.get("top_repairs") else "-")
    t.add_row("store", str(stats.get("path")))
    _sh.console.print(t)
    notifier.info("The planner reorders already-allowed moves from this "
                  "memory — it never authorises anything by itself.")


def cmd_run_diff(shell, arg: str):
    """run-diff <checkpointA> <checkpointB> - Compare two runs structurally.

    Every auto/agent run writes checkpoints (data/sessions/auto_*/
    checkpoint.json). This command loads two of them (or two WorldModel
    dumps) and answers the question a score never will: did the second
    run LEARN more, LOSE ground, hit NEW walls, resolve old ones?

    Findings are keyed (kind, key); a confidence shift beyond 0.05 or a
    source change counts as changed. Dead-capability maps are diffed into
    walls resolved vs walls new. Pure file comparison: nothing runs.

    Example:
      run-diff data/sessions/auto_1700000001/checkpoint.json \
               data/sessions/auto_1700090000/checkpoint.json
    """
    parts = arg.split()
    if len(parts) != 2:
        notifier.usage("run-diff", "<checkpointA> <checkpointB>",
                       hint="two checkpoint files (auto/agent runs) or "
                            "WorldModel dumps")
        return
    from phantom.core.run_diff import diff_files, format_report
    try:
        d = diff_files(parts[0], parts[1])
    except FileNotFoundError as exc:
        notifier.error(f"Checkpoint not found: {exc.filename}",
                       hint="checkpoints live in data/sessions/auto_*/ "
                            "and agent_*/")
        return
    except ValueError as exc:
        notifier.error(str(exc),
                       hint="both files must be checkpoint/WorldModel "
                            "JSON dumps")
        return
    _sh.console.print(format_report(d), markup=False)
    if d.progressed and not d.regressed:
        notifier.success("Il secondo run è andato oltre il primo.")
    elif d.regressed and not d.progressed:
        notifier.warn("Il secondo run ha REGREDITO: niente di nuovo, "
                      "conoscenza o terreno persi.")
    elif d.regressed:
        notifier.warn("Risultato misto: nuove conoscenze E regressioni.")


def cmd_why(shell, arg: str):
    """why [capability] - Why did the agent do (or veto) that move?

    Reads the DECISION TRACE — the ordered ledger of arbitrated moves the
    agent keeps in memory and inside every checkpoint — so the answer
    works both live (this session) and offline (from a checkpoint file).

      why                  the last decision + which lens decided most
      why <capability>     every decision for one capability, in order
      why --trace <file>   read the ledger from a checkpoint instead of
                           the live session

    The trace records what the arbiter already decided — base score,
    driver lens, runner-up, top contributions, profile, veto — nothing
    here re-decides anything.
    """
    from phantom.automation.brain.trace import DecisionTrace

    parts = arg.split()
    trace = None
    cap = ""
    if "--trace" in parts:
        i = parts.index("--trace")
        if i + 1 >= len(parts):
            notifier.usage("why --trace", "<checkpoint>",
                           hint="the decision ledger inside a checkpoint")
            return
        path = parts[i + 1]
        parts = parts[:i] + parts[i + 2:]
        try:
            import json
            with open(path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            wm_raw = raw.get("wm") if isinstance(raw.get("wm"), dict) \
                else {}
            trace = DecisionTrace.from_dict(
                wm_raw.get("trace") or raw.get("trace"))
        except FileNotFoundError:
            notifier.error(f"Checkpoint not found: {path}",
                           hint="checkpoints live in data/sessions/")
            return
        except ValueError as exc:
            notifier.error(f"Not a readable checkpoint: {exc}")
            return
    cap = parts[0] if parts else ""
    if trace is None:
        from phantom.core.session import session
        trace = getattr(session, "_last_decision_trace", None) or \
            getattr(session, "decision_trace", None)
        if trace is None:
            notifier.error("No decision trace available in this session.",
                           hint="live decisions come from auto/agent runs; "
                                "for a finished run use "
                                "'why --trace <checkpoint>'")
            return
    if not trace:
        notifier.info("The decision ledger is empty for this source — "
                      "nothing was arbitrated yet.")
        return
    if cap:
        entries = trace.of(cap)
        if not entries:
            notifier.unknown("capability", cap,
                             sorted({e.capability for e in trace.entries}),
                             hint="'why' alone shows the latest decision")
            return
        for line in [e.explain() for e in entries]:
            _sh.console.print(line, markup=False)
        return
    last = trace.last()
    if last:
        _sh.console.print(last.explain(), markup=False)
    drivers = trace.drivers()
    if drivers:
        top = ", ".join(f"{k}={v}" for k, v in
                        sorted(drivers.items(), key=lambda kv: -kv[1])[:5])
        _sh.console.print(f"decided most often by: {top}", markup=False)


def cmd_doctor(shell, arg: str):
    """doctor [--net] - Environmental self-check in one command.

    The automation preflight guards scope and OPSEC; the doctor guards the
    ENVIRONMENT: Python version, core dependencies, beacon toolchain,
    data dir writability, config coherence (C2 endpoint, dead drop),
    learning-memory store, LLM advisor file, transports. Every check is
    offline by default; --net adds the active probes (C2 listener, msf
    rpc, dead drop reachability) — nothing touches targets.

    Every FAIL carries its fix in the ↳ hint. Run it before an
    engagement instead of discovering a missing tool mid-run.
    """
    from phantom.core.doctor import render, run_doctor
    net = "--net" in arg.split()
    try:
        report = run_doctor(net=net)
    except Exception as exc:
        notifier.error(f"Doctor failed: {exc}")
        return
    render(report)


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


def cmd_tool(shell, arg: str):
    """tool list|import <binary>|approve <id>|enable <id>|disable <id> - Runtime tool drivers.

    Manage capabilities Phantom discovers at runtime (a JSON manifest in
    data/drivers/). Every capability crosses explicit trust states
    (discovered -> candidate -> reviewed -> approved -> enabled) before the
    planner may load it: a found file is a CANDIDATE, never executable on
    its own.

      tool list              show every discovered capability + its state
      tool import <binary>   probe a new binary (--help/--version only) and
                             propose a DISABLED candidate manifest
      tool approve <id>      review + approve (walks the state machine)
      tool enable <id>       approve if needed, then enable for the planner
      tool disable <id>      revoke: demote to discovered, clear approval
    """
    import os

    from rich.table import Table

    from phantom.automation.runtime import capability_registry as reg_mod
    from phantom.automation.runtime import import_tool as imp

    parts = arg.split()
    sub = parts[0].lower() if parts else "list"
    reg = reg_mod.CapabilityRegistry()
    reg.load()

    if sub in ("list", "ls", "status"):
        rows = reg.report()
        if not rows:
            notifier.info("No runtime capabilities registered. Discover one "
                          "with 'tool import <binary>'.")
            return
        table = Table(title="[bold]Runtime capabilities[/]",
                      border_style="magenta")
        table.add_column("Capability", style="cyan")
        table.add_column("Tool", style="white")
        table.add_column("State", style="white")
        table.add_column("Enabled", style="white")
        table.add_column("Source", style="dim")
        table.add_column("sha256", style="dim")
        for r in rows:
            table.add_row(r["capability"], r["tool"], r["state"],
                          "yes" if r.get("enabled") else "no",
                          r.get("source", ""), (r.get("sha256") or "")[:12])
        _sh.console.print(table)
        return

    if sub in ("import", "add", "probe"):
        if len(parts) < 2:
            notifier.usage("tool import", "<binary> [category]",
                           hint="probes --help/--version only and leaves a "
                                "disabled candidate")
            return
        binary = parts[1]
        category = parts[2].lower() if len(parts) > 2 else "recon"
        proposal = imp.propose(binary, category=category, registry=reg)
        reg.save()
        if not proposal.probe.found:
            notifier.error(f"Binary not found: {binary}",
                           hint="pass a name on PATH or an absolute path")
            return
        try:
            from phantom.utils.paths import data_dir
            drivers_dir = os.path.join(data_dir(), "drivers")
        except Exception:
            drivers_dir = "drivers"
        path = imp.render_manifest(proposal, drivers_dir)
        notifier.success(
            f"Candidate '{proposal.cap_id}' created (DISABLED).")
        notifier.info(
            f"Probe: {proposal.probe.version or 'no version output'}")
        if path:
            notifier.info(f"Manifest skeleton: {path}")
        notifier.info(
            "Add the real command/argv to the manifest, then run "
            f"'tool approve {proposal.cap_id}' and 'tool enable "
            f"{proposal.cap_id}'.")
        return

    if sub == "approve":
        if len(parts) < 2:
            notifier.usage("tool approve", "<id>")
            return
        ok = reg.approve(parts[1])
        reg.save()
        if ok:
            notifier.success(f"{parts[1]} approved (state "
                             f"{reg.of(parts[1]).state}).")
        else:
            notifier.error(f"Cannot approve '{parts[1]}'.",
                           hint="is the id registered? 'tool list' shows ids")
        return

    if sub == "enable":
        if len(parts) < 2:
            notifier.usage("tool enable", "<id>")
            return
        ok = reg.enable(parts[1])
        reg.save()
        if ok:
            notifier.success(f"{parts[1]} enabled — the planner may load it.")
        else:
            notifier.error(f"Cannot enable '{parts[1]}'.",
                           hint="approve it first: 'tool approve <id>'")
        return

    if sub in ("disable", "revoke", "demote"):
        if len(parts) < 2:
            notifier.usage("tool disable", "<id>")
            return
        ok = reg.demote(parts[1], reason="revoked by operator")
        reg.save()
        if ok:
            notifier.warn(f"{parts[1]} demoted to discovered (approval "
                          "cleared).")
        else:
            notifier.info(f"'{parts[1]}' was not enabled.")
        return

    notifier.unknown("subcommand", sub,
                     ["list", "import", "approve", "enable", "disable"],
                     hint="'tool list' shows the registry")


COMMANDS = {
    "help": cmd_help,
    "config": cmd_config,
    "tool": cmd_tool,
    "setup": cmd_setup,
    "coverage": cmd_coverage,
    "doctor": cmd_doctor,
    "why": cmd_why,
    "run_diff": cmd_run_diff,
    "experience": cmd_experience,
    "back": cmd_back,
    "exit": cmd_exit,
    "quit": cmd_quit,
}
