"""Run & recon commands: run/suggest/plan/preflight/craft/map/install/scan-diff."""
from __future__ import annotations

from phantom.core.session import session
import phantom.core.shell as _sh  # live console: _sh.console resolves the package attr at call time (test patch point)
from phantom.utils.notifier import notifier


def _run_suggested_move(shell, index: int) -> None:
    """Execute entry <index> of the last ranking (one step, not three)."""
    from phantom.core import next_moves as _nm
    moves = _nm.pending()
    if not moves:
        notifier.error("No ranked moves yet.",
                       hint="run 'suggest' to rank the next steps first")
        return
    if index < 1 or index > len(moves):
        notifier.error(f"Move {index} out of range.",
                       hint=f"valid entries are 1..{len(moves)} "
                            f"(run 'suggest' to re-rank)")
        return
    move = moves[index - 1]
    _sh.console.print(f"[bold cyan]── RUN {index}: {move.title} ──[/]")
    if move.why:
        _sh.console.print(f"  [dim]why: {move.why}[/]")
    _nm.execute_move(shell, move)


def cmd_run(shell, arg: str):
    """run [n | module [args]] — one step, from the ranked moves or a module.

    `suggest` prints a ranked, numbered list; `run <n>` executes entry n
    here (scope, tools and the aggressive confirmation still apply), so a
    recommendation is one step instead of `use` + `run` + selection.

    With no argument: executes the top-ranked move. With a module name it
    runs that module (aliases work); extra words are passed to the module
    flow, e.g. `run scan --quiet` for the non-interactive path.
    """
    if not session.target:
        notifier.error("No target set. Use: set target <ip|email|username|domain>")
        return
    tokens = arg.strip().split()
    if not tokens:
        from phantom.core import next_moves as _nm
        ranked = _nm.rank_next_moves(shell)
        if not ranked.moves:
            notifier.info("Nothing actionable right now. Try 'use scan' → 'run', "
                          "or the full chain: auto <target>")
            return
        top = ranked.moves[0]
        _sh.console.print(f"[bold cyan]── NEXT STEP: {(top.module or top.capability).upper()} ──[/]")
        _sh.console.print(f"  [dim]reason: {top.why or 'best next step from current findings'}[/]")
        if not _nm.execute_move(shell, top):
            # the top move needs an interactive module flow: fall back to it
            instance = shell._instantiate_module(top.module) if top.module else None
            if instance is not None and not shell._warn_identity_target(top.module):
                try:
                    instance.do_run("")
                except NotImplementedError:
                    notifier.warn(f"{top.module} has no automated run — opening interactive shell.")
                    instance.cmdloop()
        return

    head = tokens[0]
    if head.isdigit():
        _run_suggested_move(shell, int(head))
        return
    module = shell.MODULE_ALIASES.get(head.lower(), head.lower())
    module_args = " ".join(tokens[1:])
    instance = shell._instantiate_module(module)
    if instance is None:
        notifier.error(f"Unknown module: {module} (use: use <module>)")
        return
    if not shell._warn_identity_target(module):
        try:
            # module args pass through: `run scan --quiet` runs the module's
            # top suggestion non-interactively (previously unreachable here)
            instance.do_run(module_args)
        except NotImplementedError:
            notifier.warn(f"{module} has no automated run — opening interactive shell.")
            instance.cmdloop()


def cmd_suggest(shell, arg: str):
    """suggest — ranked, directly executable next moves.

    One ranked list instead of a flat per-module dump: the planner's next
    chain step and the evidence-tagged commands are scored together, each
    row shows WHY (the findings behind it), a TRUST score and its
    preflight state (missing tools, already-ran, out-of-scope), and the
    paths the planner REFUSED are listed with their real reason.

    `run <n>` executes row n — no `use` + `run` + selection detour.
    """
    from phantom.core import next_moves as _nm
    if not session.target:
        notifier.error("No target set. Use: set target <ip|email|username|domain>")
        return
    _nm.render_moves(_nm.rank_next_moves(shell))


def cmd_plan(shell, arg: str):
    """plan <goal> — the reasoning engine lays out the chain to a goal.

    Goals: beacon | creds | lateral | ad | identity | deep
    Shows the ordered steps the planner would take with the facts each
    step needs and produces; `suggest` then highlights where you are.
    Nothing is executed.
    """
    from phantom.core.suggest_meta import _wm_evidence
    goal = (arg.strip().lower() or "beacon")
    valid = {"beacon", "creds", "lateral", "ad", "identity", "deep",
             "footprint", "post_exploit", "crack", "cloud"}
    if goal not in valid:
        notifier.error(f"Unknown goal '{goal}'. Goals: {', '.join(sorted(valid))}")
        return
    if not session.target:
        notifier.error("No target set. Use: set target <ip|email|username|domain>")
        return
    try:
        from phantom.core.knowledge import session_wm
        from phantom.automation.planner import Planner, GOAL_FACTS
        from phantom.automation.guidance.commands import make_registry
        from phantom.automation.guidance.stealth import StealthEngine
        from phantom.automation.guidance.threatmodel import BlueTeamModel
        from phantom.automation.guidance.stealth import StealthConfig
        wm = session_wm()
        engine = StealthEngine(
            wm, StealthConfig(), BlueTeamModel.for_profile("enterprise"))
        planner = Planner(make_registry(), engine)
        plan = planner.plan(wm, goal=goal, max_steps=8)
    except Exception as e:
        notifier.error(f"Planner unavailable: {e}")
        return
    _sh.console.print(f"[bold cyan]── PLAN → {goal.upper()} "
                  f"({session.target}) ──[/]")
    facts = GOAL_FACTS.get(goal, [])
    done = any(wm.has_any(f) for f in facts)
    if plan.complete and done:
        _sh.console.print("  [green]Goal already satisfied by current findings.[/]")
        return
    if not plan.steps:
        _sh.console.print(f"  [yellow]No viable path to '{goal}' with current "
                      "findings — scan/enumerate more and re-plan.[/]")
        if plan.blocked_reason:
            _sh.console.print(f"  [dim]blocked: {plan.blocked_reason}[/]")
        # WHY nothing was affordable: the planner keeps the rejected
        # candidates with their concrete reason; showing them turns
        # "no path" from a mystery into a to-do list.
        for r in (plan.rejected or [])[:8]:
            _sh.console.print(
                f"  [dim]· {r.capability} for '{r.fact}': {r.reason}[/]")
        if len(plan.rejected or []) > 8:
            _sh.console.print(f"  [dim](+{len(plan.rejected) - 8} more "
                              "rejected candidates)[/]")
        return
    for i, s in enumerate(plan.steps, 1):
        cap = s.capability
        why = s.reason or ""
        _sh.console.print(
            f"  {i:2}. [white]{cap.id}[/] "
            f"[dim]cost={cap.opsec_cost} stealth={cap.stealth_level}"
            f"{' — ' + why if why else ''}[/]")
    _sh.console.print("  [dim]Nothing executed. Steps map to modules: "
                  "scan→'use scan', web→'use web', creds→'use brute', "
                  "beacon→'use payload'. 'suggest' shows your next move.[/]")


def cmd_preflight(shell, arg: str):
    """preflight [module] — check the tools a module needs and show
    install hints for the missing ones. Without arguments checks the
    module you would run next."""
    # ONE gate: the same helper a module's own `run` uses, so `preflight`
    # and the run can never disagree — and resolution is alias-aware
    # (impacket-secretsdump satisfies secretsdump.py).
    from phantom.core.executor import module_missing_tools, module_tools

    module_name = arg.strip().lower()
    aliases = shell.MODULE_ALIASES
    module_name = aliases.get(module_name, module_name)
    if module_name:
        names = [module_name]
    else:
        names = ["scan"]

    missing = []
    for name in names:
        instance = shell._instantiate_module(name)
        if instance is None:
            notifier.error(f"Unknown module: {name}")
            continue
        if not module_tools(instance):
            _sh.console.print(f"  [dim]○ {name}: no commands available yet "
                              "(set target first to evaluate its tools).[/]")
        missing.extend(module_missing_tools(instance))

    if not missing:
        notifier.success("All required tools are installed.")
        return
    _sh.console.print("[bold yellow]Missing tools:[/]")
    for tool, hint in missing:
        _sh.console.print(f"  [red]✖ {tool}[/]  [dim]→ {hint}[/]")
    notifier.info("Run 'preflight' again after installing to confirm.")
    notifier.info("Use 'export json report.json' to generate a report.")


def _print_lure(out: dict, what: str):
    _sh.console.print(f"\n  [bold cyan]► {what}[/]")
    _sh.console.print(f"  [bold]READY TO PASTE:[/] {out.get('url', '')}")
    m = out.get("masked") or {}
    if m:
        # the SAME lure with the visible text swapped for a plausible
        # platform share URL — the destination stays the tracker
        _sh.console.print("  [bold]MASKED (link shows a reel URL, goes to the tracker):[/]")
        _sh.console.print(f"    telegram/html : {m.get('telegram_html', '')}")
        _sh.console.print(f"    discord       : {m.get('discord_markdown', '')}")
        _sh.console.print(f"    email anchor  : {m.get('email_anchor', '')}")
        _sh.console.print(f"    [dim]{m.get('note', '')}[/]")
    _sh.console.print(f"  [dim]code: {out.get('code', '')} | tracker: {out.get('base', '')}[/]")
    _sh.console.print("  [dim]watch it with: craft wait <code> | craft hits <code>[/]")


def _print_hits(data: dict):
    hits = data.get("hits") or []
    opens = data.get("opens") or []
    creds = data.get("creds") or []
    sessions = data.get("sessions") or []
    if not (hits or opens or creds or sessions):
        notifier.info("No hits yet — the lure is live and waiting.")
        return
    for h in hits:
        fp = "/".join(x for x in (h.get("os"), h.get("device"),
                                  h.get("browser")) if x) or "device?"
        loc = f"  [{h.get('geo')}]" if h.get("geo") else ""
        _sh.console.print(f"  [red]⚡ HIT[/] {h['ip']}  {fp}{loc}  {h['ua'][:30]}")
    for o in opens:
        _sh.console.print(f"  [yellow]◉ OPEN[/] {o['ip']}  {o['ua'][:40]}")
    for c in creds:
        # live operator surface: explicitly unwrap the Secret type
        # (every persisted copy of this dict keeps the mask)
        from phantom.utils.redact import unwrap
        _sh.console.print(f"  [magenta]◈ CREDS[/] {c['ip']}  "
                      f"{c['username']}:{unwrap(c['password'])}")
    for s in sessions:
        # an AiTM session outlives the credentials: the cookies ARE the
        # logged-in browser, MFA already satisfied
        _sh.console.print(f"  [bright_magenta]⛨ SESSION[/] {s['ip']}  "
                      f"{s.get('username') or '(no user)'}")
    notifier.success(
        f"{len(hits)} hit(s) · {len(opens)} open(s) · "
        f"{len(creds)} cred(s) · {len(sessions)} session(s)")


def cmd_craft(shell, arg: str):
    """craft <ipgrab|reel|image|pixel|beacon|hits|wait> — build a
    social lure and get it ready to paste, then watch for the target.

      craft ipgrab [label]            plain click-tracking link
      craft reel <url|search-term>    video lure on a REAL video YOU pick
                                      (IG/TikTok/YT link to mirror, or a
                                      search term; identifier stripped)
      craft image <file|url>          ZERO-CLICK image lure: IP + device +
                                      location captured when it RENDERS
      craft pixel [label]             1x1 tracking pixel (email opens)
      craft beacon [platform]         one-click beacon link disguised as
                                      a reel URL
      craft beacon-player [platform]  upgraded: reel page plays a REAL video,
                                      play click downloads the beacon
                                      (stealth fallback if C2 is down)
      craft real <real-url> [kind]    REAL first hop: a genuine YouTube/
                                      Drive/Notion URL goes in the message,
                                      the capture link goes INSIDE that
                                      content (ipgrab|reel|beacon-player)
      craft channels [url|code]       WHERE the destination can be hidden
                                      (anchor text) and where the raw
                                      domain is all the target reads
      craft idn <domain>              Will a homograph/IDN domain actually
                                      display as the brand? (punycode
                                      verdict, with evidence)
      craft aitm <login-url>          ENTERPRISE (opt-in): AiTM reverse
                                      proxy — serves the REAL login page
                                      and captures credentials AND the
                                      session cookies (beats plain MFA)
      craft hits <code>               every recorded hit/open/cred/session
      craft sessions <code>           sessions taken by an AiTM mount
      craft wait <code> [secs]        live-wait for the target
    """
    from phantom.modules import craft as _craft
    parts = (arg or "").split()
    sub = parts[0].lower() if parts else ""
    if not sub:
        _sh.console.print(cmd_craft.__doc__)
        return

    if sub == "ipgrab":
        label = parts[1] if len(parts) > 1 else "phish"
        out = _craft.craft_ipgrab(label=label)
        _print_lure(out, "IP grabber link (click = IP + device)")
    elif sub == "reel":
        arg = arg.split(maxsplit=1)[1] if len(parts) > 1 else ""
        out = _craft.craft_reel(arg=arg)
        if "error" in out:
            notifier.error(out["error"])
            return
        _print_lure(out, f"Reel lure ({out.get('video', {}).get('title', '')[:50]})")
        if out.get("hint"):
            notifier.info(out["hint"])
    elif sub == "image":
        src = arg.split(maxsplit=1)[1] if len(parts) > 1 else ""
        out = _craft.craft_image(src)
        if "error" in out:
            notifier.error(out["error"])
            return
        _print_lure(out, "Image lure (zero-click on render)")
        _sh.console.print(f"\n  [cyan]HTML for email/page:[/]\n  {out.get('html', '')}")
        if out.get("hint"):
            notifier.info(out["hint"])
    elif sub == "pixel":
        label = parts[1] if len(parts) > 1 else "px"
        out = _craft.craft_pixel(label=label)
        _print_lure(out, "Tracking pixel — zero-click: IP when rendered")
        _sh.console.print(f"\n  [cyan]HTML for email/page:[/]\n  {out.get('html', '')}")
    elif sub == "beacon":
        platform = parts[1] if len(parts) > 1 else "auto"
        out = _craft.craft_beacon(platform=platform)
        if "error" in out:
            notifier.error(out["error"])
            notifier.info(out.get("hint", ""))
            return
        _print_lure(out, "Beacon delivery (camouflaged reel link)")
        _sh.console.print(f"  [dim]redirects to: {out.get('payload_url', '')}[/]")
        if out.get("hint"):
            notifier.info(out["hint"])
    elif sub == "beacon-player":
        platform = parts[1] if len(parts) > 1 else "auto"
        out = _craft.craft_beacon_player(platform=platform)
        if "error" in out:
            notifier.error(out["error"])
            notifier.info(out.get("hint", ""))
            return
        _print_lure(out, "Beacon player delivery (reel page, play-click beacon)")
        _sh.console.print(f"  [dim]redirects to: {out.get('payload_url', '')}[/]")
        if out.get("hint"):
            notifier.info(out["hint"])
    elif sub == "real":
        args = parts[1:]
        outer = args[0] if args else ""
        inner = args[1] if len(args) > 1 else "ipgrab"
        out = _craft.craft_real(outer_url=outer, inner=inner)
        if "error" in out:
            notifier.error(out["error"])
            if out.get("hint"):
                notifier.info(out["hint"])
            return
        _sh.console.print(f"\n  [bold cyan]► Real first hop "
                      f"({out.get('outer_host')} — {out.get('inner')})[/]")
        _sh.console.print(f"  [bold]1) IN THE DM / EMAIL (real URL):[/] "
                      f"{out.get('outer_url')}")
        _sh.console.print(f"  [bold]2) INSIDE THE CONTENT:[/] "
                      f"{out.get('inner_paste')}")
        _sh.console.print(f"  [dim]tracker url: {out.get('inner_url')}[/]")
        _sh.console.print(f"  [dim]where: {out.get('placement')}[/]")
        if out.get("supports_anchor"):
            _sh.console.print("  [green]this surface hides the destination: "
                          "the target reads "
                          f"{out.get('inner_display')}[/]")
        else:
            notifier.error(out.get("warning", ""))
            _sh.console.print(f"  [dim]anchor-capable middle hops: "
                          f"{', '.join(out.get('recommended_middle_hops', []))}[/]")
        _sh.console.print(f"  [dim]code: {out.get('inner_code')} "
                      f"(craft hits / craft wait)[/]")
        _sh.console.print(f"\n  [bold]DM text:[/]\n    {out.get('dm_text')}")
        _sh.console.print(f"\n  [bold]Email:[/] subject: "
                      f"{out.get('email_subject')}")
        body = str(out.get("email_body", "")).replace("\n", "\n    ")
        _sh.console.print(f"    {body}")
        if out.get("note"):
            notifier.info(out["note"])
    elif sub == "idn":
        dom = parts[1] if len(parts) > 1 else ""
        out = _craft.idn_verdict(dom)
        if "error" in out:
            notifier.error(out["error"])
            return
        _sh.console.print(f"\n  [bold cyan]► IDN verdict: "
                      f"{out.get('domain')}[/]")
        _sh.console.print(f"  scripts:  {', '.join(out.get('scripts') or [])}"
                      f"  [dim](mixed: "
                      f"{out.get('mixed_scripts')})[/]")
        _sh.console.print(f"  punycode: {out.get('punycode')}")
        _sh.console.print(f"  [bold]address bar shows:[/] "
                      f"{out.get('displayed_in_address_bar')}")
        (notifier.error if out.get("mixed_scripts") else notifier.info)(
            out.get("verdict", ""))
        _sh.console.print(f"\n  [dim]{out.get('free_alternative')}[/]")
    elif sub == "channels":
        arg1 = parts[1] if len(parts) > 1 else ""
        if arg1.lower().startswith(("http://", "https://")):
            matrix = _craft.channel_matrix(url=arg1)
        else:
            matrix = _craft.channel_matrix(code=arg1)
        _sh.console.print("\n  [bold cyan]► Link rendering matrix[/]")
        for name, row in (matrix.get("channels") or {}).items():
            hides = row.get("hides_destination")
            mark = ("[green]HIDES  [/]" if hides else "[red]VISIBLE[/]")
            _sh.console.print(f"  {mark}  [bold]{name}[/] "
                          f"[dim]({row.get('where')})[/]")
            _sh.console.print(f"           [dim]paste: "
                          f"{row.get('paste')}[/]")
        mech = matrix.get("mechanisms") or {}
        anchor = mech.get("anchor") or {}
        rdr = mech.get("middle_hop_redirect") or {}
        _sh.console.print("\n  [bold cyan]► Mechanism A — anchor (link text)[/]")
        _sh.console.print(f"    works on: {', '.join(anchor.get('works_on', []))}")
        _sh.console.print(f"    fails on: {', '.join(anchor.get('fails_on', []))}")
        _sh.console.print(f"    cost: {anchor.get('cost')}")
        _sh.console.print("\n  [bold cyan]► Mechanism B — real third-party "
                      "domain in front[/]")
        _sh.console.print(f"    works on: {rdr.get('works_on')}")
        _sh.console.print(f"    paste: {rdr.get('paste')}")
        _sh.console.print(f"    cost: {rdr.get('cost')}")
        _sh.console.print(f"\n  [dim]{matrix.get('truth')}[/]")
    elif sub == "aitm":
        upstream = parts[1] if len(parts) > 1 else ""
        out = _craft.craft_aitm(upstream)
        if "error" in out:
            notifier.error(out["error"])
            if out.get("hint"):
                notifier.info(out["hint"])
            return
        _print_lure(out, "AiTM relay (real login page, credentials + "
                         "session)")
        _sh.console.print(f"  [dim]upstream: {out.get('upstream')}[/]")
        if out.get("hint"):
            notifier.info(out["hint"])
    elif sub == "sessions":
        code = parts[1] if len(parts) > 1 else ""
        if not code:
            notifier.usage("craft sessions", "<code>",
                           "the code is the tracker id from 'craft ipgrab'")
            return
        data = _craft.craft_sessions(code)
        rows = data.get("sessions") or []
        if not rows:
            notifier.info("No sessions captured for this code yet.")
            return
        _sh.console.print("\n  [bold cyan]► Captured sessions[/]")
        for s in rows:
            _sh.console.print(f"  [bold]{s.get('username') or '(no user)'}[/] "
                          f"[dim]{s.get('ip')} {s.get('time')}[/]")
            _sh.console.print(f"    cookies: {s.get('cookies')}")
    elif sub == "hits":
        code = parts[1] if len(parts) > 1 else ""
        if not code:
            notifier.usage("craft hits", "<code>",
                           "the code is the tracker id from 'craft ipgrab'")
            return
        data = _craft.craft_hits(code)
        _print_hits(data)
    elif sub == "wait":
        code = parts[1] if len(parts) > 1 else ""
        if not code:
            notifier.usage("craft wait", "<code> [seconds]",
                           "returns as soon as a hit lands, or at the timeout")
            return
        timeout = float(parts[2]) if len(parts) > 2 else 300.0
        _craft.craft_wait(code, timeout=timeout)
    else:
        _sh.console.print(cmd_craft.__doc__)


def cmd_map(shell, arg: str):
    """map [cidr] — discover live hosts on the local network (or the
    given CIDR), feed the network map + WorldModel, then rank every
    device by reachable attack surface and suggest where to start."""
    from phantom.core.netmap import (
        discover_network, seed_worldmodel, recommend_starting_target,
        check_hosts_alive)
    target = arg.strip() or None
    notifier.status("Mapping the network... (arp-scan → nmap -sn → ping)")
    res = discover_network(target=target)
    hosts = res.get("hosts") or []
    # live/dead status: the discovery only answers for hosts that are
    # up NOW, so every freshly found device is alive — the liveness
    # pass matters for hosts kept from earlier scans/ARP cache
    check_hosts_alive(hosts, force=True)
    seed_worldmodel(hosts)
    if not hosts:
        notifier.warn(f"No live hosts found ({res.get('method')}).")
        return
    topo = res.get("topology") or {}
    if topo.get("kind"):
        _sh.console.print(f"[bold magenta]Topology: {str(topo.get('kind')).upper()}[/] "
                      f"[dim](gateway {topo.get('gateway') or '?'} · "
                      f"{int(100 * (topo.get('confidence') or 0))}% confidence) "
                      f"— {topo.get('note', '')}[/]")
    _sh.console.print(f"[bold cyan]Devices on the network ({res.get('method')}, "
                  f"{res.get('elapsed')}s):[/]")
    _sh.console.print(f"  {'':1}{'IP':<16}{'HOSTNAME':<24}{'OS GUESS':<17}SERVICES / PORTS")
    for h in hosts:
        os_g = h.get("os_guess", "") or "—"
        svc = h.get("services") or ("-" if not h.get("ports") else "closed")
        name = (h.get("hostname") or "-")[:23]
        live = h.get("alive", True)
        mark = "[green]●[/]" if live else "[dim]○[/]"
        suffix = "" if live else " [dim](offline)[/]"
        _sh.console.print(f"  {mark} {h.get('ip', ''):<15}{name:<24}{os_g:<17}{svc}{suffix}")
    # exposure ranking: quick TCP probe of common ports on every device
    notifier.status("Ranking devices by attack surface (TCP probe, "
                    "bounded)...")
    verdict = recommend_starting_target(hosts)
    ranked = verdict.get("ranked") or []
    if ranked:
        _sh.console.print()
        _sh.console.print("[bold yellow]── Most exposed devices (live only) ──[/]")
        _sh.console.print(f"  {'IP':<18}{'RISK':<9}{'SCORE':<7}OPEN PORTS")
        for r in ranked[:8]:
            ports = ", ".join(f"{p['port']}/{p['service']}"
                               for p in r["open_ports"][:6])
            _sh.console.print(
                f"  {r.get('ip', ''):<18}{r.get('risk', ''):<9}"
                f"{r.get('score', 0):<7}{ports}")
        rec = verdict.get("recommended")
        if rec:
            _sh.console.print()
            _sh.console.print(f"[bold green]▶ Suggested starting target: "
                          f"{rec.get('ip')}[/] "
                          f"[dim]({verdict.get('reason', '')})[/]")
            _sh.console.print("  [dim]→ set target and start: "
                          f"set target {rec.get('ip')} → use scan → run[/]")
    else:
        _sh.console.print(f"[dim]  {verdict.get('reason', 'No exposed services.')}[/]")
    dead = sum(1 for h in hosts if not h.get("alive", True))
    note = f"{len(hosts)} device(s) found"
    if dead:
        note += f" ({dead} offline, shown faded — powered-off devices are never ranked as targets)"
    notifier.success(note + " — see them on the network map (Electron) "
                     "or in the WorldModel.")


def cmd_install(shell, arg: str):
    """install <tool> — install a missing tool in the current backend
    environment (apt / brew / choco / pip, auto-selected; WSL on
    Windows). Shows the live output."""
    tool = arg.strip().lower()
    if not tool:
        notifier.usage("install", "<tool>", "e.g. install hydra")
        return
    from phantom.core.executor import install_tool
    notifier.status(f"Installing {tool}... (this can take a while)")
    res = install_tool(tool)
    out = (res.get("output") or "").strip()
    if res.get("ok"):
        notifier.success(f"Installed: {tool}")
    else:
        notifier.error(f"Install failed: {tool}")
    if out:
        _sh.console.print(out[-1500:])
    else:
        notifier.info(f"Command used: {res.get('command', '')}")


def cmd_scan_diff(shell, arg: str):
    """scan-diff <target> [--since YYYY-MM-DD | --old TS --new TS]"""
    import argparse
    from datetime import datetime
    from phantom.utils.scan_history import load_history, diff_scans
    parser = argparse.ArgumentParser(prog="scan-diff", add_help=False)
    parser.add_argument("target", help="Target to diff")
    parser.add_argument("--since", help="Compare last scan with the one after this date (YYYY-MM-DD)")
    parser.add_argument("--old", help="Old timestamp (format: YYYYMMDD_HHMMSS)")
    parser.add_argument("--new", help="New timestamp (format: YYYYMMDD_HHMMSS)")
    try:
        args = parser.parse_args(arg.split())
    except SystemExit:
        return

    history = load_history(args.target)
    if len(history) < 2:
        notifier.warn("Need at least two scans for diff.")
        return

    if args.old and args.new:
        old = next((h for h in history if args.old in h["timestamp"]), None)
        new = next((h for h in history if args.new in h["timestamp"]), None)
    elif args.since:
        since_dt = datetime.strptime(args.since, "%Y-%m-%d")
        new = history[0]  # latest
        candidates = [h for h in history if datetime.fromisoformat(h["timestamp"]) > since_dt]
        old = candidates[-1] if candidates else None
    else:
        new = history[0]
        old = history[1]

    if not old or not new:
        notifier.error("Could not find matching scans.")
        return

    added, removed, changed = diff_scans(old["services"], new["services"])

    _sh.console.print(f"[bold cyan]Diff: {old['timestamp']} → {new['timestamp']}[/]")
    if added:
        _sh.console.print("[green][+] Added ports:[/]")
        for s in added:
            _sh.console.print(f"    {s['port']}/{s['protocol']}  {s['service']}  {s['version']}")
    if removed:
        _sh.console.print("[red][-] Removed ports:[/]")
        for s in removed:
            _sh.console.print(f"    {s['port']}/{s['protocol']}  {s['service']}  {s['version']}")
    if changed:
        _sh.console.print("[yellow][*] Changed services:[/]")
        for old_s, new_s in changed:
            _sh.console.print(f"    {old_s['port']}/{old_s['protocol']}: {old_s['service']} {old_s['version']} → {new_s['service']} {new_s['version']}")
    if not (added or removed or changed):
        notifier.info("No changes detected.")


COMMANDS = {
    "run": cmd_run,
    "suggest": cmd_suggest,
    "plan": cmd_plan,
    "preflight": cmd_preflight,
    "craft": cmd_craft,
    "map": cmd_map,
    "install": cmd_install,
    "scan_diff": cmd_scan_diff,
}
