"""Operations commands: c2, malleable, ad, wordlists, export."""
from __future__ import annotations

from phantom.core.session import session
from phantom.utils.notifier import notifier


def cmd_c2(shell, arg: str):
    """c2 - Enter the Phantom C2 Operations Center"""
    notifier.status("Transitioning to C2 Interface...")
    from phantom.core.c2_shell import run_c2
    run_c2()


def cmd_malleable(shell, arg: str):
    """malleable [show|save|recommend] - Manage malleable C2 profiles for beacon stealth"""
    from phantom.utils.malleable import handle_malleable_command
    handle_malleable_command(arg)


def cmd_ad(shell, arg: str):
    """ad [tree|paths|add-user <u> [opts]|add-edge <src> <type> <dst>|reset]
        - BloodHound-style AD attack graph from session knowledge.

    subcommands:
      (none) | tree      render the domain graph + attack paths
      paths              only the attack paths to Domain Admin
      add-user <u>       register a user; flags: --kerberoastable
                         --as-rep --cracked --admin-to <host>
                         --session-on <host> --group <g>
      add-edge <s> <t> <d>  raw edge (member_of/admin_to/session/owns)
      add-dc <host>      register the domain controller
      reset              clear the graph (new engagement)"""
    from phantom.core.ad_graph import ADGraph, EDGE_TYPES
    from phantom.core.knowledge import session_wm
    g = ADGraph()
    # ingest whatever the session already knows (idempotent)
    try:
        from phantom.core.ad_graph import ingest_from_wm
        g = ingest_from_wm(session_wm())
    except Exception:
        pass
    parts = arg.strip().split()
    sub = parts[0].lower() if parts else "tree"

    if sub in ("", "tree"):
        for line in g.ascii_tree():
            notifier.info(line)
        return
    if sub == "paths":
        paths = g.paths_to("DA")
        if not paths:
            notifier.warn("No attack paths to DA known yet — collect "
                          "more AD data (add-user --kerberoastable, "
                          "--session-on, --admin-to)")
            return
        for i, p in enumerate(paths, 1):
            chain = " -> ".join(f"{s}[{t}]{d}" for s, t, d in p)
            notifier.info(f"[{i}] {chain}")
        return
    if sub == "add-user":
        if len(parts) < 2:
            notifier.usage(
                "ad add-user",
                "<user> [--kerberoastable] [--as-rep] [--cracked] "
                "[--admin-to H] [--session-on H] [--group G]",
                "run 'ad tree' to see the nodes already recorded")
            return
        u = parts[1]
        g.add_node(u, "user", label=u)
        opts = parts[2:]
        i = 0
        while i < len(opts):
            o = opts[i].lower()
            if o == "--kerberoastable":
                g.nodes[u].props["kerberoastable"] = True
            elif o == "--as-rep":
                g.nodes[u].props["as_rep_roastable"] = True
            elif o == "--cracked":
                g.nodes[u].props["cracked"] = True
            elif o in ("--admin-to", "--session-on") and i + 1 < len(opts):
                host = opts[i + 1]
                et = "admin_to" if o == "--admin-to" else "session"
                g.add_node(host, "computer")
                g.add_edge(u, host, et)
                i += 1
            elif o == "--group" and i + 1 < len(opts):
                grp = opts[i + 1]
                g.add_node(grp, "group")
                g.add_edge(u, grp, "member_of")
                i += 1
            i += 1
        g._save()
        notifier.success(f"AD user {u} recorded ({sum(len(v.props) for v in g.nodes.values())} graph nodes total)")
        return
    if sub == "add-dc":
        if len(parts) < 2:
            notifier.usage("ad add-dc", "<host>",
                           "auto-mode records the DC when it enumerates the "
                           "domain; add it manually if you collected it "
                           "out-of-band")
            return
        g.add_node(parts[1], "dc", label="Domain Controller")
        if g.domain:
            g.add_edge(g.domain, parts[1], "owns")
        g._save()
        notifier.success(f"DC {parts[1]} recorded")
        return
    if sub == "add-edge":
        if len(parts) < 4 or parts[2].lower() not in EDGE_TYPES:
            notifier.usage("ad add-edge",
                           f"<src> <{'|'.join(EDGE_TYPES)}> <dst>",
                           "edge type is positional, between src and dst")
            return
        s, t, d = parts[1], parts[2].lower(), parts[3]
        for nid, ntype in ((s, "user"), (d, "computer")):
            if nid not in g.nodes:
                g.add_node(nid, ntype)
        g.add_edge(s, d, t)
        notifier.success(f"edge {s} -[{t}]-> {d} recorded")
        return
    if sub == "reset":
        from phantom.core import ad_graph as _m
        _m.STATE_PATH.unlink(missing_ok=True)
        from phantom.core.ad_graph import ADGraph as _G
        g2 = _G()
        notifier.success("AD graph cleared")
        return
    notifier.unknown("ad subcommand", sub,
                     ["tree", "paths", "add-user", "add-dc", "add-edge",
                      "reset"],
                     hint="run 'ad tree' for the current graph")


def cmd_wordlists(shell, arg: str):
    """wordlists list | wordlists use <name> | wordlists search <keyword> | wordlists info <name>"""
    from phantom.utils.wordlists import WordlistManager
    WordlistManager().handle(arg)


def cmd_export(shell, arg: str):
    """export <json|pdf|html> [filename] — export session results"""
    from phantom.modules.report import ReportModule
    parts = arg.strip().split()
    if not parts:
        notifier.usage("export", "<json|pdf|html> [filename]")
        return
    fmt = parts[0].lower()
    if fmt not in ("json", "pdf", "html"):
        notifier.unknown("export format", fmt, ["json", "pdf", "html"])
        return
    default_name = f"report_{session.target or 'phantom'}.{fmt}"
    filename = parts[1] if len(parts) > 1 else default_name
    rm = ReportModule()
    rm.export(fmt, filename)


def cmd_guardrails(shell, arg: str):
    """guardrails [list|enable <key>|disable <key>|why|record] — safety controls

    Shows every safety control, whether it is on, and WHICH LAYER decided
    that (default / config / env / run flag). Controls an operator turned off
    are marked, because an override nobody can see is how an engagement ends
    up running outside the scope it was sold with.

    Subcommands:
      list             the manifest (default)
      why              what each control does and how to restore it
      enable <key>     turn a control back on
      disable <key>    turn one off (recorded in the next report)
      record           append the manifest to the hash-chained audit log
    """
    from phantom.utils import guardrails as gr

    parts = arg.strip().split()
    sub = parts[0].lower() if parts else "list"

    if sub in ("list", ""):
        from rich.console import Console
        console = Console()
        m = gr.build(scope=getattr(session, "scope", None),
                     targets=[session.target] if session.target else None)
        console.print(gr.render(m))
        return

    if sub == "why":
        from rich.table import Table
        from rich.console import Console
        console = Console()
        table = Table(title="Guardrails: what they do and how to restore them",
                      border_style="cyan")
        table.add_column("Control", style="cyan")
        table.add_column("Protects", style="white")
        table.add_column("Restore with", style="yellow")
        m = gr.build(scope=getattr(session, "scope", None))
        for g in m.guards:
            table.add_row(f"{g.label}\n[{g.source}]", g.detail,
                          g.remedy or "not operator-toggleable")
        console.print(table)
        return

    if sub in ("enable", "disable"):
        if len(parts) < 2:
            notifier.error(f"Usage: guardrails {sub} <key>")
            return
        ok, msg = gr.set_guardrail(parts[1].lower(), sub == "enable")
        if ok:
            notifier.success(msg)
            notifier.warn("The change is recorded in the next report — an "
                          "override is never silent.")
        else:
            notifier.error(msg)
        return

    if sub == "record":
        m = gr.build(scope=getattr(session, "scope", None),
                     targets=[session.target] if session.target else None)
        entry = gr.snapshot_to_audit(m, event="guardrails_snapshot")
        if entry is None:
            notifier.error("Could not append to the audit log (unwritable "
                           "store?). The manifest is still in the report.")
            return
        notifier.success(f"Guardrails appended to the audit log "
                         f"(digest {m.digest()})")
        return

    notifier.error(f"Unknown guardrails subcommand: {sub}")
    notifier.info("Usage: guardrails [list | why | enable <key> | "
                  "disable <key> | record]")


def cmd_deps(shell, arg: str):
    """deps [report|install <tool>...] -- the external tools Phantom shells out to

    A missing binary used to look exactly like a clean run: the command
    produced nothing and the module stored an empty result. `report` names what
    is absent and the exact command that would install it on THIS machine
    (Kali/WSL, other Linux, macOS, Windows); `install <tool>` asks the operator
    before it runs a package manager, and refuses when the answer is no.
    """
    from phantom.utils import toolchain as tc

    parts = arg.strip().split()
    sub = parts[0].lower() if parts else "report"

    if sub in ("report", "list", ""):
        from rich.console import Console
        Console().print(tc.report())
        return

    if sub == "install":
        wanted = parts[1:]
        if not wanted:
            notifier.error("Usage: deps install <tool> [<tool> ...]")
            return
        for tool in wanted:
            ok, msg = tc.install(tool, confirm=_ask_to_install)
            (notifier.success if ok else notifier.error)(msg)
        return

    notifier.error("Unknown deps subcommand: " + sub)
    notifier.info("Usage: deps [report | install <tool> ...]")


def cmd_llm(shell, arg: str):
    """llm [journal [refusals] | propose [n] | proposals | accept <id> | reject <id> [reason] | clear]

    The model reasons freely but may not execute. `propose` asks it for
    concrete commands; each lands PENDING here. `accept <id>` is the only path
    that runs one, and it runs through the same gate as any operator command
    (scope, hostnames named inside the command, tool availability). `journal`
    shows what the model wanted and why the algorithm refused it.
    """
    from phantom.automation import llm_journal, llm_proposals
    from rich.console import Console

    parts = arg.strip().split()
    sub = parts[0].lower() if parts else "proposals"

    if sub in ("journal", "log"):
        refused = len(parts) > 1 and parts[1].lower() in ("refusals", "refused",
                                                          "dropped")
        Console().print(llm_journal.journal.render(limit=25,
                                                  refused_only=refused))
        return

    if sub in ("proposals", "queue", "list"):
        Console().print(llm_proposals.render())
        return

    if sub == "propose":
        limit = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 5
        from phantom.automation.llm_advisor import LLMAdvisor
        from phantom.core.knowledge import session_wm
        advisor = LLMAdvisor(enabled=True)
        if not advisor.available():
            notifier.error("LLM advisor unavailable: "
                           + str(advisor._error or "no model configured"))
            notifier.info("See: llm journal (reasoning) | config (backend)")
            return
        props = advisor.propose_commands(session_wm(), limit=limit,
                                         agent="cli")
        if not props:
            notifier.info("the model proposed no usable command "
                          "(see: llm journal)")
            return
        Console().print(llm_proposals.render())
        notifier.info("Nothing has run: accept one with 'llm accept <id>'")
        return

    if sub in ("accept", "reject"):
        if len(parts) < 2 or not parts[1].isdigit():
            notifier.error(f"Usage: llm {sub} <id>" + (" [reason]" if sub == "reject" else ""))
            return
        pid = int(parts[1])
        if sub == "reject":
            reason = " ".join(parts[2:])
            ok, msg = llm_proposals.queue.refuse(pid, reason)
            (notifier.success if ok else notifier.error)(msg)
            return
        ok, msg = llm_proposals.queue.accept(pid)
        if not ok:
            notifier.error(msg)
            return
        notifier.success(msg)
        prop = llm_proposals.queue.get(pid)
        if not session.target:
            notifier.error("No target set: an accepted proposal is executed in "
                           "the engagement scope. Use: set target <ip|host>")
            llm_proposals.queue.record_result(pid, ok=False,
                                              excerpt="no session target")
            return
        bad = llm_proposals.out_of_scope_hosts(prop.command, session.scope)
        if bad:
            notifier.error("Refused by the scope gate: " + ", ".join(bad)
                           + " is/are out of scope")
            llm_proposals.queue.record_result(
                pid, ok=False, excerpt="out of scope: " + ", ".join(bad))
            return
        out = llm_proposals.execute(prop, target=session.target,
                                    scope=session.scope)
        llm_proposals.queue.record_result(pid, ok=bool(out),
                                          excerpt=(out or "").strip())
        return

    if sub == "clear":
        n = llm_proposals.queue.clear()
        notifier.info(f"cleared {n} proposal(s)")
        return

    notifier.error("Unknown llm subcommand: " + sub)
    notifier.info("Usage: llm [journal [refusals] | propose [n] | proposals | "
                  "accept <id> | reject <id> [reason] | clear]")


def _ask_to_install(tool: str, cmd) -> bool:
    """Ask the operator, in the shell, before running a package manager.

    Defaults to NO on anything other than an explicit yes, and treats a
    non-interactive shell as a no: an automated run must never install software
    on the operator's machine just because a scan wanted a tool.
    """
    from rich.prompt import Confirm
    try:
        return bool(Confirm.ask(
            "Install " + tool + "?  ($ " + " ".join(cmd) + ")", default=False))
    except Exception:
        return False


COMMANDS = {
    "c2": cmd_c2,
    "malleable": cmd_malleable,
    "ad": cmd_ad,
    "wordlists": cmd_wordlists,
    "export": cmd_export,
    "guardrails": cmd_guardrails,
    "deps": cmd_deps,
    "llm": cmd_llm,
}
