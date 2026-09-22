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
            notifier.error("Usage: ad add-user <user> [--kerberoastable] "
                           "[--as-rep] [--cracked] [--admin-to H] "
                           "[--session-on H] [--group G]")
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
            notifier.error("Usage: ad add-dc <host>")
            return
        g.add_node(parts[1], "dc", label="Domain Controller")
        if g.domain:
            g.add_edge(g.domain, parts[1], "owns")
        g._save()
        notifier.success(f"DC {parts[1]} recorded")
        return
    if sub == "add-edge":
        if len(parts) < 4 or parts[2].lower() not in EDGE_TYPES:
            notifier.error(f"Usage: ad add-edge <src> <{'|'.join(EDGE_TYPES)}> <dst>")
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
    notifier.error(f"Unknown ad subcommand: {sub}")


def cmd_wordlists(shell, arg: str):
    """wordlists list | wordlists use <name> | wordlists search <keyword> | wordlists info <name>"""
    from phantom.utils.wordlists import WordlistManager
    WordlistManager().handle(arg)


def cmd_export(shell, arg: str):
    """export <json|pdf|html> [filename] — export session results"""
    from phantom.modules.report import ReportModule
    parts = arg.strip().split()
    if not parts:
        notifier.error("Usage: export <json|pdf|html> [filename]")
        return
    fmt = parts[0].lower()
    if fmt not in ("json", "pdf", "html"):
        notifier.error("Invalid format. Use json, pdf, or html.")
        return
    default_name = f"report_{session.target or 'phantom'}.{fmt}"
    filename = parts[1] if len(parts) > 1 else default_name
    rm = ReportModule()
    rm.export(fmt, filename)


COMMANDS = {
    "c2": cmd_c2,
    "malleable": cmd_malleable,
    "ad": cmd_ad,
    "wordlists": cmd_wordlists,
    "export": cmd_export,
}
