"""ad_graph.py — BloodHound-style AD attack graph for the manual core.

The auto-mode gets AD depth from the post/ package (ad_enum, kerberoast,
AS-REP, DCSync). The MANUAL core so far had no way to SEE the AD
structure an operator collected by hand. This module closes that gap:

  * `ad` command in the phantom shell renders the domain graph as an
    ASCII tree (users, groups, kerberoastable, sessions, admin-to) and
    computes attack paths to Domain Admin from any node;
  * the same graph is served as JSON at /api/ad/graph for the Electron
    panel (nodes/edges like BloodHound's view, but computed locally from
    session knowledge — no collection agent required);
  * data sources: the session WorldModel (ad_domain, ad_user, creds,
    kerberoastable, session, admin_to, group_member findings) populated
    by `use ad`, the auto-mode, or manual `set`/`note` of the operator.

Attack-path logic is explicit and explainable (BloodHound's shortest-path
semantics on a curated edge set), not a black box:

    kerberoastable user -> crackable hash -> creds -> admin_to -> DA
    session(DC)         -> creds in memory  -> DA
    user in AD group    -> member-of chain  -> DA
"""

from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

STATE_PATH = Path("data/ad_graph.json")


# ── model ────────────────────────────────────────────────────────────────

NODE_TYPES = ("domain", "user", "group", "computer", "dc")

EDGE_TYPES = (
    "member_of",     # user -> group
    "admin_to",      # user -> computer/DC
    "session",       # user -> computer/DC (interactive session)
    "kerberoastable",# user -> (flagged; cracking = creds)
    "as_rep_roastable",
    "cracked",       # user -> creds known
    "owns",          # generic full control
)


@dataclass
class ADNode:
    id: str
    type: str                    # NODE_TYPES
    props: Dict = field(default_factory=dict)


@dataclass
class ADEdge:
    src: str
    dst: str
    type: str                    # EDGE_TYPES
    note: str = ""


class ADGraph:
    """Mutable in-memory graph, persisted to data/ad_graph.json so it
    survives sessions like the rest of the engagement state."""

    def __init__(self) -> None:
        self.nodes: Dict[str, ADNode] = {}
        self.edges: List[ADEdge] = []
        self.domain: str = ""
        self._load()

    # ── mutation ─────────────────────────────────────────────────────
    def add_node(self, id: str, type: str, **props) -> ADNode:
        n = self.nodes.get(id)
        if n is None:
            n = ADNode(id=id, type=type, props=dict(props))
            self.nodes[id] = n
        else:
            n.props.update(props)
        if type == "domain":
            self.domain = id
        self._save()
        return n

    def add_edge(self, src: str, dst: str, type: str, note: str = "") -> None:
        if src not in self.nodes or dst not in self.nodes:
            return
        for e in self.edges:
            if (e.src, e.dst, e.type) == (src, dst, type):
                if note and note not in e.note:
                    e.note = f"{e.note}; {note}" if e.note else note
                self._save()
                return
        self.edges.append(ADEdge(src=src, dst=dst, type=type, note=note))
        self._save()

    # ── queries ──────────────────────────────────────────────────────
    def kerberoastables(self) -> List[str]:
        return [e.src for e in self.edges if e.type == "kerberoastable"]

    def cracked(self) -> List[str]:
        return [e.src for e in self.edges if e.type == "cracked"]

    def paths_to(self, target: str = "DA", max_paths: int = 5
                 ) -> List[List[Tuple[str, str, str]]]:
        """Shortest attack paths (node, edge, node) ... to `target`
        (the DA node id or 'DA' alias). BFS over directed edges WITH
        transitive group nesting: a user reaches what its groups reach —
        member_of chains are expanded (user -> groupA -> groupB -> DA),
        the BloodHound property direct edges alone miss.
        """
        dst = target if target in self.nodes else self._da_id()
        if dst is None or dst not in self.nodes:
            return []
        adj: Dict[str, List[ADEdge]] = {}
        for e in self.edges:
            adj.setdefault(e.src, []).append(e)
        # TRANSITIVE GROUP NESTING: a user inherits the POWER of every
        # group it reaches through member_of chains (direct OR nested).
        # member_of links need no expansion — BFS walks the real chain
        # nodes; what direct edges CANNOT express is "my nested group can
        # admin DC01, therefore so can I" — those become implied edges.
        # Cycle guard keeps pathological loops from hanging the expansion.
        eff: Dict[str, List[ADEdge]] = {k: list(v) for k, v in adj.items()}
        for u in [n.id for n in self.nodes.values() if n.type == "user"]:
            seen_groups = set()
            frontier = [e.dst for e in adj.get(u, [])
                        if e.type == "member_of"]
            depth = 0
            while frontier and depth < 8:      # nesting depth guard
                nxt: List[str] = []
                for g in frontier:
                    if g in seen_groups:
                        continue
                    seen_groups.add(g)
                    for e in adj.get(g, []):
                        if e.type == "member_of":
                            nxt.append(e.dst)   # keep walking the chain
                        else:
                            # the group's POWER edges become the user's:
                            # group -> admin_to/owns X  ⇒  user can reach X
                            eff.setdefault(u, []).append(ADEdge(
                                src=u, dst=e.dst, type=e.type,
                                note=f"via group {g}"))
                frontier = nxt
                depth += 1
        adj = eff
        paths: List[List[Tuple[str, str, str]]] = []
        # multi-source BFS from every node is O(V*E); the graphs we handle
        # are small (<500 nodes) — clarity over cleverness
        for start in self.nodes:
            if start == dst:
                continue
            # BFS from start to dst
            prev: Dict[str, Tuple[str, ADEdge]] = {}
            q: deque = deque([start])
            seen = {start}
            while q and dst not in seen:
                cur = q.popleft()
                for e in adj.get(cur, []):
                    if e.dst not in seen:
                        seen.add(e.dst)
                        prev[e.dst] = (cur, e)
                        q.append(e.dst)
            if dst in seen:
                chain: List[Tuple[str, str, str]] = []
                cur = dst
                while cur != start:
                    p, e = prev[cur]
                    chain.append((p, e.type, cur))
                    cur = p
                chain.reverse()
                paths.append(chain)
            if len(paths) >= max_paths:
                break
        paths.sort(key=len)
        return paths[:max_paths]

    def _da_id(self) -> Optional[str]:
        for n in self.nodes.values():
            if n.type in ("user", "group") and (
                    "domain admin" in n.props.get("label", "").lower()
                    or n.id.lower() in ("da", "domain admins")):
                return n.id
        return None

    # ── rendering ────────────────────────────────────────────────────
    def ascii_tree(self) -> List[str]:
        lines: List[str] = []
        dom = self.domain or "(no domain collected — run `use ad` or auto-mode)"
        lines.append(f"DOMAIN {dom}")
        dcs = [n for n in self.nodes.values() if n.type == "dc"]
        for dc in dcs:
            lines.append(f"  DC {dc.id}")
            for u in self._users_on(dc.id):
                marks = self._user_marks(u)
                lines.append(f"    {u} {marks}")
        plain = [n for n in self.nodes.values() if n.type == "computer"
                 and n.id not in {d.id for d in dcs}]
        for c in plain:
            lines.append(f"  HOST {c.id}")
            for u in self._users_on(c.id):
                marks = self._user_marks(u)
                lines.append(f"    {u} {marks}")
        users = [n for n in self.nodes.values() if n.type == "user"
                 and not self._user_sessions(n.id)]
        for u in users:
            marks = self._user_marks(u)
            groups = [e.dst for e in self.edges
                      if e.type == "member_of" and e.src == u.id]
            lines.append(f"  USER {u.id} {marks}"
                         + (f" member_of={','.join(groups)}" if groups else ""))
        if not self.nodes or len(self.nodes) <= 1:
            lines.append("  (empty — collect AD data with `use ad`, "
                         "auto-mode, or `ad add-user`)")
        paths = self.paths_to("DA")
        if paths:
            lines.append("")
            lines.append(f"ATTACK PATHS to Domain Admin ({len(paths)} shown):")
            for i, p in enumerate(paths, 1):
                chain = " -> ".join(
                    f"{src}[{et}]{dst}" for src, et, dst in p)
                lines.append(f"  [{i}] {chain}")
        return lines

    def _user_sessions(self, user: str) -> List[str]:
        return [e.dst for e in self.edges
                if e.type == "session" and e.src == user]

    def _users_on(self, host: str) -> List[str]:
        return [e.src for e in self.edges
                if e.type in ("session", "admin_to") and e.dst == host]

    def _user_marks(self, user_id: str) -> str:
        marks = []
        if any(e.src == user_id and e.type == "kerberoastable"
               for e in self.edges):
            marks.append("KERBEROASTABLE")
        if any(e.src == user_id and e.type == "as_rep_roastable"
               for e in self.edges):
            marks.append("AS_REP")
        if any(e.src == user_id and e.type == "cracked"
               for e in self.edges):
            marks.append("CREDS")
        return ("[" + ",".join(marks) + "]") if marks else ""

    # ── persistence ──────────────────────────────────────────────────
    def _load(self) -> None:
        try:
            data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
            self.domain = data.get("domain", "")
            self.nodes = {k: ADNode(id=k, type=v.get("type", "user"),
                                    props=v.get("props", {}))
                          for k, v in (data.get("nodes") or {}).items()}
            self.edges = [ADEdge(**e) for e in (data.get("edges") or [])]
        except Exception:
            pass

    def _save(self) -> None:
        try:
            STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
            STATE_PATH.write_text(json.dumps({
                "domain": self.domain,
                "nodes": {k: {"type": n.type, "props": n.props}
                          for k, n in self.nodes.items()},
                "edges": [{"src": e.src, "dst": e.dst, "type": e.type,
                           "note": e.note} for e in self.edges],
            }, indent=1), encoding="utf-8")
        except OSError:
            pass

    # ── electron payload ─────────────────────────────────────────────
    def to_json(self) -> Dict:
        return {
            "domain": self.domain,
            "nodes": [{"id": n.id, "type": n.type, **(n.props or {})}
                      for n in self.nodes.values()],
            "edges": [{"src": e.src, "dst": e.dst, "type": e.type,
                       "note": e.note} for e in self.edges],
            "paths": [[{"src": s, "edge": t, "dst": d} for s, t, d in p]
                      for p in self.paths_to("DA")],
        }


# ── seeding from the session WorldModel ──────────────────────────────────

def ingest_from_wm(wm) -> ADGraph:
    """Fold every AD fact the session already holds (auto-mode run, `use
    ad` module, operator notes) into the graph. Idempotent."""
    g = ADGraph()
    dom_f = wm.find("ad_domain")
    if dom_f:
        v = dom_f[0].value if isinstance(dom_f[0].value, dict) else {}
        domain = str(v.get("domain", "")) or str(dom_f[0].key)
        dc = str(v.get("dc_host", ""))
        g.add_node(domain, "domain")
        if dc:
            g.add_node(dc, "dc", label="Domain Controller")
            g.add_edge(domain, dc, "owns")
    for f in wm.find("ad_user"):
        uid = str(f.key)
        v = f.value if isinstance(f.value, dict) else {}
        g.add_node(uid, "user", label=str(v.get("label", uid)))
        if v.get("kerberoastable"):
            # flags are boolean node props (self-loops would corrupt BFS)
            g.nodes[uid].props["kerberoastable"] = True
        if v.get("as_rep"):
            g.nodes[uid].props["as_rep_roastable"] = True
        if v.get("cracked") or v.get("password"):
            g.nodes[uid].props["cracked"] = True
        if v.get("admin_to"):
            for host in (v["admin_to"] if isinstance(v["admin_to"], list)
                         else [v["admin_to"]]):
                if host not in g.nodes:
                    g.add_node(str(host), "computer")
                g.add_edge(uid, str(host), "admin_to")
        if v.get("session_on"):
            for host in (v["session_on"] if isinstance(v["session_on"], list)
                         else [v["session_on"]]):
                if host not in g.nodes:
                    g.add_node(str(host), "computer")
                g.add_edge(uid, str(host), "session")
    # ── finding kinds the AGENT actually emits ──────────────────────
    # ad_users: the ad-awareness / enum pass discovered a user list
    #   {"users": ["alice", "bob"]} (or "names", or a list value)
    for f in wm.find("ad_users"):
        v = f.value if isinstance(f.value, dict) else {}
        names = v.get("users") or v.get("names") or v.get("accounts") \
            or (v if isinstance(v, list) else [])
        for u in (names or [])[:50]:
            u = str(u).strip()
            if u and u not in g.nodes:
                g.add_node(u, "user", label=u)
    # ad_weakness: anonymous LDAP bind / other domain weaknesses
    for f in wm.find("ad_weakness"):
        v = f.value if isinstance(f.value, dict) else {}
        host = str(v.get("host", ""))
        if host and host not in g.nodes:
            g.add_node(host, "computer", label=host)
        if host:
            g.nodes[host].props.setdefault("weaknesses", []).append(
                str(v.get("type", "")))
    # ad_creds: kerberoast / as_rep / dc_sync / hash_crack outputs —
    # credentialed access to the DOMAIN user is a graph-grade fact
    for f in wm.find("ad_creds"):
        v = f.value if isinstance(f.value, dict) else {}
        dom = str(v.get("domain", ""))
        # cracked domain creds ALSO arrive as kind=creds service=domain;
        # here we only map the hash-bearing ad_creds facts
        if v.get("hash") and dom and dom not in g.nodes:
            g.add_node(dom, "domain", label=dom)
    # creds with service=domain: a valid domain login becomes a user
    # node the graph can walk from (kerberoast/DCSync prerequisites) —
    # the edge is recorded EVEN when the node already exists (users
    # usually appear first from enumeration)
    for f in wm.find("creds"):
        v = f.value if isinstance(f.value, dict) else {}
        if str(v.get("service", "")) == "domain":
            u = str(v.get("username", "")).strip()
            dom = str(v.get("domain", ""))
            if not u:
                continue
            if u not in g.nodes:
                g.add_node(u, "user", label=u)
            if dom:
                if dom not in g.nodes:
                    g.add_node(dom, "domain", label=dom)
                g.add_edge(u, dom, "member_of",
                           note="valid domain creds")
    # edges from findings with explicit relationships
    for f in wm.find("ad_edge"):
        v = f.value if isinstance(f.value, dict) else {}
        src, dst, et = str(v.get("src", "")), str(v.get("dst", "")), \
            str(v.get("type", ""))
        if src and dst and et in EDGE_TYPES:
            if src not in g.nodes:
                g.add_node(src, "user")
            if dst not in g.nodes:
                g.add_node(dst, "computer")
            g.add_edge(src, dst, et, str(v.get("note", "")))
    return g
