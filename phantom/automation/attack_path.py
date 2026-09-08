"""
attack_path.py — BloodHound-style attack-path graph for the agent.

Models the identity/privilege relationships the agent discovers and
answers the question a senior operator asks mid-engagement: "what is the
cheapest path from my current foothold to the crown jewels (domain admin
/ domain controller)?"

Deterministic and offline: nodes are hosts, accounts and domains; edges
are typed relationships. Only *actionable* edges are traversable for path
finding — `has_creds` (an account can authenticate to a host) and
`admin_on` / `member_of` (privilege) — while `reaches` (host is domain-
joined) is recorded as context but never treated as a pivot step.
"""

from __future__ import annotations

from collections import deque
from typing import Any, Dict, List, Optional, Set

from phantom.automation.belief import WorldModel


class AttackPathGraph:
    """Undirected identity/privilege graph with typed, traversable edges."""

    def __init__(self) -> None:
        self.nodes: List[Dict[str, Any]] = []
        self.edges: List[Dict[str, Any]] = []

    @staticmethod
    def _key(kind: str, value: str) -> str:
        return f"{kind}:{value}"

    def add_node(self, kind: str, value: str, **attrs) -> Dict[str, Any]:
        k = self._key(kind, value)
        for n in self.nodes:
            if n["key"] == k:
                n.update(attrs)
                return n
        n = {"key": k, "kind": kind, "value": value, **attrs}
        self.nodes.append(n)
        return n

    def add_edge(self, a_kind: str, a_val: str, b_kind: str, b_val: str,
                 rel: str, traversable: bool = True) -> Dict[str, Any]:
        a = self._key(a_kind, a_val)
        b = self._key(b_kind, b_val)
        self.add_node(a_kind, a_val)
        self.add_node(b_kind, b_val)
        for e in self.edges:
            if e["rel"] == rel and {e["a"], e["b"]} == {a, b}:
                return e
        e = {"a": a, "b": b, "rel": rel, "traversable": traversable}
        self.edges.append(e)
        return e

    def neighbors(self, key: str) -> List[str]:
        """Adjacent nodes over ACTIONABLE (traversable) edges only."""
        out = []
        for e in self.edges:
            if not e.get("traversable", True):
                continue
            if e["a"] == key:
                out.append(e["b"])
            elif e["b"] == key:
                out.append(e["a"])
        return out

    def nodes_of(self, kind: str) -> List[Dict[str, Any]]:
        return [n for n in self.nodes if n["kind"] == kind]

    def privileged_accounts(self) -> Set[str]:
        """Account node keys holding admin/membership on a host or domain."""
        out: Set[str] = set()
        for e in self.edges:
            if e["rel"] in ("admin_on", "member_of"):
                out.add(e["a"])
        return out

    def shortest_path(self, start_key: str, targets: Set[str]) -> List[str]:
        """BFS shortest path (traversable edges) from start to any target."""
        if start_key in targets:
            return [start_key]
        prev: Dict[str, Optional[str]] = {start_key: None}
        q = deque([start_key])
        while q:
            cur = q.popleft()
            for nb in self.neighbors(cur):
                if nb in prev:
                    continue
                prev[nb] = cur
                if nb in targets:
                    path = [nb]
                    step = nb
                    while prev[step] is not None:
                        step = prev[step]
                        path.append(step)
                    return path[::-1]
                q.append(nb)
        return []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [{"key": n["key"], "kind": n["kind"],
                       "value": n["value"]} for n in self.nodes],
            "edges": [{"a": e["a"], "b": e["b"], "rel": e["rel"],
                       "traversable": e.get("traversable", True)}
                      for e in self.edges],
        }


def build_attack_path(wm: WorldModel,
                      peers: Optional[List[str]] = None) -> AttackPathGraph:
    """Build the graph from the world model's findings."""
    g = AttackPathGraph()
    hosts = [wm.target] + [p for p in (peers or []) if p and p != wm.target]
    for h in hosts:
        g.add_node("host", h)

    domain = ""
    for kind in ("ad_domain", "ad_hint"):
        for f in wm.find(kind):
            if isinstance(f.value, dict) and f.value.get("domain"):
                domain = str(f.value["domain"])
    if domain:
        g.add_node("domain", domain)
        for h in hosts:
            # context: host is domain-joined — NOT a pivot step
            g.add_edge("host", h, "domain", domain, "reaches",
                       traversable=False)

    # valid credentials grant access from the account to the hosts
    for f in wm.find("creds"):
        v = f.value if isinstance(f.value, dict) else {}
        user = str(v.get("username") or "")
        if not user:
            continue
        g.add_node("account", user)
        if v.get("valid"):
            for h in hosts:
                g.add_edge("account", user, "host", h, "has_creds")

    # SYSTEM/DCSync foothold => the operator holds a privileged account
    if wm.find("system_privilege") or wm.find("ad_creds"):
        users = [n["value"] for n in g.nodes_of("account")]
        priv_user = users[0] if users else "privileged-account"
        g.add_node("account", priv_user)
        if domain:
            g.add_edge("account", priv_user, "domain", domain, "admin_on")
    return g


def pivot_plan(wm: WorldModel,
               peers: Optional[List[str]] = None) -> Dict[str, Any]:
    """Concrete lateral-movement guidance from the graph:

      * foothold_accounts — accounts the operator holds valid creds for
      * next_peers        — peers those accounts can authenticate to
      * privileged_accounts — domain-admin candidates
      * reached_privileged — the foothold already holds a DA
    """
    g = build_attack_path(wm, peers)
    start = g._key("host", wm.target)

    foothold_accounts = [
        e["b"] if e["a"] == start else e["a"]
        for e in g.edges
        if e["rel"] == "has_creds" and (e["a"] == start or e["b"] == start)
    ]
    reachable_hosts: Set[str] = set()
    for acc in foothold_accounts:
        for e in g.edges:
            if e["rel"] != "has_creds":
                continue
            if e["a"] == acc:
                reachable_hosts.add(e["b"])
            elif e["b"] == acc:
                reachable_hosts.add(e["a"])
    next_peers = sorted(
        h.split(":", 1)[1] for h in reachable_hosts
        if h.startswith("host:") and h != start
    )

    privileged = g.privileged_accounts()
    path = (g.shortest_path(start, privileged) if privileged else [])
    reached = bool(path)

    return {
        "graph": g.to_dict(),
        "foothold_accounts": sorted(foothold_accounts),
        "next_peers": next_peers,
        "privileged_accounts": sorted(privileged),
        "reached_privileged": reached,
        "path_to_privileged": path,
    }
