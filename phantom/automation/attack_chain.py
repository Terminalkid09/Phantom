"""
attack_chain.py — cross-service attack graph composition.

Takes all findings in the WorldModel and builds a directed graph of
possible attack paths: how one discovered fact enables the next step.

Example chains:
  SSRF web → 169.254.169.254 → IAM creds → S3 list → source code → DB
  SMB null session → share → plaintext password → SSH login → beacon
  MySQL default → LOAD DATA LOCAL → /etc/shadow → crack → SSH
  SNMP community → device config → VLAN info → lateral targets
  LDAP anonymous → Domain Users → password spray candidates
  Redis no-auth → SLAVEOF → rogue master → persistence

The planner reads the graph to decide the most promising path instead
of treating findings as isolated items.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from phantom.automation.belief import WorldModel, Finding


# ── graph model ────────────────────────────────────────────────────────

@dataclass
class AttackNode:
    """A node in the attack graph — a fact that was discovered."""
    id: str
    kind: str                      # service | creds | vuln | fingerprint | ...
    label: str                     # human-readable summary
    finding: Optional[Finding] = None
    cost: float = 0.0              # OPSEC cost to reach this node
    score: float = 0.0             # value toward the goal
    reachable: bool = True
    exploited: bool = False        # already used in a chain

    def __hash__(self) -> int:
        return hash(self.id)


@dataclass
class AttackEdge:
    """A directed edge: from_node ENABLES to_node."""
    from_id: str
    to_id: str
    label: str                     # how from enables to (e.g. "creds → SSH login")
    confidence: float = 0.7        # how likely this path works
    technique: str = ""            # MITRE ATT&CK technique ID when applicable


@dataclass
class AttackPath:
    """A complete attack path from start to goal."""
    nodes: List[str] = field(default_factory=list)
    edges: List[AttackEdge] = field(default_factory=list)
    total_cost: float = 0.0
    total_confidence: float = 1.0
    goal: str = "beacon"

    @property
    def length(self) -> int:
        return len(self.nodes)

    @property
    def summary(self) -> str:
        return " → ".join(self.nodes)


# ── rule engine (declarative: finding X + finding Y = possible edge) ───

# Each rule: (from_kind, from_value_condition, to_kind, to_value_condition,
#             edge_label, confidence, technique)
# from_value_condition and to_value_condition are callables that take the
# Finding.value and return True if this rule applies.

ChainRule = Tuple[str, Any, str, Any, str, float, str]


def _has_creds(value: Any) -> bool:
    """Finding value contains valid credentials."""
    if isinstance(value, dict):
        return bool(value.get("username") and value.get("password"))
    return False


def _has_hash(value: Any) -> bool:
    """Finding value contains a hash (crackable)."""
    if isinstance(value, dict):
        return bool(value.get("hash"))
    return False


def _is_web_service(value: Any) -> bool:
    """Finding value is a web service (HTTP/HTTPS)."""
    if isinstance(value, dict):
        svc = str(value.get("service", "")).lower()
        return svc in ("http", "https", "web", "www")
    return False


def _is_database(value: Any) -> bool:
    """Finding value is a database."""
    if isinstance(value, dict):
        svc = str(value.get("service", "")).lower()
        return svc in ("mysql", "mssql", "postgresql", "mongodb", "redis", "oracle")
    return False


def _is_smb(value: Any) -> bool:
    if isinstance(value, dict):
        return str(value.get("service", "")).lower() == "smb"
    return False


def _has_smb_anon(value: Any) -> bool:
    if isinstance(value, dict):
        return value.get("anonymous") is True or value.get("null_session") is True
    return False


def _is_ssh(value: Any) -> bool:
    if isinstance(value, dict):
        return str(value.get("service", "")).lower() == "ssh"
    return False


def _is_rdp(value: Any) -> bool:
    if isinstance(value, dict):
        return str(value.get("service", "")).lower() == "rdp"
    return False


def _is_ftp(value: Any) -> bool:
    if isinstance(value, dict):
        return str(value.get("service", "")).lower() == "ftp"
    return False


def _is_ldap(value: Any) -> bool:
    if isinstance(value, dict):
        return str(value.get("service", "")).lower() == "ldap"
    return False


def _is_snmp(value: Any) -> bool:
    if isinstance(value, dict):
        return str(value.get("service", "")).lower() == "snmp"
    return False


def _is_redis(value: Any) -> bool:
    if isinstance(value, dict):
        return str(value.get("service", "")).lower() == "redis"
    return False


def _is_docker(value: Any) -> bool:
    if isinstance(value, dict):
        return str(value.get("service", "")).lower() == "docker"
    return False


def _has_ssrf(value: Any) -> bool:
    if isinstance(value, dict):
        return bool(value.get("cls") == "ssrf" or "ssrf" in str(value.get("cls", "")))
    return False


def _has_ssti_rce(value: Any) -> bool:
    if isinstance(value, dict):
        v = str(value)
        return ("ssti" in v.lower() and value.get("confirmed")) or \
               (value.get("severity") in ("critical", "high") and "rce" in str(value).lower())
    return False


def _is_sql_injection(value: Any) -> bool:
    if isinstance(value, dict):
        return value.get("cls") == "sqli" and value.get("confirmed")
    return False


def _has_path_traversal(value: Any) -> bool:
    if isinstance(value, dict):
        return value.get("cls") == "traversal" and value.get("confirmed")
    return False


def _always_true(_: Any) -> bool:
    return True


# ── chain rules ────────────────────────────────────────────────────────

CHAIN_RULES: List[ChainRule] = [
    # Credential reuse: any creds → any reachable service
    ("creds", _has_creds, "service", _is_ssh,
     "SSH login with found credentials", 0.8, "T1078"),
    ("creds", _has_creds, "service", _is_smb,
     "SMB share access with found credentials", 0.75, "T1078"),
    ("creds", _has_creds, "service", _is_rdp,
     "RDP login with found credentials", 0.7, "T1078"),
    ("creds", _has_creds, "service", _is_ftp,
     "FTP login with found credentials", 0.85, "T1078"),
    ("creds", _has_creds, "service", _is_database,
     "Database login with found credentials", 0.8, "T1078"),
    ("creds", _has_creds, "service", _is_ldap,
     "LDAP bind with found credentials", 0.7, "T1078"),
    ("creds", _has_creds, "service", _is_redis,
     "Redis AUTH with found credentials", 0.9, "T1078"),
    ("creds", _has_creds, "service", _is_docker,
     "Docker API with found credentials", 0.75, "T1078"),

    # Default/Misconfig → quick access
    ("service", _is_smb, "smb_anon", _has_smb_anon,
     "SMB null session discovered", 0.9, "T1021.002"),
    ("service", _is_redis, "service", lambda v: v.get("auth_required") is False,
     "Redis no-auth access", 0.95, "T1190"),
    ("service", _is_snmp, "service", lambda v: v.get("community") == "public",
     "SNMP default community string", 0.9, "T1040"),
    ("service", _is_ftp, "service", lambda v: v.get("anonymous") is True,
     "FTP anonymous access", 0.9, "T1078"),

    # Service → lateral discovery
    ("service", _is_smb, "peer_discovery", _always_true,
     "SMB share enumeration → discover peers", 0.7, "T1018"),
    ("service", _is_ldap, "peer_discovery", _always_true,
     "LDAP enumeration → discover domain assets", 0.75, "T1018"),
    ("service", _is_snmp, "peer_discovery", _always_true,
     "SNMP walk → discover VLAN peers", 0.65, "T1018"),

    # Web vulns → deeper access
    ("hunt_anomaly", _has_ssrf, "cloud_creds", _always_true,
     "SSRF → AWS metadata → IAM credentials", 0.6, "T1526"),
    ("hunt_anomaly", _has_ssti_rce, "rce", _always_true,
     "SSTI → remote code execution confirmed", 0.7, "T1190"),
    ("hunt_anomaly", _has_path_traversal, "file_read", _always_true,
     "Path traversal → file read confirmed", 0.65, "T1003"),
    ("hunt_anomaly", _is_sql_injection, "data_exfil", _always_true,
     "SQL injection → data exfiltration confirmed", 0.7, "T1565"),

    # Hash → crack → creds
    ("hash", _has_hash, "creds", _always_true,
     "Offline hash cracking", 0.5, "T1110.002"),

    # RCE → beacon
    ("rce", _always_true, "beacon", _always_true,
     "RCE → beacon injection", 0.8, "T1105"),
    ("cloud_creds", _always_true, "beacon", _always_true,
     "Cloud credentials → lateral beacon deploy", 0.6, "T1105"),
    ("cloud_creds", _always_true, "cloud_lateral", _always_true,
     "Cloud credentials → IAM role enumeration + STS assume", 0.7, "T1552.005"),
    ("cloud_lateral", _always_true, "cloud_access", _always_true,
     "Assumed role → cross-account data access", 0.65, "T1078.004"),
    ("creds", _has_creds, "beacon", _always_true,
     "Credentials → beacon deployment", 0.75, "T1105"),

    # Docker API → container escape potential
    ("service", _is_docker, "container_escape", _always_true,
     "Docker API exposed → container escape potential", 0.5, "T1610"),
]


# ── graph builder ──────────────────────────────────────────────────────

class AttackGraph:
    """Build and query an attack graph from WorldModel findings."""

    def __init__(self, wm: WorldModel) -> None:
        self.wm = wm
        self.nodes: Dict[str, AttackNode] = {}
        self.edges: List[AttackEdge] = []
        self._built = False

    def build(self) -> None:
        """Construct the graph from current WorldModel findings."""
        self.nodes.clear()
        self.edges.clear()

        # Step 1: create nodes for every finding
        for f in self.wm.all_findings():
            node_id = f"{f.kind}:{f.key}"
            label = self._node_label(f)
            self.nodes[node_id] = AttackNode(
                id=node_id, kind=f.kind, label=label,
                finding=f, cost=0.0, score=self._node_score(f),
            )

        # Step 2: apply chain rules to discover edges
        for from_node in list(self.nodes.values()):
            for to_node in list(self.nodes.values()):
                if from_node.id == to_node.id:
                    continue
                for rule in CHAIN_RULES:
                    from_kind, from_cond, to_kind, to_cond, label, conf, tech = rule
                    if from_node.kind == from_kind and to_node.kind == to_kind:
                        from_val = from_node.finding.value if from_node.finding else None
                        to_val = to_node.finding.value if to_node.finding else None
                        if from_val is not None and to_val is not None:
                            try:
                                if from_cond(from_val) and to_cond(to_val):
                                    self.edges.append(AttackEdge(
                                        from_id=from_node.id, to_id=to_node.id,
                                        label=label, confidence=conf, technique=tech,
                                    ))
                            except Exception:
                                pass

        # Step 3: propagate reachability from "entry" nodes
        # Entry nodes: kind=service (no incoming edges needed from operator)
        self._propagate_reachability()
        self._built = True

    def _node_label(self, f: Finding) -> str:
        """Human-readable label for a finding node."""
        value = f.value
        if isinstance(value, dict):
            svc = value.get("service", "") or value.get("product", "")
            port = value.get("port", "")
            ver = value.get("version", "")
            if svc and port:
                label = f"{svc}:{port}"
            elif svc:
                label = svc
            else:
                label = f"{f.kind}:{f.key}"
            if ver:
                label += f" ({ver})"
            return label
        return f"{f.kind}:{f.key}"

    def _node_score(self, f: Finding) -> float:
        """Heuristic score for how valuable this node is toward beacon injection."""
        scores = {
            "beacon": 100,
            "creds": 50,
            "rce": 80,
            "cloud_creds": 60,
            "service": 20,
            "fingerprint": 15,
            "hunt_anomaly": 40,
            "vuln": 50,
            "smb_anon": 30,
            "peer_discovery": 30,
            "file_read": 35,
            "container_escape": 45,
        }
        return scores.get(f.kind, 10)

    def _propagate_reachability(self) -> None:
        """BFS from entry nodes (services) to mark all reachable nodes."""
        from collections import deque
        # Entry points: any service node
        queue: deque[AttackNode] = deque()
        for node in self.nodes.values():
            if node.kind in ("service", "fingerprint"):
                node.reachable = True
                queue.append(node)

        while queue:
            current = queue.popleft()
            for edge in self.edges:
                if edge.from_id == current.id:
                    target = self.nodes.get(edge.to_id)
                    if target and not target.reachable:
                        target.reachable = True
                        queue.append(target)

    def find_paths(self, goal: str = "beacon", max_paths: int = 5) -> List[AttackPath]:
        """Find the best attack paths from any entry node to the goal."""
        if not self._built:
            self.build()

        if goal not in {n.kind for n in self.nodes.values()}:
            return []  # goal not in graph yet

        paths: List[AttackPath] = []

        def _dfs(current_id: str, visited: Set[str],
                 path_nodes: List[str], path_edges: List[AttackEdge],
                 cost: float, confidence: float):
            if len(paths) >= max_paths:
                return
            current = self.nodes.get(current_id)
            if current is None or current_id in visited:
                return
            visited.add(current_id)
            path_nodes.append(current_id)

            if current.kind == goal and path_nodes:
                paths.append(AttackPath(
                    nodes=list(path_nodes),
                    edges=list(path_edges),
                    total_cost=cost,
                    total_confidence=confidence,
                    goal=goal,
                ))
                visited.discard(current_id)
                path_nodes.pop()
                return

            for edge in self.edges:
                if edge.from_id == current_id and edge.to_id not in visited:
                    next_node = self.nodes.get(edge.to_id)
                    if next_node and next_node.reachable:
                        path_edges.append(edge)
                        _dfs(edge.to_id, visited, path_nodes, path_edges,
                             cost + 1.0, confidence * edge.confidence)
                        path_edges.pop()

            visited.discard(current_id)
            path_nodes.pop()

        # Start from entry nodes (services/fingerprints)
        for node in self.nodes.values():
            if node.kind in ("service", "fingerprint", "creds", "hunt_anomaly", "rce") and node.reachable:
                _dfs(node.id, set(), [], [], 0.0, 1.0)
                if len(paths) >= max_paths:
                    break

        # Sort by confidence (descending)
        paths.sort(key=lambda p: p.total_confidence, reverse=True)
        return paths[:max_paths]

    def best_path(self, goal: str = "beacon") -> Optional[AttackPath]:
        """The single best path to the goal."""
        paths = self.find_paths(goal, max_paths=1)
        return paths[0] if paths else None

    def missing_for_goal(self, goal: str = "beacon") -> List[str]:
        """What capabilities are missing from the graph to reach the goal?"""
        paths = self.find_paths(goal, max_paths=5)
        if paths:
            return []  # goal is reachable

        # Check what kinds of findings are completely absent
        missing = []
        necessary_kinds = {"creds", "rce", "cloud_creds", "file_read"}
        present = {n.kind for n in self.nodes.values()}
        for kind in necessary_kinds:
            if kind not in present:
                missing.append(kind)
        return missing

    def summary(self) -> str:
        """One-line summary of the attack graph."""
        if not self._built:
            self.build()
        n_nodes = len(self.nodes)
        n_edges = len(self.edges)
        n_reachable = sum(1 for n in self.nodes.values() if n.reachable)
        paths_to_beacon = len(self.find_paths("beacon", max_paths=10))
        return (
            f"AttackGraph: {n_nodes} nodes, {n_edges} edges, "
            f"{n_reachable} reachable, {paths_to_beacon} path(s) to beacon"
        )


def build_attack_summary(wm: WorldModel) -> Dict[str, Any]:
    """High-level summary: what the planner can use to prioritize."""
    graph = AttackGraph(wm)
    graph.build()
    best = graph.best_path("beacon")
    missing = graph.missing_for_goal("beacon")
    return {
        "nodes": len(graph.nodes),
        "edges": len(graph.edges),
        "paths_to_beacon": len(graph.find_paths("beacon", max_paths=10)),
        "best_path": [graph.nodes[n].label for n in (best.nodes if best else [])],
        "best_confidence": best.total_confidence if best else 0.0,
        "missing_for_beacon": missing,
        "entry_points": [n.label for n in graph.nodes.values()
                         if n.kind == "service" and n.reachable],
    }