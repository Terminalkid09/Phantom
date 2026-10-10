"""social_graph.py — the identity graph the recon engine kept throwing away.

`recon.py` proves a lot about a target (commenters, tagged handles, second-hop
circles, avatar hashes, visible emails) and then emits all of it as FLAT MARKER
LINES. A human can read those lines; nothing can reason over them, so two
questions the operator actually asks stayed unanswerable:

  * who is in this person's circle, and through HOW MANY independent proofs?
  * which handles are the SAME person (so the money is worth spending on one
    pivot instead of four), and which are merely adjacent?

This module is the graph: nodes are identities (handle/person/email/phone/
domain/place/hashtag) and edges are PROOFS, each carrying the evidence string
and a confidence. Same evidence string twice is ONE edge with a source set, not
two edges: counting an "independent proof" twice is the fastest way to convince
yourself of a false positive.

Design rules, all of them deliberate:

  * dependency-free — the recon engine runs before any exploit tool exists on
    the box, so no networkx, no graphviz. GraphML export is hand-rolled XML and
    opens in Gephi/yEd; the Electron view consumes `to_dict()`.
  * pure and offline-testable — `mine_posts()` and the ingest functions take
    ALREADY-FETCHED json/html, so the whole graph can be verified without a
    network call. The network lives in `recon.py`, not here.
  * every edge keeps its provenance and every node its sources, because a lead
    without provenance is a rumour and one without a source cannot be walked
    back when it turns out to be somebody else's handle.

The authenticated part of the mining is the operator's own session: `recon`
builds the jar from the WorldModel's `stolen_cookies` (the operator's work
account) and replays ONLY what a browser would send to that exact host. This
module never fetches anything, so it cannot leak a cookie anywhere.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# ── vocabulary (closed sets: a typo must not create a silent new kind) ───────

NODE_KINDS = ("person", "handle", "email", "phone", "domain", "url", "place",
              "hashtag", "post")

# directed kinds: A -> B means "A acts on B" (A tags B, A comments on B's post)
EDGE_KINDS = (
    "same_person",        # two handles proven to be one human
    "username_variant",   # near-identical handle, weaker than same_person
    "tagged_in",          # A tagged/mentioned B
    "comments_on",        # A commented on B's content
    "follows",            # A follows B
    "followed_by",        # A is followed by B
    "same_avatar",        # avatar hash match
    "email_match",        # an email appears on both identities
    "reset_flow_match",   # password-reset oracle agreed (email_enum.py)
    "interest",           # A posts about topic B (hashtag/place)
    "search_hit",         # a search result linked the two
    "second_hop",         # circle overlap with the target
)

# strong proofs can CONFIRM an identity; weak ones only suggest a pivot
STRONG_KINDS = frozenset(("same_person", "email_match", "reset_flow_match",
                          "same_avatar"))

MAX_NODES = 500
MAX_EDGES = 2000


def _norm(value: str) -> str:
    return re.sub(r"\s+", "", str(value or "").strip().lower().lstrip("@"))


def node_key(kind: str, value: str) -> str:
    """Stable id: `handle:jane_doe` — kind-prefixed so `jane` (a person) and
    `jane.example.com` (a domain) can never collide."""
    return f"{kind}:{_norm(value)}"


@dataclass
class Node:
    key: str
    kind: str
    label: str = ""
    platform: str = ""
    confidence: float = 0.5
    sources: List[str] = field(default_factory=list)
    attrs: Dict[str, Any] = field(default_factory=dict)

    def merge(self, other: "Node") -> None:
        """Fold a second sighting in: best confidence, union of provenance."""
        self.confidence = max(self.confidence, other.confidence)
        for src in other.sources:
            if src not in self.sources:
                self.sources.append(src)
        for key, val in other.attrs.items():
            if val not in (None, "", [], {}) and self.attrs.get(key) in (None, "", [], {}):
                self.attrs[key] = val
        if not self.label and other.label:
            self.label = other.label
        if not self.platform and other.platform:
            self.platform = other.platform

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.key, "kind": self.kind, "label": self.label,
                "platform": self.platform, "confidence": round(self.confidence, 3),
                "sources": list(self.sources), "attrs": dict(self.attrs)}


@dataclass
class Edge:
    src: str
    dst: str
    kind: str
    evidence: str = ""
    confidence: float = 0.5
    sources: List[str] = field(default_factory=list)
    attrs: Dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> Tuple[str, str, str]:
        return (self.src, self.dst, self.kind)

    @property
    def strong(self) -> bool:
        return self.kind in STRONG_KINDS

    def merge(self, other: "Edge") -> None:
        """Fold a second sighting in: best confidence, union of provenance.

        `evidence` keeps the FIRST evidence string (it is the marker a human
        reads) and a DIFFERENT second one is preserved as an extra provenance
        token, so neither proof is lost while the same string twice stays one
        item.
        """
        self.confidence = max(self.confidence, other.confidence)
        fresh = ([other.evidence] if other.evidence and
                 other.evidence != self.evidence else [])
        for token in fresh + list(other.sources):
            if token and token not in self.sources:
                self.sources.append(token)
        for key, val in other.attrs.items():
            self.attrs.setdefault(key, val)

    def to_dict(self) -> Dict[str, Any]:
        return {"source": self.src, "target": self.dst, "kind": self.kind,
                "evidence": self.evidence, "confidence": round(self.confidence, 3),
                "sources": list(self.sources), "strong": self.strong,
                "attrs": dict(self.attrs)}


class SocialGraph:
    """Bounded identity graph: add, merge, walk, export."""

    def __init__(self, max_nodes: int = MAX_NODES,
                 max_edges: int = MAX_EDGES) -> None:
        self.max_nodes = max_nodes
        self.max_edges = max_edges
        self.nodes: Dict[str, Node] = {}
        self.edges: Dict[Tuple[str, str, str], Edge] = {}
        self.dropped_nodes = 0
        self.dropped_edges = 0

    # ------------------------------------------------------------------ add

    def add_node(self, key: str, kind: str = "handle", *, label: str = "",
                 platform: str = "", confidence: float = 0.5,
                 source: str = "", **attrs: Any) -> Optional[Node]:
        if not key or kind not in NODE_KINDS:
            return None
        node = Node(key=key, kind=kind, label=label or _norm(key), platform=platform,
                    confidence=float(confidence), attrs=dict(attrs))
        if source:
            node.sources.append(source)
        existing = self.nodes.get(key)
        if existing is not None:
            existing.merge(node)
            return existing
        if len(self.nodes) >= self.max_nodes:
            self.dropped_nodes += 1
            return None
        self.nodes[key] = node
        return node

    def add_handle(self, handle: str, *, platform: str = "", source: str = "",
                   confidence: float = 0.5, **attrs: Any) -> Optional[Node]:
        h = _norm(handle)
        if not h:
            return None
        return self.add_node(node_key("handle", h), "handle", label=h,
                             platform=platform, source=source,
                             confidence=confidence, **attrs)

    def add_edge(self, src: str, dst: str, kind: str, *, evidence: str = "",
                 confidence: float = 0.5, source: str = "",
                 **attrs: Any) -> Optional[Edge]:
        """Add a proof. Duplicate (src, dst, kind) MERGES instead of counting."""
        if not src or not dst or src == dst or kind not in EDGE_KINDS:
            return None
        if src not in self.nodes or dst not in self.nodes:
            return None
        edge = Edge(src=src, dst=dst, kind=kind, evidence=evidence,
                    confidence=float(confidence), attrs=dict(attrs))
        if source:
            edge.sources.append(source)
        existing = self.edges.get(edge.key)
        if existing is not None:
            existing.merge(edge)
            return existing
        if len(self.edges) >= self.max_edges:
            self.dropped_edges += 1
            return None
        self.edges[edge.key] = edge
        return edge

    def merge(self, other: "SocialGraph") -> Dict[str, int]:
        """Fold another graph in (the Electron/CLI path merges per-run graphs)."""
        nodes = edges = 0
        for node in other.nodes.values():
            before = node.key in self.nodes
            self.add_node(node.key, node.kind, label=node.label,
                          platform=node.platform, confidence=node.confidence,
                          **node.attrs)
            if node.key in self.nodes:
                for src in node.sources:
                    if src not in self.nodes[node.key].sources:
                        self.nodes[node.key].sources.append(src)
            nodes += 0 if before else 1
        for edge in other.edges.values():
            if edge.key in self.edges:
                self.edges[edge.key].merge(edge)
            else:
                self.add_edge(edge.src, edge.dst, edge.kind,
                              evidence=edge.evidence, confidence=edge.confidence,
                              **edge.attrs)
                edges += 1
        return {"nodes": nodes, "edges": edges}

    # ---------------------------------------------------------------- walks

    def neighbors(self, key: str, kinds: Optional[Iterable[str]] = None,
                  direction: str = "both") -> List[Edge]:
        kinds = set(kinds) if kinds else None
        out = []
        for edge in self.edges.values():
            if kinds and edge.kind not in kinds:
                continue
            if direction in ("out", "both") and edge.src == key:
                out.append(edge)
            elif direction in ("in", "both") and edge.dst == key:
                out.append(edge)
        return out

    def bfs(self, start: str, depth: int = 2, max_nodes: int = 50,
            kinds: Optional[Iterable[str]] = None) -> List[str]:
        """Bounded breadth-first walk, deterministic order, never loops."""
        if start not in self.nodes:
            return []
        seen = [start]
        frontier = [start]
        for _ in range(max(int(depth), 0)):
            nxt: List[str] = []
            for key in frontier:
                for edge in self.neighbors(key, kinds):
                    other = edge.dst if edge.src == key else edge.src
                    if other not in seen and len(seen) < max_nodes:
                        seen.append(other)
                        nxt.append(other)
            if not nxt:
                break
            frontier = nxt
        return seen

    def clusters(self, kinds: Optional[Iterable[str]] = None) -> List[List[str]]:
        """Connected components over undirected edges (the graph view groups
        by cluster: the target's circle, then the pockets of its own)."""
        seen: set = set()
        out: List[List[str]] = []
        for key in self.nodes:
            if key in seen:
                continue
            component = self.bfs(key, depth=99, max_nodes=self.max_nodes,
                                 kinds=kinds)
            if not component:
                component = [key]
            seen.update(component)
            out.append(component)
        return sorted(out, key=lambda c: (-len(c), c[0]))

    def same_person_groups(self) -> List[List[str]]:
        """Handles tied by a CONFIRMING proof (not a mere co-occurrence)."""
        peers: Dict[str, set] = {}
        for edge in self.edges.values():
            if edge.kind not in STRONG_KINDS:
                continue
            a, b = edge.src, edge.dst
            if self.nodes.get(a, None) is not None and self.nodes[a].kind != "handle":
                continue
            if self.nodes.get(b, None) is None or self.nodes[b].kind != "handle":
                continue
            peers.setdefault(a, set()).add(b)
            peers.setdefault(b, set()).add(a)
        groups: List[List[str]] = []
        seen: set = set()
        for key in sorted(peers):
            if key in seen:
                continue
            group = sorted(self._flood(key, peers))
            seen.update(group)
            if len(group) > 1:
                groups.append(group)
        return groups

    @staticmethod
    def _flood(start: str, peers: Dict[str, set]) -> set:
        seen = {start}
        stack = [start]
        while stack:
            cur = stack.pop()
            for nxt in peers.get(cur, ()):
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        return seen

    def pivot_leads(self, kinds: Sequence[str] = ("handle", "email", "phone"),
                    min_confidence: float = 0.0) -> List[Node]:
        """Nodes worth spending a run on, ranked by confidence then proof count."""
        out = [n for n in self.nodes.values()
               if n.kind in kinds and n.confidence >= min_confidence]
        out.sort(key=lambda n: (-n.confidence, -len(self.proofs(n.key)), n.key))
        return out

    def proofs(self, key: str) -> List[Edge]:
        return self.neighbors(key)

    def evidence_count(self, src: str, dst: str) -> int:
        """How many INDEPENDENT proofs connect two nodes (not how many times
        the same proof was seen)."""
        return len([e for e in self.neighbors(src) if e.dst == dst or e.src == dst])

    def interests(self, key: str, limit: int = 20) -> List[Tuple[str, int]]:
        """Topics the person posts about, by frequency (pretext material)."""
        counts: Dict[str, int] = {}
        for edge in self.neighbors(key, kinds=("interest",)):
            label = self.nodes[edge.dst].label if edge.dst in self.nodes else edge.dst
            # a topic is case-insensitive: `#torino` and the place `Torino`
            # are the same interest and must accumulate, not split
            label = _norm(label)
            counts[label] = counts.get(label, 0) + 1
        ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
        return ranked[:limit]

    # -------------------------------------------------------------- exports

    def stats(self) -> Dict[str, Any]:
        by_kind: Dict[str, int] = {}
        for node in self.nodes.values():
            by_kind[node.kind] = by_kind.get(node.kind, 0) + 1
        by_edge: Dict[str, int] = {}
        for edge in self.edges.values():
            by_edge[edge.kind] = by_edge.get(edge.kind, 0) + 1
        return {"nodes": len(self.nodes), "edges": len(self.edges),
                "node_kinds": by_kind, "edge_kinds": by_edge,
                "clusters": len(self.clusters()),
                "same_person_groups": [list(g) for g in self.same_person_groups()],
                "max_confidence": max((n.confidence for n in self.nodes.values()),
                                      default=0.0),
                "dropped_nodes": self.dropped_nodes,
                "dropped_edges": self.dropped_edges}

    def to_dict(self) -> Dict[str, Any]:
        return {"nodes": [n.to_dict() for n in self.nodes.values()],
                "edges": [e.to_dict() for e in self.edges.values()],
                "stats": self.stats()}

    def to_graphml(self) -> str:
        """Hand-rolled GraphML (Gephi/yEd open it; no dependency needed)."""
        import xml.sax.saxutils as sx

        def esc(value: Any) -> str:
            return sx.escape(str(value if value is not None else ""))

        lines = ['<?xml version="1.0" encoding="UTF-8"?>',
                 '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
                 '  <key id="kind" for="node" attr.name="kind" '
                 'attr.type="string"/>',
                 '  <key id="label" for="node" attr.name="label" '
                 'attr.type="string"/>',
                 '  <key id="confidence" for="node" attr.name="confidence" '
                 'attr.type="double"/>',
                 '  <key id="evidence" for="edge" attr.name="evidence" '
                 'attr.type="string"/>',
                 '  <key id="confidence_e" for="edge" attr.name="confidence" '
                 'attr.type="double"/>',
                 '  <graph id="phantom-social" edgedefault="undirected">']
        for node in self.nodes.values():
            lines.append(f'    <node id="{esc(node.key)}">')
            lines.append(f'      <data key="kind">{esc(node.kind)}</data>')
            lines.append(f'      <data key="label">{esc(node.label)}</data>')
            lines.append(f'      <data key="confidence">{node.confidence:.3f}'
                         '</data>')
            lines.append('    </node>')
        for i, edge in enumerate(self.edges.values(), 1):
            lines.append(f'    <edge id="e{i}" source="{esc(edge.src)}" '
                         f'target="{esc(edge.dst)}" '
                         f'label="{esc(edge.kind)}">')
            lines.append(f'      <data key="evidence">{esc(edge.evidence)}'
                         '</data>')
            lines.append(f'      <data key="confidence_e">{edge.confidence:.3f}'
                         '</data>')
            lines.append('    </edge>')
        lines += ['  </graph>', '</graphml>']
        return "\n".join(lines) + "\n"

    def render(self, limit: int = 200) -> str:
        """Plain-text view for the CLI (the desktop view uses `to_dict`)."""
        if not self.nodes:
            return "social graph: empty"
        stats = self.stats()
        out = [f"social graph: {stats['nodes']} nodes, {stats['edges']} edges, "
               f"{stats['clusters']} cluster(s)"]
        groups = stats["same_person_groups"]
        if groups:
            out.append("  same-person groups (confirming proofs only):")
            for group in groups:
                out.append("    - " + ", ".join(group))
        out.append("  nodes:")
        for node in list(self.nodes.values())[:limit]:
            mark = f"{node.kind:<7}"
            extra = f" platform={node.platform}" if node.platform else ""
            out.append(f"    {mark} {node.label or node.key} "
                       f"conf={node.confidence:.2f} "
                       f"proofs={len(self.proofs(node.key))}{extra}")
            for edge in self.proofs(node.key)[:3]:
                other = edge.dst if edge.src == node.key else edge.src
                arrow = "->" if edge.src == node.key else "<-"
                label = self.nodes[other].label if other in self.nodes else other
                out.append(f"          {arrow} {edge.kind:<16} {label}"
                           + (f"  [{edge.evidence}]" if edge.evidence else ""))
        if len(self.nodes) > limit:
            out.append(f"  ... {len(self.nodes) - limit} more node(s)")
        return "\n".join(out)


# ── post-level mining (the "per-post" layer recon never had) ─────────────────

_MENTION_RE = re.compile(r"@([A-Za-z0-9._]{2,40})")
_HASHTAG_RE = re.compile(r"#([A-Za-z0-9_]{2,40})")
_URL_RE = re.compile(r"https?://([A-Za-z0-9.-]+)")


@dataclass
class PostInsight:
    """One mined post: what it was about, and who it pointed at."""

    post_id: str = ""
    caption: str = ""
    mentions: List[str] = field(default_factory=list)
    hashtags: List[str] = field(default_factory=list)
    places: List[str] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    taken_at: str = ""
    likes: str = ""
    comments: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"post_id": self.post_id, "caption": self.caption[:300],
                "mentions": list(self.mentions), "hashtags": list(self.hashtags),
                "places": list(self.places), "links": list(self.links),
                "taken_at": self.taken_at, "likes": self.likes,
                "comments": self.comments}


def _caption_from(node: Dict[str, Any]) -> str:
    for key in ("edge_media_to_caption", "caption"):
        val = node.get(key)
        if isinstance(val, dict):
            edges = val.get("edges") or []
            if edges and isinstance(edges[0], dict):
                inner = edges[0].get("node") or {}
                if isinstance(inner, dict) and isinstance(inner.get("text"), str):
                    return inner["text"]
            if isinstance(val.get("text"), str):
                return val["text"]
        elif isinstance(val, str):
            return val
        elif isinstance(val, dict) and isinstance(val.get("text"), str):
            return val["text"]
    return ""


def _int_ish(value: Any) -> str:
    if isinstance(value, dict):
        value = value.get("count", "")
    return "" if value in (None, "") else str(value)


def _iter_posts(obj: Any, out: List[Dict[str, Any]], depth: int = 0) -> None:
    """Find post-shaped nodes anywhere in an embedded JSON blob."""
    if depth > 12 or len(out) >= 50:
        return
    if isinstance(obj, dict):
        # a post node: has an id AND caption/taken_at/mentions keys
        if isinstance(obj.get("id"), (str, int)) and any(
                k in obj for k in ("edge_media_to_caption", "caption",
                                   "taken_at", "taken_at_timestamp",
                                   "shortcode", "edge_media_to_tagged_user")):
            if "node" not in obj or isinstance(obj.get("node"), dict):
                out.append(obj)
        for value in obj.values():
            _iter_posts(value, out, depth + 1)
    elif isinstance(obj, list):
        for value in obj:
            _iter_posts(value, out, depth + 1)


def _tagged_handles(node: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for key in ("edge_media_to_tagged_user", "edge_media_to_parent_comment"):
        val = node.get(key)
        if not isinstance(val, dict):
            continue
        for edge in (val.get("edges") or []):
            inner = (edge or {}).get("node") or {}
            user = inner.get("user") or inner.get("owner") or {}
            if isinstance(user, dict):
                name = user.get("username") or user.get("full_name")
                if isinstance(name, str) and name.strip():
                    out.append(_norm(name))
    return out


def mine_posts(html_or_blobs: Any, *, author: str = "") -> List[PostInsight]:
    """Mine per-post intelligence from ALREADY-FETCHED data (never fetches).

    Accepts raw HTML or an already-parsed blob list. For every post it collects
    the caption, @mentions, #hashtags, linked domains and the location, which is
    what turns a profile into a pretext: the model gets "posts about climbing
    and #torino", not "some guy". Bounded (50 posts) and never raises.
    """
    posts: List[Dict[str, Any]] = []
    try:
        if isinstance(html_or_blobs, str):
            raw = html_or_blobs
            blobs: List[Any] = []
            # a raw JSON document is a legitimate input (a caller that already
            # parsed the page response should not have to fake HTML for us)
            stripped = raw.strip()
            if stripped[:1] in ("{", "["):
                try:
                    parsed = json.loads(stripped)
                    blobs = ([x for x in parsed if isinstance(x, dict)]
                             if isinstance(parsed, list) else [parsed])
                except (ValueError, TypeError):
                    blobs = []
            if not blobs:
                from phantom.automation.social.recon import _extract_json_blobs
                blobs = _extract_json_blobs(raw)
        else:
            blobs = list(html_or_blobs or [])
            raw = ""
        for blob in blobs:
            _iter_posts(blob, posts)
        if raw and not posts:
            # regex fallback for pages that ship no embedded JSON at all
            for match in re.finditer(r'"caption"\s*:\s*"((?:[^"\\]|\\.)*)"', raw):
                posts.append({"caption": match.group(1)[:600],
                              "id": f"raw{len(posts)}"})
    except Exception:
        return []

    out: List[PostInsight] = []
    seen: set = set()
    for node in posts:
        pid = str(node.get("shortcode") or node.get("id") or "")
        if pid and pid in seen:
            continue
        seen.add(pid)
        caption = _caption_from(node)
        hashtags = [_norm(h) for h in _HASHTAG_RE.findall(caption)]
        mentions = [_norm(m) for m in _MENTION_RE.findall(caption)]
        # tagged users count as mentions even when the caption omits them
        for handle in _tagged_handles(node):
            if handle and handle not in mentions:
                mentions.append(handle)
        if author:
            mentions = [m for m in mentions if m != _norm(author)]
        places: List[str] = []
        loc = node.get("location")
        if isinstance(loc, dict):
            name = loc.get("name") or loc.get("slug")
            if isinstance(name, str) and name.strip():
                places.append(name.strip()[:80])
        elif isinstance(loc, str) and loc.strip():
            places.append(loc.strip()[:80])
        taken = node.get("taken_at")
        if taken in (None, ""):
            taken = node.get("taken_at_timestamp")
        out.append(PostInsight(
            post_id=pid, caption=caption[:600], mentions=mentions,
            hashtags=hashtags, places=places,
            links=sorted({m.lower() for m in _URL_RE.findall(caption)}),
            taken_at=_int_ish(taken),
            likes=_int_ish(node.get("edge_liked_by")
                           or node.get("like_count") or node.get("likes")),
            comments=_int_ish(node.get("edge_media_to_comment")
                              or node.get("comment_count")),
        ))
        if len(out) >= 50:
            break
    return out


def graph_from_posts(posts: Sequence[PostInsight], *, author: str,
                     platform: str = "",
                     graph: Optional[SocialGraph] = None,
                     source: str = "post-mining") -> SocialGraph:
    """Turn mined posts into graph edges: who the author talks about, and what
    they are interested in. The author is a HANDLE node, topics are hashtag /
    place nodes, so `graph.interests(author)` becomes a one-liner."""
    g = graph if graph is not None else SocialGraph()
    me = g.add_handle(author, platform=platform, source=source,
                      confidence=0.6, role="subject")
    if me is None:
        return g
    for post in posts:
        post_key = node_key("post", f"{platform}:{author}:{post.post_id}")
        if post.post_id and g.add_node(post_key, "post",
                                       label=post.caption[:60] or post.post_id,
                                       platform=platform, source=source,
                                       confidence=0.5,
                                       taken_at=post.taken_at) is not None:
            g.add_edge(me.key, post_key, "interest", evidence=source,
                       confidence=0.4)
        for handle in post.mentions:
            other = g.add_handle(handle, platform=platform, source=source,
                                 confidence=0.5)
            if other is not None:
                g.add_edge(me.key, other.key, "tagged_in",
                           evidence=f"post:{post.post_id or '?'}",
                           confidence=0.5, source=source)
        for tag in post.hashtags:
            topic = g.add_node(node_key("hashtag", tag), "hashtag", label=tag,
                               source=source, confidence=0.5)
            if topic is not None:
                g.add_edge(me.key, topic.key, "interest",
                           evidence=f"#{tag}", confidence=0.4, source=source)
        for place in post.places:
            node = g.add_node(node_key("place", place), "place", label=place,
                              source=source, confidence=0.5)
            if node is not None:
                g.add_edge(me.key, node.key, "interest",
                           evidence=f"place:{place}", confidence=0.5,
                           source=source)
    return g


# ── ingest from the recon engine ─────────────────────────────────────────────

_LEAD_EDGE = {
    "identity": ("email", "email_match", 0.8),
    "account_link": ("handle", "second_hop", 0.6),
    "commenter": ("handle", "comments_on", 0.5),
    "tagged": ("handle", "tagged_in", 0.45),
}


def graph_from_recon(results: Sequence[Any], *,
                     graph: Optional[SocialGraph] = None) -> SocialGraph:
    """Build the graph from `ReconResult` objects (already-computed, no I/O).

    The subject is a handle node; each lead becomes a node plus a typed edge
    with its own evidence string, so `recon`'s flat markers become walkable.
    Corroboration is FREE here and it is the point: an `account_link` lead whose
    handle already exists as the SAME handle on another platform gets a second
    proof and its confidence rises, which is exactly the "same person on 2
    platforms" signal the dossier wants.
    """
    g = graph if graph is not None else SocialGraph()
    for result in results or []:
        username = getattr(result, "username", "") or ""
        platform = getattr(result, "platform", "") or ""
        if not username:
            continue
        subject = g.add_handle(username, platform=platform,
                               source=f"recon:{platform}", confidence=0.7,
                               state=getattr(result, "state", ""),
                               full_name=getattr(result, "full_name", ""))
        if subject is None:
            continue
        for attr in ("full_name", "bio", "avatar_dhash", "avatar_hash",
                     "followers", "following", "posts"):
            value = getattr(result, attr, "")
            if value and str(value) not in (subject.attrs.get(attr),) and \
                    subject.attrs.get(attr) in (None, "", [], {}):
                subject.attrs[attr] = str(value)[:200]
        avatar = getattr(result, "avatar_dhash", "") or getattr(result, "avatar_hash", "")
        if avatar:
            avatar_node = g.add_node(node_key("url", f"avatar:{avatar}"), "url",
                                     label=f"avatar:{avatar[:12]}",
                                     source=f"recon:{platform}",
                                     confidence=0.7)
            if avatar_node is not None:
                # the subject's OWN avatar, so two profiles whose avatars hash
                # the same meet on this node (see `_link_same_avatar`)
                g.add_edge(subject.key, avatar_node.key, "same_avatar",
                           evidence=f"avatar:{avatar[:12]}", confidence=0.75,
                           source=f"recon:{platform}")
        for lead in getattr(result, "leads", []) or []:
            kind = getattr(lead, "kind", "")
            value = getattr(lead, "value", "") or ""
            evidence = getattr(lead, "evidence", "") or ""
            conf = float(getattr(lead, "confidence", 0.5) or 0.5)
            if not value:
                continue
            if kind not in _LEAD_EDGE:
                if kind == "search_hit":
                    # a search result is a URL, not an identity: keep the
                    # domain as a weak lead instead of a fake handle
                    g.add_node(node_key("url", value), "url", label=value[:80],
                               source=evidence, confidence=conf)
                continue
            node_kind, edge_kind, base = _LEAD_EDGE[kind]
            if node_kind == "email":
                key = node_key("email", value)
                other = g.add_node(key, "email", label=_norm(value),
                                   source=evidence, confidence=conf)
            else:
                other = g.add_handle(value, platform=getattr(lead, "platform", "")
                                     or platform, source=evidence,
                                     confidence=conf)
            if other is None:
                continue
            g.add_edge(subject.key, other.key, edge_kind, evidence=evidence,
                       confidence=max(base, conf if kind == "identity" else base),
                       source=f"recon:{platform}")
            # NOTE: no avatar edge for a lead. A `Lead` carries no avatar hash,
            # and the avatar node here belongs to the SUBJECT: attaching a
            # commenter to it would invent a shared-avatar proof nobody made.
    _link_same_avatar(g)
    _link_shared_emails(g)
    return g


def _link_same_avatar(g: SocialGraph) -> int:
    """Handles sharing an avatar node are ONE person (strong edge)."""
    by_avatar: Dict[str, List[str]] = {}
    for edge in list(g.edges.values()):
        if edge.kind == "same_avatar":
            by_avatar.setdefault(edge.dst, []).append(edge.src)
    made = 0
    for handles in by_avatar.values():
        for i, first in enumerate(handles):
            for second in handles[i + 1:]:
                key = (first, second, "same_person")
                if key in g.edges:
                    continue
                if g.add_edge(first, second, "same_person",
                              evidence="avatar-hash-equality",
                              confidence=0.8, source="correlate:avatar"):
                    made += 1
    return made


def _link_shared_emails(g: SocialGraph) -> int:
    """One email on two handles is CONFIRMED-grade identity evidence."""
    by_email: Dict[str, List[str]] = {}
    for edge in list(g.edges.values()):
        if edge.kind == "email_match" and g.nodes[edge.dst].kind == "email":
            by_email.setdefault(edge.dst, []).append(edge.src)
    made = 0
    for handles in by_email.values():
        for i, first in enumerate(handles):
            for second in handles[i + 1:]:
                key = (first, second, "same_person")
                if key in g.edges:
                    continue
                if g.add_edge(first, second, "same_person",
                              evidence="shared-email",
                              confidence=0.85, source="correlate:email"):
                    made += 1
    return made


_RELATION_EDGE = {"commenter": "comments_on", "tagged": "tagged_in"}


def graph_from_wm(wm: Any, *, graph: Optional[SocialGraph] = None) -> SocialGraph:
    """Rebuild the graph from the session's existing findings (NO network).

    The markers above are already turned into `profile` / `account_link` /
    `identity` findings by the social interpreter, so the CLI can show the
    graph of what the engagement already knows — instantly and offline —
    instead of re-running the recon to display it. Finding shapes are read
    defensively: a malformed finding is skipped, never fatal.
    """
    g = graph if graph is not None else SocialGraph()
    subjects: List[Tuple[str, str]] = []      # (handle, platform)

    def _find(kind: str) -> List[Any]:
        try:
            return list(wm.find(kind)) or []
        except Exception:
            return []

    for finding in _find("profile"):
        value = getattr(finding, "value", None) or {}
        if not isinstance(value, dict):
            continue
        username = str(value.get("username", "") or "")
        if not username:
            continue
        platform = str(value.get("platform", "") or "")
        node = g.add_handle(username, platform=platform, source="session",
                            confidence=0.7, state=value.get("state", ""),
                            full_name=value.get("full_name", ""),
                            followers=value.get("followers", ""),
                            private=bool(value.get("private")))
        if node is not None:
            subjects.append((node.key, platform))

    def _subject_for(platform: str, on: str) -> Optional[str]:
        on_norm = _norm(on)
        if on_norm:
            for key, _platform in subjects:
                if key == node_key("handle", on_norm):
                    return key
        for key, subj_platform in subjects:
            if platform and subj_platform == platform:
                return key
        return subjects[0][0] if subjects else None

    for finding in _find("account_link"):
        value = getattr(finding, "value", None) or {}
        if not isinstance(value, dict):
            continue
        handle = str(value.get("handle", "") or "")
        platform = str(value.get("platform", "") or "")
        if not handle:
            continue
        subject = _subject_for(platform, str(value.get("on", "") or ""))
        if subject is None:
            continue
        other = g.add_handle(handle, platform=platform, source="session",
                             confidence=float(getattr(finding, "confidence", 0.5)
                                              or 0.5))
        if other is None:
            continue
        relation = str(value.get("relation", "") or "")
        g.add_edge(subject, other.key, _RELATION_EDGE.get(relation, "second_hop"),
                   evidence=str(value.get("evidence", "") or "session"),
                   confidence=float(getattr(finding, "confidence", 0.5) or 0.5),
                   source="session")

    subject_key = subjects[0][0] if subjects else None
    for finding in _find("identity"):
        value = getattr(finding, "value", None) or {}
        if not isinstance(value, dict):
            continue
        email = str(value.get("email", "") or "")
        if not email or "." not in email:
            continue
        node = g.add_node(node_key("email", email), "email", label=email,
                          source="session",
                          confidence=float(getattr(finding, "confidence", 0.5)
                                           or 0.5))
        if node is not None and subject_key:
            g.add_edge(subject_key, node.key, "email_match",
                       evidence="identity-finding", confidence=0.8,
                       source="session")

    for finding in _find("identity_conf"):
        value = getattr(finding, "value", None) or {}
        if not isinstance(value, dict):
            continue
        key = node_key("handle", str(value.get("handle", "") or ""))
        node = g.nodes.get(key)
        if node is None:
            continue
        try:
            node.confidence = max(node.confidence,
                                  float(value.get("score") or 0.0))
        except (TypeError, ValueError):
            pass
        if value.get("tier"):
            node.attrs["tier"] = str(value["tier"])
    return g


def correlate(results: Sequence[Any]) -> SocialGraph:
    """Convenience: results -> graph (the call `recon` and the CLI both want)."""
    return graph_from_recon(results)


def to_json(graph: SocialGraph, indent: int = 2) -> str:
    return json.dumps(graph.to_dict(), indent=indent, default=str)
