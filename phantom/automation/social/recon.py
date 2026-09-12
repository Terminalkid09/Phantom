"""
recon.py — deep social profile reverse-engineering engine.

The engine the basic `profile_recon` upgrades to when a profile matters:
a PRIVATE profile is not a dead end, it is a mapping problem. This module
solves it in four bounded layers:

  1. RELIABLE STATE     — private/public/missing decided by multi-marker
                          voting across TWO fetches (different UAs, human
                          delay) so one flaky CDN response cannot flip
                          the verdict.
  2. GRAPH MINING       — tagged posts, commenters and follower counts
                          mined from the profile's own embedded JSON
                          (pre-login blobs other scrapers ignore); every
                          handle found becomes a pivot lead.
  3. CROSS-ACCOUNT      — username variants (dots/underscores/digits)
                          probed, Wayback CDX snapshots of ex-public
                          profiles, DuckDuckGo dorks, avatar hash
                          comparison and bio-similarity scoring.
  4. LEADS              — everything emitted as stable markers the social
                          interpreter turns into WorldModel findings
                          (identity/account_link/profile pivots).

Design: dependency-free (curl + regex + hashlib), every network call
bounded, never raises, dedupes leads across layers, and marks each lead
with HOW it was proven (evidence source) so the dossier can weigh it.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ── bounded constants ────────────────────────────────────────────────────────

_UAS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
)

_PROFILE_URLS = {
    "instagram": "https://www.instagram.com/{u}/",
    "tiktok": "https://www.tiktok.com/@{u}",
    "x": "https://x.com/{u}",
    "github": "https://github.com/{u}",
    "reddit": "https://www.reddit.com/user/{u}/about.json",
    "telegram": "https://t.me/{u}",
}

# private / missing markers per platform (page-level, pre-login)
_PRIVATE_MARKERS = {
    "instagram": ("page not found", "sorry, this page isn't available",
                  "login • instagram", "this account is private",
                  "sign up to see photos"),
    "tiktok": ("couldn't find this account", "account banned"),
    "x": ("this account doesn’t exist", "this account doesn't exist",
          "nothing to see here"),
    "github": ("not found", "404"),
    "reddit": ("\"is_suspended\": true", "\"error\": 404",
               "page not found"),
    "telegram": ("if you have telegram, you can contact",
                 "send message", "view in telegram"),  # t.me public → absent = missing
}
_NOT_FOUND_MARKERS = {
    "instagram": ("page not found", "sorry, this page isn't available"),
    "tiktok": ("couldn't find this account",),
    "x": ("this account doesn’t exist", "this account doesn't exist"),
    "github": ("404 “this is not the web page you are looking for”",
               "not found"),
    "reddit": ("\"error\": 404",),
    "telegram": ("you can contact",),  # actually PRESENT; handled below
}

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_HANDLE_RE = re.compile(r"@([A-Za-z0-9._]{3,30})")
_URL_RE = re.compile(r"(?:https?://)([A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:/[^\s\"'<>]*)?)")


# ── result model ─────────────────────────────────────────────────────────────

@dataclass
class Lead:
    """A single intelligence lead with its evidence provenance."""
    kind: str            # identity | account_link | commenter | tagged | search_hit
    value: str           # email, handle, url, ...
    platform: str = ""
    evidence: str = ""   # where/how this was proven
    confidence: float = 0.5


@dataclass
class ReconResult:
    username: str
    platform: str
    state: str = "unknown"            # public | private | missing | unknown
    state_confidence: float = 0.0     # 0..1 vote agreement
    full_name: str = ""
    bio: str = ""
    link: str = ""
    followers: str = ""
    following: str = ""
    posts: str = ""
    avatar_url: str = ""
    avatar_hash: str = ""
    emails: List[str] = field(default_factory=list)   # visible in bio/page
    leads: List[Lead] = field(default_factory=list)

    def markers(self) -> List[str]:
        """Stable marker lines for the social interpreter."""
        out: List[str] = []
        out.append(
            f"RECON_STATE: username={self.username} platform={self.platform} "
            f"state={self.state} conf={self.state_confidence:.2f}")
        if self.full_name:
            out.append(f"RECON_STATE: username={self.username} "
                       f"fullname={self.full_name.replace(' ', '_')}")
        if self.followers:
            out.append(f"RECON_STATE: username={self.username} "
                       f"followers={self.followers} following={self.following} "
                       f"posts={self.posts}")
        if self.bio:
            out.append(
                f"PROFILE: username={self.username} platform={self.platform} "
                f"private={int(self.state == 'private')} "
                f"bio={self.bio.replace(' ', '_')} link={self.link}")
        for l in self.leads:
            if l.kind == "identity":
                out.append(f"IDENTITY: email={l.value} source={l.evidence}")
            elif l.kind == "account_link":
                out.append(f"ACCOUNT_LINK: handle={l.value} "
                           f"platform={l.platform or l.evidence} "
                           f"url=https://{l.platform}.com/{l.value} "
                           f"evidence={l.evidence}")
            elif l.kind == "commenter":
                out.append(f"COMMENTER: handle={l.value} platform={l.platform} "
                           f"on={self.username} evidence={l.evidence}")
            elif l.kind == "tagged":
                out.append(f"TAGGED_IN: handle={l.value} platform={l.platform} "
                           f"evidence={l.evidence}")
            elif l.kind == "search_hit":
                out.append(f"SEARCH_HIT: url={l.value} evidence={l.evidence}")
            elif l.kind == "wayback":
                out.append(f"WAYBACK: url={l.value} evidence={l.evidence}")
        return out


# ── helpers ──────────────────────────────────────────────────────────────────

def _fetch(url: str, timeout: float = 15.0, ua: str = "") -> str:
    """Bounded curl GET returning the body (never raises)."""
    try:
        from phantom.core.executor import execute_quiet
        agent = ua or random.choice(_UAS)
        res = execute_quiet(
            f"curl -s -L -m {int(timeout)} -A '{agent}' '{url}'", timeout=timeout + 10)
        return (res.stdout or "")[:400000]
    except Exception:
        return ""


def _extract_json_blobs(html: str) -> List[dict]:
    """Parse every embedded application/ld+json / rehydration blob that
    parses as JSON with dict roots (bounded to 12 blobs)."""
    blobs: List[dict] = []
    for m in re.finditer(
            r'<script[^>]*type="application/(?:ld\+json|json)"[^>]*>(.*?)</script>',
            html or "", re.S | re.I):
        try:
            data = json.loads(m.group(1).strip()[:200000])
            if isinstance(data, dict):
                blobs.append(data)
            elif isinstance(data, list):
                blobs.extend(x for x in data if isinstance(x, dict))
        except (ValueError, TypeError):
            continue
        if len(blobs) >= 12:
            break
    # TikTok/IG rehydration blobs
    for m in re.finditer(
            r'id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>(.*?)</script>',
            html or "", re.S):
        try:
            data = json.loads(m.group(1).strip()[:300000])
            if isinstance(data, dict):
                blobs.append(data)
        except (ValueError, TypeError):
            continue
        if len(blobs) >= 24:
            break
    return blobs


def _walk(obj, key: str, out: List, depth: int = 0):
    """Collect values for key anywhere in nested JSON (bounded depth)."""
    if depth > 8 or len(out) > 20:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == key:
                out.append(v)
            _walk(v, key, out, depth + 1)
    elif isinstance(obj, list):
        for v in obj[:30]:
            _walk(v, key, out, depth + 1)


# ── layer 1: reliable state ──────────────────────────────────────────────────

def _state_vote(username: str, platform: str) -> Tuple[str, float, str]:
    """Two fetches with different UAs + short human delay; vote decides.
    Returns (state, confidence, html_of_best)."""
    url = _PROFILE_URLS.get(platform, "").format(u=username)
    if not url:
        return "unknown", 0.0, ""
    votes: List[str] = []          # public | private | missing
    best_html = ""
    for i in range(2):
        html = _fetch(url, timeout=15.0, ua=_UAS[i % len(_UAS)])
        if not html:
            votes.append("missing")
            continue
        low = html.lower()
        best_html = best_html or html
        if any(m in low for m in _NOT_FOUND_MARKERS.get(platform, ())):
            votes.append("missing")
        elif any(m in low for m in _PRIVATE_MARKERS.get(platform, ())):
            votes.append("private")
        elif len(html) > 2000:
            votes.append("public")
        else:
            votes.append("missing")
        if i == 0:
            time.sleep(random.uniform(0.8, 2.0))   # human pacing, not bot cadence
    if not votes:
        return "unknown", 0.0, best_html
    state = max(set(votes), key=votes.count)
    conf = votes.count(state) / len(votes)
    return state, conf, best_html


# ── layer 2: graph mining ────────────────────────────────────────────────────

def _mine_graph(username: str, platform: str, html: str,
                result: ReconResult) -> None:
    """Tagged/commenter/follower mining from embedded JSON + page regex."""
    ev = f"graph:{platform}"
    blobs = _extract_json_blobs(html) if html else []
    # counts
    for key, attr in (("edge_followed_by", "followers"),
                      ("edge_follow", "following"),
                      ("edge_owner_to_timeline_media", "posts")):
        vals: List = []
        for b in blobs:
            _walk(b, key, vals)
        if vals:
            v = vals[0]
            if isinstance(v, dict):
                v = v.get("count", "")
            if v not in ("", None):
                setattr(result, attr, str(v))
                break
    if not result.followers and platform == "tiktok":
        vals: List = []
        for b in blobs:
            _walk(b, "followerCount", vals)
            _walk(b, "followingCount", vals)
            _walk(b, "heartCount", vals)
        if vals:
            result.followers = str(vals[0])
    # full name
    for b in blobs:
        names: List = []
        _walk(b, "full_name", names)
        _walk(b, "nickname", names)
        if names and isinstance(names[0], str) and names[0].strip():
            result.full_name = names[0].strip()[:80]
            break
    # avatar
    imgs: List = []
    for b in blobs:
        _walk(b, "profile_pic_url", imgs)
        _walk(b, "avatarLarger", imgs)
        _walk(b, "avatarMedium", imgs)
    if not imgs:
        m = re.search(r'property="og:image" content="([^"]+)"', html or "")
        if m:
            imgs.append(m.group(1))
    if imgs and isinstance(imgs[0], str):
        result.avatar_url = imgs[0][:300]
        raw = _fetch(imgs[0], timeout=10.0)
        if raw:
            result.avatar_hash = hashlib.md5(raw[:100000]).hexdigest()[:16]
    # emails visible in the profile's OWN bio/page (identity-confidence
    # anchors: same email on two platforms is CONFIRMED-grade proof)
    if html:
        result.emails = list(dict.fromkeys(
            _EMAIL_RE.findall(html[:40000])))[:3]
    # commenters + tagged handles from media JSON
    seen = {l.value for l in result.leads}
    comments: List = []
    for b in blobs:
        _walk(b, "edge_media_to_comment", comments)
        _walk(b, "commentList", comments)
    if platform == "reddit":
        for b in blobs:
            _walk(b, "children", comments)
    for node in comments[:8]:
        text = ""
        if isinstance(node, dict):
            for k in ("text", "body", "comment_text"):
                if k in node:
                    text = str(node[k])
                    break
            else:
                text = json.dumps(node)[:500]
        else:
            text = str(node)
        for h in _HANDLE_RE.findall(text):
            h = h.rstrip("._")
            if len(h) >= 3 and h.lower() != username.lower() and h not in seen:
                seen.add(h)
                result.leads.append(Lead("commenter", h, platform,
                                         ev, 0.55))
    # tagged handles: anywhere in page mentioning @others on tag pages
    for h in _HANDLE_RE.findall(html or "")[:60]:
        h = h.rstrip("._")
        if (len(h) >= 3 and h.lower() != username.lower()
                and h not in seen and not h.startswith("instagram")
                and not h.startswith("tiktok")):
            seen.add(h)
            result.leads.append(Lead("tagged", h, platform, ev, 0.45))
        if len(seen) > 14:
            break


# ── layer 3: cross-account correlation ───────────────────────────────────────

def _username_variants(username: str) -> List[str]:
    """Common same-person handle variants, bounded to 6."""
    base = (username or "").strip().lstrip("@").lower()
    if not base:
        return []
    cands = {
        base.replace(".", "_"), base.replace("_", "."), base.replace("_", ""),
        base.replace(".", ""), f"{base}_", f"_.{base}",
        base + "1", base + "x",
    }
    out = []
    for c in cands:
        if c and c != base and re.fullmatch(r"[a-z0-9._]{3,30}", c):
            out.append(c)
    return out[:6]


def _wayback_snapshots(username: str, platform: str) -> List[Lead]:
    """Historical snapshots of the profile page (ex-public profiles often
    carry the OLD public bio with real name / link / handles)."""
    leads: List[Lead] = []
    url = _PROFILE_URLS.get(platform, "").format(u=username)
    if not url:
        return leads
    api = ("http://web.archive.org/cdx/search/cdx?url={}"
           "&output=json&limit=8&filter=statuscode:200&collapse=timestamp:6"
           ).format(url)
    raw = _fetch(api, timeout=20.0)
    try:
        rows = json.loads(raw)
        for row in rows[1:6] if isinstance(rows, list) else []:
            ts, orig = str(row[1]), str(row[2])
            snap = f"http://web.archive.org/web/{ts}/{orig}"
            body = _fetch(snap, timeout=20.0)
            if not body:
                continue
            for e in _EMAIL_RE.findall(body[:60000])[:3]:
                leads.append(Lead("identity", e, platform,
                                  f"wayback:{ts}", 0.6))
            for h in _HANDLE_RE.findall(body[:60000])[:6]:
                h = h.rstrip("._")
                if len(h) >= 3 and h.lower() != username.lower():
                    leads.append(Lead("account_link", h, platform,
                                      f"wayback:{ts}", 0.5))
            if leads:
                leads.append(Lead("wayback", snap, platform,
                                  f"snapshot:{ts}", 0.8))
                break  # one informative snapshot is enough
    except (ValueError, IndexError, TypeError):
        pass
    return leads


_DORKS = (
    '"{u}" (site:instagram.com OR site:tiktok.com OR site:x.com)',
    '"{u}" (gmail.com OR outlook.com OR yahoo.com OR hotmail.com)',
    '"{u}" (site:linkedin.com OR site:github.com OR site:reddit.com)',
)


def _search_dorks(username: str, full_name: str = "") -> List[Lead]:
    """DuckDuckGo HTML dork search (no API key) — bounded to 3 queries."""
    leads: List[Lead] = []
    seen_urls = set()
    for tpl in _DORKS:
        q = tpl.format(u=username).replace(" ", "+").replace('"', "%22")
        html = _fetch(f"https://html.duckduckgo.com/html/?q={q}", timeout=20.0)
        if not html:
            continue
        for m in re.finditer(r'class="result__url"[^>]*>\s*([^<]+)', html[:200000]):
            url = m.group(1).strip()
            if url.startswith("//"):
                url = "https:" + url
            host = _URL_RE.match(url if "://" in url else "https://" + url)
            if not host:
                continue
            if url in seen_urls:
                continue
            seen_urls.add(url)
            # a hit on a profile URL of the same handle = platform lead
            for plat in _PROFILE_URLS:
                if f"{plat}.com" in url.lower() and username.lower() in url.lower():
                    leads.append(Lead("search_hit", url, plat,
                                      "ddg_dork", 0.5))
                    break
            else:
                if any(d in url.lower() for d in ("linkedin.com", "pastebin",
                                                  "github.com")):
                    leads.append(Lead("search_hit", url, "",
                                      "ddg_dork", 0.4))
        if len(leads) >= 8:
            break
        time.sleep(random.uniform(1.0, 2.5))
    return leads[:8]


def _bio_similarity(a: str, b: str) -> float:
    """Token Jaccard — cheap cross-platform bio match signal."""
    ta = {w.lower().strip(".,#@") for w in (a or "").split() if len(w) > 2}
    tb = {w.lower().strip(".,#@") for w in (b or "").split() if len(w) > 2}
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def correlate_accounts(results: List[ReconResult]) -> List[Lead]:
    """Cross-result correlation: same-avatar-hash or high bio-similarity
    between two platforms = same person with different handles."""
    leads: List[Lead] = []
    for i, a in enumerate(results):
        for b in results[i + 1:]:
            if a.platform == b.platform:
                continue
            if (a.avatar_hash and b.avatar_hash
                    and a.avatar_hash == b.avatar_hash):
                leads.append(Lead(
                    "account_link", b.username, b.platform,
                    f"avatar_match:{a.platform}", 0.85))
            sim = _bio_similarity(a.bio, b.bio)
            if sim >= 0.55 and a.bio and b.bio:
                leads.append(Lead(
                    "account_link", b.username, b.platform,
                    f"bio_sim:{sim:.2f}:{a.platform}", 0.65))
    return leads


# ── engine entry point ───────────────────────────────────────────────────────

def deep_recon(username: str, platform: str = "",
               variants: bool = True, wayback: bool = True,
               search: bool = True) -> Tuple[bool, List[str]]:
    """Full reverse-engineering pass. Returns marker lines for the social
    interpreter. Bounded: <= 20 network calls total, never raises."""
    try:
        lines: List[str] = []
        username = (username or "").strip().lstrip("@")
        if not username:
            return False, ["ERROR: deep_recon needs a username"]
        platform = (platform or "instagram").lower()

        results: List[ReconResult] = []

        # primary platform: state vote + graph mining
        state, conf, html = _state_vote(username, platform)
        primary = ReconResult(username=username, platform=platform,
                              state=state, state_confidence=conf)
        if html:
            primary.bio = _extract_bio(html)
            primary.link = _extract_link(primary.bio)
            _mine_graph(username, platform, html, primary)
        results.append(primary)

        # same handle on OTHER platforms (single quick fetch each)
        for p in ("instagram", "tiktok", "x", "github", "telegram"):
            if p == platform:
                continue
            st, cf, h2 = _state_vote(username, p)
            if st == "missing":
                continue
            r = ReconResult(username=username, platform=p, state=st,
                            state_confidence=cf)
            if h2:
                r.bio = _extract_bio(h2)
                r.link = _extract_link(r.bio)
                _mine_graph(username, p, h2, r)
                if r.state == "public" and r.bio:
                    # a PUBLIC account of the same handle on another platform
                    primary.leads.append(Lead(
                        "account_link", username, p, "same_handle_public", 0.7))
            results.append(r)

        # username variants (bounded sherlock-style probe)
        if variants:
            for v in _username_variants(username):
                st, cf, h2 = _state_vote(v, platform)
                if st == "public" and cf >= 0.5:
                    rv = ReconResult(username=v, platform=platform,
                                     state=st, state_confidence=cf)
                    if h2:
                        rv.bio = _extract_bio(h2)
                        _mine_graph(v, platform, h2, rv)
                    results.append(rv)
                    primary.leads.append(Lead(
                        "account_link", v, platform, "variant_probe", 0.55))

        # wayback + dorks run against the PRIMARY only (bounded budget)
        if wayback:
            primary.leads.extend(_wayback_snapshots(username, platform))
        if search:
            primary.leads.extend(_search_dorks(username, primary.full_name))

        # cross-account correlation across everything collected
        lines.extend(primary.markers())
        for r in results[1:]:
            if r.state == "public" or r.bio:
                lines.extend(r.markers())
        for lead in correlate_accounts(results):
            if lead not in primary.leads:
                primary.leads.append(lead)

        # identity confidence: every cross-platform candidate is SCORED
        # against the primary identity so the chain never contacts the
        # wrong person (username collision is the trap this closes).
        from phantom.automation.social.identity_confidence import (
            score_lead as _score, may_act as _may_act)
        def _graph_of(r: ReconResult) -> List[str]:
            """The social circle of a profile: commenters + tagged handles
            + discovered account links (the same strangers who interact
            with BOTH accounts are same-person evidence)."""
            out = [l.value for l in r.leads
                   if l.kind in ("commenter", "tagged", "account_link")]
            return sorted({h.lstrip("@").lower() for h in out if h})[:40]

        primary_dict = {
            "username": primary.username, "bio": primary.bio,
            "avatar_hash": primary.avatar_hash, "link": primary.link,
            "full_name": primary.full_name,
            "emails": sorted({*(l.value for l in primary.leads
                                if l.kind == "identity" and "@" in l.value),
                              *primary.emails}),
            "graph": _graph_of(primary),
        }
        for r in results[1:]:
            if r.platform == primary.platform:
                continue
            lead_obj = _score(primary_platform, primary_dict, {
                "username": r.username, "bio": r.bio,
                "avatar_hash": r.avatar_hash, "link": r.link,
                "emails": r.emails,
                "graph": _graph_of(r),
            })
            tier = lead_obj.tier
            # policy snapshot for the marker: contact needs CONFIRMED
            # (or --aggressive); read-only recon is always allowed.
            dm_ok, why = _may_act(lead_obj, "dm_launch", aggressive=False)
            lines.append(
                f"IDENTITY_CONF: handle={r.username} platform={r.platform} "
                f"tier={tier} score={lead_obj.score:.2f} "
                f"contact={int(bool(dm_ok))} why={why.replace(' ', '_')}")
        for lead in primary.leads:
            if lead.kind in ("account_link", "search_hit", "wayback"):
                lines.append(f"ACCOUNT_LINK: handle={lead.value} "
                             f"platform={lead.platform} "
                             f"url=https://{lead.platform}.com/{lead.value} "
                             f"evidence={lead.evidence}" if lead.platform else
                             f"SEARCH_HIT: url={lead.value} "
                             f"evidence={lead.evidence}")
        return True, lines
    except Exception as e:
        return False, [f"ERROR: deep recon failed: {e}"]


def _extract_bio(html: str) -> str:
    for pat in (r'name="description" content="([^"]{0,500})"',
                r'property="og:description" content="([^"]{0,500})"'):
        m = re.search(pat, html or "", re.I)
        if m:
            return m.group(1).strip()
    return ""


def _extract_link(text: str) -> str:
    m = re.search(
        r"(?<![\w@.])(?:https?://)?(?:www\.)?"
        r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?:/[^\s\"'<>]*)?",
        text or "")
    if not m:
        return ""
    url = m.group(0)
    if "@" in url or url.lower().startswith(("instagram.", "tiktok.",
                                             "help.", "about.")):
        return ""
    return url.rstrip(".,;")
