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
from typing import Any, Dict, List, Optional, Tuple

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

# The five socials an operator can PIN the OSINT to (the UI checkbox list).
# A username is NOT a person: the same handle on another network is very
# often somebody else, and mixing those namesakes into the identity graph
# is what ruins the plan downstream (a DM/follow lands on a stranger). The
# operator therefore says WHERE the handle belongs and the pass stays there.
TOP_SOCIALS = ("instagram", "tiktok", "x", "github", "telegram")

# every fetchable platform that is NOT one of the five above: what the
# "other" scope searches instead of them.
ALT_PLATFORMS = tuple(p for p in _PROFILE_URLS if p not in TOP_SOCIALS)

# every platform this module can actually fetch (API/UI validate against it)
SUPPORTED_PLATFORMS = tuple(_PROFILE_URLS)

# the value the operator/UI sends for "not one of those five": exclude the
# five and look elsewhere.
_OTHER_SCOPE_VALUES = ("other", "alt", "others", "elsewhere", "altro")

# domain -> label, used ONLY to label a search hit found elsewhere. Nothing
# here is ever fetched, so no marker set is needed for it.
_OTHER_SITES = {
    "reddit.com": "reddit",
    "linkedin.com": "linkedin",
    "facebook.com": "facebook",
    "pinterest.com": "pinterest",
    "tumblr.com": "tumblr",
    "medium.com": "medium",
    "gitlab.com": "gitlab",
    "stackoverflow.com": "stackoverflow",
    "keybase.io": "keybase",
    "linktr.ee": "linktree",
    "about.me": "aboutme",
}

# platform -> the site a dork restricts to / excludes
_SITE_DOMAINS = {
    "instagram": "instagram.com",
    "tiktok": "tiktok.com",
    "x": "x.com",
    "github": "github.com",
    "reddit": "reddit.com",
    "telegram": "t.me",
    "linkedin": "linkedin.com",
    "facebook": "facebook.com",
}


def _site_of(platform: str) -> str:
    return _SITE_DOMAINS.get(str(platform or "").lower(),
                             f"{str(platform or '').lower()}.com")


def normalize_scope(platform: str = "", scope: str = "") -> Tuple[str, str]:
    """(scope, platform) from the operator's ONE platform value.

    * ``""``                -> ``("auto", "")``   legacy: primary defaults
                                             to instagram, every platform
                                             probed and cross-scored
    * a known social         -> ``("pin", name)``  ONLY that platform is
                                             probed, so no other network's
                                             namesake can enter the graph
    * ``"other"`` (or alt/…) -> ``("other", "")``  the five top socials are
                                             EXCLUDED and the pass looks
                                             everywhere else

    An explicit ``scope`` of ``"pin"``/``"other"``/``"auto"`` wins over the
    derivation (``"auto"`` keeps ``platform`` as the primary, which is the
    pre-pin legacy semantic). An unknown value falls back to ``"auto"``:
    guessing a platform is exactly the mistake this function prevents.
    """
    p = str(platform or "").strip().lower().lstrip("@")
    s = str(scope or "").strip().lower()
    if s in ("pin", "other"):
        return s, (p if s == "pin" else "")
    if s == "auto":
        return "auto", (p if p in _PROFILE_URLS else "")
    if p in _OTHER_SCOPE_VALUES:
        return "other", ""
    if p in TOP_SOCIALS:
        return "pin", p
    return "auto", ""


def _primary_for(scope: str, platform: str) -> str:
    """Which platform the pass opens on.

    ``pin``   -> the pinned one; ``other`` -> the first alternative (reddit);
    ``auto``  -> the caller's value or instagram.
    """
    if scope == "other":
        return ALT_PLATFORMS[0] if ALT_PLATFORMS else "instagram"
    return platform or "instagram"

# private / missing markers per platform (page-level, pre-login)
_PRIVATE_MARKERS = {
    "instagram": ("this account is private", "sign up to see photos"),
    # GitHub has no private-profile PAGE: a profile with no activity renders
    # the same public shell. "404" lived here and matched a real profile
    # (every GitHub page embeds 404 in assets), so a real account was voted
    # `private`.
    "github": (),
    "tiktok": (),
    "x": (),
    "reddit": (),
    # t.me has no private page either: these strings were PRESENCE markers
    # (verified 2026-10-16: they appear on a real handle's page), which is why
    # a real Telegram account used to be voted `private`.
    "telegram": (),
}
_NOT_FOUND_MARKERS = {
    "instagram": ("page not found", "sorry, this page isn't available"),
    # "couldn't find this account" is an i18n BUNDLE string: it is present in
    # every TikTok page, real or not (verified), so it proved nothing.
    "tiktok": (),
    # Verified against a handle that cannot exist: X answers with
    # "user profile not found" in the title and "hmm...this page doesn't
    # exist" in the body. The old marker carried a typographic apostrophe the
    # page never matched, so a non-existent account was voted `public`.
    "x": ("user profile not found", "this page doesn", "doesn\u2019t exist",
          "the account may be private, deleted"),
    "github": ("404 \u201cthis is not the web page you are looking for\u201d",
               "not found"),
    "reddit": ("\"error\": 404",),
    "telegram": ("you can contact",),  # verified: absent handle only
}
# POSITIVE evidence that the fetched page really is the account's profile.
# A LARGE page is not evidence: Instagram and TikTok answer EVERY path with
# the same multi-hundred-KB JavaScript shell (verified 2026-10-16 — a handle
# that cannot exist returned the byte-identical shell), so `len(html) > 2000`
# used to declare `public conf=1.00` for accounts that do not exist, and the
# graph grew by seven variant "accounts" that were nothing but that shell.
_PUBLIC_MARKERS = {
    "instagram": (),
    "tiktok": (),
    "github": ('itemprop="name"', 'id="user-profile-frame"', "vcard-fullname"),
    "telegram": ("tgme_page_title", "tgme_page_photo", "view in telegram"),
    "reddit": ('"total_karma"', '"is_employee"', '"comment_karma"'),
}
# Platforms whose page is a shell for EVERY handle: no marker can confirm a
# profile, so the honest verdict is `unknown` — "we could not read it" — and
# the graph claims nothing.
_UNREADABLE = {"instagram", "tiktok"}


def _has_public_evidence(platform: str, low_html: str) -> bool:
    """True when the page carries a marker only a real profile has."""
    return any(m in low_html for m in _PUBLIC_MARKERS.get(platform, ()))

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_HANDLE_RE = re.compile(r"@([A-Za-z0-9._]{3,30})")
_URL_RE = re.compile(r"(?:https?://)([A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:/[^\s\"'<>]*)?)")

# A raw page is NOT a list of people. Scanning it for `@token` mints CSS
# at-rules and JS pragma comments as circle members: live evidence
# (2026-10-16) — the identity graph of a real Instagram profile carried the
# handle `media` with EIGHT confirming proofs (that is `@media`, the CSS
# at-rule), and `__pure` on X (that is `/** @__PURE__ */`). A false lead is
# worse than no lead: the graph's whole value is that its nodes are people.
_CSS_AT_RULES = {
    "media", "supports", "import", "charset", "keyframes", "font-face",
    "layer", "namespace", "page", "container", "property", "scope",
    "starting-style", "apply", "tailwind", "screen", "viewport", "charset",
}
_JUNK_TOKENS = {
    "pure", "private", "public", "abstract", "type", "param", "license",
    "flow", "ts-check", "ts-ignore", "ts-expect-error", "jsx", "deprecated",
    "example", "example.com", "media.css", "gmail.com", "outlook.com",
}
# A handle never ends in one of these: `@media.css`, `@x.js`, `@site.com`
# are URLs, file names and mail domains, not accounts.
_HANDLE_TAIL_JUNK = {
    "js", "mjs", "cjs", "css", "scss", "less", "map", "json", "xml", "html",
    "htm", "png", "jpg", "jpeg", "gif", "svg", "webp", "avif", "ico", "mp4",
    "webm", "woff", "woff2", "ttf", "otf", "com", "net", "org", "it", "io",
    "co", "uk", "dev", "info", "biz", "edu", "gov",
}


def _is_real_handle(handle: str) -> bool:
    """Can this `@token` plausibly be a social handle at all?

    Rejects the two shapes that provably pollute the graph: CSS/JS
    directives, and URL/file/mail fragments. Anything else passes — the
    check is deliberately about SHAPE, not about guessing who is a person.
    """
    h = (handle or "").strip().strip("._").lower()
    if len(h) < 3 or h in _CSS_AT_RULES or h in _JUNK_TOKENS:
        return False
    if h.rsplit(".", 1)[-1] in _HANDLE_TAIL_JUNK:
        return False
    return True


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
    avatar_dhash: str = ""       # perceptual hash: survives re-encoding
    emails: List[str] = field(default_factory=list)   # visible in bio/page
    leads: List[Lead] = field(default_factory=list)
    posts: List[Any] = field(default_factory=list)    # mine_posts() output
    topics: List[str] = field(default_factory=list)  # top interests

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
        if self.avatar_url:
            # operator-display surface: avatar + counts travel with the
            # profile so a human (or the confirm gate) can eyeball it
            out.append(
                f"AVATAR: username={self.username} platform={self.platform} "
                f"url={self.avatar_url}")
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
                # the network label travels with the hit: "found elsewhere"
                # is only useful if the operator can see WHERE.
                out.append(f"SEARCH_HIT: url={l.value} "
                           f"platform={l.platform} evidence={l.evidence}"
                           if l.platform else
                           f"SEARCH_HIT: url={l.value} evidence={l.evidence}")
            elif l.kind == "wayback":
                out.append(f"WAYBACK: url={l.value} evidence={l.evidence}")
        return out


# ── helpers ──────────────────────────────────────────────────────────────────

def _q(arg: str) -> str:
    """Quote ONE argument for the shell line this module builds.

    These fetches go through `execute_quiet`, which runs the line with
    `shell=True`: `sh` on POSIX, cmd.exe on Windows. cmd.exe has NO
    single-quote quotes — see `executor.quote_arg` for the live evidence (an
    existing Instagram account reported `missing` because every fetch died
    with rc=3 "URL malformed"). One wrong quote made the whole passive-recon
    surface lie.
    """
    from phantom.core.executor import quote_arg
    return quote_arg(arg)


def _fetch(url: str, timeout: float = 15.0, ua: str = "",
           cookies: str = "") -> str:
    """Bounded curl GET returning the body (never raises).

    `cookies`: a pre-built `Cookie:` header value for THIS host (from
    the operator's own stolen-cookie jar). Read-only views only — the
    delivery paths never receive cookies (separate code, no parameter).
    Values are sanitized to header-safe characters; anything exotic is
    dropped rather than quoted.
    """
    try:
        from phantom.core.executor import execute_quiet
        agent = ua or random.choice(_UAS)
        header = ""
        if cookies:
            safe = re.sub(r"[^A-Za-z0-9._~+/%=&*\-; ]", "", str(cookies))[:4000]
            if safe.strip():
                header = f" -H {_q('Cookie: ' + safe.strip())}"
        res = execute_quiet(
            f"curl -s -L -m {int(timeout)} -A {_q(agent)}{header} {_q(url)}",
            timeout=timeout + 10)
        return (res.stdout or "")[:400000]
    except Exception:
        return ""


def _jar_for(url: str, jar: Dict[str, str]) -> str:
    """Pick the Cookie header for a URL from {domain-suffix: header}.
    Longest suffix wins (login.company.com beats company.com)."""
    try:
        from urllib.parse import urlsplit
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""
    if not host or not jar:
        return ""
    best, best_len = "", -1
    for suffix, header in (jar or {}).items():
        sfx = str(suffix or "").lower().lstrip(".")
        if sfx and (host == sfx or host.endswith("." + sfx)):
            if len(sfx) > best_len:
                best, best_len = str(header or ""), len(sfx)
    return best


def session_jar(wm) -> Dict[str, str]:
    """Build the operator-session jar from WorldModel stolen_cookies
    findings: {domain-suffix: 'n=v; n2=v2'}.

    Source of truth is the cookie-stealer chain (beacon on the
    operator's own work box, CDP harvest, manual import): the operator
    uses THEIR work account, and Phantom replays ONLY what the browser
    would send to that same host. Values never leave this process
    except inside the Cookie header itself.
    """
    jar: Dict[str, str] = {}
    try:
        findings = wm.find("stolen_cookies") if wm is not None else []
    except Exception:
        return jar
    for f in findings or []:
        v = getattr(f, "value", None)
        entries = v.get("cookies", []) if isinstance(v, dict) else []
        buckets: Dict[str, List[str]] = {}
        for c in entries:
            if not isinstance(c, dict):
                continue
            host = str(c.get("host", "") or "").lower().lstrip(".")
            name = str(c.get("name", "") or "")
            value = str(c.get("value", "") or "")
            if not host or not name or not value:
                continue
            if not re.fullmatch(r"[A-Za-z0-9._~+/%=&*\-]+", name):
                continue
            if not re.fullmatch(r"[A-Za-z0-9._~+/%=&*\-]+", value):
                continue
            buckets.setdefault(host, []).append(f"{name}={value}")
        for host, pairs in buckets.items():
            jar[host] = "; ".join(pairs)[:4000]
    return jar


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

def _state_vote(username: str, platform: str, jar=None) -> Tuple[str, float, str]:
    """Two fetches with different UAs + short human delay; vote decides.
    Returns (state, confidence, html_of_best). `jar` (from session_jar)
    attaches the operator's own session cookies to profile views so
    authed-visible fields (bio/counts of a private account) resolve;
    public infrastructure (archives, search) never gets cookies."""
    url = _PROFILE_URLS.get(platform, "").format(u=username)
    if not url:
        return "unknown", 0.0, ""
    votes: List[str] = []          # public | private | missing | unknown
    best_html = ""
    cookies = _jar_for(url, jar or {})
    for i in range(2):
        html = _fetch(url, timeout=15.0, ua=_UAS[i % len(_UAS)],
                      cookies=cookies)
        if not html:
            # A failed fetch is NOT a missing account: `missing` is a claim
            # about the world and here we did not read the world at all
            # (timeout, TLS, block). Saying so keeps the graph honest.
            votes.append("unknown")
            continue
        low = html.lower()
        best_html = best_html or html
        if any(m in low for m in _NOT_FOUND_MARKERS.get(platform, ())):
            votes.append("missing")
        elif any(m in low for m in _PRIVATE_MARKERS.get(platform, ())):
            votes.append("private")
        elif _PUBLIC_MARKERS.get(platform):
            # a platform whose real page carries identifiable structure:
            # correct evidence earns `public`, its absence means we did not
            # read a profile — never a size-based guess
            votes.append("public" if _has_public_evidence(platform, low)
                         else "unknown")
        elif platform in _UNREADABLE:
            votes.append("unknown")
        elif len(html) > 2000:
            votes.append("public")
        else:
            votes.append("missing")
        if i == 0:
            time.sleep(random.uniform(0.8, 2.0))   # human pacing, not bot cadence
    if not votes:
        return "unknown", 0.0, best_html
    # Deterministic aggregation. The old `max(set(votes), key=votes.count)`
    # leaned on set iteration order whenever the vote split 1-1, so the SAME
    # two pages could return `private` in one process and `unknown` in the
    # next one (string hashes are seeded per process). Ties now resolve by
    # evidence precedence: a page that stated a fact about the account
    # (`private` marker, `missing` marker, public structure) beats one we
    # could not read at all, and confidence stays honest at 1/len(votes).
    counts = {v: votes.count(v) for v in votes}
    top = max(counts.values())
    winners = [v for v, c in counts.items() if c == top]
    if len(winners) > 1:
        for fact in ("private", "missing", "public"):
            if fact in winners:
                winners = [fact]
                break
    state = winners[0]
    conf = counts[state] / len(votes)
    return state, conf, best_html


# ── layer 2: graph mining ────────────────────────────────────────────────────

def _mine_all(username: str, platform: str, html: str,
              result: ReconResult, jar=None) -> None:
    """`_mine_graph` plus the per-post layer (never fetches anything extra).

    Post mining is pure: it reads the JSON already in hand, so the topics,
    mentions, places and links of what the target actually posts about cost
    nothing on the network budget and are the best pretext material there is.
    """
    _mine_graph(username, platform, html, result, jar)
    try:
        from phantom.automation.social import social_graph as _sg
        result.posts = _sg.mine_posts(html, author=username)
        counts: dict = {}
        for post in result.posts:
            for tag in list(post.hashtags) + [_norm_place(p) for p in post.places]:
                counts[tag] = counts.get(tag, 0) + 1
        result.topics = [t for t, _c in sorted(counts.items(),
                                              key=lambda kv: (-kv[1], kv[0]))[:8]]
    except Exception:
        result.posts = []


def _norm_place(value: str) -> str:
    return (value or "").strip().lower()


def _mine_graph(username: str, platform: str, html: str,
                result: ReconResult, jar=None) -> None:
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
        raw = _fetch(imgs[0], timeout=10.0,
                     cookies=_jar_for(imgs[0], jar or {}))
        if raw:
            result.avatar_hash = hashlib.md5(raw[:100000]).hexdigest()[:16]
            try:
                from phantom.automation.social.identity_confidence import (
                    compute_dhash)
                result.avatar_dhash = compute_dhash(raw)
            except Exception:
                result.avatar_dhash = ""
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
            if (_is_real_handle(h) and len(h) >= 3
                    and h.lower() != username.lower() and h not in seen):
                seen.add(h)
                result.leads.append(Lead("commenter", h, platform,
                                         ev, 0.55))
    # tagged handles: anywhere in page mentioning @others on tag pages
    for h in _HANDLE_RE.findall(html or "")[:60]:
        h = h.rstrip("._")
        if (_is_real_handle(h) and len(h) >= 3
                and h.lower() != username.lower()
                and h not in seen and not h.startswith("instagram")
                and not h.startswith("tiktok")):
            seen.add(h)
            result.leads.append(Lead("tagged", h, platform, ev, 0.45))
        if len(seen) > 14:
            break


# ── layer 2b: second-hop graph mining ────────────────────────────────

_SECOND_HOP_MAX = 3      # circle members whose profile we fetch
_SECOND_HOP_BUDGET = 3   # hard network-call cap for the whole pass


def _graph_handles(r: "ReconResult") -> set:
    """The handles a profile's page exposes (commenters + tagged)."""
    return {l.value.lstrip("@").lower() for l in r.leads
            if l.kind in ("commenter", "tagged") and l.value}


def _second_hop(primary: "ReconResult", platform: str, jar) -> List["Lead"]:
    """Fetch a few of the primary's circle and mine THEIR circles.

    A stranger who interacts with BOTH the target and a member of the
    target's circle is the strongest same-person / close-circle evidence
    available without following anyone — and it is the path that still
    works on a PRIVATE target, whose public posts show a commenter/tag
    surface even when the profile itself does not.

    Bounded: <= _SECOND_HOP_MAX profile fetches and _SECOND_HOP_BUDGET
    total network calls; never raises.
    """
    circle = sorted({l.value.lstrip("@").lower() for l in primary.leads
                     if l.kind in ("commenter", "tagged") and l.value})
    circle = [h for h in circle if len(h) >= 3][:_SECOND_HOP_MAX]
    if not circle:
        return []
    primary_graph = _graph_handles(primary)
    out: List[Lead] = []
    calls = 0
    for handle in circle:
        if calls >= _SECOND_HOP_BUDGET:
            break
        try:
            st, cf, html = _state_vote(handle, platform, jar)
            calls += 1
        except Exception:
            continue
        if not html:
            continue
        if st not in ("public", "private"):
            # a shell/unreadable page tells us nothing about the circle:
            # mining it only manufactures handles
            continue
        second = ReconResult(username=handle, platform=platform,
                             state=st, state_confidence=cf)
        try:
            _mine_graph(handle, platform, html, second, jar)
        except Exception:
            continue
        mutual = sorted(primary_graph & _graph_handles(second))
        for h in mutual[:5]:
            out.append(Lead("commenter", h, platform,
                            f"mutual_graph_2hop_via_{handle}", 0.6))
        if st == "public" and cf >= 0.5:
            out.append(Lead("account_link", handle, platform,
                            "second_hop_public", 0.5))
    return out


# ── layer 3: cross-account correlation ───────────────────────────────

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
                if _is_real_handle(h) and h.lower() != username.lower():
                    leads.append(Lead("account_link", h, platform,
                                      f"wayback:{ts}", 0.5))
            if leads:
                leads.append(Lead("wayback", snap, platform,
                                  f"snapshot:{ts}", 0.8))
                break  # one informative snapshot is enough
    except (ValueError, IndexError, TypeError):
        pass
    return leads


def _dork_queries(username: str, full_name: str = "", scope: str = "auto",
                  platform: str = "") -> List[str]:
    """The bounded dork set for one pass, in the operator's scope.

    ``full_name`` was accepted and then IGNORED by the old three templates:
    a person is looked up by their NAME as much as by their handle, and the
    name query is the one that surfaces a real profile on a site the handle
    never appeared on. A name query carries the handle too when we have
    both, so a hit can be tied back to the identity instead of to a
    namesake who happens to share the name.
    """
    name = " ".join((full_name or "").split())[:60]
    q: List[str] = []
    if scope == "pin" and platform:
        q.append(f'site:{_site_of(platform)} "{username}"')
        if name:
            q.append(f'site:{_site_of(platform)} "{name}"')
            q.append(f'site:{_site_of(platform)} "{name}" "{username}"')
        return q[:4]
    if scope == "other":
        excl = " ".join(f"-site:{_site_of(p)}" for p in TOP_SOCIALS)
        q.append(f'"{username}" {excl}')
        if name:
            q.append(f'"{name}" {excl}')
            q.append(f'"{name}" "{username}"')
        return q[:4]
    # auto: the legacy shape (same handle across the big three, mail
    # providers, code/leak sites) PLUS the name queries the parameter
    # promised and never ran.
    q.append(f'"{username}" (site:instagram.com OR site:tiktok.com '
             f'OR site:x.com)')
    q.append(f'"{username}" (gmail.com OR outlook.com OR yahoo.com '
             f'OR hotmail.com)')
    q.append(f'"{username}" (site:linkedin.com OR site:github.com '
             f'OR site:reddit.com)')
    if name:
        q.append(f'"{name}" "{username}"')
        q.append(f'"{name}" (site:linkedin.com OR site:facebook.com '
                 f'OR site:reddit.com)')
    return q[:5]


def _platform_of_url(url: str) -> str:
    """Which network a search hit belongs to ("" when it is just a URL)."""
    low = (url or "").lower()
    for plat, dom in _SITE_DOMAINS.items():
        if dom in low:
            return plat
    for dom, label in _OTHER_SITES.items():
        if dom in low:
            return label
    return ""


def _search_dorks(username: str, full_name: str = "",
                  scope: str = "auto", platform: str = "") -> List[Lead]:
    """DuckDuckGo HTML dork search (no API key) — bounded to 5 queries.

    Scope-aware: a PINNED pass stays inside that one site; the "other"
    scope EXCLUDES the five top socials and looks everywhere else, and
    every hit carries the network it came from.
    """
    from urllib.parse import quote_plus
    leads: List[Lead] = []
    seen_urls = set()
    for tpl in _dork_queries(username, full_name, scope, platform):
        html = _fetch(
            f"https://html.duckduckgo.com/html/?q={quote_plus(tpl)}",
            timeout=20.0)
        if not html:
            continue
        for m in re.finditer(r'class="result__url"[^>]*>\s*([^<]+)',
                             html[:200000]):
            url = m.group(1).strip()
            if url.startswith("//"):
                url = "https:" + url
            host = _URL_RE.match(url if "://" in url else "https://" + url)
            if not host or url in seen_urls:
                continue
            seen_urls.add(url)
            plat = _platform_of_url(url)
            leads.append(Lead("search_hit", url, plat, "ddg_dork",
                              0.5 if plat else 0.4))
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


# ── ambiguity: operator disambiguation ───────────────────────────────────────

# Two PROBABLE+ candidates close together below CONFIRMED: the engine
# cannot tell them apart, and guessing contacts the wrong person. The
# safe default (no ask hook) widens once, then halts without contact.
# With an ask hook (interactive shell / API answer), the operator sees
# avatar+bio+links and decides: same:<handle> | stop | widen.
_AMBIGUITY_BAND = 0.15


def _resolve_ambiguity(scored, ask) -> List[str]:
    """scored: [(handle, platform, tier, score, evidence, result)]."""
    from phantom.automation.social.identity_confidence import (
        CONFIRMED, PROBABLE)
    contenders = sorted(
        [(h, p, t, s, e, r) for h, p, t, s, e, r in scored
         if t in (CONFIRMED, PROBABLE)],
        key=lambda x: x[3], reverse=True)
    if len(contenders) < 2:
        return []
    (h1, p1, t1, s1, e1, r1), (h2, p2, t2, s2, e2, r2) = contenders[:2]
    if t1 == CONFIRMED or (s1 - s2) > _AMBIGUITY_BAND:
        return []  # clear winner: no question to ask
    desc = (f"{h1}@{p1} ({t1} {s1:.2f}) vs {h2}@{p2} ({t2} {s2:.2f})")
    if ask is None:
        return [f"IDENTITY_AMBIGUOUS: candidates={h1}@{p1},{h2}@{p2} "
                f"decision=widen_once_then_halt evidence={desc.replace(' ', '_')}"]
    try:
        decision = (ask(desc, [(h1, p1, r1), (h2, p2, r2)]) or "").strip()
    except Exception:
        decision = ""
    if decision.startswith("same:"):
        winner = decision.split("same:", 1)[1].strip().lstrip("@").lower()
        return [f"IDENTITY_RESOLVED: winner={winner} by=operator "
                f"evidence={desc.replace(' ', '_')}"]
    if decision == "stop":
        return ["IDENTITY_RESOLVED: winner=none by=operator_stop "
                f"evidence={desc.replace(' ', '_')}"]
    return [f"IDENTITY_AMBIGUOUS: candidates={h1}@{p1},{h2}@{p2} "
            f"decision=widen evidence={desc.replace(' ', '_')}"]


# ── operator confirmation surface ────────────────────────────────────────────

def preview_profile(username: str, platform: str,
                    jar=None) -> ReconResult:
    """One bounded look at a profile (2 fetches max): state vote + bio +
    counts + avatar, no variants/search/wayback. Powers the start-gate
    ("is this him?") in CLI/API/UI BEFORE a run commits to a target."""
    username = (username or "").strip().lstrip("@")
    platform = (platform or "instagram").lower()
    result = ReconResult(username=username, platform=platform)
    if not username:
        return result
    state, conf, html = _state_vote(username, platform, jar)
    result.state, result.state_confidence = state, conf
    if html:
        result.bio = _extract_bio(html)
        result.link = _extract_link(result.bio)
        _mine_graph(username, platform, html, result, jar)
    return result


def present_candidate(result: "ReconResult") -> str:
    """One-screen operator summary of a candidate profile: avatar URL
    (the UI renders the image), bio, follower/following/posts counts,
    link and state. Used by the start-gate ("is this him?") and by the
    mid-run disambiguation ("which one?"). Pure rendering, no I/O."""
    lines = [f"@{result.username} ({result.platform}) — {result.state}"]
    if result.full_name:
        lines.append(f"  name: {result.full_name}")
    if result.bio:
        lines.append(f"  bio: {result.bio[:220]}")
    counts = " / ".join(
        f"{k}: {v}" for k, v in
        (("followers", result.followers), ("following", result.following),
         ("posts", result.posts)) if v)
    if counts:
        lines.append(f"  {counts}")
    if result.link:
        lines.append(f"  link: {result.link}")
    if result.avatar_url:
        lines.append(f"  avatar: {result.avatar_url}")
    return "\n".join(lines)


# ── engine entry point ───────────────────────────────────────────────────────

def deep_recon(username: str, platform: str = "",
               variants: bool = True, wayback: bool = True,
               search: bool = True, second_hop: bool = True,
               ask=None, jar=None, graph=None,
               scope: str = "") -> Tuple[bool, List[str]]:
    """Full reverse-engineering pass. Returns marker lines for the social
    interpreter. Bounded: <= 20 network calls total, never raises.

    `scope` (or, derived from `platform`, one of):

    * `pin`   — `platform` is the ONE network the handle belongs to. No
      other platform is fetched, so a namesake on another network can
      never enter the identity graph. This is what the operator selects
      when they know where the handle lives.
    * `other` — the five top socials are EXCLUDED and the pass looks
      everywhere else (alternatives + dorks that carry `-site:` for the
      five), reporting every correspondence it finds.
    * `auto`  — legacy: `platform` as primary, every platform probed.

    An unknown/empty value is `auto` (see `normalize_scope`).

    `ask`: optional operator hook for ambiguity
    (ask(description, [(handle, platform, result), ...]) -> "same:<handle>"
    | "stop" | "widen" | ""). None = safe default (widen once, halt
    without contact).

    `jar`: operator-session cookies ({domain-suffix: header}) from the
    stealer chain. Attached ONLY to platform profile views (never to
    archives/search), so an authed-visible bio/counts resolves on
    private accounts. Which hosts used it is emitted as SESSION_USED.

    `graph`: optional `SocialGraph` to fill in (in/out), so the CLI/API can
    render or export the identity graph without re-deriving it. The markers
    are emitted either way, so auto-mode gets the graph through the social
    interpreter whether or not a caller passed one.
    """
    try:
        lines: List[str] = []
        username = (username or "").strip().lstrip("@")
        if not username:
            return False, ["ERROR: deep_recon needs a username"]
        scope, platform = normalize_scope(platform, scope)
        platform = _primary_for(scope, platform)
        jar = jar or {}

        results: List[ReconResult] = []

        # primary platform: state vote + graph mining
        state, conf, html = _state_vote(username, platform, jar)
        primary = ReconResult(username=username, platform=platform,
                              state=state, state_confidence=conf)
        if html:
            primary.bio = _extract_bio(html)
            primary.link = _extract_link(primary.bio)
            _mine_all(username, platform, html, primary, jar)
        results.append(primary)

        # same handle on OTHER platforms (single quick fetch each).
        # A PINNED pass probes NOTHING else on purpose: the same handle on
        # another network is very often a different person, and a wrong
        # candidate costs the whole chain (the DM lands on a stranger).
        if scope == "pin":
            cross: List[str] = []
        elif scope == "other":
            cross = list(ALT_PLATFORMS)          # everything but the top five
        else:
            cross = list(TOP_SOCIALS)
        for p in cross:
            if p == platform:
                continue
            st, cf, h2 = _state_vote(username, p, jar)
            if st in ("missing", "unknown"):
                # `unknown` = the platform served a shell we cannot read (or
                # the fetch failed). A node built on it would claim an account
                # nobody saw, and the graph's value is that its nodes are real.
                continue
            r = ReconResult(username=username, platform=p, state=st,
                            state_confidence=cf)
            if h2:
                r.bio = _extract_bio(h2)
                r.link = _extract_link(r.bio)
                _mine_all(username, p, h2, r, jar)
                if r.state == "public" and r.bio:
                    # a PUBLIC account of the same handle on another platform
                    primary.leads.append(Lead(
                        "account_link", username, p, "same_handle_public", 0.7))
            results.append(r)

        # username variants (bounded sherlock-style probe)
        if variants:
            for v in _username_variants(username):
                st, cf, h2 = _state_vote(v, platform, jar)
                if st == "public" and cf >= 0.5:
                    rv = ReconResult(username=v, platform=platform,
                                     state=st, state_confidence=cf)
                    if h2:
                        rv.bio = _extract_bio(h2)
                        _mine_all(v, platform, h2, rv, jar)
                    results.append(rv)
                    primary.leads.append(Lead(
                        "account_link", v, platform, "variant_probe", 0.55))

        # wayback + dorks run against the PRIMARY only (bounded budget)
        if wayback:
            primary.leads.extend(_wayback_snapshots(username, platform))
        if search:
            primary.leads.extend(_search_dorks(username, primary.full_name,
                                               scope=scope, platform=platform))

        # second hop: mine the circles of a few circle members (the path that
        # still works on a PRIVATE target, whose public posts show a
        # commenter/tag surface). Bounded and additive.
        if second_hop:
            try:
                for lead in _second_hop(primary, platform, jar):
                    if lead not in primary.leads:
                        primary.leads.append(lead)
            except Exception:
                pass

        # cross-account correlation across everything collected
        if scope == "pin":
            lines.append(
                "RECON_SCOPE: mode=pin platform=%s excluded=%s "
                "contact_scope=operator"
                % (platform, ",".join(p for p in TOP_SOCIALS
                                      if p != platform)))
        elif scope == "other":
            lines.append(
                "RECON_SCOPE: mode=other excluded=%s platforms=%s"
                % (",".join(TOP_SOCIALS), ",".join(ALT_PLATFORMS)))
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
        # `ask`, when provided, resolves AMBIGUITY live: 2+ candidates
        # close together below CONFIRMED pause for one operator decision
        # (same <handle> | stop | widen), otherwise the safe default
        # applies (widen once, then halt without contact).
        from phantom.automation.social.identity_confidence import (
            score_lead as _score, may_act as _may_act)
        from phantom.automation.social.identity_confidence import CONFIRMED as _CONFIRMED

        def _graph_of(r: ReconResult) -> List[str]:
            """The social circle of a profile: commenters + tagged handles
            + discovered account links (the same strangers who interact
            with BOTH accounts are same-person evidence)."""
            out = [l.value for l in r.leads
                   if l.kind in ("commenter", "tagged", "account_link")]
            return sorted({h.lstrip("@").lower() for h in out if h})[:40]

        def _outbound_of(r: ReconResult) -> List[str]:
            """Handles the primary page itself points at (bio links,
            discovered account links): the other half of a bidirectional
            cross-link check."""
            out = [l.value for l in r.leads if l.kind == "account_link"]
            if r.link:
                out.append(r.link)
            return sorted({str(h).lstrip("@").lower() for h in out if h})[:20]

        primary_dict = {
            "username": primary.username, "bio": primary.bio,
            "avatar_hash": primary.avatar_hash,
            "avatar_dhash": primary.avatar_dhash, "link": primary.link,
            "outbound": _outbound_of(primary),
            "full_name": primary.full_name,
            "emails": sorted({*(l.value for l in primary.leads
                                 if l.kind == "identity" and "@" in l.value),
                               *primary.emails}),
            "graph": _graph_of(primary),
        }
        scored = []  # (handle, platform, tier, score, evidence)
        for r in results[1:]:
            if r.platform == primary.platform:
                continue
            lead_obj = _score(primary.platform, primary_dict, {
                "username": r.username, "bio": r.bio,
                "avatar_hash": r.avatar_hash,
                "avatar_dhash": r.avatar_dhash, "link": r.link,
                "full_name": r.full_name,
                "emails": r.emails,
                "graph": _graph_of(r),
            })
            tier = lead_obj.tier
            scored.append((r.username, r.platform, tier, lead_obj.score,
                           lead_obj.evidence, r))
            # policy snapshot for the marker: contact needs CONFIRMED
            # (or --aggressive); read-only recon is always allowed.
            dm_ok, why = _may_act(lead_obj, "dm_launch", aggressive=False)
            lines.append(
                f"IDENTITY_CONF: handle={r.username} platform={r.platform} "
                f"tier={tier} score={lead_obj.score:.2f} "
                f"contact={int(bool(dm_ok))} why={why.replace(' ', '_')}")
        if ask is not None:
            lines.extend(_resolve_ambiguity(scored, ask))
        if jar:
            # operator-session receipt: WHICH platform views went out
            # with the operator's own cookies (read-only views only —
            # archives/search never receive them). Counts and platforms
            # only: values never enter a marker.
            try:
                from urllib.parse import urlsplit
                used = set()
                for r in results:
                    probe = _PROFILE_URLS.get(r.platform, "").format(
                        u=r.username or "x")
                    host = (urlsplit(probe).hostname or "").lower()
                    if host and _jar_for(f"https://{host}/", jar):
                        used.add(r.platform)
                if used:
                    lines.append(
                        f"SESSION_USED: platforms={','.join(sorted(used))} "
                        f"source=operator_session readonly=1")
            except Exception:
                pass
        # 2-hop receipt: who the primary's circle and a member's circle
        # SHARE — the mutual-graph strangers. Emitted as one summary line on
        # top of the per-handle COMMENTER markers below.
        mutual = sorted({l.value for l in primary.leads
                         if "mutual_graph_2hop" in (l.evidence or "")})
        if mutual:
            lines.append("SOCIAL_2HOP: platform=%s mutual=%s"
                         % (platform, ",".join(mutual[:8])))
        # PRIVATE-account path: on a private target, say WHICH routes are
        # still viable (a public same-handle elsewhere, the mutual-graph
        # circle, the operator's own stolen session) instead of leaving the
        # operator to guess there is nothing left.
        if primary.state == "private":
            routes = []
            public_same = sorted({r.platform for r in results[1:]
                                  if r.platform != platform
                                  and r.state == "public" and r.bio})
            if public_same:
                routes.append("same_handle_public:" + ",".join(public_same))
            if mutual:
                routes.append(f"mutual_graph:{len(mutual)}")
            if jar:
                routes.append("operator_session")
            if routes:
                lines.append("PRIVATE_PATH: platform=%s routes=%s"
                             % (platform, " ".join(routes)))
        for lead in primary.leads:
            if lead.kind in ("account_link", "search_hit", "wayback"):
                lines.append(f"ACCOUNT_LINK: handle={lead.value} "
                             f"platform={lead.platform} "
                             f"url=https://{lead.platform}.com/{lead.value} "
                             f"evidence={lead.evidence}" if lead.platform else
                             f"SEARCH_HIT: url={lead.value} "
                             f"evidence={lead.evidence}")

        # ── the identity GRAPH ──────────────────────────────────────────
        # Every fact above was emitted as a flat marker line, so nothing could
        # reason over it: not who is in the circle, not which two handles are
        # the SAME person, not what the target posts about. The graph makes it
        # walkable, and the markers below carry the summary to auto-mode.
        try:
            from phantom.automation.social import social_graph as _sg
            built = _sg.graph_from_recon(results)
            for r in results:
                if getattr(r, "posts", None):
                    _sg.graph_from_posts(r.posts, author=r.username,
                                         platform=r.platform, graph=built,
                                         source="post-mining")
            if graph is not None:
                graph.merge(built)
                view = graph
            else:
                view = built
            stats = view.stats()
            lines.append("SOCIAL_GRAPH: nodes=%d edges=%d clusters=%d "
                         "same_person=%d"
                         % (stats["nodes"], stats["edges"], stats["clusters"],
                            len(stats["same_person_groups"])))
            for group in stats["same_person_groups"]:
                lines.append("SAME_PERSON: handles=%s evidence=confirming"
                             % ",".join(h.split(":", 1)[-1]
                                        for h in group))
            primary_key = _sg.node_key("handle", username)
            for node in view.pivot_leads(("handle", "email"),
                                         min_confidence=0.5)[:10]:
                if node.key == primary_key:
                    continue
                lines.append("GRAPH_PIVOT: kind=%s value=%s conf=%.2f proofs=%d"
                             % (node.kind, node.label, node.confidence,
                                len(view.proofs(node.key))))
            topics = view.interests(primary_key, limit=8)
            if topics:
                lines.append("POST_TOPIC: username=%s topics=%s"
                             % (username,
                                ",".join("%s:%d" % (t, c) for t, c in topics)))
        except Exception:
            pass
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
