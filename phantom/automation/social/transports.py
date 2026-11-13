"""
transports.py — transport capability detection for the social chain.

Every social-engineering channel is either LOCAL (works out of the box:
tracker, persona generation, pretext rendering) or EXTERNAL (needs a
credential: SMTP, Telegram, Discord, SMS carrier, public URL). This module
reports which channels are actually usable right now, so the auto-mode can:

  * choose the best available channel (email vs SMS vs DM);
  * SKIP a phase with a clear reason when its transport is missing
    ("phish skipped: no SMTP credentials — run 'phantom setup'")
    instead of failing blindly;
  * tell the operator exactly what to configure.

Config source: ``data/config.json`` (auto-created) with ``PHANTOM_*`` env
vars taking precedence — a fresh checkout needs ZERO configuration to run
the local chain, and only per-engagement channels can be missing.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from phantom.automation.social.mailers import env_mail_config
from phantom.utils import config as cfg

# capability ids -> the transport keys (from transport_status) they need
# to actually deliver. Names must match transport_status() channels.
# phish_identity is special-cased: email OR sms both satisfy it.
_TRANSPORT_NEEDS: Dict[str, List[str]] = {
    # A lure that leaves this machine SHOULD show a public domain: a link
    # exposing the operator's IP is an OPSEC failure. That is a warning, not
    # a missing transport — the tracker is local and always usable, and the
    # refusal happens where the lure is built (the deliverability preflight;
    # lab/CTF runs opt in with engagement.allow_unscoped). Blocking a whole
    # phase here used to stall the chain on a fresh checkout.
    "phish_identity": ["email", "tracker"],
    "campaign_launch": ["email", "tracker"],
    "dm_launch": ["dm", "tracker"],
    # stage 2 sends a LINK: it needs the DM channel wired, nothing else
    "dm_stage2": ["dm"],
    # local-only phases never block:
    "harvest_campaign": [],
    "wait_follow": [],
    "dm_follow": [],
    "persona_create": [],
    "persona_profile": [],
    "poll_hits": [],
    "osint_identity": [],
    "breach_check": [],
}


def _lab_lures_allowed() -> bool:
    """Explicit opt-in for lab/CTF runs where a private-IP lure link is
    acceptable (the operator accepted it by setting the escape hatch)."""
    return str(cfg.get("engagement.allow_unscoped", "",
                       env="PHANTOM_ALLOW_UNSCOPED")).strip().lower() \
        in ("1", "true", "yes", "on")


def _tracker_public() -> bool:
    """True when the configured lure URL is a DOMAIN (not a bare IP)."""
    try:
        from phantom.automation.social.tracker import tracker_is_public
        return tracker_is_public()
    except Exception:
        return False


def _smtp_ready() -> bool:
    mc = env_mail_config()
    return bool(mc.username and mc.password)


def _sms_ready() -> bool:
    if not _smtp_ready():
        return False
    carrier = str(cfg.get("transports.sms_carrier", "",
                          env="PHANTOM_SMS_CARRIER")).strip()
    return bool(carrier)


def _dm_ready() -> bool:
    custom = str(cfg.get("transports.dm_transport", "",
                         env="PHANTOM_DM_TRANSPORT")).strip()
    telegram = str(cfg.get("transports.telegram_bot_token", "",
                           env="PHANTOM_TELEGRAM_BOT_TOKEN")).strip()
    discord = str(cfg.get("transports.discord_webhook", "",
                          env="PHANTOM_DISCORD_WEBHOOK")).strip()
    return bool(custom or telegram or discord)


def transport_status() -> Dict[str, dict]:
    """Current usability of every social channel.

    Returns {channel: {ready, detail}} where ``detail`` explains how to
    enable it when not ready — so CLI/Electron can render a "setup" hint.
    """
    tracker_url = str(cfg.get("tracker.public_url", "",
                              env="PHANTOM_TRACK_URL")).strip()
    breach_api = str(cfg.get("breach.custom_api", "",
                             env="PHANTOM_BREACH_API")).strip()
    hibp = str(cfg.get("breach.hibp_api_key", "",
                       env="PHANTOM_HIBP_API_KEY")).strip()
    llm = str(cfg.get("llm.model_path", "",
                      env="PHANTOM_LLM_MODEL")).strip()
    smtp_ready = _smtp_ready()
    return {
        "email": {
            "ready": smtp_ready,
            "detail": "" if smtp_ready else
                      "set SMTP username/password (phantom setup > email)",
        },
        "sms": {
            "ready": _sms_ready(),
            "detail": "" if _sms_ready() else
                      "needs SMTP creds + a carrier (phantom setup > sms)",
        },
        "dm": {
            "ready": _dm_ready(),
            "detail": "" if _dm_ready() else
                      "set a Telegram bot token, Discord webhook or custom "
                      "DM transport (phantom setup > dm)",
        },
        "tracker": {
            # The tracker is a LOCAL transport: it runs with zero
            # configuration, so it is never MISSING — blocking a whole
            # phase on it stalls the chain on a fresh checkout, which this
            # module's contract forbids ("a fresh checkout needs ZERO
            # configuration to run the local chain").
            #
            # A bare-IP lure is an OPSEC problem, not a missing channel: it
            # is reported here (`public`) and enforced where the lure is
            # actually built — the deliverability preflight refuses a link
            # that carries the operator's IP for a real engagement, and
            # lab/CTF runs opt in with engagement.allow_unscoped.
            "ready": True,
            "public": _tracker_public(),
            "detail": ("public URL: " + tracker_url) if _tracker_public()
                      else ("lab mode (unscoped escape hatch): lure links "
                            "would expose your machine"
                            if _lab_lures_allowed() else
                            "usable locally, NOT public — set a DOMAIN "
                            "(with TLS) in tracker.public_url before "
                            "sending a lure to a real target; a link "
                            "showing your IP is readable by any SOC "
                            "analyst"),
        },
        "breach": {
            "ready": bool(breach_api or hibp),
            "detail": "" if (breach_api or hibp) else
                      "offline wordlists only (optional API key)",
        },
        "llm": {
            "ready": bool(llm),
            "detail": "" if llm else "bundled default used when present",
        },
    }


def missing_transports(capability_id: str) -> List[str]:
    """Transport keys missing for a social capability ([] = can run now)."""
    status = transport_status()
    if capability_id == "phish_identity":
        # a phone target is phished over SMS (email-to-SMS, needs SMTP too)
        # and an email target over SMTP: either channel unblocks the phase
        blocks = [] if (status["email"]["ready"] or status["sms"]["ready"]) \
            else ["email"]
        if not status["tracker"]["ready"]:
            blocks.append("tracker")
        return blocks
    needs = _TRANSPORT_NEEDS.get(capability_id, [])
    return [t for t in needs if t in status and not status[t]["ready"]]


def setup_hint(missing: List[str]) -> str:
    status = transport_status()
    return "; ".join(f"{k}: {status[k]['detail']}" for k in missing
                     if k in status)


def recommended_delivery() -> str:
    """Best available channel for a lure, or '' when none exists."""
    st = transport_status()
    if st["email"]["ready"] and st["sms"]["ready"]:
        return "sms"          # email-to-SMS is the stealthiest free channel
    if st["email"]["ready"]:
        return "email"
    if st["dm"]["ready"]:
        return "dm"
    return ""