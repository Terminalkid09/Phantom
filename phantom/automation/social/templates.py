"""
templates.py — pretext library + OSINT-driven personalization.

A pretext is a believable story with a subject, a plain-text body and an
HTML body. Every placeholder is filled from what the engagement ACTUALLY
discovered (identity findings, breach facts, platform), never from static
fiction — a personalized lure converts far better than a generic one and
stays consistent with the persona that delivers it.

Placeholders (all optional; unknown values degrade to a neutral default):

    {name}         local-part of the discovered email, title-cased
    {platform}     the platform OSINT tied to the identity (e.g. LinkedIn)
    {breach}       a real breach the email was found in (HIBP/BREACH data)
    {company}      domain of the discovered email, without TLD
    {sender}       sender display name for the pretext role
    {hook}         one-line recognition hook from the target dossier (breach
                   correlation / phone tail) — empty when nothing is known
    {link}         the tracking / credential-harvest link
    {link_label}   anchor text for the link ("Verify now", "Download", ...)

Templates are deliberately short, human and typo-free — the goal is a
credible single-purpose lure, not a corporate newsletter.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# pretext library
# ---------------------------------------------------------------------------

@dataclass
class Pretext:
    id: str
    label: str
    sender: str                       # display name used as From
    subject: str
    body_text: str
    link_label: str = "Continue"
    # short human hint shown in `campaign --list` / help
    description: str = ""


_PRESTEXT_DEFS: Dict[str, Dict[str, str]] = {
    "security_alert": {
        "label": "Security alert",
        "sender": "Security Operations",
        "subject": "Suspicious sign-in blocked on your {platform} account",
        "body_text": (
            "Hi {name},\n\n"
            "We blocked a sign-in attempt to your {platform} account from an "
            "unrecognized device. If this wasn't you, note that your address "
            "was also exposed in the recent {breach} data breach - please "
            "confirm your recent sessions to keep the account active.\n\n"
            "{hook}\n\n"
            "{link}\n\n"
            "This request expires in 24 hours.\n"
            "{sender}"),
        "link_label": "Review my recent sessions",
        "description": "Fake security alert with a real breach angle when known",
    },
    "it_helpdesk": {
        "label": "IT helpdesk",
        "sender": "IT Service Desk",
        "subject": "Action required: update your mailbox settings",
        "body_text": (
            "Hi {name},\n\n"
            "Our mail server was updated on {company} infrastructure. "
            "Mailboxes that are not re-authenticated by the end of the week "
            "will be temporarily suspended.\n\n"
            "Re-authenticate here: {link}\n\n"
            "Thanks,\n{company} IT Service Desk"),
        "link_label": "Re-authenticate my mailbox",
        "description": "Mailbox re-auth request that feels like routine IT work",
    },
    "hr_benefits": {
        "label": "HR benefits",
        "sender": "HR Department",
        "subject": "Your updated benefits statement is ready",
        "body_text": (
            "Hi {name},\n\n"
            "Your updated benefits statement for this quarter is available. "
            "Please review it and confirm your details before the payroll cut-off.\n\n"
            "View statement: {link}\n\n"
            "Regards,\n{company} HR"),
        "link_label": "View my statement",
        "description": "Benefits statement lure — quiet and rarely reported",
    },
    "recruiter": {
        "label": "Recruiter",
        "sender": "Talent Acquisition",
        "subject": "Interesting opportunity matching your profile",
        "body_text": (
            "Hi {name},\n\n"
            "I came across your profile and think you'd be a strong fit for a "
            "senior role we're hiring for. Before we schedule a call, could you "
            "confirm your availability?\n\n"
            "{link}\n\n"
            "Best,\n{company} Talent Acquisition"),
        "link_label": "Check availability",
        "description": "Recruiter lure for username/email targets with a public profile",
    },
    "package_delivery": {
        "label": "Package delivery",
        "sender": "Courier Support",
        "subject": "Your package is on hold — confirm a delivery time",
        "body_text": (
            "Hi {name},\n\n"
            "We couldn't deliver your package because no one was available. "
            "Choose a new delivery window so we can complete the shipment.\n\n"
            "{hook}\n\n"
            "{link}\n\n"
            "{sender}"),
        "link_label": "Reschedule delivery",
        "description": "Delivery notification — high open rate, low suspicion",
    },
    "password_reset": {
        "label": "Password reset",
        "sender": "Account Security",
        "subject": "Reset your {platform} password",
        "body_text": (
            "Hi {name},\n\n"
            "A password reset was requested for your {platform} account. If "
            "this was you, complete the reset below. If it wasn't, your "
            "password has NOT been changed.\n\n"
            "{hook}\n\n"
            "{link}\n\n"
            "{sender}"),
        "link_label": "Reset my password",
        "description": "Classic reset lure tied to the platform OSINT found",
    },
    "doc_share": {
        "label": "Shared document",
        "sender": "Documents",
        "subject": "{company} shared a document with you",
        "body_text": (
            "Hi {name},\n\n"
            "{company} shared the document \"Q3 Review — {name}\" with you. "
            "You can open it until the sharing link expires.\n\n"
            "{link}\n\n"
            "{sender}"),
        "link_label": "Open document",
        "description": "Document share lure with the target's own name as filename",
    },
}


def pretext_ids() -> List[str]:
    return list(_PRESTEXT_DEFS.keys())


def get_pretext(pretext_id: str) -> Optional[Pretext]:
    d = _PRESTEXT_DEFS.get(pretext_id)
    if d is None:
        return None
    return Pretext(
        id=pretext_id, label=d["label"], sender=d["sender"],
        subject=d["subject"], body_text=d["body_text"],
        link_label=d.get("link_label", "Continue"),
        description=d.get("description", ""))


def default_pretext() -> str:
    return "security_alert"


# ---------------------------------------------------------------------------
# context building (OSINT -> placeholders)
# ---------------------------------------------------------------------------

def _name_from_email(email: str) -> str:
    local = (email or "").split("@")[0]
    local = "".join(c for c in local if c.isalnum() or c in "._-")
    parts = [p for p in local.replace(".", " ").replace("_", " ").replace("-", " ")
             .split() if p]
    if not parts:
        return "there"
    return " ".join(p.capitalize() for p in parts[:2])


def _company_from_email(email: str) -> str:
    domain = (email or "").split("@")[-1]
    domain = domain.split(".")[0] if domain else ""
    return domain.capitalize() or "our"


def build_context(email: str = "", platform: str = "",
                  breaches: Optional[List[str]] = None,
                  discovered_names: Optional[List[str]] = None,
                  hook: str = "") -> Dict[str, str]:
    """Assemble the placeholder map from real engagement findings.

    `breaches` are the actual breach names discovered (HIBP / breach API).
    `hook` is the strategic one-liner from the target dossier (breach
    correlation / phone tail); it renders as an empty line when unknown.
    Unknown values degrade to neutral defaults so a template never renders
    "None" or an empty placeholder.
    """
    ctx: Dict[str, str] = {
        "name": _name_from_email(email) if email else "there",
        "company": _company_from_email(email) if email else "our",
        "platform": platform or "online",
        "breach": (breaches or [""])[0],
        "hook": hook or "",
        "sender": "The Team",
    }
    if discovered_names:
        ctx["name"] = discovered_names[0]
    return ctx


def render_pretext(pretext_id: str, context: Dict[str, str],
                   link: str = "", link_label: str = "") -> Optional[Dict[str, str]]:
    """Render a pretext into {subject, body_text, link_label, sender}.

    Returns None for an unknown pretext id. `link` and `link_label` are
    injected AFTER the placeholder pass so a link never appears inside a
    template file and every campaign can swap it per-target.
    """
    pre = get_pretext(pretext_id)
    if pre is None:
        return None
    ctx = {k: (v or "") for k, v in context.items()}
    ctx.setdefault("link", link or "https://example.com")
    label = link_label or pre.link_label
    ctx.setdefault("link_label", label)
    subject = pre.subject.format(**ctx)
    body_text = pre.body_text.format(**ctx)
    return {
        "subject": subject,
        "body_text": body_text,
        "link_label": label,
        "sender": pre.sender,
    }


# ---------------------------------------------------------------------------
# HTML body builder (delivery hardening)
# ---------------------------------------------------------------------------

_HTML_BASE = """<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"></head><body style="font-family:{font},sans-serif;color:#222;max-width:560px;margin:0 auto;padding:24px">
<!-- {noise} -->
<p style="font-size:14px;line-height:1.5">{intro}</p>
<p style="margin:28px 0"><a href="{link}" style="background:{btn};color:#fff;text-decoration:none;padding:{pad}px 18px;border-radius:{radius}px;display:inline-block;font-size:14px">{link_label}</a></p>
<p style="font-size:14px;line-height:1.5">{tail}</p>
<p style="font-size:11px;color:#999;margin-top:32px;border-top:1px solid #eee;padding-top:12px">{footer}</p>
{tracking}
</body></html>"""

# per-send variation so a campaign never shares one HTML fingerprint
_BRANDS = ("#0a5bd3", "#1a73e8", "#0066cc", "#2e5aac", "#0057b8")
_FONTS = ("Arial", "Helvetica", "Segoe UI", "Verdana", "Tahoma")
_FOOTERS = (
    "You are receiving this message because you have an active account. "
    "If you believe this was sent in error, you can adjust your "
    "notification preferences in account settings.",
    "This is an automated service message. To stop receiving these "
    "emails, update your communication preferences from your profile.",
    "Sent by the notifications service. Manage your alert settings in "
    "your account dashboard at any time.",
)


def build_html_body(subject: str, body_text: str, link: str,
                    link_label: str, tracking_pixel: str = "") -> str:
    """Convert a plain-text pretext body into a realistic HTML email.

    Keeps the visible text identical to the plain version (delivery
    consistency), adds one action button and injects the open-tracking
    pixel before </body>.

    Delivery hardening: per-send randomized button color / font / paddings
    and a rotating legitimate-looking footer, so a multi-target campaign
    never shares one template fingerprint (bulk-template detectors group
    identical HTML across recipients; real mail never matches 1:1)."""
    import random
    paras = [p.strip() for p in body_text.split("\n\n") if p.strip()]
    intro = " ".join(paras[:-1]) if len(paras) > 1 else (paras[0] if paras else body_text)
    tail = paras[-1] if paras else ""
    # NEVER display:none: a hidden image is a classic spam marker, and Gmail
    # strips it — which silently kills open tracking on top of hurting
    # delivery. The pixel is a normal inline 1x1 with a plausible alt, the
    # way real service mail carries one.
    tracking = (f'<img src="{tracking_pixel}" width="1" height="1" '
                f'style="border:0;outline:none" alt="status">'
                ) if tracking_pixel else ""
    noise = "".join(random.choices(
        "abcdefghijklmnopqrstuvwxyz0123456789", k=10))
    return _HTML_BASE.format(
        intro=intro, link=link, link_label=link_label,
        tail=tail, tracking=tracking,
        font=random.choice(_FONTS),
        btn=random.choice(_BRANDS),
        pad=random.choice((9, 10, 11, 12)),
        radius=random.choice((3, 4, 4, 5, 6)),
        footer=random.choice(_FOOTERS),
        noise=noise)
