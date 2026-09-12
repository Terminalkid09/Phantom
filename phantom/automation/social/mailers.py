"""
mailers.py — sending channels for social engineering.

Mail and SMS go through free tiers (SMTP2GO / Brevo for mail, email-to-SMS
carrier gateways for texts). Transport is injectable so tests never send.
"""

from __future__ import annotations

import os
import smtplib
from dataclasses import dataclass
from typing import Callable, Optional

from phantom.automation.social.persona import carrier_sms_address

# free-tier SMTP endpoints
SMTP2GO_HOST = "mail.smtp2go.com"
BREVO_HOST = "smtp-relay.brevo.com"


@dataclass
class MailConfig:
    smtp_host: str = SMTP2GO_HOST
    smtp_port: int = 2525
    username: str = ""
    password: str = ""
    use_tls: bool = True


def env_mail_config() -> MailConfig:
    """MailConfig from data/config.json (transports.smtp) with legacy
    PHANTOM_SMTP_* environment variables taking precedence.

    SMTP2GO and Brevo both offer free tiers; ``phantom setup`` writes the
    credentials into config.json so a .env is never required.
    """
    from phantom.utils import config as cfg
    host = cfg.get("transports.smtp.host", SMTP2GO_HOST, env="PHANTOM_SMTP_HOST")
    try:
        port = int(cfg.get("transports.smtp.port", "2525",
                           env="PHANTOM_SMTP_PORT"))
    except (TypeError, ValueError):
        port = 2525
    use_tls = str(cfg.get("transports.smtp.tls", "1",
                          env="PHANTOM_SMTP_TLS")) not in ("0", "false", "no", "")
    return MailConfig(
        smtp_host=str(host),
        smtp_port=port,
        username=str(cfg.get("transports.smtp.username", "",
                             env="PHANTOM_SMTP_USER")),
        password=str(cfg.get("transports.smtp.password", "",
                             env="PHANTOM_SMTP_PASSWORD")),
        use_tls=use_tls,
    )


class Mailer:
    """High-level sender: plain/HTML email or email-to-SMS via carrier gateway."""

    def __init__(self, config: Optional[MailConfig] = None,
                 transport: Optional[Callable] = None) -> None:
        """transport(sender, to, subject, body, html=None) -> bool —
        injectable for tests (a 4-arg transport keeps working)."""
        self.config = config if config is not None else env_mail_config()
        self._transport = transport or self._smtp_send
        self._jitter = False

    def _build_message(self, sender: str, to: str, subject: str, body: str,
                   html: Optional[str] = None,
                   reply_to: Optional[str] = None) -> bytes:
        import email.utils
        import random as _random
        import string as _string
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        msg = MIMEMultipart("alternative")
        msg["From"] = sender
        msg["To"] = to
        msg["Subject"] = subject
        msg["Date"] = email.utils.formatdate(localtime=True)
        # Message-ID on the SENDING domain (phantom.local is an instant
        # spam signal); random left-part like real MUAs generate
        mid_domain = "mail.com"
        try:
            from_addr = sender.split("<")[-1].rstrip(">").strip()
            if "@" in from_addr:
                mid_domain = from_addr.split("@", 1)[1]
        except (IndexError, AttributeError):
            pass
        msg["Message-ID"] = f"<{_random.randbytes(8).hex()}.{''.join(_random.choices(_string.ascii_lowercase, k=6))}@{mid_domain}>"
        # headers real MUAs set and spam filters expect: their ABSENCE is
        # the loudest phishing signal, more than any content filter
        msg["MIME-Version"] = "1.0"
        msg["X-Mailer"] = "Microsoft Outlook 16.0"
        msg["Thread-Index"] = _random.randbytes(11).hex()
        msg["Content-Language"] = "en-US"
        msg["Accept-Language"] = "en-US"
        if reply_to:
            msg["Reply-To"] = reply_to
        msg.attach(MIMEText(body, "plain", "utf-8"))
        if html:
            msg.attach(MIMEText(html, "html", "utf-8"))
        return msg.as_bytes()

    def _smtp_send(self, sender: str, to: str, subject: str, body: str,
                   html: Optional[str] = None,
                   reply_to: Optional[str] = None) -> bool:
        if not self.config.username:
            return False  # no credentials configured → operator must review
        msg = self._build_message(sender, to, subject, body, html, reply_to)
        try:
            with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port, timeout=15) as server:
                if self.config.use_tls:
                    server.starttls()
                server.login(self.config.username, self.config.password)
                server.sendmail(sender, [to], msg)
            return True
        except Exception:
            return False

    # -- API ----------------------------------------------------------------

    def send_email(self, sender: str, to: str, subject: str, body: str,
                   html: Optional[str] = None,
                   reply_to: Optional[str] = None) -> bool:
        """Send plain (and optionally HTML) email. `sender` may be
        `"Display Name <addr>"` — delivery hardening keeps the display name
        consistent with the pretext role.

        Campaign mode: send_email(..., jitter=True) sleeps a human-paced
        random delay before relaying so a burst of identical-moment
        submissions (the classic bulk-phish signature) never hits the MX."""
        if getattr(self, "_jitter", False):
            import random
            import time as _t
            _t.sleep(random.uniform(1.0, 4.5))
        try:
            return self._transport(sender, to, subject, body, html, reply_to)
        except TypeError:
            # 4-arg injected transport (legacy tests): degrade to plain text
            return self._transport(sender, to, subject, body)

    def set_jitter(self, enabled: bool) -> None:
        """Enable human-paced send jitter for campaigns (anti-burst)."""
        self._jitter = bool(enabled)

    def send_sms(self, from_name: str, phone: str, carrier: str,
                 message: str) -> bool:
        """Reach a phone via email-to-SMS gateway. Returns False if unknown carrier."""
        addr = carrier_sms_address(phone, carrier)
        if not addr:
            return False
        return self._transport(f"{from_name} <{from_name.lower().replace(' ', '.')}@mail.com>",
                               addr, "", message)

    # -- templates ----------------------------------------------------------

    @staticmethod
    def sms_short_link(message: str, link: str, max_len: int = 160) -> str:
        body = f"{message} {link}"
        if len(body) <= max_len:
            return body
        budget = max(1, max_len - len(link) - 1)
        return f"{message[:budget]} {link}"
