"""redact.py — secret redaction for client-facing surfaces.

Harvested credentials (password / OTP / session tokens) are legitimate
FINDINGS in a red-team engagement — the planner needs them to pivot — but
they must never leak into the sanitized client report, the Electron event
stream or any audit trail that can be shared. This module masks values
whose keys look like secrets while leaving the FINDING itself intact
(kind + key + confidence + source stay visible, so the operator knows a
credential was found without the value being dumped).

Applied at the serialization boundary (reports, API stream), never inside
the WorldModel, so the kill chain keeps working on the real values.

P1-10 adds the non-persistible `Secret` type: capture code wraps raw
credentials in it, and every serializable boundary (json, logs, reports)
renders only the mask — the value survives solely in memory and only an
explicit `reveal()` on a live operator surface can show it.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from typing import Any

_SECRET_KEYS = {
    "password", "pass", "pwd", "passwd",
    "otp", "totp", "mfa", "2fa",
    "secret", "secret_key",
    "token", "access_token", "refresh_token", "api_token",
    "api_key", "apikey", "apikey", "client_secret",
    "master_key", "session_key", "private_key", "privkey",
    "cookie", "sessionid", "auth",
    "nt_hash", "ntlm_hash", "lm_hash", "hash", "kerberoast", "dcsync",
    "credential", "creds", "plaintext",
}

_SECRET_KEY_RE = re.compile(r"^(?:[a-z0-9_]*[_-])?(?:%s)$" % "|".join(
    re.escape(k) for k in sorted(_SECRET_KEYS, key=len, reverse=True)), re.I)


# Credential-bearing FINDING kinds. A `found` event carries its value
# summary under "<kind>:<key>" (e.g. "creds:ssh", "ad_creds:administrator"),
# so the key part is just a service/account name and the KIND is the only
# signal that the value is a credential. Without this list a harvested
# password travelled to the UI stream and to the LLM advisor under a key
# that looked innocent ("ssh", "administrator").
_CREDENTIAL_FINDING_KINDS = {
    "creds", "cred", "creds_found", "ad_creds", "cloud_creds",
    "stolen_cookies", "cdp_cookies", "kerberoast", "dcsync", "cracked",
    "hash", "password", "shadow", "otp", "token",
}


def _is_secret_key(key: str) -> bool:
    k = str(key).lower().strip()
    if k in _SECRET_KEYS:
        return True
    # prefixed/suffixed variants: api_key, client_secret, nt_hash, aws_token …
    if _SECRET_KEY_RE.match(k):
        return True
    # finding-shaped key "<kind>:<key>": the KIND decides, never the key part
    if k.split(":", 1)[0] in _CREDENTIAL_FINDING_KINDS:
        return True
    # Provider / credential keys named by their provider: `shodan_key`,
    # `virustotal_key`, `hibp_key`, `aws_access_key`, `google_api_key` … The
    # fixed list above only caught `api_key`/`apikey`, so an API key stored
    # under a provider name travelled to reports / UI / the LLM unredacted.
    # A false positive here only hides a value the report did not need.
    if k == "key" or k.endswith(("_key", "-key", ".key")):
        return True
    # broad shape: password/otp/secret/token anywhere in the key name
    return any(s in k for s in ("password", "passwd", "pwd", "otp",
                                "secret", "token", "api_key", "apikey",
                                "master_key", "privkey", "hash", "cookie"))


def redact(obj: Any) -> Any:
    """Recursively mask values under secret-looking keys."""
    if isinstance(obj, Secret):
        return _MASK_JSON
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k == "cookies" and isinstance(v, list):
                # stolen-cookie jar: keep the LIST structure (the
                # operator must see which sessions exist) while the
                # per-entry rule below masks each live value. Without
                # this carve-out the substring rule ("cookie" in
                # "cookies") would nuke the whole jar into one mask.
                out[k] = [redact(x) for x in v]
            elif _is_secret_key(k):
                out[k] = "[REDACTED]"
            elif k == "value" and _is_cookie_entry(obj):
                # stolen-cookie entry {host,name,path,value}: the VALUE
                # is a live session — mask it, keep host/name for ops
                out[k] = "[REDACTED]"
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    if isinstance(obj, tuple):
        return tuple(redact(x) for x in obj)
    return obj


def _is_cookie_entry(d: dict) -> bool:
    """Cookie-entry shape from the stealer chain ({host,name,path,value}).
    Precise on purpose: generic {"name":..., "value":...} pairs elsewhere
    are untouched."""
    keys = set(d.keys())
    return "value" in keys and "host" in keys and "name" in keys


_TEXT_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|otp|totp|secret|token|api[_-]?key|"
    r"master[_-]?key|priv(?:ate)?[_-]?key|client[_-]?secret)"
    r"\s*[=:]\s*[^\s,;\"']+")

# `sshpass -p Sup3rS3cret`, `mysql -pSecret`, `--password=...` in commands.
# `-p` is ambiguous (ssh -p 22 is a PORT), so the substitution only fires
# when the value is NOT purely numeric.
_FLAG_SECRET_RE = re.compile(
    r"(?:^|\s)(?:-p|--password|--pass|--secret|--token)"
    r"(?:\s|=)(?P<val>[^\s\"']+)")


def _mask_key_value(m: "re.Match") -> str:
    head = m.group(0)
    key = head.split("=", 1)[0].split(":", 1)[0]
    return key + "=[REDACTED]"


# ── Secret: the non-persistible credential type (P1-10) ────────────────────

@dataclass(frozen=True)
class Secret:
    """A raw credential that must never cross a persistence boundary.

    Every generic serialization renders the MASK (repr, str, json default
    handler), so a Secret that reaches a report / audit / log / export by
    accident is still inert. The plaintext exists only in memory and is
    readable via `reveal()` — used exclusively by live operator surfaces.
    """
    value: str

    def __repr__(self) -> str:  # logs, tracebacks, f-strings with !r
        return "Secret([REDACTED])"

    def __str__(self) -> str:   # f-strings, str(), format()
        return "[REDACTED]"

    def reveal(self) -> str:
        """Explicit unwrap — live operator surfaces ONLY."""
        return self.value


_MASK_JSON = "[REDACTED]"


def _json_default(obj: Any) -> Any:
    """`json.dumps(..., default=_json_default)` renders Secrets as the mask
    instead of raising, so a persisted dump can never crash OR leak."""
    if isinstance(obj, Secret):
        return _MASK_JSON
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def safe_dumps(obj: Any, **kw: Any) -> str:
    """json.dumps with the Secret-safe default handler."""
    return json.dumps(obj, default=_json_default, **kw)


def unwrap(value: Any) -> Any:
    """Reveal one value if it is a Secret, pass anything else through."""
    return value.reveal() if isinstance(value, Secret) else value


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# Long base64-shaped runs (>=24 chars of the b64 alphabet). Real secrets
# carry high entropy; long code identifiers usually do not — the entropy
# floor keeps us from redacting ordinary long words.
_RX_B64 = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")
_B64_ENTROPY_FLOOR = 4.5   # truffleHog's classic base64 threshold

# JWTs: the header segment always starts with `eyJ` (base64 of `{"`) and
# the structured payload pushes char-entropy BELOW the b64 floor, so the
# generic rule misses them — the shape rule catches the whole token.
_RX_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]+)*\b")


def _mask_b64(m: "re.Match") -> str:
    tok = m.group(0)
    if _shannon(tok) >= _B64_ENTROPY_FLOOR:
        return "<base64>"
    return tok


def _mask_flag(m: "re.Match") -> str:
    val = m.group("val")
    if val.isdigit():  # ssh -p 22 -> a port, not a secret
        return m.group(0)
    prefix = m.group(0)[:m.start("val") - m.start()]
    return prefix + "[REDACTED]"


def redact_text(text: Any) -> str:
    """Mask `password=x` / `token: y` / `-p <secret>` patterns inside
    free-form text (commands, task output, notes), plus high-entropy
    base64-shaped blobs (P1-9 v2: adversarial canaries, JWT-style tokens,
    encoded credentials inside JSON/YAML blobs)."""
    if not isinstance(text, str):
        return "" if text is None else str(text)
    out = _TEXT_SECRET_RE.sub(_mask_key_value, text)
    out = _RX_JWT.sub("<jwt>", out)
    out = _RX_B64.sub(_mask_b64, out)
    return _FLAG_SECRET_RE.sub(_mask_flag, out)