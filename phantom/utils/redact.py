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
"""

from __future__ import annotations

import re
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


def _is_secret_key(key: str) -> bool:
    k = str(key).lower().strip()
    if k in _SECRET_KEYS:
        return True
    # broad shape: password/otp/secret/token anywhere in the key name
    return any(s in k for s in ("password", "passwd", "pwd", "otp",
                                "secret", "token", "api_key", "apikey",
                                "master_key", "privkey", "hash", "cookie"))


def redact(obj: Any) -> Any:
    """Recursively mask values under secret-looking keys."""
    if isinstance(obj, dict):
        return {k: ("[REDACTED]" if _is_secret_key(k) else redact(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    if isinstance(obj, tuple):
        return tuple(redact(x) for x in obj)
    return obj


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


def _mask_flag(m: "re.Match") -> str:
    val = m.group("val")
    if val.isdigit():  # ssh -p 22 -> a port, not a secret
        return m.group(0)
    prefix = m.group(0)[:m.start("val") - m.start()]
    return prefix + "[REDACTED]"


def redact_text(text: Any) -> str:
    """Mask `password=x` / `token: y` / `-p <secret>` patterns inside
    free-form text (commands, task output, notes)."""
    if not isinstance(text, str):
        return "" if text is None else str(text)
    out = _TEXT_SECRET_RE.sub(_mask_key_value, text)
    return _FLAG_SECRET_RE.sub(_mask_flag, out)