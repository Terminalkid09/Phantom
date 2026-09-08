"""Per-beacon enrollment, HMAC, and optional mTLS material.

This module manages operator-side identity material only. It does not add
beacon capabilities. Registry and private-key files are runtime artifacts and
must remain outside source control.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import shutil
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from phantom.utils.paths import certs_dir, data_dir

_REGISTRY_LOCK = threading.RLock()
_REGISTRY_ENV = "PHANTOM_BEACON_REGISTRY"


def registry_path() -> str:
    return os.getenv(
        _REGISTRY_ENV,
        os.path.join(data_dir(), "beacons", "beacon_registry.json"),
    )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read_registry() -> dict[str, Any]:
    try:
        with open(registry_path(), "r", encoding="utf-8") as handle:
            data = json.load(handle)
        if isinstance(data, dict) and isinstance(data.get("beacons"), dict):
            return data
    except (OSError, ValueError, TypeError):
        pass
    return {"version": 1, "beacons": {}}


def _secure_file(path: str, mode: int = 0o600) -> None:
    if os.name != "nt":
        try:
            os.chmod(path, mode)
        except OSError:
            pass


def _write_registry(data: dict[str, Any]) -> None:
    path = registry_path()
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".beacon-registry-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
        _secure_file(temp_path)
        os.replace(temp_path, path)
        _secure_file(path)
    finally:
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass


def _new_secret() -> bytes:
    return secrets.token_bytes(32)


def _secret_text(secret: bytes) -> str:
    return base64.urlsafe_b64encode(secret).decode("ascii").rstrip("=")


def _secret_bytes(value: str) -> Optional[bytes]:
    try:
        padded = value + "=" * (-len(value) % 4)
        secret = base64.urlsafe_b64decode(padded.encode("ascii"))
        return secret if len(secret) == 32 else None
    except (ValueError, TypeError):
        return None


def _pem_literal(value: str) -> str:
    return json.dumps(value)


def _mtls_paths(cert_directory: Optional[str] = None) -> dict[str, str]:
    directory = cert_directory or os.getenv("PHANTOM_MTLS_CERT_DIR", "").strip() or certs_dir()
    return {
        "directory": directory,
        "ca_cert": os.path.join(directory, "client_ca.crt"),
        "ca_key": os.path.join(directory, "client_ca.key"),
        "server_cert": os.path.join(directory, "mtls_server.crt"),
        "server_key": os.path.join(directory, "mtls_server.key"),
    }


def ensure_mtls_material(cert_directory: Optional[str] = None,
                         host: str = "localhost") -> dict[str, str]:
    """Create a private CA and server certificate for an mTLS listener."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    paths = _mtls_paths(cert_directory)
    os.makedirs(paths["directory"], exist_ok=True)
    if not (os.path.exists(paths["ca_cert"]) and os.path.exists(paths["ca_key"])):
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Phantom Beacon Client CA")])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name).issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        with open(paths["ca_key"], "wb") as handle:
            handle.write(ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        with open(paths["ca_cert"], "wb") as handle:
            handle.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        _secure_file(paths["ca_key"])

    if not (os.path.exists(paths["server_cert"]) and os.path.exists(paths["server_key"])):
        with open(paths["ca_key"], "rb") as handle:
            ca_key = serialization.load_pem_private_key(handle.read(), password=None)
        with open(paths["ca_cert"], "rb") as handle:
            ca_cert = x509.load_pem_x509_certificate(handle.read())
        server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        names: list[x509.GeneralName] = [x509.DNSName("localhost")]
        if host and host != "0.0.0.0":
            try:
                import ipaddress
                names.append(x509.IPAddress(ipaddress.ip_address(host)))
            except ValueError:
                names.append(x509.DNSName(host))
        server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host or "localhost")])
        server_cert = (
            x509.CertificateBuilder()
            .subject_name(server_name).issuer_name(ca_cert.subject)
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        with open(paths["server_key"], "wb") as handle:
            handle.write(server_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ))
        with open(paths["server_cert"], "wb") as handle:
            handle.write(server_cert.public_bytes(serialization.Encoding.PEM))
        _secure_file(paths["server_key"])
    return paths


def issue_client_certificate(beacon_id: str,
                             cert_directory: Optional[str] = None) -> dict[str, str]:
    """Issue a client certificate and return PEM/PFX material for one beacon."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    paths = ensure_mtls_material(cert_directory)
    with open(paths["ca_key"], "rb") as handle:
        ca_key = serialization.load_pem_private_key(handle.read(), password=None)
    with open(paths["ca_cert"], "rb") as handle:
        ca_cert = x509.load_pem_x509_certificate(handle.read())
    with open(paths["server_cert"], "rb") as handle:
        server_cert = x509.load_pem_x509_certificate(handle.read())

    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, beacon_id)])
    client_cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(ca_cert.subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=825))
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    cert_pem = client_cert.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = client_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    ca_pem = open(paths["ca_cert"], "rb").read().decode()
    pfx = pkcs12.serialize_key_and_certificates(
        beacon_id.encode(), client_key, client_cert, [ca_cert],
        serialization.NoEncryption(),
    )
    return {
        "client_cert_pem": cert_pem,
        "client_key_pem": key_pem,
        "client_ca_pem": ca_pem,
        "client_pfx_b64": base64.b64encode(pfx).decode("ascii"),
        "server_fingerprint": server_cert.fingerprint(hashes.SHA256()).hex(),
    }


def enroll_beacon(beacon_id: Optional[str] = None) -> dict[str, Any]:
    """Create and persist a new identity, returning the private secret once."""
    with _REGISTRY_LOCK:
        data = _read_registry()
        records = data.setdefault("beacons", {})
        beacon_id = beacon_id or "B-" + secrets.token_hex(8).upper()
        if beacon_id in records:
            raise ValueError(f"beacon identity already exists: {beacon_id}")
        secret = _new_secret()
        record = {
            "status": "active", "version": 1, "secret": _secret_text(secret),
            "created_at": _now(), "rotated_at": None, "revoked_at": None,
        }
        records[beacon_id] = record
        _write_registry(data)
        return {**record, "beacon_id": beacon_id, "secret": secret}


def get_beacon_record(beacon_id: str) -> Optional[dict[str, Any]]:
    with _REGISTRY_LOCK:
        record = _read_registry().get("beacons", {}).get(beacon_id)
        return dict(record) if isinstance(record, dict) else None


def get_beacon_secrets(beacon_id: str) -> list[bytes]:
    record = get_beacon_record(beacon_id)
    if not record or record.get("status") != "active":
        return []
    values: list[bytes] = []
    try:
        previous_expires = float(record.get("previous_expires_at", 0))
    except (TypeError, ValueError):
        previous_expires = 0
    for field in ("secret", "previous_secret"):
        value = record.get(field)
        if field == "previous_secret" and time.time() > previous_expires:
            continue
        if isinstance(value, str):
            secret = _secret_bytes(value)
            if secret:
                values.append(secret)
    return values


def get_beacon_secret(beacon_id: str) -> Optional[bytes]:
    values = get_beacon_secrets(beacon_id)
    return values[0] if values else None


def enroll_or_get_secret(beacon_id: str) -> Optional[bytes]:
    """Return an active secret for a beacon identity, enrolling on demand.

    Used by preflight probes and other throwaway identities that must prove
    the real check-in path (HMAC signing) without the operator enrolling
    them by hand. Returns ``None`` when the identity exists but is revoked
    or has no usable secret.
    """
    secret = get_beacon_secret(beacon_id)
    if secret:
        return secret
    try:
        identity = enroll_beacon(beacon_id)
        return identity["secret"]
    except ValueError:
        return get_beacon_secret(beacon_id)


@contextmanager
def isolated_registry():
    """Redirect the beacon registry to a throwaway temp file for one block.

    Preflight probes enroll throwaway identities; writing them into the
    operator's real registry would pollute it with probe entries. This
    context manager swaps ``PHANTOM_BEACON_REGISTRY`` for the duration of
    the block (any concurrent registry access briefly sees an empty
    registry, so a live beacon check-in during a preflight probe simply
    retries on its next poll — beacons are built for that).
    """
    with _REGISTRY_LOCK:
        original = os.environ.get(_REGISTRY_ENV)
        tmp_dir = tempfile.mkdtemp(prefix="phantom-probe-registry-")
        probe_path = os.path.join(tmp_dir, "registry.json")
        os.environ[_REGISTRY_ENV] = probe_path
    try:
        yield probe_path
    finally:
        with _REGISTRY_LOCK:
            if original is None:
                os.environ.pop(_REGISTRY_ENV, None)
            else:
                os.environ[_REGISTRY_ENV] = original
            try:
                shutil.rmtree(tmp_dir, ignore_errors=True)
            except OSError:
                pass


def rotate_beacon(beacon_id: str) -> dict[str, Any]:
    with _REGISTRY_LOCK:
        data = _read_registry()
        record = data.get("beacons", {}).get(beacon_id)
        if not isinstance(record, dict) or record.get("status") != "active":
            raise ValueError(f"active beacon identity not found: {beacon_id}")
        old_secret = _secret_bytes(str(record.get("secret", "")))
        if old_secret is None:
            raise ValueError(f"invalid stored secret for beacon: {beacon_id}")
        secret = _new_secret()
        version = int(record.get("version", 1)) + 1
        record.update({
            "previous_secret": _secret_text(old_secret),
            "previous_version": version - 1,
            "previous_expires_at": time.time() + 120,
            "secret": _secret_text(secret), "version": version, "rotated_at": _now(),
        })
        _write_registry(data)
        return {**record, "beacon_id": beacon_id, "secret": secret}


def revoke_beacon(beacon_id: str) -> bool:
    with _REGISTRY_LOCK:
        data = _read_registry()
        record = data.get("beacons", {}).get(beacon_id)
        if not isinstance(record, dict):
            return False
        record["status"] = "revoked"
        record["revoked_at"] = _now()
        _write_registry(data)
        return True


def write_beacon_auth_config(beacon_dir: str, beacon_id: Optional[str] = None) -> str:
    """Enroll an identity and write generated HMAC/mTLS C++ material."""
    identity = enroll_beacon(beacon_id)
    src_dir = os.path.join(beacon_dir, "src")
    os.makedirs(src_dir, exist_ok=True)
    path = os.path.join(src_dir, "beacon_auth.h")
    secret = identity["secret"]
    values = ", ".join(f"0x{byte:02x}" for byte in secret)
    from phantom.utils.state import use_mtls
    mtls_enabled = use_mtls()
    mtls = issue_client_certificate(identity["beacon_id"]) if mtls_enabled else None
    extra = ""
    if mtls:
        extra = f"""
#define BEACON_MTLS_ENABLED 1
#define BEACON_SERVER_FINGERPRINT \"{mtls['server_fingerprint']}\"
static const char BEACON_CLIENT_CERT_PEM[] = { _pem_literal(mtls['client_cert_pem']) };
static const char BEACON_CLIENT_KEY_PEM[] = { _pem_literal(mtls['client_key_pem']) };
static const char BEACON_CLIENT_CA_PEM[] = { _pem_literal(mtls['client_ca_pem']) };
static const unsigned char BEACON_CLIENT_PFX[] = {{ {', '.join(f'0x{b:02x}' for b in base64.b64decode(mtls['client_pfx_b64']))} }};
static const unsigned long BEACON_CLIENT_PFX_LEN = sizeof(BEACON_CLIENT_PFX);
"""
    else:
        extra = "\n#define BEACON_MTLS_ENABLED 0\n"
    content = f"""#pragma once
// Auto-generated; do not commit. Generated by Phantom enrollment.
#define BEACON_AUTH_ENABLED 1
#define BEACON_AUTH_ID \"{identity['beacon_id']}\"
#define BEACON_AUTH_VERSION {identity['version']}
static const unsigned char BEACON_AUTH_SECRET[32] = {{ {values} }};
{extra}"""
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    _secure_file(path)
    return path


def canonical_request(method: str, path: str, timestamp: str,
                      counter: str, nonce: str, body: str) -> bytes:
    return "\n".join((method.upper(), path, timestamp, counter, nonce, body)).encode()


def sign_request(secret: bytes, method: str, path: str, timestamp: str,
                 counter: str, nonce: str, body: str) -> str:
    return hmac.new(secret, canonical_request(method, path, timestamp, counter, nonce, body), hashlib.sha256).hexdigest()


def verify_request(secret: bytes, method: str, path: str, timestamp: str,
                   counter: str, nonce: str, signature: str, body: str,
                   *, now: Optional[float] = None, max_skew: int = 120) -> bool:
    try:
        timestamp_value = int(timestamp)
        counter_value = int(counter)
        current = int(time.time() if now is None else now)
        if counter_value < 0 or abs(current - timestamp_value) > max_skew:
            return False
    except (TypeError, ValueError):
        return False
    if not nonce or len(nonce) > 128 or len(signature) != 64:
        return False
    expected = sign_request(secret, method, path, timestamp, counter, nonce, body)
    return hmac.compare_digest(expected, signature.lower())
