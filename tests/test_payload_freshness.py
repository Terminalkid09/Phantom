"""Phase-5 tests for the NEW payload/beacon build features.

These are the guarantees a toolchain bump (or a careless edit) can silently
break, and none of them had a test:

  * FRESHNESS — every build must ship a DIFFERENT compile-time CONFIG_SEED
    (same seed = the config of any binary decrypts with any other's
    keystream), and the rewritten header must stay compilable;
  * MALLEABLE — the generated C++ header must be valid for any profile,
    including one carrying quotes/backslashes;
  * PE PARSING — the RVA->file-offset walk (the fix for the wrong-RVA bug
    in the audit) must respect section boundaries exactly;
  * REBUILD — a crypto-config change must force a rebuild, a same-config
    run must not.

Nothing here needs a compiler: these are pure-function invariants.
"""
import os
import re
import struct

import pytest

from phantom.utils import builder as B
from phantom.utils import malleable as M


# ── config seed freshness ────────────────────────────────────────────────

_SEED_RE = re.compile(r"constexpr uint64_t CONFIG_SEED = 0x([0-9A-Fa-f]+)ULL;")


def _seed_of(path) -> str:
    return _SEED_RE.search(path.read_text(encoding="utf-8")).group(1)


@pytest.fixture()
def beacon_dir(tmp_path):
    """A beacon source tree carrying the REAL config header.

    The header is GENERATED from the tracked template, the way a build does
    it: it is deliberately not tracked (.gitignore, and ci_beacon_lint fails
    if it is ever committed), so the old fixture — which copied the working
    tree's copy — only worked where a build had already run. A clean checkout
    got three FileNotFoundError ERRORs, and a clean checkout is the whole
    point of CI.
    """
    (tmp_path / "src").mkdir()
    B.write_config_encrypted(str(tmp_path))
    return tmp_path


def test_seed_rotates_on_every_build(beacon_dir):
    """Two consecutive builds must not share a keystream."""
    path = beacon_dir / "src" / "config_encrypted.h"
    B._write_config_seed(str(beacon_dir))
    first = _seed_of(path)
    B._write_config_seed(str(beacon_dir))
    second = _seed_of(path)
    assert first != second


def test_rotated_header_stays_well_formed(beacon_dir):
    """A malformed replacement would break EVERY build: the line must keep
    its exact shape, appear exactly once, and nothing else may change."""
    path = beacon_dir / "src" / "config_encrypted.h"
    before = path.read_text(encoding="utf-8")
    B._write_config_seed(str(beacon_dir))
    after = path.read_text(encoding="utf-8")

    assert len(_SEED_RE.findall(after)) == 1
    assert re.search(
        r"constexpr uint64_t CONFIG_SEED = 0x[0-9A-F]{16}ULL;", after)
    # only the seed value changed
    assert _SEED_RE.sub("SEED", before) == _SEED_RE.sub("SEED", after)


def test_seed_is_64_bit_and_not_the_placeholder(beacon_dir):
    path = beacon_dir / "src" / "config_encrypted.h"
    B._write_config_seed(str(beacon_dir))
    seed = int(_seed_of(path), 16)
    assert 0 <= seed < (1 << 64)
    assert seed != 0  # a zeroed keystream is no obfuscation at all


def test_seed_rotation_without_the_header_is_a_noop(tmp_path):
    """Missing/mutated header: the build must not crash on the seed step."""
    missing = tmp_path / "src"
    missing.mkdir()
    out = B._write_config_seed(str(tmp_path))
    assert out.endswith("config_encrypted.h")

    header = missing / "config_encrypted.h"
    header.write_text("#pragma once\n// no seed here\n", encoding="utf-8")
    B._write_config_seed(str(tmp_path))
    assert header.read_text(encoding="utf-8") == "#pragma once\n// no seed here\n"


# ── malleable profile ────────────────────────────────────────────────────

def test_default_malleable_header_is_valid(tmp_path):
    out = M.write_malleable_config(str(tmp_path))
    content = open(out, encoding="utf-8").read()
    assert "#define MALLEABLE_PROFILE_DEFINED" in content
    assert "malleable_build_profile()" in content
    assert "/api/v1/ping" in content
    assert content.count("{") == content.count("}")


def test_malleable_profile_values_are_honoured(tmp_path):
    profile = tmp_path / "prof.json"
    profile.write_text(
        '{"get_paths": ["/only/one"], "sleep_ms": 9999, "jitter": 500}',
        encoding="utf-8")
    out = M.write_malleable_config(str(tmp_path), str(profile))
    content = open(out, encoding="utf-8").read()
    assert "/only/one" in content
    assert "p.sleep_ms = 9999;" in content
    # validation clamps jitter instead of emitting an out-of-range value
    assert "p.jitter = 100;" in content


def test_malleable_escapes_quotes_and_backslashes(tmp_path):
    """A profile with a quote would otherwise produce a header that does not
    compile — the failure would surface only at build time."""
    profile = tmp_path / "prof.json"
    profile.write_text(
        r'{"extra_headers": ["X-Evil: a\"b\\c"]}', encoding="utf-8")
    out = M.write_malleable_config(str(tmp_path), str(profile))
    content = open(out, encoding="utf-8").read()
    assert '\\"b\\\\c' in content


def test_load_profile_falls_back_on_bad_types(tmp_path):
    profile = tmp_path / "prof.json"
    profile.write_text('{"get_paths": "not-a-list", "sleep_ms": "soon"}',
                       encoding="utf-8")
    loaded = M.load_profile(str(profile))
    assert loaded["get_paths"] == M.DEFAULT_PROFILE["get_paths"]
    assert loaded["sleep_ms"] == M.DEFAULT_PROFILE["sleep_ms"]
    assert loaded["sleep_ms"] >= 1000


# ── PE RVA -> file offset ────────────────────────────────────────────────

def _synthetic_pe() -> bytes:
    """Two sections with known virtual/raw addresses."""
    pe = bytearray(0x800)
    sect_hdr_off = 0x100

    def section(i, va, vsize, raw_ptr):
        off = sect_hdr_off + i * 40
        struct.pack_into("<I", pe, off + 8, vsize)     # VirtualSize
        struct.pack_into("<I", pe, off + 12, va)       # VirtualAddress
        struct.pack_into("<I", pe, off + 20, raw_ptr)  # PointerToRawData

    section(0, 0x1000, 0x200, 0x400)
    section(1, 0x2000, 0x100, 0x600)
    return bytes(pe)


def test_rva_maps_inside_a_section():
    pe = _synthetic_pe()
    assert B._rva_to_fileoff(pe, 0x1000, 0x100, 2) == 0x400
    assert B._rva_to_fileoff(pe, 0x1050, 0x100, 2) == 0x450
    assert B._rva_to_fileoff(pe, 0x2000, 0x100, 2) == 0x600


def test_rva_section_boundary_is_exact():
    """`va <= rva < va + vs`: the last byte of a section maps, the first byte
    after it does not (this is what the wrong-RVA bug got wrong)."""
    pe = _synthetic_pe()
    assert B._rva_to_fileoff(pe, 0x11FF, 0x100, 2) == 0x5FF
    assert B._rva_to_fileoff(pe, 0x1200, 0x100, 2) is None
    assert B._rva_to_fileoff(pe, 0x0FFF, 0x100, 2) is None


def test_rva_out_of_range_returns_none():
    pe = _synthetic_pe()
    assert B._rva_to_fileoff(pe, 0x900000, 0x100, 2) is None


def test_virtualalloc_rva_never_raises_on_junk(tmp_path):
    """_get_virtualalloc_rva runs against whatever kernel32 it is handed;
    a truncated or foreign file must return None, never raise."""
    junk = tmp_path / "kernel32.dll"
    junk.write_bytes(b"not a PE at all")
    assert B._get_virtualalloc_rva(str(junk)) is None

    truncated = tmp_path / "trunc.dll"
    truncated.write_bytes(b"MZ" + b"\x00" * 10)
    assert B._get_virtualalloc_rva(str(truncated)) is None

    assert B._get_virtualalloc_rva(str(tmp_path / "missing.dll")) is None


# ── rebuild triggers ─────────────────────────────────────────────────────

def test_rebuild_when_crypto_config_changes(tmp_path, monkeypatch):
    out = tmp_path / "beacon.exe"
    out.write_bytes(b"MZ")
    monkeypatch.setattr(B, "crypto_fingerprint", lambda: "fp-1")
    assert B._needs_rebuild(str(tmp_path), "beacon.exe") is True  # unmarked
    B._mark_built(str(tmp_path), "beacon.exe")
    assert B._needs_rebuild(str(tmp_path), "beacon.exe") is False  # same keys
    monkeypatch.setattr(B, "crypto_fingerprint", lambda: "fp-2")
    assert B._needs_rebuild(str(tmp_path), "beacon.exe") is True  # keys rotated


def test_rebuild_when_binary_is_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(B, "crypto_fingerprint", lambda: "fp")
    assert B._needs_rebuild(str(tmp_path), "beacon.exe") is True
