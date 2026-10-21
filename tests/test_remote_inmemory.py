"""P0-5: remote module is delivered as a reflective PIC, not an on-disk PE."""

import os
import struct
import tempfile

from phantom.utils.builder import (
    _pe_entry_rva,
    build_remote_mem_payload,
)


def _minimal_pe(entry_rva=0x1234):
    data = bytearray(0x200)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x40)
    data[0x40:0x44] = b"PE\x00\x00"
    opt = 0x58
    struct.pack_into("<H", data, opt, 0x20B)  # PE32+
    struct.pack_into("<I", data, opt + 0x10, entry_rva)
    return bytes(data)


def test_entry_rva_parser():
    with tempfile.TemporaryDirectory() as td:
        path = os.path.join(td, "fake.exe")
        with open(path, "wb") as f:
            f.write(_minimal_pe(0xBEEF))
        assert _pe_entry_rva(path) == 0xBEEF


def test_reflective_mem_payload_patches_loader_and_xors(tmp_path):
    pkg = tmp_path
    remote = pkg / "payloads" / "remote"
    remote.mkdir(parents=True)
    exe = remote / "remote.exe"
    pe = _minimal_pe(0x4321)
    exe.write_bytes(pe)

    loader = bytearray(96)
    marker = 17
    loader[marker:marker + 4] = b"\xAA\xBB\xCC\xDD"
    loader_path = tmp_path / "loader.bin"
    loader_path.write_bytes(loader)

    out = build_remote_mem_payload(str(pkg), str(exe), str(loader_path))
    assert out
    raw = open(out, "rb").read()
    plain = bytes(octet ^ 0xAA for octet in raw)

    expected_loader = bytearray(loader)
    struct.pack_into("<Q", expected_loader, marker + 4, len(loader))
    struct.pack_into("<Q", expected_loader, marker + 12, 0x4321)
    assert len(plain) == len(loader) + len(pe)
    assert plain[:len(loader)] == bytes(expected_loader)
    assert plain[len(loader):] == pe
    assert struct.unpack_from("<Q", plain, marker + 4)[0] == len(loader)
    assert struct.unpack_from("<Q", plain, marker + 12)[0] == 0x4321
    # The PE is inside the PIC; no separate srv*.exe is produced on the target.
    assert not list(remote.glob("srv*.exe"))
