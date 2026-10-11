"""The release-path beacon smoke test must FAIL loudly on a bad artefact.

The CI step is only worth having if the script refuses a missing, tiny or
non-ELF binary — a smoke test that passes on garbage is worse than none. It
must also refuse an ELF of the WRONG ARCHITECTURE: the Android job exists to
prove an aarch64 payload was produced, and an x86-64 build of the same source
is still \x7fELF.

The toolchain probe is mocked so these assertions stay about artefact
validation and pass on any runner, and ``main`` is driven with an explicit
argv instead of the pytest process's own ``sys.argv``.
"""
import importlib.util
import os
import tempfile
import unittest
from unittest import mock

_SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "scripts", "ci_beacon_smoke.py")

_LINUX = ["--platform", "linux"]
_ANDROID = ["--platform", "android"]


def _elf(machine: int, *, ei_class: int = 2, ei_data: int = 1,
         body: int = 5000) -> bytes:
    """A minimal ELF64 header for ``machine``, padded to a plausible size."""
    ident = b"\x7fELF" + bytes([ei_class, ei_data, 1, 0]) + b"\x00" * 8
    header = ident + b"\x02\x00" + machine.to_bytes(2, "little")
    assert len(header) == 20, len(header)
    return header + b"\x00" * body


X86_64, AARCH64 = 0x3E, 0xB7


def _load():
    spec = importlib.util.spec_from_file_location("ci_beacon_smoke", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestBeaconSmoke(unittest.TestCase):
    def setUp(self):
        self.mod = _load()

    def _run(self, *argv):
        ready = mock.patch.object(self.mod, "_toolchain_ready",
                                  return_value=(True, ""))
        with ready:
            return self.mod.main(list(argv))

    def test_missing_artefact_fails(self):
        with mock.patch("phantom.utils.builder.compile_beacon",
                        return_value=None):
            self.assertEqual(self._run(*_LINUX), 1)

    def test_non_elf_fails(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fh:
            fh.write(b"NOT-AN-ELF" + b"x" * 4096)
            path = fh.name
        try:
            with mock.patch("phantom.utils.builder.compile_beacon",
                            return_value=path):
                self.assertEqual(self._run(*_LINUX), 1)
        finally:
            os.unlink(path)

    def _artefact(self, blob: bytes) -> str:
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fh:
            fh.write(blob)
            return fh.name

    def _verdict(self, blob: bytes, *argv) -> int:
        path = self._artefact(blob)
        try:
            with mock.patch("phantom.utils.builder.compile_beacon",
                            return_value=path):
                return self._run(*argv)
        finally:
            os.unlink(path)

    def test_a_real_elf_passes(self):
        self.assertEqual(self._verdict(_elf(X86_64), *_LINUX), 0)

    def test_an_elf_with_no_architecture_is_refused_for_linux(self):
        """The header the old test wrote: ELFmagic and five thousand zeroes.

        e_machine 0 means "no architecture", i.e. no toolchain that built
        anything real — which is exactly the artefact a smoke test that only
        looked at the magic would wave through.
        """
        zero_machine = b"\x7fELF" + b"\x00" * 5000
        self.assertEqual(self._verdict(zero_machine, *_LINUX), 1)

    def test_an_aarch64_elf_passes_for_android(self):
        self.assertEqual(self._verdict(_elf(AARCH64), *_ANDROID), 0)

    def test_an_x86_64_elf_fails_for_android(self):
        """The point of the Android job: ARM64, not merely "an ELF"."""
        self.assertEqual(self._verdict(_elf(X86_64), *_ANDROID), 1)

    def test_a_32_bit_elf_fails_for_android(self):
        self.assertEqual(
            self._verdict(_elf(AARCH64, ei_class=1), *_ANDROID), 1)


if __name__ == "__main__":
    unittest.main()
