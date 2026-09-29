"""The release-path beacon smoke test must FAIL loudly on a bad artefact.

The CI step is only worth having if the script refuses a missing, tiny or
non-ELF binary — a smoke test that passes on garbage is worse than none.

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

    def test_a_real_elf_passes(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as fh:
            fh.write(b"\x7fELF" + b"\x00" * 5000)
            path = fh.name
        try:
            with mock.patch("phantom.utils.builder.compile_beacon",
                            return_value=path):
                self.assertEqual(self._run(*_LINUX), 0)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
