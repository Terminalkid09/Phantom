"""The token-scan gate must prove absence in a real artefact AND catch presence.

Two failure modes matter: a build that leaks the deployment token (must fail)
and a scan that is blind (would pass on anything). Both are asserted here.
"""
import importlib.util
import os
import tempfile
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRIPT = os.path.join(_ROOT, "scripts", "ci_beacon_token_scan.py")


def _load():
    spec = importlib.util.spec_from_file_location("ci_beacon_token_scan",
                                                  _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestTokenScan(unittest.TestCase):
    def setUp(self):
        self.mod = _load()
        self.token = "phantom-canary-unit-test"

    def test_generator_contract_holds(self):
        self.assertEqual(self.mod._generator_contract(self.token), 0)

    def test_a_binary_containing_the_token_fails(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(b"\x7fELF" + b"junk" + self.token.encode() + b"tail")
            path = fh.name
        try:
            self.assertEqual(self.mod._scan_artefact(path, self.token), 1)
        finally:
            os.unlink(path)

    def test_a_utf16_leak_is_detected_too(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(b"\x7fELF" + self.token.encode("utf-16-le"))
            path = fh.name
        try:
            self.assertEqual(self.mod._scan_artefact(path, self.token), 1)
        finally:
            os.unlink(path)

    def test_a_clean_binary_passes(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(b"\x7fELF" + b"\x00" * 4096)
            path = fh.name
        try:
            self.assertEqual(self.mod._scan_artefact(path, self.token), 0)
        finally:
            os.unlink(path)

    def test_a_missing_artefact_fails(self):
        self.assertEqual(self.mod._scan_artefact("/nope/missing", self.token), 1)


if __name__ == "__main__":
    unittest.main()
