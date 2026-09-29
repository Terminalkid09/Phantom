"""The beacon hygiene linter must pass on a clean tree AND actually catch.

A linter is only worth its CI slot if it fails on the bug it exists for. These
tests run it against the real repo (it must be clean) and against a synthetic
tracked-file list (it must reject a generated header or an artefact).
"""
import importlib.util
import os
import tempfile
import unittest
from unittest import mock

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRIPT = os.path.join(_ROOT, "scripts", "ci_beacon_lint.py")


def _load():
    spec = importlib.util.spec_from_file_location("ci_beacon_lint", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestBeaconLint(unittest.TestCase):
    def setUp(self):
        self.mod = _load()

    def test_the_repo_is_clean(self):
        self.assertEqual(self.mod.main(), 0)

    def test_a_tracked_generated_header_is_rejected(self):
        tracked = "phantom/payloads/beacon/src/c2_config.h\n"
        with mock.patch.object(self.mod, "_git", return_value=tracked):
            self.assertEqual(self.mod.check_generated_not_tracked(), 1)

    def test_a_tracked_artefact_is_rejected(self):
        tracked = "phantom/payloads/beacon/syscalls.o\n"
        with mock.patch.object(self.mod, "_git", return_value=tracked):
            self.assertEqual(self.mod.check_generated_not_tracked(), 1)

    def test_a_secret_literal_in_tracked_source_is_rejected(self):
        tracked = "phantom/payloads/beacon/src/leaky.h\n"
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "phantom", "payloads", "beacon", "src")
            os.makedirs(src)
            with open(os.path.join(src, "leaky.h"), "w",
                      encoding="utf-8") as handle:
                handle.write('#define C2_PAYLOAD_TOKEN "deadbeef"\n')
            with mock.patch.object(self.mod, "_git", return_value=tracked), \
                    mock.patch.object(self.mod, "ROOT", tmp):
                self.assertEqual(self.mod.check_no_tracked_secrets(), 1)

    def test_an_empty_secret_literal_is_allowed(self):
        tracked = "phantom/payloads/beacon/src/ok.h\n"
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "phantom", "payloads", "beacon", "src")
            os.makedirs(src)
            with open(os.path.join(src, "ok.h"), "w", encoding="utf-8") as fh:
                fh.write('#define C2_PAYLOAD_TOKEN ""\n')
            with mock.patch.object(self.mod, "_git", return_value=tracked), \
                    mock.patch.object(self.mod, "ROOT", tmp):
                self.assertEqual(self.mod.check_no_tracked_secrets(), 0)


if __name__ == "__main__":
    unittest.main()
