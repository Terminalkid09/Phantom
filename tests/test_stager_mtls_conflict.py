"""The stager-vs-mTLS guardrail.

`c2.mtls_require_client_cert=true` (default) refuses any TLS client without a
certificate. The PowerShell PIC stager has none, so the `generate` -> paste
flow is a trap under the default: the operator is told to paste a one-liner
the listener will hang up on. Live symptom (2026-10-16, host MSI): `curl -k`
against /x returned http=000 with "schannel: recv returned error 56" and
Net.WebClient reported "Connessione sottostante chiusa" while the listener
was up and healthy. These tests pin the warning that now precedes the paste.
"""
import os
import unittest
from unittest import mock

from phantom.utils.builder import stager_mtls_conflict

STRICT_ENV = {"PHANTOM_MTLS_REQUIRE_CLIENT_CERT": "1"}
LAX_ENV = {"PHANTOM_MTLS_REQUIRE_CLIENT_CERT": "0"}


class TestStagerMtlsConflict(unittest.TestCase):

    def test_strict_mtls_on_https_windows_is_flagged(self):
        with mock.patch.dict(os.environ, STRICT_ENV, clear=False):
            msg = stager_mtls_conflict("windows", True)
        self.assertIn("mTLS", msg)
        self.assertIn("c2.mtls_require_client_cert=false", msg)
        self.assertIn("binary", msg)          # the working alternative

    def test_the_documented_opt_out_clears_the_warning(self):
        with mock.patch.dict(os.environ, LAX_ENV, clear=False):
            self.assertEqual(stager_mtls_conflict("windows", True), "")

    def test_no_warning_when_it_cannot_apply(self):
        with mock.patch.dict(os.environ, STRICT_ENV, clear=False):
            self.assertEqual(stager_mtls_conflict("windows", False), "")
            self.assertEqual(stager_mtls_conflict("linux", True), "")
            self.assertEqual(stager_mtls_conflict("android", True), "")

    def test_a_config_read_failure_warns_rather_than_stays_silent(self):
        """"I could not read the config" must not be reported as "all good" —
        the failure mode we are fixing is precisely a silent green light."""
        with mock.patch("phantom.utils.config.get_bool",
                        side_effect=RuntimeError("boom")):
            msg = stager_mtls_conflict("windows", True)
        self.assertNotEqual(msg, "")
