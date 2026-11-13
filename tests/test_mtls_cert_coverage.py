"""The served mTLS certificate must name the host clients dial.

Live defect 2026-10-16: the beacon pinned ``data/certs/mtls_server.crt`` (pin
matched), connected to ``https://127.0.0.1:9443``, and NO HTTP request ever
reached the listener. The certificate had been generated for host
``0.0.0.0`` (CN 0.0.0.0, SAN: ``DNS:localhost`` only) and
``ensure_mtls_material`` reused it forever, so schannel (WinHTTP) verified the
SAN against the URL host and aborted the handshake client-side — the listener
only saw a connection that died mid-TLS. These tests pin the reuse rule:
reuse only when the existing certificate still covers the requested host,
regenerate from the SAME CA when it does not, and never rotate on bind-all.
"""
import hashlib
import os
import tempfile
import unittest

from phantom.utils.beacon_auth import (ensure_mtls_material,
                                       server_cert_covers_host)


def _sha(path: str) -> str:
    with open(path, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


class TestServerCertCoverage(unittest.TestCase):

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="phantom_mtls_")
        self.addCleanup(self._tmp.cleanup)
        self.tmp = self._tmp.name

    def test_cert_generated_for_a_host_covers_it(self):
        paths = ensure_mtls_material(self.tmp, "127.0.0.1")
        self.assertTrue(server_cert_covers_host(paths["server_cert"], "127.0.0.1"))
        # the historical contract: localhost is always a SAN
        self.assertTrue(server_cert_covers_host(paths["server_cert"], "localhost"))

    def test_reuse_is_safe_when_covered(self):
        paths = ensure_mtls_material(self.tmp, "127.0.0.1")
        before = _sha(paths["server_cert"])
        paths2 = ensure_mtls_material(self.tmp, "127.0.0.1")
        self.assertEqual(before, _sha(paths2["server_cert"]),
                         "a covered certificate must NOT rotate (every "
                         "deployed beacon pins it and would die)")

    def test_host_change_regenerates_but_keeps_the_ca(self):
        paths = ensure_mtls_material(self.tmp, "127.0.0.1")
        ca_before, cert_before = _sha(paths["ca_cert"]), _sha(paths["server_cert"])
        paths2 = ensure_mtls_material(self.tmp, "192.168.1.50")
        self.assertNotEqual(cert_before, _sha(paths2["server_cert"]))
        self.assertEqual(ca_before, _sha(paths2["ca_cert"]),
                         "the CA must survive: issued client certificates "
                         "stay valid across a server-certificate rotation")
        self.assertTrue(server_cert_covers_host(paths2["server_cert"],
                                                "192.168.1.50"))
        self.assertTrue(server_cert_covers_host(paths2["server_cert"],
                                                "localhost"))

    def test_the_live_defect_shape_regenerates(self):
        """host=0.0.0.0 (bind all) then a 127.0.0.1 dial: the reopened cert
        must cover the loopback address the beacon actually dials."""
        stale = ensure_mtls_material(self.tmp, "0.0.0.0")
        self.assertTrue(server_cert_covers_host(stale["server_cert"],
                                                "localhost"))
        self.assertFalse(server_cert_covers_host(stale["server_cert"],
                                                 "127.0.0.1"))
        fixed = ensure_mtls_material(self.tmp, "127.0.0.1")
        self.assertTrue(server_cert_covers_host(fixed["server_cert"],
                                                "127.0.0.1"))

    def test_bind_all_reuse_never_rotates(self):
        paths = ensure_mtls_material(self.tmp, "0.0.0.0")
        before = _sha(paths["server_cert"])
        ensure_mtls_material(self.tmp, "0.0.0.0")
        self.assertEqual(before, _sha(paths["server_cert"]),
                         "0.0.0.0 says nothing about the dial name: it must "
                         "not rotate the material")

    def test_dns_host_name(self):
        paths = ensure_mtls_material(self.tmp, "c2.lab.local")
        self.assertTrue(server_cert_covers_host(paths["server_cert"],
                                                "c2.lab.local"))
        self.assertFalse(server_cert_covers_host(paths["server_cert"],
                                                 "other.lab.local"))

    def test_unreadable_or_absent_cert_is_not_covered(self):
        self.assertFalse(server_cert_covers_host(
            os.path.join(self.tmp, "missing.crt"), "localhost"))


if __name__ == "__main__":
    unittest.main()
