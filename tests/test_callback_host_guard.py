"""A listener may bind 0.0.0.0, but a payload must never dial it.

The two roles are deliberately separate: bind is local/all-interfaces,
connect is a routable address from the target's network. This guard prevents
generating an artefact that can never check in and cannot be fixed without a
rebuild.
"""

from __future__ import annotations

import os
import unittest

import phantom
from phantom.utils.builder import (
    _callback_host_error,
    compile_beacon,
    compile_remote,
    generate_dropper,
    generate_remote_dropper,
)


PKG_ROOT = os.path.dirname(os.path.abspath(phantom.__file__))


class CallbackHostGuardTests(unittest.TestCase):
    def test_wildcard_is_rejected(self):
        for host in ("0.0.0.0", "::", "[::]", " 0.0.0.0 "):
            with self.subTest(host=host):
                self.assertIn("wildcard", _callback_host_error(host).lower())

    def test_normal_hosts_are_allowed(self):
        for host in ("127.0.0.1", "c2.example.test", "203.0.113.10"):
            with self.subTest(host=host):
                self.assertEqual(_callback_host_error(host), "")

    def test_compile_beacon_refuses_wildcard(self):
        self.assertIsNone(
            compile_beacon("windows", PKG_ROOT, host="0.0.0.0", port=8443)
        )

    def test_compile_beacon_refuses_wildcard_fallback(self):
        self.assertIsNone(
            compile_beacon("windows", PKG_ROOT, host="127.0.0.1", port=8443,
                           hosts=["0.0.0.0"])
        )

    def test_compile_remote_refuses_wildcard(self):
        self.assertIsNone(
            compile_remote("windows", PKG_ROOT, host="0.0.0.0", port=8443)
        )

    def test_droppers_refuse_wildcard(self):
        self.assertEqual(
            generate_dropper("windows", "0.0.0.0", 8443, use_ssl=True), ""
        )
        self.assertEqual(
            generate_remote_dropper("windows", "0.0.0.0", 8443,
                                    use_ssl=True),
            "",
        )


if __name__ == "__main__":
    unittest.main()
