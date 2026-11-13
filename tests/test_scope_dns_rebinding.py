"""Scope must resolve A AND AAAA, refuse mixed resolutions, and freeze.

The bug class: a scope gate that resolves ONE IPv4 address lets a CDN's other
addresses through, and a name that re-resolves between the check and the action
(DNS rebinding) defeats the check entirely. Resolution is mocked here so the
rule is asserted deterministically, with no live DNS.
"""
import socket
import unittest
from unittest import mock

from phantom.core import scope


def _fake_getaddrinfo(mapping):
    """A getaddrinfo stand-in returning an AF_UNSPEC-shaped result."""
    def _call(host, port, family=0, socktype=0, proto=0, flags=0):
        if host not in mapping:
            raise socket.gaierror(f"unknown host {host}")
        out = []
        for addr in mapping[host]:
            if ":" in addr:
                sockaddr = (addr, port or 0, 0, 0)
                out.append((socket.AF_INET6, socket.SOCK_STREAM, 6, "", sockaddr))
            else:
                sockaddr = (addr, port or 0)
                out.append((socket.AF_INET, socket.SOCK_STREAM, 6, "", sockaddr))
        return out
    return _call


class TestScopeResolution(unittest.TestCase):
    def setUp(self):
        scope.clear_scope_cache()

    def tearDown(self):
        scope.clear_scope_cache()

    def test_resolve_addresses_covers_ipv4_and_ipv6(self):
        mapping = {"dual.example": ["10.0.0.5", "2001:db8::1"]}
        with mock.patch.object(scope.socket, "getaddrinfo",
                               _fake_getaddrinfo(mapping)):
            addrs = scope.resolve_addresses("dual.example")
        self.assertIn("10.0.0.5", addrs)
        self.assertIn("2001:db8::1", addrs)

    def test_resolve_addresses_strips_ipv6_zone_id(self):
        mapping = {"link.example": ["fe80::1%eth0"]}
        with mock.patch.object(scope.socket, "getaddrinfo",
                               _fake_getaddrinfo(mapping)):
            addrs = scope.resolve_addresses("link.example")
        self.assertEqual(addrs, ["fe80::1"])

    def test_uniform_resolution_in_scope_is_allowed(self):
        mapping = {"cdn.example": ["10.0.0.5", "10.0.0.6"]}
        with mock.patch.object(scope.socket, "getaddrinfo",
                               _fake_getaddrinfo(mapping)):
            self.assertTrue(scope.is_in_scope("cdn.example", ["10.0.0.0/24"]))

    def test_mixed_resolution_is_refused(self):
        """One in-scope and one out-of-scope address = rebinding shape."""
        mapping = {"mix.example": ["10.0.0.5", "8.8.8.8"]}
        with mock.patch.object(scope.socket, "getaddrinfo",
                               _fake_getaddrinfo(mapping)):
            self.assertFalse(scope.is_in_scope("mix.example", ["10.0.0.0/24"]))

    def test_ipv6_only_in_scope(self):
        mapping = {"v6.example": ["2001:db8::1"]}
        with mock.patch.object(scope.socket, "getaddrinfo",
                               _fake_getaddrinfo(mapping)):
            self.assertTrue(scope.is_in_scope("v6.example", ["2001:db8::/32"]))

    def test_mixed_v4_v6_is_refused(self):
        mapping = {"dual.example": ["10.0.0.5", "2001:db8::1"]}
        with mock.patch.object(scope.socket, "getaddrinfo",
                               _fake_getaddrinfo(mapping)):
            self.assertFalse(scope.is_in_scope("dual.example",
                                               ["10.0.0.0/24"]))

    def test_unresolvable_fails_closed_but_explicit_name_wins(self):
        mapping = {}
        with mock.patch.object(scope.socket, "getaddrinfo",
                               _fake_getaddrinfo(mapping)):
            self.assertFalse(scope.is_in_scope("ghost.example",
                                               ["10.0.0.0/24"]))
            self.assertTrue(scope.is_in_scope("ghost.example",
                                              ["10.0.0.0/24",
                                               "ghost.example"]))

    def test_frozen_resolution_survives_a_rebind(self):
        """A name that passes the check, then re-resolves out of scope, stays
        authorized only by the FROZEN result — and a cleared cache re-judges."""
        in_scope = {"rebind.example": ["10.0.0.5"]}
        out_of_scope = {"rebind.example": ["8.8.8.8"]}
        with mock.patch.object(scope.socket, "getaddrinfo",
                               _fake_getaddrinfo(in_scope)):
            self.assertTrue(scope.is_in_scope("rebind.example",
                                              ["10.0.0.0/24"]))
        # the name now points somewhere else, but the answer is frozen
        with mock.patch.object(scope.socket, "getaddrinfo",
                               _fake_getaddrinfo(out_of_scope)):
            self.assertTrue(scope.is_in_scope("rebind.example",
                                              ["10.0.0.0/24"]))
        scope.clear_scope_cache()
        with mock.patch.object(scope.socket, "getaddrinfo",
                               _fake_getaddrinfo(out_of_scope)):
            self.assertFalse(scope.is_in_scope("rebind.example",
                                               ["10.0.0.0/24"]))

    def test_scope_reason_explains_rebinding(self):
        mapping = {"mix.example": ["10.0.0.5", "8.8.8.8"]}
        with mock.patch.object(scope.socket, "getaddrinfo",
                               _fake_getaddrinfo(mapping)):
            reason = scope.scope_reason("mix.example", ["10.0.0.0/24"])
        self.assertIsNotNone(reason)
        self.assertIn("MIXED", reason)

    def test_scope_reason_is_none_when_authorized(self):
        self.assertIsNone(scope.scope_reason("10.0.0.5", ["10.0.0.0/24"]))

    def test_scope_status_uses_the_strict_rule(self):
        mapping = {"mix.example": ["10.0.0.5", "8.8.8.8"]}
        with mock.patch.object(scope.socket, "getaddrinfo",
                               _fake_getaddrinfo(mapping)):
            self.assertEqual(
                scope.scope_status("mix.example", ["10.0.0.0/24"]),
                "out_of_scope")


if __name__ == "__main__":
    unittest.main()
