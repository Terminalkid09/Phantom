"""Beacon transport — the endpoint ladder, the proxy posture, the pin.

Three layers, matching what can actually be verified where:

    generated config   `c2_config.h` really carries C2_HOSTS / C2_PROXY, and
                       a malformed endpoint is DROPPED rather than escaped
    resolution         PHANTOM_C2_FALLBACK / PHANTOM_C2_PROXY (and the config
                       keys) feed the build
    source invariants  the C++ that cannot run in this test process: the
                       proxy posture, the ladder wiring, the pin gate. These
                       are guards against silent regressions, not assertions
                       of runtime behaviour — the runtime behaviour of the
                       ladder/proxy parser is proven by
                       `phantom/payloads/beacon/src/test_transport.cpp`,
                       which is compiled and RUN (see docs/ROADMAP.md).

The bug class this file exists for: a beacon compiled with one endpoint and
`WINHTTP_ACCESS_TYPE_NO_PROXY` is unreachable from any managed network, and
nothing in a green test suite would have noticed.
"""

import os
import re
import unittest

from phantom.utils.c2_crypto import (
    _c2_literal,
    beacon_config_endpoint,
    server_cert_fingerprint,
    write_beacon_c2_config,
)
from phantom.utils.network import beacon_pin, get_c2_fallbacks, get_c2_proxy

BEACON_SRC = os.path.join("phantom", "payloads", "beacon", "src")
NETWORK_H = os.path.join(BEACON_SRC, "network.h")
MAIN_CPP = os.path.join(BEACON_SRC, "main.cpp")


def _read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _strip_cpp_comments(text):
    """Code only, no prose.

    The guards below assert that a LEGACY API is absent; a comment that
    explains *why* it was removed must not trip them (and, symmetrically, a
    mention in prose must not be mistaken for a call site).
    """
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


class TestGeneratedConfig(unittest.TestCase):

    def _write(self, **kw):
        import tempfile
        tmp = tempfile.mkdtemp(prefix="c2cfg_")
        path = write_beacon_c2_config(tmp, **kw)
        return _read(path)

    def test_the_ladder_and_proxy_land_in_the_header(self):
        text = self._write(host="c2.example.com", port=443,
                           hosts=["backup.example.net"],
                           proxy="http://proxy.corp.local:3128")
        self.assertIn('#define C2_HOST "c2.example.com"', text)
        self.assertIn('#define C2_HOSTS "backup.example.net"', text)
        self.assertIn('#define C2_PORT 443', text)
        self.assertIn('#define C2_PROXY "http://proxy.corp.local:3128"', text)

    def test_an_empty_ladder_and_an_empty_proxy_are_valid(self):
        text = self._write(host="c2.example.com", port=8443)
        self.assertIn('#define C2_HOSTS ""', text)
        self.assertIn('#define C2_PROXY ""', text)

    def test_the_primary_is_never_repeated_in_the_ladder(self):
        text = self._write(host="c2.example.com", port=443,
                           hosts=["c2.example.com", "c2.example.com",
                                  "backup.example.net"])
        self.assertIn('#define C2_HOSTS "backup.example.net"', text)

    def test_a_malformed_endpoint_is_dropped_not_escaped(self):
        """A mangled C2 host is worse than a missing fallback: the beacon
        would dial something the operator never typed."""
        text = self._write(host="c2.example.com", port=443,
                           hosts=['bad"quote', "bad,comma", "bad host",
                                  "bad\\slash", "good.example.net"])
        self.assertIn('#define C2_HOSTS "good.example.net"', text)
        for bad in ("bad\"quote", "bad,comma", "bad host", "bad\\slash"):
            self.assertNotIn(bad, text)

    def test_a_hostile_primary_falls_back_to_loopback(self):
        text = self._write(host='evil"host', port=443)
        self.assertIn('#define C2_HOST "127.0.0.1"', text)

    def test_the_literal_sanitizer_keeps_legitimate_forms(self):
        self.assertEqual(_c2_literal("c2.example.com"), "c2.example.com")
        self.assertEqual(_c2_literal("  c2.example.com  "), "c2.example.com")
        self.assertEqual(_c2_literal('"c2.example.com"'), "c2.example.com")
        self.assertEqual(_c2_literal("[2001:db8::1]"), "[2001:db8::1]")
        self.assertEqual(_c2_literal("10.0.0.5"), "10.0.0.5")
        for bad in ('a"b', "a,b", "a b", "a\\b", "a\tb", "", "   "):
            self.assertEqual(_c2_literal(bad), "", bad)


class TestPinnedPeer(unittest.TestCase):
    """TLS without a pin completes a handshake with ANY server.

    The runtime verifier (`verify_server_pin` / `CryptHashCertificate`) was
    already pin-first; what was missing is a pin in a NON-mTLS build — the
    define was emitted only on the mTLS path, so in every ordinary build the
    verifier was unreachable code and the peer was unauthenticated.
    """

    def _self_signed(self, tmp, cn="phantom-c2.local"):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        cert = (x509.CertificateBuilder()
                .subject_name(name).issuer_name(name)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.utcnow()
                                  - datetime.timedelta(days=1))
                .not_valid_after(datetime.datetime.utcnow()
                                 + datetime.timedelta(days=1))
                .sign(key, hashes.SHA256()))
        path = os.path.join(tmp, "server.crt")
        with open(path, "wb") as handle:
            handle.write(cert.public_bytes(serialization.Encoding.PEM))
        return path, cert.fingerprint(hashes.SHA256()).hex()

    def test_the_pin_digest_matches_the_certificate(self):
        """SHA-256 over DER — the exact value the C++ verifier compares."""
        import tempfile
        path, expected = self._self_signed(tempfile.mkdtemp(prefix="pin_"))
        self.assertEqual(server_cert_fingerprint(path), expected)

    def test_no_certificate_means_no_pin(self):
        self.assertEqual(server_cert_fingerprint("does/not/exist.crt"), "")

    def test_the_build_embeds_the_pin(self):
        import tempfile
        path, expected = self._self_signed(tempfile.mkdtemp(prefix="pin_"))
        pin = server_cert_fingerprint(path)
        tmp = tempfile.mkdtemp(prefix="c2cfg_")
        text = _read(write_beacon_c2_config(tmp, host="c2.example.com", port=443,
                                            pin=pin))
        self.assertIn(f'#define BEACON_SERVER_FINGERPRINT "{expected}"', text)

    def test_a_build_without_a_certificate_has_no_pin_define(self):
        import tempfile
        tmp = tempfile.mkdtemp(prefix="c2cfg_")
        text = _read(write_beacon_c2_config(tmp, host="c2.example.com", port=443))
        self.assertNotIn("BEACON_SERVER_FINGERPRINT", text)

    def test_a_non_digest_pin_is_dropped_not_embedded(self):
        """A pin is a digest or nothing: an arbitrary string would both escape
        the literal and pin a peer nobody can verify."""
        import tempfile
        tmp = tempfile.mkdtemp(prefix="c2cfg_")
        for bad in ('abc"def', "not-a-digest", "z" * 64):
            text = _read(write_beacon_c2_config(
                tmp, host="c2.example.com", port=443, pin=bad))
            self.assertNotIn("BEACON_SERVER_FINGERPRINT", text, bad)
        good = "a" * 64
        text = _read(write_beacon_c2_config(
            tmp, host="c2.example.com", port=443, pin=good.upper()))
        self.assertIn(f'#define BEACON_SERVER_FINGERPRINT "{good}"', text)

    def test_the_rebuild_decision_reads_the_embedded_endpoint(self):
        """The callers compared the whole rendered header to decide a rebuild,
        which ALWAYS differed (ladder/proxy/pin are added by the builder) → a
        forced full recompile on every build. The decision must be about the
        endpoint in the binary."""
        import tempfile
        tmp = tempfile.mkdtemp(prefix="c2cfg_")
        beacon_dir = os.path.join(tmp, "beacon")
        self.assertIsNone(beacon_config_endpoint(beacon_dir))
        write_beacon_c2_config(beacon_dir, host="c2.example.com", port=443,
                               hosts=["backup.example.net"],
                               proxy="http://proxy:3128", pin="a" * 64)
        self.assertEqual(beacon_config_endpoint(beacon_dir),
                         ("c2.example.com", 443))
        # a different ladder/proxy/pin must NOT look like an endpoint change
        write_beacon_c2_config(beacon_dir, host="c2.example.com", port=443)
        self.assertEqual(beacon_config_endpoint(beacon_dir),
                         ("c2.example.com", 443))
        write_beacon_c2_config(beacon_dir, host="other.example.com", port=443)
        self.assertEqual(beacon_config_endpoint(beacon_dir),
                         ("other.example.com", 443))

    def test_pinning_can_be_turned_off_deliberately(self):
        """Regenerating the C2 certificate invalidates every deployed beacon:
        correct behaviour, but it must be a decision, not a surprise."""
        saved = os.environ.get("PHANTOM_BEACON_PIN")
        try:
            os.environ["PHANTOM_BEACON_PIN"] = "0"
            self.assertEqual(beacon_pin(), "")
        finally:
            if saved is None:
                os.environ.pop("PHANTOM_BEACON_PIN", None)
            else:
                os.environ["PHANTOM_BEACON_PIN"] = saved


class TestResolution(unittest.TestCase):

    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in
                       ("PHANTOM_C2_FALLBACK", "PHANTOM_C2_PROXY")}

    def tearDown(self):
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def test_fallbacks_come_from_the_environment(self):
        os.environ["PHANTOM_C2_FALLBACK"] = "b.example, c.example , b.example"
        self.assertEqual(get_c2_fallbacks(), ["b.example", "c.example"])

    def test_no_fallbacks_configured_is_an_empty_ladder(self):
        os.environ.pop("PHANTOM_C2_FALLBACK", None)
        self.assertEqual(get_c2_fallbacks(), [])

    def test_the_proxy_comes_from_the_environment(self):
        os.environ["PHANTOM_C2_PROXY"] = "http://proxy.corp.local:3128"
        self.assertEqual(get_c2_proxy(), "http://proxy.corp.local:3128")

    def test_the_default_proxy_posture_is_the_endpoint_system_proxy(self):
        """Empty means \"follow the endpoint's own configuration\": that is the
        only posture that works unconfigured (PAC/WPAD, http_proxy)."""
        os.environ.pop("PHANTOM_C2_PROXY", None)
        self.assertEqual(get_c2_proxy(), "")


class TestBuilderPlumbing(unittest.TestCase):

    def test_compile_beacon_carries_hosts_and_proxy(self):
        src = _read(os.path.join("phantom", "utils", "builder.py"))
        self.assertIn("hosts: Optional[List[str]] = None", src)
        self.assertIn("proxy: str = \"\"", src)
        self.assertIn("hosts=list(hosts or [])", src)
        self.assertIn("proxy=proxy or \"\"", src)

    def test_compile_beacon_resolves_from_the_environment(self):
        src = _read(os.path.join("phantom", "utils", "builder.py"))
        self.assertIn("get_c2_fallbacks", src)
        self.assertIn("get_c2_proxy", src)


class TestCppInvariants(unittest.TestCase):
    """Guards for the C++ paths a Python test process cannot execute."""

    def setUp(self):
        self.network = _read(NETWORK_H)
        self.main = _read(MAIN_CPP)
        # the negatives run against code, never against comments
        self.network_code = _strip_cpp_comments(self.network)
        self.main_code = _strip_cpp_comments(self.main)

    def test_the_windows_session_is_proxy_aware(self):
        self.assertIn("WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY", self.network)
        self.assertIn("WINHTTP_OPTION_PROXY", self.network)
        self.assertNotIn("WINHTTP_ACCESS_TYPE_NO_PROXY", self.network_code)

    def test_the_posix_path_tunnels_through_a_proxy(self):
        self.assertIn("inline bool proxy_tunnel", self.network)
        self.assertIn("CONNECT ", self.network)
        self.assertIn("proxy_from_env", self.network)
        self.assertIn("proxy_bypassed", self.network)

    def test_the_posix_path_is_ipv6_capable(self):
        """The legacy resolver was IPv4-only: an IPv6 or dual-stack C2 was
        unreachable."""
        self.assertIn("inline int dial_tcp", self.network)
        self.assertIn("getaddrinfo", self.network)
        self.assertIn("AF_UNSPEC", self.network)
        self.assertNotIn("gethostbyname", self.network_code)

    def test_no_beacon_source_resolves_ipv4_only(self):
        """Same class of bug, every TU: the CDP pivot dials a host it
        discovered, so it must not be IPv4-only either."""
        pivot = _strip_cpp_comments(
            _read(os.path.join(BEACON_SRC, "cdp_pivot.h")))
        self.assertNotIn("gethostbyname", pivot)
        self.assertIn("getaddrinfo", pivot)
        self.assertIn("AF_UNSPEC", pivot)

    def test_macos_sets_the_proxy_explicitly(self):
        self.assertIn("CURLOPT_PROXY", self.network)

    def test_the_pin_is_enforced_independently_of_mtls(self):
        self.assertIn("BEACON_PIN_ENFORCED", self.network)
        # the pin block is gated on the fingerprint, not on mTLS
        pin_block = self.network.split("BEACON_PIN_ENFORCED", 2)[2]
        self.assertIn("BEACON_SERVER_FINGERPRINT", pin_block)
        self.assertIn("SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, "
                      "verify_server_pin)", self.network)

    def test_pin_verification_cannot_be_skipped_by_a_self_signed_cert(self):
        """The old callback returned 0 whenever the chain check failed, so
        against a self-signed C2 the pin was NEVER reached."""
        callback = self.network.split("inline int verify_server_pin", 1)[1]
        callback = callback.split("\n}", 1)[0]
        self.assertIn("(void)preverify_ok;", callback)
        self.assertIn("depth", callback)

    def test_the_beacon_seeds_the_ladder_and_the_proxy(self):
        self.assertIn("cfg.seed_ladder(C2_HOST, C2_HOSTS)", self.main)
        self.assertIn("cfg.proxy = C2_PROXY", self.main)

    def test_an_argv_host_does_not_discard_the_ladder(self):
        self.assertIn("cfg.prefer_endpoint(host_str)", self.main)
        self.assertNotIn("cfg.host = host_str", self.main_code)

    def test_the_checkin_loop_rotates_endpoints_on_failure(self):
        self.assertIn("cfg.on_failure()", self.main)
        self.assertIn("cfg.on_success()", self.main)

    def test_the_rotating_hook_drops_cached_connection_state(self):
        """A stale WinHTTP session still points at the OLD endpoint."""
        block = self.main.split("if (cfg.on_failure())", 1)[1].split("}", 1)[0]
        self.assertIn("g_ctx.cleanup()", block)

    def test_the_transport_harness_exists(self):
        """The ladder/proxy logic is proven by running this TU, so it must
        stay in the tree and stay self-contained."""
        path = os.path.join(BEACON_SRC, "test_transport.cpp")
        self.assertTrue(os.path.exists(path))
        text = _read(path)
        self.assertIn("#include \"network.h\"", text)
        self.assertIn("__has_include(\"c2_config.h\")", text)


if __name__ == "__main__":
    unittest.main()
