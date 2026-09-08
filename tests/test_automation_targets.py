"""Tests for target auto-classification (ip/domain/url/email/username/phone)."""
import unittest

from phantom.automation.guidance.targets import (
    classify_target,
    target_host,
    is_identity_target,
    is_network_target,
)


class TestClassifyTarget(unittest.TestCase):

    def test_ipv4(self):
        self.assertEqual(classify_target("192.168.1.1"), "ip")
        self.assertEqual(classify_target("10.0.0.5"), "ip")

    def test_ipv6(self):
        self.assertEqual(classify_target("2001:db8::1"), "ip")

    def test_domain(self):
        self.assertEqual(classify_target("example.com"), "domain")
        self.assertEqual(classify_target("sub.example.co.uk"), "domain")

    def test_url(self):
        self.assertEqual(classify_target("https://example.com"), "url")
        self.assertEqual(classify_target("http://192.168.1.1/admin"), "url")

    def test_email(self):
        self.assertEqual(classify_target("bob@corp.com"), "email")
        self.assertEqual(classify_target("first.last@mail.example.org"), "email")

    def test_phone_intl(self):
        self.assertEqual(classify_target("+391234567890"), "phone")
        self.assertEqual(classify_target("+1-555-123-4567"), "phone")

    def test_phone_plain(self):
        self.assertEqual(classify_target("15551234567"), "phone")

    def test_username(self):
        self.assertEqual(classify_target("bob_smith"), "username")
        self.assertEqual(classify_target("@bob"), "username")
        self.assertEqual(classify_target("bob"), "username")

    def test_username_with_dots(self):
        """Usernames containing dots must NOT be classified as domains."""
        self.assertEqual(classify_target("super.mario"), "username")
        self.assertEqual(classify_target("mario.rossi"), "username")
        self.assertEqual(classify_target("giulia.b"), "username")

    def test_internal_hostnames_still_domains(self):
        """Internal/pseudo-TLD suffixes keep classifying as domains."""
        self.assertEqual(classify_target("dc01.corp"), "domain")
        self.assertEqual(classify_target("web.internal"), "domain")
        self.assertEqual(classify_target("build.local"), "domain")
        self.assertEqual(classify_target("mail.google.com"), "domain")

    def test_username_like_email_missing_dot(self):
        # x@y without a dot after the @ is a username handle, not an email
        self.assertEqual(classify_target("bob@github"), "username")

    def test_identity_vs_network(self):
        self.assertTrue(is_identity_target(classify_target("bob@corp.com")))
        self.assertTrue(is_identity_target(classify_target("bob_smith")))
        self.assertTrue(is_identity_target(classify_target("+391234567890")))
        self.assertFalse(is_identity_target(classify_target("10.0.0.5")))
        self.assertFalse(is_identity_target(classify_target("example.com")))
        self.assertFalse(is_identity_target(classify_target("https://example.com")))
        self.assertFalse(is_network_target(classify_target("bob@corp.com")))
        self.assertTrue(is_network_target(classify_target("10.0.0.5")))
        self.assertTrue(is_network_target(classify_target("example.com")))
        self.assertTrue(is_network_target(classify_target("https://example.com")))

    def test_target_host(self):
        self.assertEqual(target_host("192.168.1.1"), "192.168.1.1")
        self.assertEqual(target_host("https://example.com:443/x"), "example.com")
        self.assertEqual(target_host("http://10.0.0.5/admin"), "10.0.0.5")
        self.assertEqual(target_host("bob@corp.com"), "bob@corp.com")


if __name__ == "__main__":
    unittest.main()
