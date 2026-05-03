import pytest

from phantom.core.scope import is_in_scope


class TestScope:
    def test_empty_scope_allows_everything(self):
        """An empty scope should allow any target."""
        assert is_in_scope("10.0.0.1", []) is True
        assert is_in_scope("example.com", []) is True

    def test_domain_names_are_always_allowed(self):
        """Domain names should be treated as in-scope even when scope is defined."""
        assert is_in_scope("example.com", ["10.0.0.0/24"]) is True

    def test_ip_in_scope_returns_true(self):
        """Valid IP addresses within scope should return True."""
        assert is_in_scope("10.0.0.5", ["10.0.0.0/24"]) is True
        assert is_in_scope("192.168.1.10", ["192.168.1.10"]) is True

    def test_ip_out_of_scope_returns_false(self):
        """IP targets outside the configured scope should return False."""
        assert is_in_scope("10.0.1.5", ["10.0.0.0/24"]) is False

    def test_invalid_scope_entries_are_skipped(self):
        """Invalid scope entries should not crash and should be ignored."""
        assert is_in_scope("10.0.0.5", ["not-a-cidr", "10.0.0.0/24"]) is True
        assert is_in_scope("10.0.1.5", ["not-a-cidr"]) is False
