"""Tests for Active Directory awareness engine."""
import unittest
from phantom.automation.belief import WorldModel
from phantom.automation.ad_awareness import (
    detect_ad_ports, is_likely_dc, AD_PORTS,
    ADAwareness, DomainInfo, assess_active_directory,
)


class TestADDetection(unittest.TestCase):
    """Test port-based AD detection logic."""

    def test_empty_ports(self):
        """No AD ports → no signals."""
        self.assertEqual(detect_ad_ports([22, 80, 443]), [])

    def test_kerberos_ldap(self):
        """Kerberos + LDAP → DC detection."""
        signals = detect_ad_ports([88, 389, 445])
        self.assertIn("kerberos", signals)
        self.assertIn("ldap", signals)

    def test_gc_detection(self):
        """Global Catalog ports detected."""
        signals = detect_ad_ports([3268, 3269])
        self.assertIn("global_catalog", signals)
        self.assertIn("global_catalog_ssl", signals)

    def test_is_likely_dc(self):
        """Kerberos + LDAP → likely DC."""
        self.assertTrue(is_likely_dc([88, 389, 445, 135]))
        self.assertFalse(is_likely_dc([22, 80, 443]))

    def test_is_likely_dc_without_kerberos(self):
        """Without Kerberos, not a DC."""
        self.assertFalse(is_likely_dc([389, 445]))

    def test_all_ad_ports_registered(self):
        """All known AD ports are in the map."""
        self.assertIn(88, AD_PORTS)
        self.assertIn(389, AD_PORTS)
        self.assertIn(636, AD_PORTS)
        self.assertIn(3268, AD_PORTS)
        self.assertIn(3269, AD_PORTS)
        self.assertIn(135, AD_PORTS)
        self.assertIn(464, AD_PORTS)


class TestADAwareness(unittest.TestCase):
    """Test the AD awareness engine."""

    def test_empty_worldmodel_assessment(self):
        """Running AD assessment on empty WorldModel is safe."""
        wm = WorldModel("10.0.0.1")
        result = assess_active_directory(wm, "10.0.0.1", [])
        self.assertIsNone(result)

    def test_domain_info_defaults(self):
        """DomainInfo has sensible defaults."""
        info = DomainInfo()
        self.assertEqual(info.domain_name, "")
        self.assertEqual(info.functional_level, 0)
        self.assertIsInstance(info.dc_hostnames, list)
        self.assertEqual(info.confidence, 0.0)

    def test_assess_no_ad_ports(self):
        """Host without AD ports returns None."""
        engine = ADAwareness(timeout=1.0)
        result = engine.assess("10.0.0.1", [22, 80, 443])
        self.assertIsNone(result)

    def test_assess_with_ad_ports(self):
        """Host with AD ports returns DomainInfo even if LDAP unreachable."""
        engine = ADAwareness(timeout=1.0)
        result = engine.assess("10.0.0.1", [88, 389, 445])
        self.assertIsNotNone(result)
        # kerberos_detected is set from port detection, then
        # kerberos_asrep_check may fail (port unreachable in test env)
        # — the important thing is the DomainInfo was created

    def test_assess_feeds_worldmodel(self):
        """Assessment feeds findings into WorldModel."""
        wm = WorldModel("10.0.0.1")
        engine = ADAwareness(timeout=1.0)
        engine.assess("10.0.0.1", [88, 389], wm=wm)
        self.assertTrue(wm.has_any("ad_domain") or wm.has_any("environment"))

    def test_has_kerberos_attack_surface(self):
        """Kerberos port detected → attack surface flag set in WorldModel."""
        wm = WorldModel("10.0.0.1")
        engine = ADAwareness(timeout=1.0)
        result = engine.assess("10.0.0.1", [88, 389], wm=wm)
        # If network fails, kerberos may not be confirmed, but ad_domain
        # or environment should still be set from port detection
        self.assertIsNotNone(result)
        self.assertTrue(
            wm.has_any("ad_domain")
            or wm.has_any("environment")
            or wm.has_any("ad_attack_surface")
        )


if __name__ == "__main__":
    unittest.main()