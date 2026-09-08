"""Tests for the MITRE ATT&CK Mapping module."""
import unittest
from unittest.mock import patch

from phantom.core.attack_mapping import (
    AttackMapper, AttackTechnique,
    SERVICE_TO_TECHNIQUES, SERVICE_NAME_TO_TECHNIQUES,
    KNOWN_TECHNIQUES, attack_mapper,
)


class TestKnownTechniques(unittest.TestCase):

    def test_known_techniques_loaded(self):
        self.assertGreater(len(KNOWN_TECHNIQUES), 10)

    def test_t1021_001_exists(self):
        self.assertIn("T1021.001", KNOWN_TECHNIQUES)

    def test_t1078_exists(self):
        self.assertIn("T1078", KNOWN_TECHNIQUES)

    def test_t1190_exists(self):
        self.assertIn("T1190", KNOWN_TECHNIQUES)

    def test_technique_has_kill_chain_phase(self):
        tech = KNOWN_TECHNIQUES["T1078"]
        self.assertIsNotNone(tech.kill_chain_phase)


class TestServiceToTechniquesMapping(unittest.TestCase):

    def test_rdp_port_mapped(self):
        self.assertIn("T1021.001", SERVICE_TO_TECHNIQUES.get("3389", []))

    def test_ssh_port_mapped(self):
        self.assertIn("T1021.004", SERVICE_TO_TECHNIQUES.get("22", []))

    def test_smb_port_mapped(self):
        self.assertIn("T1021.002", SERVICE_TO_TECHNIQUES.get("445", []))

    def test_http_service_name_mapped(self):
        self.assertIn("T1190", SERVICE_NAME_TO_TECHNIQUES.get("http", []))

    def test_ldap_service_mapped(self):
        self.assertIn("T1078.002", SERVICE_NAME_TO_TECHNIQUES.get("ldap", []))


class TestAttackMapperMethods(unittest.TestCase):

    def test_map_services_to_techniques(self):
        services = [{"port": "445", "service": "microsoft-ds"}]
        techniques = attack_mapper.map_services_to_techniques(services)
        self.assertGreater(len(techniques), 0)
        ids = [t.id for t in techniques]
        self.assertIn("T1021.002", ids)

    def test_map_empty_services(self):
        techniques = attack_mapper.map_services_to_techniques([])
        self.assertEqual(len(techniques), 0)

    def test_map_http_service(self):
        services = [{"port": "80", "service": "http"}]
        techniques = attack_mapper.map_services_to_techniques(services)
        ids = [t.id for t in techniques]
        self.assertIn("T1190", ids)

    def test_map_ssh_service(self):
        services = [{"port": "22", "service": "ssh"}]
        techniques = attack_mapper.map_services_to_techniques(services)
        ids = [t.id for t in techniques]
        self.assertIn("T1021.004", ids)

    def test_map_ldap_service(self):
        services = [{"port": "389", "service": "ldap"}]
        techniques = attack_mapper.map_services_to_techniques(services)
        ids = [t.id for t in techniques]
        self.assertIn("T1078.002", ids)


class TestKillChainPhaseMapping(unittest.TestCase):

    def test_get_kill_chain_phase_known(self):
        phase = attack_mapper.get_kill_chain_phase("T1078")
        self.assertEqual(phase, "credential_access")

    def test_get_kill_chain_phase_unknown(self):
        phase = attack_mapper.get_kill_chain_phase("T9999")
        self.assertEqual(phase, "unknown")


class TestTechniquesByPhase(unittest.TestCase):

    def test_get_initial_access_techniques(self):
        techs = attack_mapper.get_techniques_for_phase("initial_access")
        self.assertGreater(len(techs), 0)

    def test_get_lateral_movement_techniques(self):
        techs = attack_mapper.get_techniques_for_phase("lateral_movement")
        self.assertGreater(len(techs), 0)


class TestEnterpriseTechniques(unittest.TestCase):

    def test_get_enterprise_techniques(self):
        techs = attack_mapper.get_enterprise_techniques()
        self.assertGreater(len(techs), 0)

    def test_all_enterprise_are_marked(self):
        for tech in attack_mapper.get_enterprise_techniques():
            self.assertTrue(tech.enterprise_common)


class TestPhasePriorityCalculation(unittest.TestCase):

    def test_empty_techniques(self):
        scores = attack_mapper.calculate_phase_priority([])
        self.assertEqual(len(scores), 0)

    def test_with_techniques(self):
        services = [{"port": "443", "service": "https"}, {"port": "3389", "service": "rdp"}]
        techniques = attack_mapper.map_services_to_techniques(services)
        scores = attack_mapper.calculate_phase_priority(techniques)
        self.assertGreater(len(scores), 0)

    def test_scores_in_range(self):
        services = [{"port": "22", "service": "ssh"}]
        techniques = attack_mapper.map_services_to_techniques(services)
        scores = attack_mapper.calculate_phase_priority(techniques)
        for phase, score in scores.items():
            self.assertGreaterEqual(score, 0.0)
            self.assertLessEqual(score, 100.0)


if __name__ == "__main__":
    unittest.main()
