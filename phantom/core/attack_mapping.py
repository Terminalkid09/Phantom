"""
attack_mapping.py — Phantom MITRE ATT&CK Mapping Module

Maps discovered services to ATT&CK techniques and calculates
priority/prevalence scores for enterprise targeting.
"""

import json
import os
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field

from phantom.utils.notifier import notifier
from phantom.core.threatintel import ThreatIntelFeed, threat_intel


@dataclass
class AttackTechnique:
    id: str  # e.g., T1078.002
    name: str  # e.g., "Valid Accounts: Pass the Hash"
    tactic: str  # e.g., "Credential Access"
    kill_chain_phase: str  # "recon", "initial_access", "execution", etc.
    platforms: List[str] = field(default_factory=list)
    detection_rate: float = 0.0  # 0-100, higher = more commonly detected in enterprise
    prevalence_score: float = 50.0  # 0-100 from threat intel feeds
    enterprise_common: bool = False
    requires_privilege: str = "low"  # "none", "low", "admin"


# Service/Port -> ATT&CK technique mappings
SERVICE_TO_TECHNIQUES: Dict[str, List[str]] = {
    # Remote Access
    "22": ["T1021.004"],  # SSH
    "23": ["T1071.001"],  # Telnet
    "3389": ["T1021.001", "T1076"],  # RDP
    "5985": ["T1021.006"],  # WinRM HTTP
    "5986": ["T1021.006"],  # WinRM HTTPS
    "445": ["T1021.002", "T1077"],  # SMB/Windows Admin Shares
    "135": ["T1021.003"],  # DCOM
    "139": ["T1021.002"],  # NetBIOS/SMB

    # Database Services
    "1433": ["T1291", "T1557.001"],  # MS SQL
    "1521": ["T1291", "T1557.001"],  # Oracle DB
    "3306": ["T1557.001", "T1291"],  # MySQL
    "5432": ["T1557.001", "T1291"],  # PostgreSQL
    "6379": ["T1557.001", "T1291"],  # Redis
    "27017": ["T1291"],  # MongoDB
    "9200": ["T1291"],  # Elasticsearch

    # Authentication
    "389": ["T1078.002", "T1557.001"],  # LDAP
    "636": ["T1078.002", "T1557.001"],  # LDAPS
    "88": ["T1558.003", "T1078.002"],  # Kerberos
    "53": ["T1557.001"],  # DNS

    # Web Applications
    "80": ["T1190"],  # Exploit Public-Facing Application
    "443": ["T1190"],
    "8080": ["T1190"],
    "8443": ["T1190"],
    "8000": ["T1190"],

    # Messaging
    "25": ["T1566.001"],  # SMTP
    "587": ["T1566.001"],  # SMTP submission

    # File Shares
    "21": ["T1557.001"],  # FTP
    "69": ["T1557.001"],  # TFTP
    "110": ["T1557.001"],  # POP3
    "143": ["T1557.001"],  # IMAP
    "993": ["T1557.001"],  # IMAPS
    "995": ["T1557.001"],  # POP3S

    # Infrastructure
    "53": ["T1557.001"],  # DNS
    "123": ["T1557.001"],  # NTP
    "161": ["T1557.001"],  # SNMP
    "162": ["T1557.001"],  # SNMPTRAP
}

# Service name -> ATT&CK technique mappings (for named services)
SERVICE_NAME_TO_TECHNIQUES: Dict[str, List[str]] = {
    "http": ["T1190"],
    "https": ["T1190"],
    "http-proxy": ["T1090"],
    "ssh": ["T1021.004"],
    "telnet": ["T1071.001"],
    "rdp": ["T1021.001", "T1076"],
    "winrm": ["T1021.006"],
    "smb": ["T1021.002", "T1077"],
    "ldap": ["T1078.002", "T1557.001"],
    "ldaps": ["T1078.002", "T1557.001"],
    "kerberos": ["T1558.003", "T1078.002"],
    "mysql": ["T1557.001", "T1291"],
    "postgresql": ["T1557.001", "T1291"],
    "redis": ["T1557.001", "T1291"],
    "mongodb": ["T1291"],
    "elasticsearch": ["T1291"],
    "mssql": ["T1557.001", "T1291"],
    "oracle": ["T1557.001", "T1291"],
    "smtp": ["T1566.001"],
    "pop3": ["T1557.001"],
    "imap": ["T1557.001"],
    "ftp": ["T1557.001"],
    "tftp": ["T1557.001"],
    "dns": ["T1557.001"],
    "snmp": ["T1557.001"],
    "ntp": ["T1557.001"],
    "vnc": ["T1021.006"],
    "docker": ["T1021.006"],
    "kubelet": ["T1610", "T1620.002"],
}

# Known enterprise techniques (commonly seen in real engagements)
KNOWN_TECHNIQUES: Dict[str, AttackTechnique] = {
    "T1021.001": AttackTechnique(
        id="T1021.001",
        name="Remote Services: Remote Desktop Protocol",
        tactic="Lateral Movement",
        kill_chain_phase="lateral_movement",
        platforms=["Windows"],
        detection_rate=75.0,
        prevalence_score=85.0,
        enterprise_common=True,
        requires_privilege="low",
    ),
    "T1021.002": AttackTechnique(
        id="T1021.002",
        name="Remote Services: SMB/Windows Admin Shares",
        tactic="Lateral Movement",
        kill_chain_phase="lateral_movement",
        platforms=["Windows"],
        detection_rate=80.0,
        prevalence_score=80.0,
        enterprise_common=True,
        requires_privilege="admin",
    ),
    "T1021.004": AttackTechnique(
        id="T1021.004",
        name="Remote Services: SSH",
        tactic="Lateral Movement",
        kill_chain_phase="lateral_movement",
        platforms=["Linux", "Windows"],
        detection_rate=40.0,
        prevalence_score=70.0,
        enterprise_common=True,
        requires_privilege="low",
    ),
    "T1076": AttackTechnique(
        id="T1076",
        name="Remote Desktop Protocol",
        tactic="Lateral Movement",
        kill_chain_phase="lateral_movement",
        platforms=["Windows"],
        detection_rate=70.0,
        prevalence_score=65.0,
        enterprise_common=True,
        requires_privilege="low",
    ),
    "T1078": AttackTechnique(
        id="T1078",
        name="Valid Accounts",
        tactic="Defense Evasion, Persistence, Privilege Escalation",
        kill_chain_phase="credential_access",
        platforms=["Windows", "Linux"],
        detection_rate=60.0,
        prevalence_score=95.0,
        enterprise_common=True,
        requires_privilege="admin",
    ),
    "T1078.002": AttackTechnique(
        id="T1078.002",
        name="Valid Accounts: Pass the Hash",
        tactic="Defense Evasion, Lateral Movement",
        kill_chain_phase="lateral_movement",
        platforms=["Windows"],
        detection_rate=65.0,
        prevalence_score=80.0,
        enterprise_common=True,
        requires_privilege="admin",
    ),
    "T1190": AttackTechnique(
        id="T1190",
        name="Exploit Public-Facing Application",
        tactic="Initial Access",
        kill_chain_phase="initial_access",
        platforms=["Linux", "Windows"],
        detection_rate=55.0,
        prevalence_score=80.0,
        enterprise_common=True,
        requires_privilege="none",
    ),
    "T1068": AttackTechnique(
        id="T1068",
        name="Exploitation for Privilege Escalation",
        tactic="Privilege Escalation",
        kill_chain_phase="privilege_escalation",
        platforms=["Linux", "Windows"],
        detection_rate=50.0,
        prevalence_score=75.0,
        enterprise_common=True,
        requires_privilege="low",
    ),
    "T1557.001": AttackTechnique(
        id="T1557.001",
        name="Man-in-the-Middle: LLMNR/NBT/Name Service Spoofing",
        tactic="Credential Access",
        kill_chain_phase="credential_access",
        platforms=["Windows", "Linux"],
        detection_rate=30.0,
        prevalence_score=70.0,
        enterprise_common=True,
        requires_privilege="low",
    ),
    "T1558.003": AttackTechnique(
        id="T1558.003",
        name="Kerberos Ticket Manipulation (Golden Ticket)",
        tactic="Credential Access, Defense Evasion",
        kill_chain_phase="privilege_escalation",
        platforms=["Windows"],
        detection_rate=40.0,
        prevalence_score=85.0,
        enterprise_common=True,
        requires_privilege="admin",
    ),
    "T1566.001": AttackTechnique(
        id="T1566.001",
        name="Phishing: Spearphishing Attachment",
        tactic="Initial Access",
        kill_chain_phase="initial_access",
        platforms=["Windows", "Linux"],
        detection_rate=65.0,
        prevalence_score=65.0,
        enterprise_common=True,
        requires_privilege="none",
    ),
    "T1046": AttackTechnique(
        id="T1046",
        name="Discovery: Network Service Scanning",
        tactic="Discovery",
        kill_chain_phase="discovery",
        platforms=["Windows", "Linux"],
        detection_rate=25.0,
        prevalence_score=90.0,
        enterprise_common=True,
        requires_privilege="low",
    ),
    "T1033": AttackTechnique(
        id="T1033",
        name="Account Discovery: System Owner/User Discovery",
        tactic="Discovery",
        kill_chain_phase="discovery",
        platforms=["Windows"],
        detection_rate=30.0,
        prevalence_score=55.0,
        enterprise_common=True,
        requires_privilege="low",
    ),
    "T1021.006": AttackTechnique(
        id="T1021.006",
        name="Remote Services: Windows Remote Management",
        tactic="Lateral Movement",
        kill_chain_phase="lateral_movement",
        platforms=["Windows"],
        detection_rate=50.0,
        prevalence_score=60.0,
        enterprise_common=True,
        requires_privilege="low",
    ),
    "T1566": AttackTechnique(
        id="T1566",
        name="Phishing",
        tactic="Initial Access",
        kill_chain_phase="initial_access",
        platforms=["Windows", "Linux"],
        detection_rate=70.0,
        prevalence_score=75.0,
        enterprise_common=True,
        requires_privilege="none",
    ),
    "T1090": AttackTechnique(
        id="T1090",
        name="Connection Proxy",
        tactic="Defense Evasion",
        kill_chain_phase="command_and_control",
        platforms=["Windows", "Linux"],
        detection_rate=55.0,
        prevalence_score=50.0,
        enterprise_common=True,
        requires_privilege="low",
    ),
    "T1071.001": AttackTechnique(
        id="T1071.001",
        name="Application Layer Protocol: Web Protocols",
        tactic="Defense Evasion, Lateral Movement",
        kill_chain_phase="lateral_movement",
        platforms=["Windows", "Linux"],
        detection_rate=45.0,
        prevalence_score=65.0,
        enterprise_common=True,
        requires_privilege="low",
    ),
    "T1291": AttackTechnique(
        id="T1291",
        name="Data from Information Repositories: Data from Network Shared Drive",
        tactic="Collection",
        kill_chain_phase="collection",
        platforms=["Windows", "Linux"],
        detection_rate=35.0,
        prevalence_score=45.0,
        enterprise_common=False,
        requires_privilege="low",
    ),
    "T1077": AttackTechnique(
        id="T1077",
        name="Windows Admin Shares",
        tactic="Lateral Movement",
        kill_chain_phase="lateral_movement",
        platforms=["Windows"],
        detection_rate=70.0,
        prevalence_score=75.0,
        enterprise_common=True,
        requires_privilege="admin",
    ),
    "T1610": AttackTechnique(
        id="T1610",
        name="Container and Cluster Enumeration",
        tactic="Discovery",
        kill_chain_phase="discovery",
        platforms=["Linux"],
        detection_rate=25.0,
        prevalence_score=40.0,
        enterprise_common=False,
        requires_privilege="low",
    ),
    "T1620.002": AttackTechnique(
        id="T1620.002",
        name="Reflective Code Loading",
        tactic="Defense Evasion",
        kill_chain_phase="execution",
        platforms=["Windows", "Linux"],
        detection_rate=40.0,
        prevalence_score=60.0,
        enterprise_common=True,
        requires_privilege="low",
    ),
}


class AttackMapper:
    """Maps discovered services to ATT&CK techniques and calculates priority."""

    def __init__(self, ti_feed: Optional[ThreatIntelFeed] = None):
        self.ti_feed = ti_feed or threat_intel

    def map_services_to_techniques(self, services: List[Dict[str, str]]) -> List[AttackTechnique]:
        """
        Map discovered services to ATT&CK techniques.

        Args:
            services: List of {"port": str, "protocol": str, "service": str}

        Returns:
            List of AttackTechnique objects
        """
        technique_ids: Set[str] = set()

        for svc in services:
            port = svc.get("port", "")
            service_name = svc.get("service", "").lower()

            # Check by port number
            if port in SERVICE_TO_TECHNIQUES:
                technique_ids.update(SERVICE_TO_TECHNIQUES[port])

            # Check by service name
            if service_name in SERVICE_NAME_TO_TECHNIQUES:
                technique_ids.update(SERVICE_NAME_TO_TECHNIQUES[service_name])

            # Check product if available
            product = svc.get("product", "").lower()
            if product:
                for known_product, techniques in SERVICE_NAME_TO_TECHNIQUES.items():
                    if known_product in product or product in known_product:
                        technique_ids.update(techniques)

        # Build technique objects with enriched data
        techniques: List[AttackTechnique] = []
        for tid in technique_ids:
            if tid in KNOWN_TECHNIQUES:
                technique = KNOWN_TECHNIQUES[tid]
                # Enrich with threat intel prevalence data
                ti_data = self.ti_feed.get_attack_technique_prevalence(tid)
                if ti_data["prevalence"] > 0:
                    # Blend known prevalence with TI feed data
                    technique.prevalence_score = round(
                        (technique.prevalence_score + ti_data["prevalence"]) / 2, 1
                    )
                techniques.append(technique)
            else:
                # Unknown technique - create basic entry
                techniques.append(AttackTechnique(
                    id=tid,
                    name=f"ATT&CK Technique {tid}",
                    tactic="Unknown",
                    kill_chain_phase="unknown",
                    prevalence_score=50.0,
                ))

        # Sort by priority: prevalence * (100 - detection_rate)
        techniques.sort(key=lambda t: t.prevalence_score * (100 - t.detection_rate), reverse=True)

        return techniques

    def get_kill_chain_phase(self, technique_id: str) -> str:
        """Get the kill chain phase for a technique."""
        technique = KNOWN_TECHNIQUES.get(technique_id)
        if technique:
            return technique.kill_chain_phase
        return "unknown"

    def get_techniques_for_phase(self, phase: str) -> List[AttackTechnique]:
        """Get all techniques that belong to a specific kill chain phase."""
        return [t for t in KNOWN_TECHNIQUES.values()
                if t.kill_chain_phase == phase]

    def get_enterprise_techniques(self) -> List[AttackTechnique]:
        """Get all techniques commonly seen in enterprise environments."""
        return [t for t in KNOWN_TECHNIQUES.values() if t.enterprise_common]

    def calculate_phase_priority(self, techniques: List[AttackTechnique]) -> Dict[str, float]:
        """
        Calculate priority scores for each kill chain phase
        based on mapped techniques.
        """
        phase_scores: Dict[str, float] = {}

        for tech in techniques:
            phase = tech.kill_chain_phase
            if phase not in phase_scores:
                phase_scores[phase] = 0.0

            # Score = prevalence * (100 - detection) / 100
            # Higher score = higher priority
            score = tech.prevalence_score * (100 - tech.detection_rate) / 100.0
            phase_scores[phase] += score

        # Normalize to 0-100 scale
        max_score = max(phase_scores.values()) if phase_scores else 1.0
        for phase in phase_scores:
            phase_scores[phase] = round((phase_scores[phase] / max_score) * 100, 1)

        return phase_scores


# Global instance
attack_mapper = AttackMapper()
