"""
risk_engine.py — Phantom Risk-Based Prioritization Engine

Calculates exposure risk for targets based on:
- Business criticality of services
- Network position (isolated, DMZ, internal, core)
- Patch status / vulnerability age
- Asset importance classification

Returns composite risk scores (0-100) for workflow prioritization.
"""

from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

from phantom.utils.notifier import notifier


# Business criticality by service/protocol (0-100)
BUSINESS_CRITICALITY = {
    "ldap": 100,      # Identity = critical
    "kerberos": 100,  # AD authentication
    "microsoft-ds": 95,
    "ms-wbt-server": 90,  # RDP
    "http": 70,       # Web frontend
    "https": 75,
    "http-proxy": 75,
    "ssh": 85,        # Remote access
    "rdp": 90,
    "winrm": 80,
    "mysql": 80,      # Database
    "postgresql": 80,
    "mssql": 90,
    "oracle": 85,
    "redis": 70,
    "mongodb": 65,
    "smtp": 75,       # Email = business critical
    "pop3": 60,
    "imap": 60,
    "dns": 95,        # Name resolution = critical
    "ftp": 55,        # File transfer (lower priority)
    "nfs": 70,
    "smb": 85,
    "vnc": 65,
    "docker": 75,
    "kubelet": 95,    # Kubernetes API
}

# Network position scoring (0-100)
NETWORK_POSITION = {
    "isolated_management": 10,   # Air-gapped mgmt network
    "dmz": 30,                   # Internet-facing
    "internal_user_vlan": 40,    # User workstations
    "internal_server_vlan": 60,  # Server network
    "domain_controller_vlan": 85, # DC network
    "core_infrastructure": 95,    # Core switches, load balancers
    "unknown": 50,
}

# Asset classification weights
ASSET_CLASSIFICATIONS = {
    "customer_data": 100,
    "financial_data": 100,
    "pii": 95,
    "intellectual_property": 90,
    "authentication_server": 100,
    "backup_server": 85,
    "domain_controller": 100,
    "jump_host": 80,
    "application_server": 70,
    "file_server": 60,
    "workstation": 30,
    "printer": 10,
    "iot_device": 15,
}


@dataclass
class RiskProfile:
    """Risk profile for a single target/service."""
    target: str
    service: str
    port: int
    business_criticality: float
    network_position_score: float
    exposure_score: float
    overall_risk: float
    factors: Dict[str, float]


class RiskEngine:
    """
    Calculates exposure risk and prioritizes targets
    for attack chain sequencing.
    """

    def __init__(self):
        self.business_criticality = dict(BUSINESS_CRITICALITY)
        self.network_position = dict(NETWORK_POSITION)

    def get_service_criticality(self, service: str) -> float:
        """Get business criticality score for a service."""
        # Normalize service name
        svc = service.lower().strip()

        # Direct match
        if svc in self.business_criticality:
            return self.business_criticality[svc]

        # Token match: split on separators and match whole tokens, so a
        # short/ambiguous service name like "sql" can never randomly match
        # "mssql", "mysql" or "postgresql" by substring.
        import re
        tokens = set(re.split(r"[^a-z0-9]+", svc))
        for key, score in self.business_criticality.items():
            if key in tokens:
                return score

        # Substring match (service contains a known key), e.g.
        # "redis-server" -> "redis". Only keys of reasonable length so
        # short keys like "ftp" don't match unrelated names.
        for key, score in self.business_criticality.items():
            if len(key) >= 4 and key in svc:
                return score

        return 25.0  # Default for unknown services

    def get_network_position_score(self, segment_info: Dict[str, Any]) -> float:
        """Get network position score based on segmentation info."""
        if not segment_info:
            return NETWORK_POSITION["unknown"]

        # Check for specific flags first (higher specificity)
        if segment_info.get("isolated_network"):
            return NETWORK_POSITION["isolated_management"]
        if segment_info.get("dmz"):
            return NETWORK_POSITION["dmz"]
        if segment_info.get("core"):
            return NETWORK_POSITION["core_infrastructure"]
        if segment_info.get("domain_controller"):
            return NETWORK_POSITION["domain_controller_vlan"]

        segment = segment_info.get("segment", "unknown")
        if segment in self.network_position:
            return self.network_position[segment]

        return NETWORK_POSITION["unknown"]

    def calculate_exposure_risk(
        self,
        target: str,
        service: str,
        port: int,
        segment_info: Optional[Dict[str, Any]] = None,
        vulnerability_age_days: Optional[int] = None,
        asset_classification: Optional[str] = None,
    ) -> RiskProfile:
        """
        Calculate comprehensive risk profile for a target.

        Args:
            target: IP address or hostname
            service: Service name (e.g., "ssh", "http")
            port: Port number
            segment_info: Network segmentation context
            vulnerability_age_days: Days since last patch (for CVE correlation)
            asset_classification: Business classification (e.g., "customer_data")

        Returns:
            RiskProfile with composite score and factors
        """
        factors = {}

        # Business criticality
        biz_score = self.get_service_criticality(service)
        factors["business_criticality"] = biz_score

        # Network position
        net_score = self.get_network_position_score(segment_info or {})
        factors["network_position"] = net_score

        # Vulnerability age factor (older = higher risk)
        vuln_factor = 0.0
        if vulnerability_age_days is not None:
            if vulnerability_age_days > 365:
                vuln_factor = 40.0
            elif vulnerability_age_days > 180:
                vuln_factor = 30.0
            elif vulnerability_age_days > 90:
                vuln_factor = 25.0
            elif vulnerability_age_days > 30:
                vuln_factor = 20.0
            elif vulnerability_age_days > 7:
                vuln_factor = 15.0
            else:
                vuln_factor = 10.0
        factors["vulnerability_age"] = vuln_factor

        # Asset classification boost
        asset_boost = 0.0
        if asset_classification and asset_classification in ASSET_CLASSIFICATIONS:
            asset_boost = ASSET_CLASSIFICATIONS[asset_classification] / 10.0
        factors["asset_classification"] = asset_boost

        # Port exposure factor
        # Well-known ports more exposed, dynamic less
        port_factor = 0.0
        if port in (22, 80, 443, 3389, 445):
            port_factor = 10.0
        elif port < 1024:
            port_factor = 5.0
        factors["port_exposure"] = port_factor

        # Calculate composite score
        # Weights: 30% business + 25% network + 25% vuln_age + 10% asset + 10% port
        overall = (
            biz_score * 0.30 +
            net_score * 0.25 +
            vuln_factor * 0.25 +
            asset_boost * 0.10 +
            port_factor * 0.10
        )

        return RiskProfile(
            target=target,
            service=service,
            port=port,
            business_criticality=biz_score,
            network_position_score=net_score,
            exposure_score=vuln_factor + port_factor,
            overall_risk=round(overall, 1),
            factors=factors,
        )

    def rank_targets(self, targets: List[RiskProfile]) -> List[RiskProfile]:
        """Rank targets by overall risk (highest first)."""
        return sorted(targets, key=lambda t: t.overall_risk, reverse=True)

    def get_recommended_phase(self, risk_score: float) -> str:
        """
        Recommend attack phase based on risk profile.
        Higher risk = more aggressive initial access.
        """
        if risk_score >= 80:
            return "initial_access_aggressive"
        elif risk_score >= 60:
            return "initial_access_balanced"
        elif risk_score >= 40:
            return "recon_enhanced"
        else:
            return "recon_stealth"

    def get_exploit_timing_risk(self, patch_days: int) -> Dict[str, Any]:
        """
        Assess timing-based exploit risk.
        Older vulnerabilities are easier to exploit but may be patched.
        """
        if patch_days < 30:
            return {
                "exploit_complexity": "high",
                "detection_risk": "high",
                "recommendation": "stealth_initial_access",
            }
        elif patch_days < 180:
            return {
                "exploit_complexity": "medium",
                "detection_risk": "medium",
                "recommendation": "targeted_exploitation",
            }
        else:
            return {
                "exploit_complexity": "low",
                "detection_risk": "high",
                "recommendation": "aggressive_exploitation",
                "warning": "May be patched - verify first",
            }


# Global instance
risk_engine = RiskEngine()
