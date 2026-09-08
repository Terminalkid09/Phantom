"""
threatmodel.py — explicit model of the defender (blue team).

The agent plans against a model of what the target's defenders run:
EDR, SIEM, DLP, mail gateways, MFA, geofencing, anomaly detection.
Every planned action is scored against these layers so the planner
can trade off aggressiveness vs. stealth.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class DefenseLayer:
    name: str
    detect: List[str]  # action categories it watches: recon | scan | brute | exploit | lateral | persistence | exfil | social
    sensitivity: float = 0.5  # 0..1 how trigger-happy it is
    mitigations: List[str] = field(default_factory=list)  # what a client should do

    def risk(self, category: str, stealth_level: str, opsec_cost: float) -> float:
        """Chance this layer catches an action of `category`."""
        if category not in self.detect:
            return 0.0
        base = self.sensitivity
        # passive actions barely register; aggressive ones scream
        if stealth_level == "passive":
            base *= 0.15
        elif stealth_level == "active":
            base *= 0.75
        return min(1.0, base + opsec_cost * 0.05)


@dataclass
class BlueTeamModel:
    """The defender stack, inferred from target type / company profile."""

    profile: str  # smb | enterprise | cloud | financial | government
    layers: List[DefenseLayer] = field(default_factory=list)

    @classmethod
    def for_profile(cls, profile: str = "enterprise") -> "BlueTeamModel":
        return cls(profile=profile, layers=_DEFAULT_STACK[profile])

    def risk(self, category: str, stealth_level: str, opsec_cost: float) -> float:
        if not self.layers:
            return 0.0
        return max(l.risk(category, stealth_level, opsec_cost) for l in self.layers)

    def detection_likelihood(self, category: str, stealth_level: str, opsec_cost: float) -> str:
        r = self.risk(category, stealth_level, opsec_cost)
        if r < 0.25:
            return "low"
        if r < 0.6:
            return "medium"
        return "high"

    def recommendations(self) -> List[str]:
        out = []
        for layer in self.layers:
            out.extend(layer.mitigations)
        return out


_DEFAULT_STACK: Dict[str, List[DefenseLayer]] = {
    # SMB: small/medium business — limited security budget, mostly perimeter-focused
    "smb": [
        DefenseLayer("AV", detect=["exploit", "beacon", "lateral", "persistence"],
                     sensitivity=0.35,
                     mitigations=["keep AV definitions current", "enforce signed executables",
                                  "consider endpoint detection upgrade"]),
        DefenseLayer("NGFW", detect=["recon", "scan", "brute", "exfil"],
                     sensitivity=0.3,
                     mitigations=["disable unused ports", "rate-limit auth endpoints",
                                  "enable IPS signatures"]),
        DefenseLayer("backup_monitoring", detect=["persistence", "lateral"],
                     sensitivity=0.2,
                     mitigations=["offline / immutable backups", "integrity alerting"]),
    ],

    # Enterprise: corporate — full security stack, SOC, behavioral analytics
    "enterprise": [
        DefenseLayer("EDR", detect=["exploit", "beacon", "lateral", "persistence"],
                     sensitivity=0.75,
                     mitigations=["enable behavioral EDR telemetry", "block unsigned drivers",
                                  "enable memory-shield (shellcode injection detection)"]),
        DefenseLayer("SIEM", detect=["scan", "brute", "recon", "lateral"],
                     sensitivity=0.65,
                     mitigations=["baseline network traffic", "alert on anomalous logins",
                                  "correlate failed auth with port scans"]),
        DefenseLayer("DLP", detect=["exfil", "social"],
                     sensitivity=0.6,
                     mitigations=["classify sensitive data", "restrict web uploads",
                                  "DLP on email attachments"]),
        DefenseLayer("mail_gateway", detect=["social", "phish"],
                     sensitivity=0.82,
                     mitigations=["SPF/DKIM/DMARC", "URL reputation filtering",
                                  "sandboxed attachment detonation"]),
        DefenseLayer("MFA", detect=["creds"],
                     sensitivity=0.78,
                     mitigations=["enforce MFA for all accounts", "disable legacy protocols",
                                  "phish-resistant FIDO2 tokens"]),
        DefenseLayer("geo_fencing", detect=["creds", "brute"],
                     sensitivity=0.5,
                     mitigations=["restrict logins by country", "alert on new-location logins"]),
        DefenseLayer("PAM", detect=["lateral", "persistence", "exfil"],
                     sensitivity=0.7,
                     mitigations=["privileged access management", "session recording",
                                  "just-in-time admin access"]),
        DefenseLayer("network_detection", detect=["scan", "lateral", "exfil"],
                     sensitivity=0.55,
                     mitigations=["NDR / network anomaly detection", "east-west traffic inspection"]),
    ],

    # Cloud: SaaS/IaaS — identity-centric, API-heavy, CASB + CNAPP
    "cloud": [
        DefenseLayer("cloud_waf", detect=["recon", "exploit", "scan"],
                     sensitivity=0.72,
                     mitigations=["WAF rules + bot management", "rate limiting",
                                  "API schema validation"]),
        DefenseLayer("identity_provider", detect=["creds", "brute"],
                     sensitivity=0.78,
                     mitigations=["conditional access policies", "credential-less auth",
                                  "continuous access evaluation (CAE)"]),
        DefenseLayer("CASB", detect=["exfil", "lateral", "social"],
                     sensitivity=0.65,
                     mitigations=["DLP on cloud storage", "OAuth app review",
                                  "block unsanctioned SaaS"]),
        DefenseLayer("CloudTrail_SIEM", detect=["recon", "scan", "lateral", "persistence"],
                     sensitivity=0.7,
                     mitigations=["CloudTrail / Audit Log to SIEM", "alert on IAM privilege escalation",
                                  "detect resource enumeration (ListBuckets, DescribeInstances)"]),
        DefenseLayer("CNAPP", detect=["exploit", "persistence", "lateral"],
                     sensitivity=0.6,
                     mitigations=["cloud security posture management (CSPM)",
                                  "runtime workload protection (CWPP)"]),
    ],

    # Financial: banks/fintech — heavily regulated, ML-based fraud, HSM-backed crypto
    "financial": [
        DefenseLayer("fraud_ml", detect=["creds", "brute", "social"],
                     sensitivity=0.92,
                     mitigations=["behavioral fraud scoring", "transaction anomaly detection",
                                  "device fingerprinting + velocity rules"]),
        DefenseLayer("network_detection", detect=["scan", "exploit", "lateral", "exfil"],
                     sensitivity=0.85,
                     mitigations=["network segmentation (PCI-DSS zones)", "data exfiltration detection",
                                  "SWIFT CSP controls"]),
        DefenseLayer("HSM_PKI", detect=["persistence", "lateral"],
                     sensitivity=0.8,
                     mitigations=["HSM-backed key management", "certificate pinning",
                                  "mutual TLS for inter-service"]),
        DefenseLayer("SOC_247", detect=["recon", "scan", "exploit", "beacon", "exfil"],
                     sensitivity=0.88,
                     mitigations=["24/7 SOC with financial threat intel feeds",
                                  "dedicated incident response retainer"]),
        DefenseLayer("DLP_financial", detect=["exfil", "social"],
                     sensitivity=0.9,
                     mitigations=["classify PII/PCI data", "block customer data to personal email",
                                  "watermark sensitive documents"]),
    ],

    # Mobile: iOS/Android — the OS sandbox hides the device from port scans;
    # the real surface is social (SMS/DM/phish), MDM enrollment, sync
    # protocols and app supply chains. Defender stack reflects that.
    "mobile": [
        DefenseLayer("OS_sandbox", detect=["exploit", "beacon", "persistence"],
                     sensitivity=0.85,
                     mitigations=["keep OS patched (iOS/Android monthly)",
                                  "disable sideloading / unknown sources",
                                  "restrict accessibility/overlay permissions"]),
        DefenseLayer("mobile_EDR", detect=["exploit", "beacon", "lateral", "persistence"],
                     sensitivity=0.8,
                     mitigations=["mobile threat defense (Zimperium/Lookout/CrowdStrike)",
                                  "managed device attestation",
                                  "real-time app behavior analysis"]),
        DefenseLayer("MDM_EMM", detect=["creds", "lateral", "persistence", "exfil"],
                     sensitivity=0.75,
                     mitigations=["enforce enrollment + compliance policies",
                                  "remote wipe capability",
                                  "block non-compliant devices from mail/data"]),
        DefenseLayer("carrier_network", detect=["recon", "scan", "brute", "social"],
                     sensitivity=0.5,
                     mitigations=["SMS firewall / anti-smishing filters",
                                  "SS7 / diameter hardening",
                                  "caller-ID spoofing protection"]),
        DefenseLayer("app_vetting", detect=["exploit", "social"],
                     sensitivity=0.6,
                     mitigations=["app store review / enterprise app attestation",
                                  "signature validation + tamper detection"]),
    ],

    # Government: military/agency — air-gapped segments, strict clearance, supply-chain controls
    "government": [
        DefenseLayer("gov_soc", detect=["recon", "scan", "brute", "exploit", "lateral",
                                         "persistence", "exfil", "social"],
                     sensitivity=0.93,
                     mitigations=["24/7 SOC monitoring", "strict egress filtering",
                                  "classified network segmentation (NIPR/SIPR/JWICS)"]),
        DefenseLayer("SCIF_controls", detect=["recon", "social", "exfil"],
                     sensitivity=0.95,
                     mitigations=["SCIF physical security", "no personal devices",
                                  "Faraday cage for sensitive compartments"]),
        DefenseLayer("supply_chain_monitoring", detect=["persistence", "lateral"],
                     sensitivity=0.85,
                     mitigations=["software supply chain review (SBOM)", "firmware integrity attestation",
                                  "hardware vendor vetting"]),
        DefenseLayer("UEBA", detect=["creds", "lateral", "exfil", "persistence"],
                     sensitivity=0.88,
                     mitigations=["user behavior analytics", "insider threat program",
                                  "clearance-level access controls"]),
    ],
}
