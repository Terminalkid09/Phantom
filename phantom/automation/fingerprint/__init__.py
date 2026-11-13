"""fingerprint/ — protocol-specific service fingerprinting.

Deep-probes that enrich the WorldModel beyond a simple nmap -sV port banner.
Each probe connects directly to the service, sends protocol-specific
handshake/query bytes, and extracts structured information that feeds the
planner, exploit module, and anomaly engine.

Contract:
- Pure Python (socket), no external tools
- Connection timeout: 5s, bounded reads
- Non-fatal: a refused connection returns None, never raises
- Silent: no console output (results go to WorldModel)
"""

from phantom.automation.fingerprint.probes import (
    FingerprintEngine,
    FingerprintResult,
    fingerprint_service,
    fingerprint_all,
)

__all__ = [
    "FingerprintEngine",
    "FingerprintResult",
    "fingerprint_service",
    "fingerprint_all",
]