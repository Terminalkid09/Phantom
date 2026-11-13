"""
adapters.py — the recon phase's execution adapters.

During the migration the bodies live in guidance/kit.py (the live
registry); this facade re-exports them so phase-internal code and tests
address the phase, not the monolith. When the body moves land here,
only this file changes.
"""

from __future__ import annotations

# re-exports: the recon adapters (the ONLY place commands exist)
from phantom.automation.guidance.kit import (  # noqa: F401
    _port_scan_adapter as port_scan,
    _version_adapter as version_detect,
    _os_adapter as os_detect,
    _ssh_banner_adapter as ssh_banner,
    _http_probe_adapter as http_probe,
    _http_get_adapter as http_get,
    _fingerprint_adapter as fingerprint_services,
    _smb_enum_adapter as smb_enum,
    _redis_info_adapter as redis_info,
    _env_probe_adapter as env_probe,
    _mobile_probe_adapter as mobile_probe,
    _mdm_fingerprint_adapter as mobile_mdm_fingerprint,
)
