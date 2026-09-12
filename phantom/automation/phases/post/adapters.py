"""
adapters.py — the post phase's execution adapters.

Re-exported from guidance/kit.py during the migration (same rationale
as the recon facade).
"""

from __future__ import annotations

from phantom.automation.guidance.kit import (  # noqa: F401
    _env_internal_adapter as env_probe_internal,
    _persist_adapter as persistence_install,
    _privesc_adapter as privesc_system,
    _inject_adapter as inject_beacon,
    _sudo_adapter as privesc_sudo,
    _service_perms_adapter as privesc_service_perms,
    _ad_enum_adapter as ad_enum,
    _kerberoast_adapter as kerberoast,
    _as_rep_adapter as as_rep_roast,
    _dc_sync_adapter as dc_sync,
    _hash_crack_adapter as hash_crack,
    _lateral_adapter as lateral_pivot,
    _smb_adapter as smb_pivot,
    _winrm_adapter as winrm_pivot,
    _cleanup_adapter as cleanup,
    _cookies_adapter as cookie_stealer,
    _bt_scan_adapter as bt_scan,
    _cdp_cookies_adapter as cdp_pivot,
    _socks_adapter as socks_proxy,
    _ransom_sim_adapter as ransom_sim,
    _trojan_deliver_adapter as trojan_deliver,
    _cloud_creds_adapter as cloud_creds_harvest,
    _cloud_s3_adapter as cloud_s3_enum,
    _cloud_iam_enum_adapter as cloud_iam_enum,
    _cloud_assume_role_adapter as cloud_assume_role,
    _cloud_cross_account_adapter as cloud_cross_account,
    _k8s_escape_adapter as k8s_escape,
)