"""
interpreters.py — the post phase's output interpreters.

Environment markers (__ENV_*), cloud markers (__CLOUD_*/__IAM_*/
__ASSUME_*/__XACCT_*), MDM vendor, K8s escape primitives. The AD /
persistence / privesc / lateral interpreters stay lazy (they live in
phantom.automation.post.* and are bound via _interp_from at runtime).
"""

from __future__ import annotations

from phantom.automation.guidance.kit import (  # noqa: F401
    _env_probe_interp as parse_env,
    _cloud_creds_interp as parse_cloud_creds,
    _cloud_iam_enum_interp as parse_cloud_iam,
    _cloud_assume_role_interp as parse_cloud_assume,
    _cloud_cross_account_interp as parse_cloud_cross,
    _cloud_s3_interp as parse_cloud_s3,
    _mdm_fingerprint_interp as parse_mdm,
    _k8s_escape_interp as parse_k8s,
)