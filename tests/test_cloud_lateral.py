"""Tests for the cloud lateral-movement capabilities (IAM enum, STS assume,
cross-account enum) — the planner-grade cloud chain."""
import pytest

from phantom.automation.belief import WorldModel, Finding
from phantom.automation.guidance.kit import (
    _cloud_iam_enum_adapter,
    _cloud_iam_enum_interp,
    _cloud_assume_role_adapter,
    _cloud_assume_role_interp,
    _cloud_cross_account_adapter,
    _cloud_cross_account_interp,
)


def _wm_with_creds() -> WorldModel:
    wm = WorldModel(target="10.0.0.5", target_type="ip")
    wm.add_finding("cloud_creds", "iam_aws",
                   {"provider": "aws", "via": "metadata",
                    "evidence": "AccessKeyId=AKIA..."},
                   confidence=0.95, source="cloud_creds_harvest",
                   target="10.0.0.5")
    return wm


# ── IAM enum ────────────────────────────────────────────────────────────────

def test_iam_enum_adapter_is_readonly():
    cmd = _cloud_iam_enum_adapter(_wm_with_creds(), {})
    assert "list-roles" in cmd
    assert "get-account-summary" in cmd
    assert "--query" in cmd  # bounded output
    assert "mkfs" not in cmd and "delete" not in cmd.lower()


def test_iam_enum_interp_roles_and_account():
    out = (
        "__IAM_START__\n"
        "account=123456789012\n"
        "app-role\tarn:aws:iam::123456789012:role/app-role\n"
        "admin-role\tarn:aws:iam::123456789012:role/admin-role\n"
        "__IAM_END__"
    )
    findings = _cloud_iam_enum_interp(out, _wm_with_creds(), {})
    kinds = [f.kind for f in findings]
    assert "cloud_access" in kinds
    assert "cloud_lateral" in kinds
    roles_f = [f for f in findings if f.kind == "cloud_lateral"][0]
    assert roles_f.value["count"] == 2
    assert "admin-role" in roles_f.value["role_arns"][1]


def test_iam_enum_interp_empty():
    assert _cloud_iam_enum_interp("", _wm_with_creds(), {}) == []
    assert _cloud_iam_enum_interp("garbage output", _wm_with_creds(), {}) == []


# ── STS assume-role ─────────────────────────────────────────────────────────

def test_assume_role_adapter_rejects_bad_arn():
    cmd = _cloud_assume_role_adapter(_wm_with_creds(), {"role_arn": "not-an-arn"})
    assert "assume-role" not in cmd
    cmd2 = _cloud_assume_role_adapter(_wm_with_creds(), {"role_arn": ""})
    assert "assume-role" not in cmd2


def test_assume_role_adapter_builds_sts_call():
    arn = "arn:aws:iam::123456789012:role/admin-role"
    cmd = _cloud_assume_role_adapter(_wm_with_creds(), {"role_arn": arn})
    assert "aws sts assume-role" in cmd
    assert arn in cmd
    assert "get-caller-identity" in cmd  # identity verification step


def test_assume_role_interp_success_and_denial():
    ok = "__ASSUME_START__\narn:aws:sts::123456789012:assumed-role/admin-role/phantom-lateral\n__ASSUME_OK__"
    f_ok = _cloud_assume_role_interp(ok, _wm_with_creds(), {"role_arn": "arn:x"})
    assert f_ok and f_ok[0].kind == "cloud_lateral"
    assert f_ok[0].value["status"] == "assumed"

    denied = "__ASSUME_START__\n__ASSUME_DENIED__"
    f_no = _cloud_assume_role_interp(denied, _wm_with_creds(), {"role_arn": "arn:x"})
    assert f_no and f_no[0].value["status"] == "denied"


# ── Cross-account enum ──────────────────────────────────────────────────────

def test_cross_account_interp_buckets():
    out = (
        "__XACCT_START__\n"
        "2026-01-01 12:00:00 secret-backups-prod\n"
        "2026-02-01 09:00:00 customer-data-eu\n"
        "__XACCT_END__"
    )
    findings = _cloud_cross_account_interp(out, _wm_with_creds(), {})
    assert findings
    b = [f for f in findings if f.key == "cross_account_buckets"][0]
    assert "secret-backups-prod" in b.value["buckets"]


def test_cross_account_interp_empty():
    assert _cloud_cross_account_interp("", _wm_with_creds(), {}) == []


# ── Planner + attack chain wiring ───────────────────────────────────────────

def test_planner_knows_cloud_lateral():
    from phantom.automation.planner import GOAL_FACTS, _FACT_SOURCES
    assert "cloud_lateral" in GOAL_FACTS["cloud"]
    assert "cloud_assume_role" in _FACT_SOURCES.get("cloud_lateral", [])


def test_attack_chain_has_cloud_lateral_edges():
    from phantom.automation.attack_chain import AttackGraph
    wm = _wm_with_creds()
    wm.add_finding("cloud_lateral", "roles",
                   {"role_arns": ["arn:aws:iam::1:role/r"], "count": 1},
                   confidence=0.85, source="cloud_iam_enum", target="10.0.0.5")
    g = AttackGraph(wm)
    g.build()
    labels = [e.label for e in g.edges]
    assert any("IAM role enumeration" in l for l in labels)


def test_capabilities_registered():
    from phantom.automation.guidance.kit import CAPABILITIES
    ids = {c.id for c in CAPABILITIES}
    assert {"cloud_iam_enum", "cloud_assume_role", "cloud_cross_account"} <= ids
