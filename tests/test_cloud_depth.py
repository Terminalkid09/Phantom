"""Fase 3 — cloud/IAM depth.

The cloud chain was AWS-shaped and disconnected: `cloud_iam_enum` discovered
the assumable roles but `cloud_assume_role` demands a `role_arn` nobody
supplied, and the adapters only spoke the AWS CLI. These tests pin:

  * provider resolution (aws|gcp|azure) from world-model evidence
  * autofill of the assume identity from the previous stage's finding
  * provider parity: gcp/azure adapters + interpreters
"""
import pytest

from phantom.automation.belief import WorldModel
from phantom.automation.guidance.kit import (
    _cloud_assumable_identity,
    _cloud_assume_role_adapter,
    _cloud_cross_account_adapter,
    _cloud_cross_account_interp,
    _cloud_iam_enum_adapter,
    _cloud_iam_enum_interp,
    _cloud_provider,
)


def _wm(provider="aws", with_creds=True):
    wm = WorldModel(target="10.0.0.5", target_type="ip")
    if with_creds:
        wm.add_finding("cloud_creds", f"iam_{provider}",
                       {"provider": provider, "via": "metadata"},
                       confidence=0.9, source="cloud_creds_harvest",
                       target="10.0.0.5")
    return wm


# ── provider resolution ─────────────────────────────────────────────────────

def test_provider_from_creds_finding():
    assert _cloud_provider(_wm("gcp")) == "gcp"
    assert _cloud_provider(_wm("azure")) == "azure"


def test_provider_from_slot_wins():
    assert _cloud_provider(_wm("aws"), {"provider": "azure"}) == "azure"


def test_provider_from_environment_fact():
    wm = WorldModel(target="10.0.0.5", target_type="ip")
    wm.add_finding("environment", "container",
                   {"cloud": "gcp-metadata"}, confidence=0.8,
                   source="env_probe", target="10.0.0.5")
    assert _cloud_provider(wm) == "gcp"


def test_provider_defaults_to_aws():
    assert _cloud_provider(WorldModel(target="10.0.0.5",
                                      target_type="ip")) == "aws"


# ── autofill of the assume identity ─────────────────────────────────────────

def test_assumable_identity_aws():
    wm = _wm("aws")
    wm.add_finding("cloud_lateral", "roles",
                   {"role_arns": ["arn:aws:iam::123456789012:role/admin",
                                  "arn:aws:iam::123456789012:role/app"]},
                   confidence=0.85, source="cloud_iam_enum",
                   target="10.0.0.5")
    assert _cloud_assumable_identity(wm) == \
        "arn:aws:iam::123456789012:role/admin"


def test_assumable_identity_gcp():
    wm = _wm("gcp")
    wm.add_finding("cloud_lateral", "roles",
                   {"role_arns": ["sa@proj.iam.gserviceaccount.com"]},
                   confidence=0.85, source="cloud_iam_enum",
                   target="10.0.0.5")
    assert _cloud_assumable_identity(wm).endswith("gserviceaccount.com")


def test_assumable_identity_empty_without_finding():
    assert _cloud_assumable_identity(_wm("aws")) == ""


# ── provider parity: adapters ───────────────────────────────────────────────

def test_iam_enum_gcp_uses_gcloud():
    cmd = _cloud_iam_enum_adapter(_wm("gcp"), {})
    assert "gcloud" in cmd and "service-accounts list" in cmd


def test_iam_enum_azure_uses_az():
    cmd = _cloud_iam_enum_adapter(_wm("azure"), {})
    assert "az " in cmd and "role assignment list" in cmd


def test_assume_role_gcp_impersonation():
    cmd = _cloud_assume_role_adapter(
        _wm("gcp"), {"role_arn": "sa@proj.iam.gserviceaccount.com"})
    assert "impersonate-service-account" in cmd


def test_assume_role_azure_token_check():
    cmd = _cloud_assume_role_adapter(_wm("azure"), {"role_arn": "Contributor"})
    assert "get-access-token" in cmd


def test_cross_account_gcp_and_azure():
    assert "gcloud storage buckets list" in \
        _cloud_cross_account_adapter(_wm("gcp"), {})
    assert "az storage account list" in \
        _cloud_cross_account_adapter(_wm("azure"), {})


# ── provider parity: interpreters ───────────────────────────────────────────

def test_iam_interp_gcp_service_accounts():
    out = ("__IAM_START__\naccount=my-project\n"
           "sa1@proj.iam.gserviceaccount.com\n"
           "sa2@proj.iam.gserviceaccount.com\n"
           "__IAM_END__")
    findings = _cloud_iam_enum_interp(out, _wm("gcp"), {})
    lat = [f for f in findings if f.kind == "cloud_lateral"]
    assert lat and lat[0].value["provider"] == "gcp"
    assert lat[0].value["count"] == 2


def test_iam_interp_dedupes():
    arn = "arn:aws:iam::1:role/x"
    out = f"__IAM_START__\n{arn}\n{arn}\n__IAM_END__"
    findings = _cloud_iam_enum_interp(out, _wm("aws"), {})
    lat = [f for f in findings if f.kind == "cloud_lateral"][0]
    assert lat.value["count"] == 1


def test_cross_account_interp_provider_neutral():
    out = ("__XACCT_START__\nproj-bucket\nother-bucket\n__XACCT_END__")
    findings = _cloud_cross_account_interp(out, _wm("gcp"), {})
    acc = [f for f in findings if f.kind == "cloud_access"]
    assert acc and set(acc[0].value["buckets"]) == {"proj-bucket",
                                                    "other-bucket"}


# ── chain wiring: the assume role is plannable end-to-end ───────────────────

def test_chain_iam_enum_then_assume_role():
    """The two capabilities compose: enum discovers, assume consumes."""
    wm = _wm("aws")
    enum_out = ("__IAM_START__\naccount=123\n"
                "app\tarn:aws:iam::123:role/app\n__IAM_END__")
    for f in _cloud_iam_enum_interp(enum_out, wm, {}):
        wm.add_finding(f.kind, f.key, f.value, confidence=f.confidence,
                       source=f.source, target=wm.target)
    ident = _cloud_assumable_identity(wm)
    assert ident == "arn:aws:iam::123:role/app"
    cmd = _cloud_assume_role_adapter(wm, {"role_arn": ident})
    assert "aws sts assume-role" in cmd and ident in cmd
