"""Tests for the MDM vendor fingerprinting capability (active mobile recon)."""
from phantom.automation.belief import WorldModel
from phantom.automation.guidance.kit import (
    _mdm_fingerprint_adapter,
    _mdm_fingerprint_interp,
    _MDM_SIGNATURES,
)


def _wm() -> WorldModel:
    return WorldModel(target="10.0.0.5", target_type="ip")


def test_adapter_probes_vendor_paths():
    cmd = _mdm_fingerprint_adapter(_wm(), {})
    assert "/enroll" in cmd
    assert "api/v1" in cmd
    assert "MDM/1.0" in cmd  # MDM user-agent
    assert "curl" in cmd


def test_adapter_uses_base_url_slot():
    cmd = _mdm_fingerprint_adapter(_wm(), {"base_url": "mdm.corp.com"})
    assert "mdm.corp.com" in cmd


def test_interp_detects_jamf():
    out = (
        "__MDM_START__\n"
        "PATH:/enroll:CODE:200\n"
        "<html>Jamf Pro enrollment portal — Casper Suite v11</html>\n"
        "PATH:/api/v1:CODE:200\n"
        "__MDM_END__"
    )
    findings = _mdm_fingerprint_interp(out, _wm(), {})
    assert findings
    f = findings[0]
    assert f.kind == "mdm_vendor"
    assert "jamf" in f.value["vendors"]
    assert "/enroll" in f.value["open_paths"]


def test_interp_detects_intune_entra():
    out = (
        "__MDM_START__\n"
        "PATH:/enroll:CODE:302\n"
        "redirect to login.microsoftonline.com — Intune Endpoint Management\n"
        "__MDM_END__"
    )
    findings = _mdm_fingerprint_interp(out, _wm(), {})
    assert findings
    assert "intune" in findings[0].value["vendors"]
    assert findings[0].value["auth_hint"] == "entra"


def test_interp_no_match_returns_empty():
    assert _mdm_fingerprint_interp("", _wm(), {}) == []
    out = "__MDM_START__\nPATH:/:CODE:404\nnginx\n__MDM_END__"
    assert _mdm_fingerprint_interp(out, _wm(), {}) == []


def test_all_signature_vendors_covered():
    # sanity: every vendor has at least one lowercase-matchable signature
    for vendor, sigs in _MDM_SIGNATURES.items():
        assert sigs, vendor
        assert all(isinstance(s, str) for s in sigs)


def test_planner_wiring():
    from phantom.automation.planner import _FACT_SOURCES, GOAL_FACTS
    assert "mobile_mdm_fingerprint" in _FACT_SOURCES.get("mdm_vendor", [])
    assert "mdm_vendor" in GOAL_FACTS.get("mobile", [])


def test_capability_registered():
    from phantom.automation.guidance.kit import CAPABILITIES
    assert any(c.id == "mobile_mdm_fingerprint" for c in CAPABILITIES)
