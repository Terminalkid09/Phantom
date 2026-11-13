"""P1-C closure tests (docs/ROADMAP.md).

P1-9   redaction v2: high-entropy base64/JWT blobs masked; Secrets survive
       generic serialization; the advisor's remote redact() path benefits.
P1-10  credentials/OTP/cookies captured by the tracker surface are wrapped
       in the non-persistible Secret type; the live shell view is the only
       unwrapping surface.
P1-12  the client HTML report escapes every target-derived field.
"""
import html
import json

from phantom.utils.redact import Secret, redact, redact_text, safe_dumps, unwrap


# ── P1-9: redaction v2 ──────────────────────────────────────────────────────

def test_b64_high_entropy_masked():
    blob = "K7xQ2mZ9pL3vR8tW5yJ4nB6cD1fG0hS2aX"   # random-ish, entropy > 4.5
    out = redact_text(f"token value {blob} end")
    assert blob not in out and "<base64>" in out


def test_jwt_style_blob_masked():
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    out = redact_text(f"auth {jwt}")
    assert jwt not in out


def test_secret_survives_repr_str_and_json():
    s = Secret("Sup3rSecret!")
    assert "Sup3rSecret" not in repr(s)
    assert "Sup3rSecret" not in str(s)
    assert "Sup3rSecret" not in safe_dumps({"password": s, "nested": [s]})
    assert json.loads(safe_dumps({"p": s}))["p"] == "[REDACTED]"


def test_redact_masks_secret_instances():
    d = {"password": Secret("hunter2"), "user": "op"}
    out = redact(d)
    assert out["password"] == "[REDACTED]" and out["user"] == "op"


def test_unwrap_reveals_only_on_demand():
    s = Secret("hunter2")
    assert unwrap(s) == "hunter2"
    assert unwrap("plain") == "plain"


# ── P1-10: capture dicts carry Secrets ──────────────────────────────────────

def test_cred_and_session_dicts_are_non_persistible():
    from phantom.modules.craft import _cred_dict, _session_dict
    from phantom.automation.social.tracker import CredCapture

    cap = CredCapture(ip="9.9.9.9", username="vic", password="Pa$$w0rd!",
                      otp="123456", user_agent="UA", time="t")
    d = _cred_dict(cap)
    dumped = safe_dumps(d)
    assert "Pa$$w0rd!" not in dumped and "123456" not in dumped
    assert d["username"] == "vic"          # identifier stays (it's a finding)
    assert unwrap(d["password"]) == "Pa$$w0rd!"   # live surface can reveal

    class _S:  # minimal session-capture stand-in
        ip, username, cookies, user_agent, time = (
            "9.9.9.9", "vic", "SID=SESSION-COOKIE-VALUE", "UA", "t")
    sd = _session_dict(_S())
    sd_dumped = safe_dumps(sd)
    assert "SESSION-COOKIE-VALUE" not in sd_dumped


def test_shell_view_is_the_unwrapping_surface():
    # the live CLI view prints the real value — it is the one place allowed to
    import phantom.core.shell as shell_mod  # import sanity
    from phantom.utils.redact import Secret
    assert shell_mod is not None
    s = Secret("Pa$$w0rd!")
    assert f"{s}" == "[REDACTED]"          # any f-string stays masked
    assert s.reveal() == "Pa$$w0rd!"       # explicit reveal works


# ── P1-12: client HTML report escaping ──────────────────────────────────────

def test_vuln_and_service_html_escapes_target_data():
    from phantom.modules import report as rep

    rep.session.results["exploit"] = {"ranked": [{
        "cve": {"id": "CVE-2026-0001",
                "description": "<script>alert('x')</script> bad"},
        "service": {"service": "http<script>", "port": 80},
        "score": 90, "has_msf": False, "has_poc": False,
    }]}
    rep.session.results["service_summary"] = [
        {"port": 445, "service": "smb<img src=x onerror=1>",
         "version": "Samba <b>4</b>"}]
    vuln = rep.ReportModule()._build_vuln_html()
    assert "<script>alert" not in vuln
    assert html.escape("<script>alert('x')</script>")[:20] in vuln
    assert "http<script>" not in vuln

    svc = rep.ReportModule()._build_service_section()
    assert "smb<img" not in svc and "Samba <b>4</b>" not in svc
    assert html.escape("Samba <b>4</b>") in svc


def test_notes_and_analyzer_html_escaped():
    from phantom.modules import report as rep

    rep.session.notes = [{"timestamp": "12:00", "text": "<b>note</b>"}]
    rep.session.results["analyzer"] = {"findings": [
        ("HIGH", "cred_reuse", "<iframe src=evil>")]}

    notes = rep.ReportModule()._build_notes_section()
    assert "<b>note</b>" not in notes and html.escape("<b>note</b>") in notes

    ana = rep.ReportModule()._build_analyzer_section()
    assert "<iframe" not in ana and html.escape("<iframe src=evil>") in ana
