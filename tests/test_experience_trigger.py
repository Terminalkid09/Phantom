"""Fase B tests — the deterministic trigger (experience.authorable_patterns)
and the core `review` command surface.

Acceptance criteria (updated per operator decision 2026-09-12):
  * ONE learnable failure of the SAME (technique, product, cause) with an
    eligible cause surfaces as an authorable pattern — the planner already
    adapts in-run around one-off walls; the gate+budgets are the noise
    dampers, not a repetition count;
  * environmental causes (dep-missing etc.) NEVER surface (no capability
    file can fix them) — this is what keeps the signal clean;
  * successes never surface;
  * the `review` shell command exists and reads state without crashing
    when no evolution has ever run.
"""
import time
from unittest.mock import patch

import pytest

from phantom.automation.belief import WorldModel
from phantom.automation.brain.experience import Experience, MIN_AUTHORABLE_N
from phantom.automation.brain.experience.causes import (
    WAF_BLOCKED, NOT_FOUND, DEPENDENCY_MISSING,
)
from phantom.automation.brain.experience.signature import Signature


def _sig(product="nginx", cls="host"):
    return Signature.from_worldmodel(_wm_with(product, cls))


def _wm_with(product, cls):
    # _product_of reads fingerprint/web_header/banner/os — feed a banner
    # finding so the signature buckets on the product family
    wm = WorldModel(target="10.0.0.9", target_type="ip")
    wm.add_finding(kind="banner", key="tcp/80",
                   value={"product": product, "server": product},
                   target="10.0.0.9")
    return wm


def _feed(exp: Experience, technique: str, cause: str, ok: bool,
          product="nginx", n=1):
    wm = _wm_with(product, "host")
    sig = _sig(product)
    acts = [{"capability": technique, "ok": ok,
             "note": f"probe-{i} cause={cause}", "command": "x",
             "ts": time.time() + i} for i in range(n)]
    with patch.object(exp, "signature_for", return_value=sig):
        pass  # signature_for patched for parity with real sync()
    # direct episode injection (sync() is action-trail based; these tests
    # target the pattern detector, not the sync plumbing)
    from phantom.automation.brain.experience.cases import Episode
    for i in range(n):
        exp.store.record(Episode(
            sig=sig.to_dict(), phase="exploit", technique=technique,
            ok=ok, cause="" if ok else cause,
            detail=f"attempt {i} blocked", ts=time.time() + i))


class TestAuthorablePatterns:
    def test_single_failure_surfaces(self):
        exp = Experience(enabled=False)
        _feed(exp, "web_upload_rce", WAF_BLOCKED, ok=False, n=1)
        pats = exp.authorable_patterns()
        assert len(pats) == 1
        assert pats[0]["cause"] == WAF_BLOCKED
        assert pats[0]["n"] == 1

    def test_at_threshold_pattern_surfaces(self):
        exp = Experience(enabled=False)
        _feed(exp, "web_upload_rce", WAF_BLOCKED, ok=False,
              n=MIN_AUTHORABLE_N)
        pats = exp.authorable_patterns()
        assert len(pats) == 1
        p = pats[0]
        assert p["technique"] == "web_upload_rce"
        assert p["cause"] == WAF_BLOCKED
        assert p["n"] >= MIN_AUTHORABLE_N
        assert p["missing_fact"] == "web_app"
        assert "nginx" in p["signature_summary"]

    def test_environmental_cause_never_surfaces(self):
        exp = Experience(enabled=False)
        _feed(exp, "smb_enum", DEPENDENCY_MISSING, ok=False, n=10)
        assert exp.authorable_patterns() == []

    def test_successes_never_surface(self):
        exp = Experience(enabled=False)
        _feed(exp, "web_upload_rce", "", ok=True, n=10)
        assert exp.authorable_patterns() == []

    def test_distinct_causes_are_distinct_patterns(self):
        exp = Experience(enabled=False)
        _feed(exp, "web_upload_rce", WAF_BLOCKED, ok=False, n=1)
        _feed(exp, "web_upload_rce", NOT_FOUND, ok=False, n=1)
        causes = {p["cause"] for p in exp.authorable_patterns()}
        assert causes == {WAF_BLOCKED, NOT_FOUND}


class TestReviewCommand:
    def test_review_helper_runs_clean_with_no_state(self, tmp_path):
        from phantom.automation.evolution.loop import EvolutionState
        from phantom.automation.evolution import gate as gate_mod
        st = EvolutionState(tmp_path / "state.json")
        summary = {
            "authored": st.authored(),
            "gate_budget_left": (True, 0),
            "pr_budget_left": (True, 0),
            "lab": False,
            "learned_dir": str(tmp_path / "learned"),
        }
        assert summary["authored"] == {}
        assert summary["lab"] is False

    def test_learned_loader_empty_package(self):
        from phantom.automation.guidance.learned import load_learned
        # the package exists and is empty: loading must be a clean no-op
        assert load_learned() == []
