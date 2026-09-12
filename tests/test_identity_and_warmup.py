"""Tests for the wrong-person guardrail (identity_confidence + ledger
gating) and the persisted social state (warmup + follow across restarts)."""
import json
import os
import time

import pytest

from phantom.automation.social.identity_confidence import (
    CONFIRMED,
    PROBABLE,
    UNRELATED,
    IdentityLead,
    may_act,
    score_lead,
)
from phantom.automation.brain.targets import TargetLedger
from phantom.automation.social.persona_state import (
    WARMUP_HOURS_AGGRESSIVE,
    WARMUP_HOURS_DEFAULT,
    PersonaState,
)


# ── identity confidence: the username-collision trap ──────────────────────

PRIMARY = {
    "username": "marco.bianchi",
    "platform": "instagram",
    "bio": "Marco Bianchi - developer based in Milano. Into cycling and photography.",
    "full_name": "Marco Bianchi",
    "emails": ["marco.bianchi@acme.com"],
    "avatar_hash": "sha256:primary-avatar",
    "graph": [],
}


def _cand(**kw):
    base = {"username": "marco.bianchi", "platform": "tiktok",
            "bio": "", "avatar_hash": "", "link": ""}
    base.update(kw)
    return base


def test_same_handle_alone_is_weak():
    """THE trap: identical username on another platform is NOT proof."""
    lead = score_lead("instagram", PRIMARY, _cand())
    assert lead.tier == UNRELATED
    ok, why = may_act(lead, "dm_launch", aggressive=False)
    assert not ok
    assert "UNRELATED" in why


def test_avatar_match_confirms():
    lead = score_lead("instagram", PRIMARY,
                      _cand(avatar_hash="sha256:primary-avatar",
                            bio="totally different"))
    assert lead.tier == CONFIRMED
    ok, _ = may_act(lead, "dm_launch", aggressive=False)
    assert ok


def test_cross_link_confirms():
    lead = score_lead("instagram", PRIMARY,
                      _cand(bio="find me -> instagram.com/marco.bianchi"))
    assert lead.tier == CONFIRMED


def test_email_in_bio_confirms():
    lead = score_lead("instagram", PRIMARY,
                      _cand(bio="biz: marco.bianchi@acme.com"))
    assert lead.tier == CONFIRMED


def test_weak_signals_sum_to_probable_not_confirmed():
    """name-in-bio + interests can never fake one strong proof."""
    lead = score_lead("instagram", PRIMARY, _cand(
        bio="marco bianchi loves cycling and photography and pizza",
        username="marco_b_92"))
    assert lead.tier in (PROBABLE, UNRELATED)
    assert lead.tier != CONFIRMED


def test_probable_read_only_ok_contact_gated():
    lead = IdentityLead(handle="x", platform="tiktok")
    lead.signals = [("name_in_bio", 0.45), ("interest_match", 0.35)]
    assert lead.tier == PROBABLE
    ok, _ = may_act(lead, "deep_recon", aggressive=False)
    assert ok                      # read-only recon always allowed
    ok, why = may_act(lead, "dm_launch", aggressive=False)
    assert not ok and "--aggressive" in why
    ok, _ = may_act(lead, "dm_launch", aggressive=True)
    assert ok                      # explicit operator override


def test_bio_similarity_strong_only_when_high():
    lead = score_lead("instagram", PRIMARY, _cand(
        bio="Marco Bianchi - developer based in Milano. Into cycling and photography."))
    assert lead.tier == CONFIRMED  # >= 0.75 jaccard


def test_contact_graph_overlap_weak_alone():
    """A shared social circle is real evidence, but a tiny overlap (1-2
    people) must never confirm — friends-of-friends overlap naturally."""
    lead = score_lead("instagram", {**PRIMARY, "graph": ["f1", "f2", "f3"]},
                      _cand(bio="totally different", avatar_hash="diff",
                            graph=["f1", "f2"]))
    assert "contact_overlap" not in [s for s, _ in lead.signals]
    assert lead.tier == UNRELATED


def test_contact_graph_overlap_strong_but_not_confirmed():
    """Multiple shared contacts = PROBABLE-grade evidence at most: an
    overlapping circle supports same-person, it cannot prove it."""
    shared = [f"f{i}" for i in range(8)]
    lead = score_lead("instagram",
                      {**PRIMARY, "graph": shared},
                      _cand(bio="totally different", avatar_hash="diff",
                            graph=shared))
    assert "contact_overlap" in [s for s, _ in lead.signals]
    assert lead.tier == PROBABLE
    assert lead.tier != CONFIRMED


def test_contact_overlap_adds_to_weak_signals():
    """Overlap + name-in-bio + interests together reach PROBABLE, never
    CONFIRMED (weak sums cap below the confirmed threshold)."""
    shared = [f"f{i}" for i in range(6)]
    lead = score_lead("instagram", PRIMARY, _cand(
        bio="marco bianchi loves cycling and photography and pizza",
        avatar_hash="diff", graph=shared))
    assert lead.tier == PROBABLE


# ── ledger gating: unconfirmed identity pivots are dead ends ──────────────

def test_ledger_blocks_unconfirmed_identity_pivot():
    ledger = TargetLedger("instagram.com/marco.bianchi")
    ledger.set_identity_tiers({"same.handle.on.tiktok": "unrelated"})
    ledger.register("same.handle.on.tiktok", source="discovered:account_link",
                    cls="identity")
    assert not ledger.activatable("same.handle.on.tiktok")


def test_ledger_aggressive_overrides():
    ledger = TargetLedger("instagram.com/marco.bianchi")
    ledger.set_identity_tiers({"h2": "probable"}, aggressive=True)
    ledger.register("h2", cls="identity")
    assert ledger.activatable("h2")


def test_primary_identity_never_gated():
    ledger = TargetLedger("instagram.com/marco.bianchi")
    ledger.set_identity_tiers({"instagram.com/marco.bianchi": "unrelated"})
    assert ledger.activatable("instagram.com/marco.bianchi")


def test_tiers_serialize():
    ledger = TargetLedger("instagram.com/marco.bianchi")
    ledger.set_identity_tiers({"h2": "confirmed"})
    d = ledger.to_dict()
    assert d["identity_tiers"] == {"h2": "confirmed"}


# ── persisted social state: warmup + follows survive restarts ─────────────

class _Clock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


@pytest.fixture
def state(tmp_path):
    clock = _Clock()
    st = PersonaState(path=str(tmp_path / "social_state.json"), now=clock)
    return st, clock


def test_warmup_blocks_day_zero(state):
    st, _ = state
    st.persona_created("Jess Miller", name="Jess Miller")
    assert not st.warmup_ok("Jess Miller")
    assert st.warmup_remaining("Jess Miller") > (WARMUP_HOURS_DEFAULT - 1) * 3600


def test_warmup_passes_after_deadline(state):
    st, clock = state
    st.persona_created("Jess Miller")
    clock.advance(WARMUP_HOURS_DEFAULT * 3600 + 1)
    assert st.warmup_ok("Jess Miller")
    assert "complete" in st.warmup_note("Jess Miller")


def test_warmup_aggressive_shortened(state):
    st, _ = state
    st.persona_created("Fast One", aggressive=True)
    rem = st.warmup_remaining("Fast One")
    assert rem <= WARMUP_HOURS_AGGRESSIVE * 3600


def test_warmup_idempotent_no_reset(state):
    """Re-registering the same persona never resets the clock."""
    st, clock = state
    st.persona_created("Jess Miller")
    clock.advance(WARMUP_HOURS_DEFAULT * 3600)   # warmup done
    st.persona_created("Jess Miller")            # session 2 re-registers
    assert st.warmup_ok("Jess Miller")           # NOT pushed back to 72h


def test_state_survives_restart(tmp_path):
    """The operator closes phantom on day 0, reopens on day 3: the
    persona is warm and the follow still pending — from DISK."""
    clock = _Clock()
    p = str(tmp_path / "social_state.json")
    s1 = PersonaState(path=p, now=clock)
    s1.persona_created("Jess Miller")
    s1.follow_sent("marco.bianchi", platform="instagram")
    clock.advance(3 * 24 * 3600)
    s2 = PersonaState(path=p, now=clock)         # the "restart"
    assert s2.warmup_ok("Jess Miller")           # warmup aged on the wall
    assert "marco.bianchi" in s2.pending_follows()
    s2.follow_accepted("marco.bianchi")
    s3 = PersonaState(path=p, now=clock)
    assert "marco.bianchi" in s3.accepted_follows()
    assert s3.follow_status("marco.bianchi")["accepted_at"] is not None


def test_corrupt_state_file_starts_empty(tmp_path):
    p = tmp_path / "broken.json"
    p.write_text("{not json", encoding="utf-8")
    st = PersonaState(path=str(p))
    assert st.pending_follows() == []
    st.follow_sent("h")   # and the next save repairs the file
    st2 = PersonaState(path=str(p))
    assert "h" in st2.pending_follows()


def test_state_file_permissions(tmp_path):
    p = str(tmp_path / "perm.json")
    st = PersonaState(path=p)
    st.follow_sent("h")
    if os.name == "posix":
        assert (os.stat(p).st_mode & 0o077) == 0


# ── email variant inference (registration-pattern breach matching) ───────

def _engine_with(**discovered):
    from phantom.automation.social.engine import SocialEngine
    e = SocialEngine()
    e._discovered.update(discovered)
    return e


def test_email_variants_from_name():
    e = _engine_with(name="Mario Rossi", platform="instagram",
                     emails=["m.rossi@acme.com"])
    v = e._email_variants()
    assert "mario.rossi@acme.com" in v
    assert "mariorossi@acme.com" in v
    assert "mrossi@acme.com" in v
    assert all("@" in x for x in v) and len(v) <= 6


def test_email_variants_excludes_known():
    e = _engine_with(name="Mario Rossi", emails=["mario.rossi@acme.com"])
    assert "mario.rossi@acme.com" not in e._email_variants()


def test_email_variants_plus_tag_fallback():
    """No usable name -> derive from the known local part with a plus tag."""
    e = _engine_with(emails=["mr88@acme.com"], platform="tiktok")
    v = e._email_variants()
    assert v == ["mr88+tiktok@acme.com"]


def test_email_variants_empty_without_data():
    e = _engine_with()
    assert e._email_variants() == []


# ── the CONTACT chokepoint gate (not just the ledger pivot) ──────────────

def test_contact_gate_blocks_unconfirmed_handles():
    e = _engine_with()
    e._identity_tiers = {"collision": "unrelated", "maybe": "probable",
                         "proven": "confirmed"}
    assert e._contact_allowed("operator_target") is True   # no tier: primary
    assert e._contact_allowed("proven") is True
    assert e._contact_allowed("collision") is False
    assert e._contact_allowed("maybe") is False


def test_contact_gate_aggressive_overrides():
    e = _engine_with()
    e._identity_tiers = {"collision": "unrelated"}
    e._aggressive = True
    assert e._contact_allowed("collision") is True


def test_identity_conf_markers_populate_tiers():
    """The engine must actually capture IDENTITY_CONF markers from the
    recon pass — otherwise the contact gate has no data to act on."""
    import phantom.automation.social.engine as eng
    from phantom.automation.social import recon as recon_mod
    e = _engine_with(platform="instagram")
    markers = (
        "ACCOUNT_LINK: handle=someone platform=tiktok "
        "url=https://tiktok.com/someone evidence=same_handle\n"
        "IDENTITY_CONF: handle=someone platform=tiktok tier=unrelated "
        "score=0.20 contact=0 reason=identity_UNRELATED\n"
        "IDENTITY_CONF: handle=trusted platform=x tier=confirmed "
        "score=0.85 contact=1 reason=identity_CONFIRMED")
    # drive the marker parse path of deep_recon directly
    orig = recon_mod.deep_recon
    recon_mod.deep_recon = lambda u, p="": (True, markers.splitlines())
    try:
        ok, lines = e.deep_recon("someone", "instagram")
    finally:
        recon_mod.deep_recon = orig
    assert ok
    assert e._identity_tiers.get("someone") == "unrelated"
    assert e._identity_tiers.get("trusted") == "confirmed"
    assert e._contact_allowed("someone") is False
