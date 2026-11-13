"""Advisors: proposals capped, drafts judged, failures fall back."""
from __future__ import annotations

from phantom.automation.ai.router import AIResult
from phantom.automation.ai.advisors import evolution, osint, social


def _ai(data, model="test-model"):
    return AIResult(ok=True, data=data, text="", model=model, error="",
                    latency_ms=1)


# ── OSINT ──────────────────────────────────────────────────────────────────

def test_osint_drops_a_pair_the_caller_never_supplied(monkeypatch):
    def fake_ask(*_a, **_k):
        return _ai({"links": [
            {"handle": "mario", "platform": "x", "confidence": 0.95,
             "reason": "same bio"},
            {"handle": "ghost", "platform": "x", "confidence": 0.9},
        ]})

    monkeypatch.setattr(osint, "ask", fake_ask)
    advice = osint.propose_links(
        {"handle": "mario"},
        [{"handle": "mario", "platform": "x", "bio": "dev"}])
    assert advice.ok is True
    assert [link["handle"] for link in advice.links] == ["mario"]


def test_osint_confidence_can_never_reach_confirmed(monkeypatch):
    monkeypatch.setattr(
        osint, "ask",
        lambda *_a, **_k: _ai({"links": [
            {"handle": "mario", "platform": "x", "confidence": 1.0}]}))
    advice = osint.propose_links({"handle": "mario"},
                                 [{"handle": "mario", "platform": "x"}])
    assert advice.links[0]["confidence"] <= 0.79


def test_osint_failure_returns_no_advice(monkeypatch):
    monkeypatch.setattr(osint, "ask",
                        lambda *_a, **_k: AIResult(ok=False, error="off"))
    advice = osint.propose_links({"handle": "mario"},
                                 [{"handle": "mario", "platform": "x"}])
    assert advice.ok is False and advice.links == []
    assert advice.error == "off"


# ── SOCIAL ─────────────────────────────────────────────────────────────────

def test_a_draft_with_a_critical_tell_is_not_ready(monkeypatch):
    monkeypatch.setattr(
        social, "ask",
        lambda *_a, **_k: _ai({"text": "Ciao Mario, inserisci la password "
                                       "per confermare il tuo account."}))
    out = social.draft({"target_name": "Mario"}, channel="dm")
    assert out.ok is True
    assert out.ready is False
    assert "credential_request" in out.issues


def test_an_invented_url_is_stripped_and_the_draft_is_not_ready(monkeypatch):
    monkeypatch.setattr(
        social, "ask",
        lambda *_a, **_k: _ai({"text": "Ciao Mario, apri "
                                       "https://evil.example/login per il "
                                       "pacco in giacenza."}))
    out = social.draft({"target_name": "Mario",
                        "link": "https://track.example/x"},
                       channel="dm")
    assert "evil.example" not in out.text
    assert "invented_url_stripped" in out.issues
    assert out.ready is False


def test_a_plausible_draft_is_ready(monkeypatch):
    monkeypatch.setattr(
        social, "ask",
        lambda *_a, **_k: _ai({"text": "Ciao Mario, sono Luca del negozio: "
                                       "il corriere ha fermato il pacco in "
                                       "giacenza, puoi confermare "
                                       "l'indirizzo?"}))
    out = social.draft({"target_name": "Mario"}, channel="dm")
    assert out.ok is True and out.ready is True
    assert out.score >= 60


def test_apply_to_body_keeps_the_original_on_fallback():
    original = "deterministic body"
    out = social.apply_to_body(
        original, social.SocialDraft(ok=False, error="ai disabled"))
    assert out[0] == original
    assert "fallback" in out[1]


def test_apply_to_body_uses_a_ready_draft():
    proposal = social.SocialDraft(ok=True, ready=True, text="AI body",
                                  score=80, model="m")
    body, marker = social.apply_to_body("deterministic", proposal)
    assert body == "AI body"
    assert "ready=1" in marker


# ── EVOLUTION ──────────────────────────────────────────────────────────────

def test_evolution_falls_back_to_deterministic_grouping(monkeypatch):
    monkeypatch.setattr(evolution, "ask",
                        lambda *_a, **_k: AIResult(ok=False, error="off"))
    cases = [
        {"goal": "footprint", "stall": "no_path"},
        {"goal": "footprint", "stall": "no_path"},
        {"goal": "creds", "stall": "auth_failed"},
    ]
    out = evolution.summarize_cases(cases)
    assert out["source"] == "deterministic"
    assert "2x footprint" in out["summary"]
    assert out["causes"][0] == "no_path"


def test_evolution_uses_the_model_when_it_answers(monkeypatch):
    monkeypatch.setattr(
        evolution, "ask",
        lambda *_a, **_k: _ai({"summary": "stable no_path on footprint",
                               "causes": ["missing proxy"],
                               "proposal": "add a proxy probe"}))
    out = evolution.summarize_cases([{"goal": "footprint",
                                      "stall": "no_path"}])
    assert out["source"] == "ai"
    assert out["summary"].startswith("stable")


# ── ENGINE HOOK ────────────────────────────────────────────────────────────

class _Link:
    short_url = "https://track.example/x"
    code = "x"


def _render_env(monkeypatch):
    """Isolate _render_for from the dossier/spoof stack (not under test)."""
    import phantom.automation.social.engine as engine_mod

    class _Dossier:
        def to_dict(self):
            return {}

    monkeypatch.setattr(engine_mod, "_load_dossier",
                        lambda: (lambda _d: _Dossier(), None, None),
                        raising=False)
    monkeypatch.setattr("phantom.automation.social.spoof.derive_sender",
                        lambda *_a, **_k: ("Sender", "s@b.com"),
                        raising=False)
    monkeypatch.setattr("phantom.automation.social.spoof.apply",
                        lambda display, addr, subj, seed=0: (display, addr,
                                                             subj),
                        raising=False)
    return engine_mod


def test_engine_adds_no_ai_marker_when_the_layer_is_off(monkeypatch):
    engine_mod = _render_env(monkeypatch)
    monkeypatch.setattr("phantom.automation.ai.ai_enabled", lambda *_a: False,
                        raising=False)
    eng = engine_mod.SocialEngine()
    eng._discovered = {}
    out = eng._render_for("a@b.com", None, "Subject",
                          "A deterministic body long enough to render.",
                          _Link(), pixel=False)
    assert out.get("ai_social", "") == ""


def test_engine_uses_a_ready_draft_only(monkeypatch):
    import phantom.automation.ai as ai_pkg
    import phantom.automation.ai.advisors.social as social_mod
    engine_mod = _render_env(monkeypatch)

    monkeypatch.setattr(ai_pkg, "ai_enabled", lambda *_a: True,
                        raising=False)
    monkeypatch.setattr(
        social_mod, "draft",
        lambda *_a, **_k: social_mod.SocialDraft(
            ok=True, ready=True, text="AI body", score=85, model="m"))
    eng = engine_mod.SocialEngine()
    eng._discovered = {}
    out = eng._render_for("a@b.com", None, "Subject",
                          "A deterministic body long enough to render.",
                          _Link(), pixel=False)
    assert out["body_text"] == "AI body"
    assert "ready=1" in out["ai_social"]
