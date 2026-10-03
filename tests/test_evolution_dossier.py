"""Point 3 — the self-improvement loop must produce APPROVABLE PRs.

The evolution loop already authored code + tests + a PR. What it could not do
was be approved safely without reading the raw transcript, and it said NOTHING
when the lab was unreachable (no lab -> the whole run was skipped). These
tests pin the two fixes:

  * the PR body is a DOSSIER (problem, authored files, gate, verification,
    blast radius, revert, checklist), not a transcript appendix;
  * an unproven artifact is published as an explicitly UNVERIFIED PR — its
    title says so, its body carries a loud banner and an unchecked box — and
    the loop no longer goes silent when the lab is down.
"""

from types import SimpleNamespace

from phantom.automation.evolution import publish as publish_mod


def _result(verified=True):
    return SimpleNamespace(
        cap_relpath="phantom/automation/guidance/learned/foo.py",
        test_relpath="tests/learned/test_foo.py",
        proposal_relpath="docs/evolution/20261002-abc.md",
        attempts=2,
        verified=verified,
        gate_history=[{"stage": "static", "ok": True, "detail": "clean"},
                      {"stage": "lab", "ok": verified, "detail": "dry-run"}],
    )


def _body(verified=True):
    gate_md = publish_mod._gate_markdown(_result(verified))
    return publish_mod._dossier("20261002-abc", "auto-evolution/20261002-abc",
                                _result(verified), "# Proposal\nbody",
                                gate_md, verified)


# ── the dossier ───────────────────────────────────────────────────────────

def test_the_pr_body_is_a_dossier_with_the_review_sections():
    body = _body(True)
    for section in ("## Failure it closes", "## What was authored",
                    "## Gate results", "## Verification", "## Blast radius",
                    "## Revert", "## Review checklist"):
        assert section in body, section
    assert "phantom/automation/guidance/learned/foo.py" in body
    assert "attempts used: 2" in body
    assert "nothing auto-loads before merge" in body.lower() or \
           "nothing auto-loads before merge" in body


def test_a_verified_pr_records_the_lab_proof():
    body = _body(True)
    assert "full gate including the lab dry-run" in body
    assert "NOT VERIFIED" not in body


def test_an_unverified_pr_is_loudly_marked():
    body = _body(False)
    assert "NOT VERIFIED" in body
    assert "- [ ] **NOT VERIFIED**" in body
    assert "Do NOT merge" in body


def test_the_title_carries_the_verification_state():
    assert publish_mod._pr_title("x", True) == \
        "[auto-evolution] learned capability x"
    assert publish_mod._pr_title("x", False) == \
        "[auto-evolution] UNVERIFIED learned capability x"


# ── the loop does not go silent when the lab is down ──────────────────────

def test_lab_unreachable_spawns_an_unverified_worker(tmp_path, monkeypatch):
    from phantom.automation.evolution import loop

    spawned_threads = []

    class FakeThread:
        def __init__(self, **kw):
            spawned_threads.append(kw)

        def start(self):
            pass

    monkeypatch.setattr(loop.threading, "Thread", FakeThread)
    state = loop.EvolutionState(tmp_path / "state.json")
    notes = []
    spawned = loop.maybe_spawn(
        [{"sig_hash": "abc123", "signature_summary": "s", "technique": "t",
          "cause": "waf_blocked"}],
        advisor=None, wm=None,
        emit=lambda kind, **d: notes.append(d.get("detail")),
        state=state, lab_ok=False)

    assert spawned, "the loop must not skip when the lab is unreachable"
    details = " ".join(str(n) for n in notes)
    assert "UNVERIFIED" in details
    # the worker was told it is unverified (so it skips the lab stage)
    assert spawned_threads[0]["kwargs"]["unverified"] is True
    assert spawned_threads[0]["kwargs"]["mode"] == "code"


def test_beta_never_loads_without_a_lab(monkeypatch):
    """Ring C, pinned: a PR-open (pre-merge) capability only ever loads
    with `--beta` AND a reachable lab AND a proven digest. Without the lab
    the loader refuses EVERYTHING rather than trusting the PR."""
    from phantom.automation.evolution import beta as beta_mod

    monkeypatch.setattr(beta_mod, "fetch_open_evolution_prs",
                        lambda: [{"number": 1, "body": "",
                                  "head": {"ref": "auto-evolution/x"}}])
    monkeypatch.setattr(beta_mod.gate_mod, "lab_available", lambda: False)
    notes = []
    res = beta_mod.load_beta(emit=lambda kind, **d: notes.append(d.get("detail")))
    assert res.loaded == 0 and res.checked == 0
    assert any("lab" in str(n) for n in notes), notes


def test_author_accepts_the_unverified_path():
    """`require_lab=False` is the flag the worker passes; the signature must
    accept it (and default to the proven path)."""
    import inspect
    from phantom.automation.evolution import author as author_mod
    sig = inspect.signature(author_mod.author)
    assert "require_lab" in sig.parameters
    assert sig.parameters["require_lab"].default is True
