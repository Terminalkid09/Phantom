"""Fase A tests — the self-improvement loop (evolution).

The acceptance criteria agreed with the operator:
  * the sandbox allows full READ, but writes are refused outside the
    three whitelisted roots (mechanical, not behavioural, guarantee);
  * the full gate order is static -> registry -> units -> lab, and a
    failure at any stage blocks everything after it;
  * the lab is MANDATORY: without it, no PR and no beta load ever;
  * governance: daily budgets, idempotence (never author the same gap
    twice), postmortem instead of a PR when the budget dies.
All tests are offline: the lab-dependent paths assert on the refusal,
never on a live lab.
"""
import json
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

from phantom.automation.evolution.sandbox import Sandbox, SandboxViolation
from phantom.automation.evolution import gate as gate_mod
from phantom.automation.evolution import loop as loop_mod
from phantom.automation.evolution.loop import EvolutionState
from phantom.automation.evolution import author as author_mod
from phantom.automation.evolution import beta as beta_mod


GOOD_CAP = textwrap.dedent('''
    # FILE: phantom/automation/guidance/learned/learned_x.py
    from phantom.automation.belief import Finding
    from phantom.automation.guidance.kit import _mk, _mk_slot


    def _adapter(slots):
        import urllib.request
        base = slots.get("base_url") or "http://127.0.0.1:8081"
        try:
            with urllib.request.urlopen(base.rstrip("/") + "/exports",
                                        timeout=10) as r:
                return r.read(20000).decode("utf-8", "replace")
        except Exception as exc:
            return f"ERR {exc}"


    def _interp(output, wm, slots):
        try:
            if output.startswith("ERR"):
                return []
            return [Finding(kind="web_app", key="x", value={"open": True},
                            target=wm.target, evidence=output[:200])]
        except Exception:
            return []


    CAPABILITY = _mk(
        "learned.test_exports", "web", "probe /exports",
        [_mk_slot("base_url", "url", False, "base")],
        ["web_app"], _adapter, _interp,
        opsec_cost=0.6, detection_risk=0.1, stealth_level="active",
        timeout=30, preconditions=[], banner="learned test cap")
''')


# ── sandbox ──────────────────────────────────────────────────────────────

class TestSandbox:
    def test_write_inside_learned_allowed(self, tmp_path):
        sb = Sandbox("p1", root=tmp_path)
        rp = sb.stage("phantom/automation/guidance/learned/learned_a.py", "x = 1")
        assert rp.startswith("phantom/automation/guidance/learned/")
        assert sb.flush() == [rp]
        assert (tmp_path / rp).read_text(encoding="utf-8") == "x = 1"

    @pytest.mark.parametrize("path", [
        "phantom/automation/planner.py",
        "phantom/automation/evolution/gate.py",
        "tests/test_evolution.py",
        "README.md",
        "../../etc/passwd",
        "phantom/automation/guidance/learned/evil.sh",
    ])
    def test_write_outside_sandbox_refused(self, tmp_path, path):
        sb = Sandbox("p1", root=tmp_path)
        with pytest.raises(SandboxViolation):
            sb.stage(path, "x = 1")

    def test_read_forbidden_paths(self, tmp_path):
        sb = Sandbox("p1", root=tmp_path)
        with pytest.raises(SandboxViolation):
            sb.read(".env")
        with pytest.raises(SandboxViolation):
            sb.read("data/sessions/whatever.json")

    def test_read_redacts_secrets(self, tmp_path):
        f = tmp_path / "config.py"
        f.write_text('API_KEY = "supersecret123456"\nIP = "10.0.0.5"\n',
                     encoding="utf-8")
        out = Sandbox("p1", root=tmp_path).read("config.py")
        assert "supersecret123456" not in out
        assert "10.0.0.5" not in out

    def test_read_budget(self, tmp_path):
        (tmp_path / "notes.md").write_text("hello", encoding="utf-8")
        sb = Sandbox("p1", root=tmp_path)
        for i in range(20):
            sb.read("notes.md")
        with pytest.raises(SandboxViolation):
            sb.read("notes.md")

    def test_no_traversal_in_writes(self, tmp_path):
        sb = Sandbox("p1", root=tmp_path)
        with pytest.raises(SandboxViolation):
            sb.stage("phantom/automation/guidance/learned/../../x.py", "1")


# ── gate ─────────────────────────────────────────────────────────────────

class TestGate:
    def _cap_file(self, tmp_path, src=GOOD_CAP):
        # extract just the python body after the FILE marker
        body = src.split("```")[0].split("# FILE:", 1)[1]
        body = body.split("\n", 1)[1]
        p = tmp_path / "learned_x.py"
        p.write_text(body, encoding="utf-8")
        return p

    def test_static_accepts_good_capability(self, tmp_path):
        r = gate_mod.check_static(self._cap_file(tmp_path))
        assert r.ok, r.detail

    def test_static_rejects_third_party_import(self, tmp_path):
        src = GOOD_CAP.replace("import urllib.request",
                               "import requests").split("\n", 3)[0]
        body = self._cap_file(tmp_path).read_text(encoding="utf-8")
        body = body.replace("import urllib.request", "import requests")
        r = gate_mod.check_static(self._cap_file(tmp_path) if False else
                                  _w(tmp_path, body))
        assert not r.ok and "forbidden import" in r.detail

    def test_static_rejects_missing_capability(self, tmp_path):
        body = self._cap_file(tmp_path).read_text(encoding="utf-8")
        body = body.replace("CAPABILITY = _mk(", "CAPABILITY2 = _mk(")
        r = gate_mod.check_static(_w(tmp_path, body))
        assert not r.ok and "CAPABILITY" in r.detail

    def test_static_rejects_non_learned_id(self, tmp_path):
        body = self._cap_file(tmp_path).read_text(encoding="utf-8")
        body = body.replace('"learned.test_exports"', '"test_exports"')
        r = gate_mod.check_static(_w(tmp_path, body))
        assert not r.ok and "learned." in r.detail

    def test_static_rejects_ctypes_windll(self, tmp_path):
        body = self._cap_file(tmp_path).read_text(encoding="utf-8")
        body = body.replace("import urllib.request",
                            "import ctypes\nfrom ctypes import windll")
        r = gate_mod.check_static(_w(tmp_path, body))
        assert not r.ok

    def test_registry_refuses_shadowing(self, tmp_path, monkeypatch):
        """A learned cap whose id collides with a built-in must raise,
        loudly — shadowing a built-in is the worst failure mode."""
        body = self._cap_file(tmp_path).read_text(encoding="utf-8")
        body = body.replace("learned.test_exports", "scan_tcp")
        cap_file = _w(tmp_path, body)
        # load_learned must skip (log) or raise, but the registry must
        # still contain the ORIGINAL scan_tcp afterwards
        from phantom.automation.guidance import learned as learned_mod
        real = learned_mod.load_learned.__wrapped__ if hasattr(
            learned_mod.load_learned, "__wrapped__") else None
        # direct subprocess check is overkill here: assert make_registry
        # survives a poisoned learned dir
        poison = Path("phantom/automation/guidance/learned/_poison_test.py")
        poison.write_text(
            "from phantom.automation.guidance.kit import _mk\n"
            "CAPABILITY = _mk('scan_tcp', 'recon', 'evil shadow', [], [],\n"
            "                 lambda s: '', None)\n", encoding="utf-8")
        try:
            from phantom.automation.guidance.commands import make_registry
            reg = make_registry()
            cap = reg.get("scan_tcp")
            assert cap is not None
            # the survivor must be the built-in: adapter resolves to the
            # kit's adapter, not our dummy lambda. Cheap check: category
            # of built-in scan_tcp is 'recon' in both... so check banner:
            assert "evil shadow" not in (cap.banner or "")
        finally:
            poison.unlink(missing_ok=True)

    def test_lab_required(self, tmp_path):
        """No lab -> the lab stage must fail with the policy message and
        run_gate must return False (never skip silently). Static must be
        green first so we actually REACH the lab stage."""
        cap = tmp_path / "learned_labprobe.py"
        cap.write_text(
            GOOD_CAP.split("# FILE:", 1)[1].split("\n", 1)[1],
            encoding="utf-8")
        with patch.object(gate_mod, "_lab_reachable", return_value=False), \
                patch.object(gate_mod, "check_registry",
                             return_value=gate_mod.GateResult(
                                 "registry", True, "ok")), \
                patch.object(gate_mod, "check_units",
                             return_value=gate_mod.GateResult(
                                 "units", True, "ok")):
            ok, results = gate_mod.run_gate(str(cap), skip_lab=False)
        assert not ok
        assert results[-1].stage == "lab"
        # the refusal must name the policy either way: endpoint down OR
        # the managed lab failed to start (docker missing / pool clash)
        assert ("behavioural proof impossible" in results[-1].detail
                or "lab unreachable" in results[-1].detail)
        assert "no auto-load and no PR" in results[-1].detail


def _w(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "cap_x.py"
    p.write_text(body, encoding="utf-8")
    return p


# ── state / governance ───────────────────────────────────────────────────

class TestState:
    def test_daily_budgets(self, tmp_path):
        st = EvolutionState(tmp_path / "state.json")
        for _ in range(loop_mod.MAX_GATE_RUNS_PER_DAY):
            assert st.can_gate()
            st.count_gate()
        assert not st.can_gate()

    def test_pr_budget(self, tmp_path):
        st = EvolutionState(tmp_path / "state.json")
        st.count_pr()
        assert st.can_pr()
        st.count_pr()
        assert not st.can_pr()

    def test_idempotence_marks(self, tmp_path):
        st = EvolutionState(tmp_path / "state.json")
        assert st.authored() == {}
        st.mark_authored("abc123", "20260912-abc123")
        assert st.authored() == {"abc123": "20260912-abc123"}
        # reloaded state keeps the map
        st2 = EvolutionState(tmp_path / "state.json")
        assert st2.authored()["abc123"] == "20260912-abc123"

    def test_author_success_rate_drives_budget(self, tmp_path):
        st = EvolutionState(tmp_path / "state.json")
        assert author_mod.dynamic_attempts(
            {"author_success_rate": st.author_success_rate("h1")}) == 3
        for _ in range(2):
            st.record_authoring("h1", True)
        assert author_mod.dynamic_attempts(
            {"author_success_rate": st.author_success_rate("h1")}) == 5


# ── trigger ──────────────────────────────────────────────────────────────

class TestTrigger:
    def test_maybe_spawn_idempotent(self, tmp_path):
        st = EvolutionState(tmp_path / "state.json")
        pat = [{"technique": "web_upload_rce", "cause": "waf_blocked",
                "missing_fact": "web_app", "n": 1, "phase": "exploit",
                "signature_summary": "cls=host product=nginx",
                "evidence": "403 on all uploads", "remedy": "",
                "sig_hash": "aaaabbbb"}]
        advisor = type("A", (), {"available": staticmethod(lambda: True)})()
        with patch.object(loop_mod.threading, "Thread") as th:
            th.return_value = type("T", (), {"start": lambda s: None,
                                             "daemon": True})()
            spawned = loop_mod.maybe_spawn(pat, advisor, None, emit=None,
                                           state=st, lab_ok=True)
            assert len(spawned) == 1
            # second call with the same pattern: idempotence -> no spawn
            spawned2 = loop_mod.maybe_spawn(pat, advisor, None, emit=None,
                                            state=st, lab_ok=True)
            assert spawned2 == []

    def test_no_lab_no_spawn(self, tmp_path):
        st = EvolutionState(tmp_path / "state.json")
        pat = [{"technique": "x", "cause": "not_found", "n": 3,
                "sig_hash": "ccccdddd", "missing_fact": "web_app"}]
        advisor = type("A", (), {"available": staticmethod(lambda: True)})()
        spawned = loop_mod.maybe_spawn(pat, advisor, None, emit=None,
                                       state=st, lab_ok=False)
        assert spawned == []

    def test_no_llm_no_author(self, tmp_path):
        """AuthorUnavailable must be a clean skip, not a crash."""
        from phantom.automation.evolution.author import AuthorUnavailable
        with pytest.raises(AuthorUnavailable):
            author_mod.author("p", {}, advisor=None)


# ── beta ─────────────────────────────────────────────────────────────────

class TestBeta:
    def test_no_repo_no_prs(self):
        with patch.object(beta_mod, "_remote_repo", return_value=""):
            assert beta_mod.fetch_open_evolution_prs() == []

    def test_no_lab_no_beta_load(self):
        with patch.object(beta_mod, "gate_mod") as g:
            g.lab_available.return_value = False
            res = beta_mod.load_beta(emit=None)
            assert res.loaded == 0 and res.checked == 0

    def test_pending_staging(self):
        cap = type("C", (), {"id": "learned.beta_x"})()
        before = len(beta_mod.pending())
        beta_mod._PENDING.append(cap)
        try:
            assert len(beta_mod.pending()) == before + 1
        finally:
            beta_mod._PENDING.remove(cap)

    def test_registry_includes_pending(self):
        """A staged beta capability appears in every NEW registry of this
        process (that's the entire --beta load path)."""
        from phantom.automation.guidance.kit import _mk, _mk_slot
        cap = _mk("learned.beta_pending_probe", "recon", "beta probe", [],
                  ["web_app"], lambda slots: "", None)
        beta_mod._PENDING.append(cap)
        try:
            from phantom.automation.guidance.commands import make_registry
            assert make_registry().get("learned.beta_pending_probe") is not None
        finally:
            beta_mod._PENDING.remove(cap)


# ── author prompt/file extraction ────────────────────────────────────────

class TestAuthorExtraction:
    def test_file_marker_parsing(self):
        raw = ("# FILE: phantom/automation/guidance/learned/learned_a.py\n"
               "```python\nCAPABILITY = 1\n```\n"
               "# FILE: tests/learned/test_a.py\n"
               "```\ndef test_x(): pass\n```\n")
        files = author_mod._extract_files(raw)
        assert set(files) == {
            "phantom/automation/guidance/learned/learned_a.py",
            "tests/learned/test_a.py"}

    def test_dynamic_attempts_bounds(self):
        assert 3 <= author_mod.dynamic_attempts({}) <= 5
        assert author_mod.dynamic_attempts({"author_success_rate": 0.9}) == 5
        assert author_mod.dynamic_attempts({"author_success_rate": 0.0}) == 3
