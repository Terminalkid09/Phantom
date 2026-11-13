"""Tests: the fuzz engine exposed as a planable capability (P3).

The generative fuzz engine (``brain/fuzz``) existed but no capability ever
invoked it, so it never reached the chain. These tests pin the seam:

* no web surface / no injected sender -> the kit's ``# comment`` convention,
  never a network call (the capability cannot invent traffic);
* a parameter whose probe trips the differential oracle -> a typed
  ``hunt_anomaly`` finding carrying evidence, the same value shape
  ``_hunt_web_interp`` produces;
* honesty: a single differential is a CANDIDATE; only a reproduced signal is
  ``confirmed`` (mirrors the anomaly engine's validation pass);
* determinism (fixed seed + fake sender) and the declared request budget;
* garbage / truncated output and a ``None`` WorldModel never raise.
"""

from phantom.automation.belief import Finding, WorldModel
from phantom.automation.brain.fuzz import capability as CAP
from phantom.automation.brain.fuzz.capability import (
    CAPABILITY_ID,
    MARKER,
    NO_OP,
    _discovered_params,
    fuzz_adapter,
    fuzz_engine,
    fuzz_interp,
    run_fuzz,
)
from phantom.automation.brain.fuzz.oracles import Response


# ── fixtures ───────────────────────────────────────────────────────────────

def _wm(target="10.13.37.9", with_web=True):
    wm = WorldModel(target=target, target_type="ip")
    if with_web:
        wm.add_finding("service", "tcp/8080",
                       {"port": "8080", "service": "http"},
                       confidence=0.9, source="scan_tcp")
    return wm


def _error_sender(calls):
    """Baseline clean, any mutation of an injectable param -> DB error."""
    def sender(param, payload):
        calls.append((param, payload))
        if payload == "phantom-baseline-0":
            return Response(200, "<html>ok</html>", 0.05)
        if param == "q":
            return Response(500, "MySQLSyntaxErrorException: syntax error",
                            0.06)
        return Response(200, "<html>ok</html>", 0.05)
    return sender


# ── (a) no precondition: comment line, no findings, no calls ──────────────

def test_no_web_surface_yields_comment_line():
    wm = _wm(target="10.13.37.9", with_web=False)
    out = fuzz_adapter(wm, {})
    assert out.startswith("#"), out
    assert fuzz_interp(out, wm, {}) == []


def test_no_sender_never_executes():
    lines = run_fuzz(_wm(), sender=None, params=["q"])
    assert lines == [NO_OP]
    assert fuzz_interp("\n".join(lines), _wm(), {}) == []


def test_no_params_yields_comment_line():
    calls = []
    lines = run_fuzz(_wm(), sender=_error_sender(calls), params=[])
    assert lines == [NO_OP]
    assert calls == []


def test_adapter_on_a_target_without_web_still_points_at_the_surface():
    # a web service exists -> the adapter is a marker stub, not a shell command
    out = fuzz_adapter(_wm(), {})
    assert out.startswith("fuzz://"), out
    assert "://" in out


# ── (b) a tripped oracle becomes a typed finding with evidence ────────────

def test_tripped_oracle_yields_typed_finding_with_evidence():
    calls = []
    wm = _wm()
    lines = run_fuzz(wm, sender=_error_sender(calls), params=["q"],
                     rounds=1, max_requests=30, seed=11)
    assert lines and lines[0].startswith(MARKER)

    findings = fuzz_interp("\n".join(lines), wm, {})
    assert findings, "no finding parsed from markers"
    for f in findings:
        assert isinstance(f, Finding)
        assert f.kind == "hunt_anomaly"
        assert f.source == CAPABILITY_ID
        assert 0.0 < f.confidence <= 0.9

    hit = [f for f in findings if f.value["param"] == "q"]
    assert hit, "the injectable parameter was not reported"
    assert hit[0].value["cls"] == "sqli"
    assert hit[0].value["signals"] == "error_based"
    assert hit[0].value["evidence"], "evidence must prove the belief"
    assert f.evidence
    # reproduced -> confirmed, and a confirmed strong signal is high/critical
    assert hit[0].value["confirmed"] is True
    assert hit[0].value["severity"] in ("high", "critical")
    assert hit[0].value["port"] == "8080"


def test_endpoint_comes_from_discovery_when_known():
    wm = _wm()
    wm.add_finding("hunt_anomaly", "sqli:8080:q",
                   {"cls": "sqli", "param": "q", "endpoint": "/search?q=1"},
                   confidence=0.6, source="hunt_web")
    calls = []
    lines = run_fuzz(wm, sender=_error_sender(calls), params=["q"],
                     rounds=1, max_requests=20, seed=3)
    hits = [l for l in lines if "endpoint=/search" in l]
    assert hits, lines


def test_discovered_params_reads_the_live_endpoint():
    wm = _wm()
    wm.add_finding("hunt_anomaly", "sqli:8080:q",
                   {"cls": "sqli", "param": "q", "endpoint": "/search?q=1"},
                   confidence=0.6, source="hunt_web")
    params = _discovered_params(wm)
    assert params[0] == "q", params


# ── honesty: one differential is a candidate, not a confirmation ──────────

def test_single_differential_is_not_confirmed():
    state = {"mutations": 0}

    def sender(param, payload):
        if payload == "phantom-baseline-0":
            return Response(200, "ok", 0.05)
        state["mutations"] += 1
        if state["mutations"] == 1:
            return Response(500, "MySQLSyntaxErrorException", 0.06)
        return Response(200, "ok", 0.05)   # the signal does not REPRODUCE

    lines = run_fuzz(_wm(), sender=sender, params=["q"], rounds=1,
                     max_requests=30, seed=5)
    findings = fuzz_interp("\n".join(lines), _wm(), {})
    assert len(findings) == 1, lines
    assert findings[0].value["confirmed"] is False
    # an unconfirmed candidate is never escalated to the confirmed band
    assert findings[0].value["severity"] in ("medium", "high")
    assert findings[0].value["severity"] != "critical"


# ── (c) determinism ───────────────────────────────────────────────────────

def test_same_seed_same_markers():
    a = run_fuzz(_wm(), sender=_error_sender([]), params=["q"], rounds=2,
                 max_requests=25, seed=99)
    b = run_fuzz(_wm(), sender=_error_sender([]), params=["q"], rounds=2,
                 max_requests=25, seed=99)
    assert a == b


# ── (d) the declared budget is a real bound ───────────────────────────────

def test_request_budget_is_respected():
    calls = []
    run_fuzz(_wm(), sender=_error_sender(calls), params=["q", "id"],
             rounds=3, max_requests=12, seed=1)
    assert len(calls) <= 12, len(calls)


# ── (e) garbage in, no exception out ─────────────────────────────────────

def test_interp_never_raises_on_garbage():
    wm = _wm()
    assert fuzz_interp(None, wm, {}) == []
    assert fuzz_interp(12345, wm, {}) == []
    assert fuzz_interp("FUZZ:\nFUZZ: garbage\nnot a marker", wm, {}) == []
    # a marker missing cls/param is skipped, not fatal
    assert fuzz_interp("FUZZ: param=q score=9.0\nFUZZ: cls=sqli", wm, {}) == []


def test_interp_tolerates_a_none_worldmodel():
    line = (f"{MARKER} cls=sqli param=q name=sqli-g0 endpoint=/ port=80 "
            "signals=error_based score=2.60 confirmed=false severity=medium "
            "requests=3 evidence=error_based:mysql_error_surfaced")
    findings = fuzz_interp(line, None, {})
    assert len(findings) == 1
    assert findings[0].target == ""


def test_adapter_survives_a_nonsense_worldmodel():
    assert fuzz_adapter(None, None).startswith("#")


# ── (f) the RUN owns the transport ────────────────────────────────────────
#
# The engine used to build its own curl transport no matter what the caller
# passed, so the capability escaped the run's governance: a live pass at 60
# requests × curl's 8s ceiling held the orchestrator's drain window open for
# minutes (measured: a 600s stall in the aggressive kill-chain test). The
# run's transport now travels in, exactly like the hunt's `runner`.

def test_the_engine_uses_the_transport_the_run_injected():
    calls = []
    out = fuzz_engine(_wm(), {}, sender=_error_sender(calls))
    assert calls, "the injected sender was never used"
    assert MARKER in out, out


def test_without_an_injected_transport_the_live_path_is_the_only_one(
        monkeypatch):
    monkeypatch.setattr(CAP, "_live_sender", lambda *a, **k: None)
    assert fuzz_engine(_wm(), {}) == NO_OP


def test_a_run_that_injects_its_transport_never_opens_its_own():
    """An injected `hunt_runner` is the run's HTTP path; the fuzz pass uses
    it instead of inventing a curl one (the offline campaign regression)."""
    from phantom.automation.agent import AutonomousAgent

    calls = []

    def hunt_runner(method, url, body="", timeout=8.0):
        calls.append((method, url))
        return Response(200, "ok", 0.0)

    wm = _wm()
    agent = AutonomousAgent(target=wm.target, target_type="ip",
                            hunt_runner=hunt_runner, shared_wm=wm)
    assert agent.fuzz_sender is not None, \
        "the injected transport was not adopted for the fuzz pass"
    agent.fuzz_sender("q", "1' OR 1=1")
    assert calls and calls[0][0] == "GET", calls
    assert "q=" in calls[0][1], calls[0]


def test_a_run_with_no_injected_transport_keeps_the_bounded_fallback():
    from phantom.automation.agent import AutonomousAgent
    agent = AutonomousAgent(target="10.13.37.9", target_type="ip")
    assert agent.fuzz_sender is None


def test_the_pass_stops_at_the_wall_clock_deadline():
    """A slow transport must not outlive the pass's declared budget."""
    import time
    calls = []

    def slow(param, payload):
        calls.append((param, payload))
        time.sleep(0.4)
        return Response(200, "ok", 0.4)

    run_fuzz(_wm(), sender=slow, params=["q"], rounds=3, max_requests=60,
             deadline=time.time() + 1.0)
    assert 0 < len(calls) <= 5, calls


# ── (g) the engine channel forwards the transport ────────────────────────

def test_run_engine_hands_the_injected_sender_to_the_engine():
    from phantom.automation.guidance.commands import make_registry, run_engine
    cap = make_registry().get(CAPABILITY_ID)
    assert cap is not None and cap.engine is not None
    calls = []
    # a port no other test uses keeps the module-level TTL cache out of the
    # way (the cache key is (cap, target, slots, injected keys))
    out = run_engine(cap, _wm(), {"port": "8123"},
                     injected={"sender": _error_sender(calls)})
    assert calls, "run_engine did not forward the sender"
    assert MARKER in out, out


def test_an_engine_that_takes_no_transport_is_untouched():
    """The forwarding is signature-aware: no engine gets a stray kwarg."""
    from phantom.automation.guidance.commands import Capability, run_engine

    def engine(wm, slots):
        return "OK: no transport here"

    cap = Capability(id="probe_engine_only", category="recon",
                     description="engine with no transport", engine=engine,
                     exec_class="in_process_engine", timeout=5)
    out = run_engine(cap, _wm(), {}, injected={"sender": object()})
    assert out == "OK: no transport here", out
