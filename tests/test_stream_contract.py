"""Tests for the shared event contract (phantom.core.stream_contract).

The bug this closes: the engines emit ~40 event kinds and three renderers
knew three different subsets, so half the signal — including the stall
diagnosis — was emitted and then dropped. These tests make that
impossible:

  * every literal kind the engines emit is CLASSIFIED in the registry
    (the fallback is a safety net, not a crutch);
  * every kind renders, at both verbosity levels, without raising;
  * the level vocabulary is the five tokens the CLI and the UI both map;
  * the UI-facing field names survive (`command`/`reason`/`stealth`), and
    the markers stay in the vocabulary the Electron panel colours by.
"""
import os
import re

import pytest

from phantom.core import stream_contract as sc

_EMIT_RE = re.compile(r"_emit\(\s*[\"']([a-z_]+)[\"']")
_ON_EVENT_RE = re.compile(r"on_event\(\s*[\"']([a-z_]+)[\"']")


def _emitted_kinds():
    """Every literal kind emitted anywhere under phantom/."""
    root = os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "phantom")
    kinds = set()
    for base, _dirs, files in os.walk(root):
        if "__pycache__" in base:
            continue
        for name in files:
            if not name.endswith(".py"):
                continue
            with open(os.path.join(base, name), encoding="utf-8",
                      errors="replace") as handle:
                text = handle.read()
            kinds |= set(_EMIT_RE.findall(text))
            kinds |= set(_ON_EVENT_RE.findall(text))
    return kinds


def test_every_emitted_kind_is_classified():
    """A new event kind must be given a level + wording by hand, not fall
    through to the generic net unnoticed."""
    emitted = _emitted_kinds()
    unclassified = sorted(k for k in emitted if k not in sc.EVENTS)
    assert unclassified == [], (
        "these emitted event kinds have no renderer in "
        f"stream_contract.EVENTS: {unclassified}")


def test_every_registered_kind_renders_at_both_levels():
    for kind in sc.EVENTS:
        for verbose in (True, False):
            rendered = sc.render_event(kind, {"target": "10.0.0.5"},
                                       verbose=verbose)
            if rendered is None:
                continue          # verbose-only and not verbose: intended
            assert rendered.level in sc.LEVELS, kind
            assert rendered.lines, kind
            assert rendered.head == rendered.lines[0]


def test_unknown_kind_still_renders():
    """The safety net: an unclassified kind is VISIBLE as unclassified,
    never silent."""
    rendered = sc.render_event("brand_new_kind", {"detail": "hello"},
                              verbose=True)
    assert rendered is not None
    assert "hello" in rendered.head
    assert "?" in rendered.head


def test_empty_payload_never_crashes():
    for kind in sc.EVENTS:
        sc.render_event(kind, {}, verbose=True)


def test_reasoning_is_verbose_only_but_the_stall_is_not():
    reason = {"hypotheses": [{"capability": "ssh_login", "reason": "reuse"}]}
    assert sc.render_event("reason", reason, verbose=False) is None
    assert sc.render_event("reason", reason, verbose=True) is not None

    stall = {"stall": "no_visibility", "reason": "nothing seen",
             "strategies": ["surface_map"]}
    visible = sc.render_event("stall", stall, verbose=False)
    assert visible is not None
    assert "no_visibility" in visible.head
    assert "surface_map" in visible.head


def test_failures_are_always_visible():
    for kind, payload in (("failed", {"capability": "ssh_banner",
                                      "output": "tool missing"}),
                          ("error", {"capability": "cells",
                                     "detail": "roster unavailable"}),
                          ("blocked", {"capability": "edr_disable",
                                       "reason": "aggressive only"})):
        rendered = sc.render_event(kind, payload, verbose=False)
        assert rendered is not None, kind
        assert rendered.level in ("error", "warn"), kind


def test_found_renders_values_and_degrades_to_the_key():
    with_values = sc.render_event("found", {
        "capability": "ssh_banner",
        "findings": ["banner:tcp/22"],
        "values": {"banner:tcp/22": "SSH-2.0-OpenSSH_8.9"}}, verbose=True)
    assert "SSH-2.0-OpenSSH_8.9" in with_values.head

    # the `banner_ssh:` case the operator saw: no value delivered by the
    # emitter must not produce a dangling separator
    bare = sc.render_event("found", {
        "capability": "ssh_banner",
        "findings": ["banner:tcp/22"]}, verbose=True)
    assert bare.head.rstrip().endswith("banner:tcp/22")


def test_run_keeps_the_ui_field_names():
    """The Electron panel reads command/reason/stealth; the engine emits
    stealth_level. Both must survive the trip."""
    rendered = sc.render_event("run", {
        "target": "10.0.0.5", "banner": "ssh banner",
        "capability": "ssh_banner", "stealth_level": "paranoid",
        "cost": 0.3, "command": "nc -w 5 10.0.0.5 22",
        "reason": "service ssh open"}, verbose=True)
    assert rendered.fields["command"] == "nc -w 5 10.0.0.5 22"
    assert rendered.fields["reason"] == "service ssh open"
    assert rendered.fields["stealth"] == "paranoid"
    assert "nc -w 5" in rendered.text


# The Electron panel colours a log line by the marker in its text. These
# kinds were coloured before the contract existed and must stay that way:
# changing a marker silently degrades the panel to monochrome.
_COLOURED = {
    "run": "[▶]", "found": "[+]", "beacon_up": "[★]",
    "failed": "[ERROR]", "error": "[ERROR]",
    "blocked": "[!]", "tool_missing": "[!]", "stall": "[!]",
    "recover": "[!]", "halt": "[!]", "escalation": "[!]",
    "llm_request": "[!]",
    "note": "[~]", "inference": "[~]", "gate": "[~]",
    "deferred": "[~]", "reason": "[?]", "hypothesis": "[?]",
}


def _payload_for(kind: str) -> dict:
    """Shape-correct payload per kind (``found`` carries bare keys,
    ``inference`` carries finding dicts — they share the field name)."""
    payload = {
        "capability": "x", "output": "y", "detail": "y", "reason": "y",
        "banner": "x", "beacon_id": "b", "stall": "s", "waited": 1,
        "hypotheses": [{"capability": "c", "reason": "r"}],
        "resolved": [{"capability": "c", "status": "confirmed"}],
    }
    if kind == "inference":
        payload["findings"] = [{"kind": "k", "key": "kk",
                                 "value": {"a": "b"}}]
    else:
        payload["findings"] = ["a:b"]
    return payload


@pytest.mark.parametrize("kind,marker", sorted(_COLOURED.items()))
def test_ui_coloured_markers_are_preserved(kind, marker):
    rendered = sc.render_event(kind, _payload_for(kind), verbose=True)
    assert rendered is not None, kind
    assert marker in rendered.head, (kind, rendered.head)


# ── `found` must always carry a value ──────────────────────────────────────
#
# The bug this closes: seven `found` emit sites passed no `values` map (and
# three more inlined their own summary, dropping the cookie-jar guard), so
# the operator saw bare keys like `banner:tcp/22:`. `_emit_found` is now the
# only way the agent emits `found`.

_AGENT_SRC = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "phantom", "automation", "agent.py")


def _agent_source():
    with open(_AGENT_SRC, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def test_agent_never_emits_found_directly():
    """Only `_emit_found` may raise a `found` event."""
    hits = re.findall(r'_emit\(\s*["\']found["\']', _agent_source())
    assert len(hits) == 1, (
        "agent.py emits `found` outside `_emit_found` — the values map (and "
        "the cookie-jar guard) would be lost for that site")


def test_every_found_helper_is_paired_with_a_value_source():
    """`_emit_found` must derive values from the findings (or explicit labels)."""
    src = _agent_source()
    assert "def _emit_found" in src
    assert "_safe_stream_value" in src.split("def _emit_found", 1)[1].split(
        "def ", 1)[0]


class _StubAgent:
    """Just enough of the agent to exercise `_emit_found`."""

    def __init__(self):
        self.events = []

    def _emit(self, kind, **data):
        self.events.append((kind, data))


class _Finding:
    def __init__(self, kind, key, value):
        self.kind = kind
        self.key = key
        self.value = value


def _emit_found(capability, findings=None, **kwargs):
    from phantom.automation.agent import AutonomousAgent
    stub = _StubAgent()
    AutonomousAgent._emit_found(stub, capability, findings, **kwargs)
    assert len(stub.events) == 1
    return stub.events[0]


def test_emit_found_carries_operator_visible_values():
    _kind, data = _emit_found(
        capability="banner_ssh",
        findings=[_Finding("banner", "tcp/22", "SSH-2.0-OpenSSH_8.9")])
    assert data["findings"] == ["banner:tcp/22"]
    assert data["values"] == {"banner:tcp/22": "SSH-2.0-OpenSSH_8.9"}
    assert data["partial"] is False


def test_emit_found_keeps_cookie_jars_local():
    _kind, data = _emit_found(
        capability="cookies",
        findings=[_Finding("stolen_cookies", "jar",
                           {"count": 7, "session": "SECRET-SESSION"})])
    rendered = data["values"]["stolen_cookies:jar"]
    assert "7" in rendered
    assert "SECRET-SESSION" not in rendered


def test_emit_found_accepts_explicit_labels_for_bare_facts():
    _kind, data = _emit_found("ad_awareness", labels=["ad_domain"])
    assert data["findings"] == ["ad_domain"]
    assert data["values"] == {}


class TestSubAgentAndGapVisibility:
    """6.5/6.6: the sub-agent lifecycle and the stall gap must be visible."""

    def test_queued_then_started_then_finished(self):
        queued = sc.render_event("worker", {"worker": "10.0.0.5",
                                            "phase": "queued", "pool": 3})
        assert "queued" in queued.lines[0]
        started = sc.render_event("worker", {"worker": "10.0.0.5",
                                             "phase": "start",
                                             "role": "lead", "workers": 1})
        assert "started" in started.lines[0]
        done = sc.render_event("worker", {
            "worker": "10.0.0.5", "phase": "done", "seconds": 12.5,
            "actions": 7, "failures": 2, "goal_met": True})
        text = done.lines[0]
        assert "12.5" in text and "goal met" in text

    def test_a_failed_sub_agent_says_so(self):
        done = sc.render_event("worker", {
            "worker": "t", "phase": "done", "goal_met": False})
        assert "goal NOT met" in done.lines[0]

    def test_worker_is_always_shown_not_verbose_only(self):
        assert sc.render_event("worker", {"phase": "done"},
                               verbose=False) is not None

    def test_the_gap_names_what_is_still_worth_trying(self):
        rendered = sc.render_event("gap", {
            "goal": "deliver", "missing": "network_beacon",
            "hints": ["beacon_deploy"], "failed": 4, "stall": "transient"})
        text = rendered.lines[0]
        assert "network_beacon" in text
        assert "beacon_deploy" in text
        assert "transient" in text

    def test_degraded_says_which_layer_died(self):
        rendered = sc.render_event("degraded", {
            "layer": "arbiter", "detail": "RuntimeError: boom"})
        assert "arbiter" in rendered.lines[0]
        assert "raw priority" in rendered.lines[0]


def test_task_found_is_verbose_only_and_shows_the_facts():
    payload = {"task": "service", "target": "10.0.0.5",
               "findings": ["service:tcp/22 = SSH-2.0-OpenSSH_8.9"]}
    assert sc.render_event("task_found", payload, verbose=False) is None
    rendered = sc.render_event("task_found", payload, verbose=True)
    text = rendered.head + " ".join(rendered.lines)
    assert "SSH-2.0-OpenSSH_8.9" in text


def test_safe_value_hides_cookie_jars():
    rendered = sc.safe_value("stolen_cookies",
                             {"count": 3, "session": "SECRET"})
    assert "3" in rendered and "SECRET" not in rendered


def test_fact_line_is_the_one_operator_visible_form():
    assert sc.fact_line("banner", "tcp/22", "OpenSSH") == \
        "banner:tcp/22 = OpenSSH"
    assert sc.fact_line("", "tcp/22", "x") == ""


def test_swarm_emits_task_found_with_staged_facts():
    """The swarm path must show what each task produced (6.1b)."""
    import inspect
    from phantom.automation import swarm as swarm_pkg
    src = inspect.getsource(swarm_pkg)
    assert '_events("task_found"' in src
    lines = swarm_pkg._staged_lines([
        {"kind": "service", "key": "tcp/22", "value": {"name": "ssh"}},
        {"kind": "stolen_cookies", "key": "jar",
         "value": {"count": 2, "session": "SECRET"}},
        "not-a-dict",
    ])
    assert len(lines) == 2
    assert "service:tcp/22 = ssh" in lines[0]
    assert "SECRET" not in lines[1]


def test_render_found_shows_value_not_bare_key():
    """The end-to-end fix for `banner_ssh:` with nothing after it."""
    rendered = sc.render_event("found", {
        "capability": "banner_ssh",
        "findings": ["banner:tcp/22"],
        "values": {"banner:tcp/22": "SSH-2.0-OpenSSH_8.9"},
    }, verbose=True)
    assert rendered is not None
    text = rendered.head + " ".join(rendered.lines)
    assert "SSH-2.0-OpenSSH_8.9" in text
    assert not re.search(r"banner:tcp/22:\s*$", text, re.MULTILINE)
