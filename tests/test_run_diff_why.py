"""tests/test_run_diff_why.py — run-diff (#4) and the why command (#5).

run_diff answers "did the second run go further?" from two checkpoints;
`why` answers "why did the agent do that?" from the persisted decision
trace. Both are pure reads: no targets, no tools.
"""
import json
import os

import pytest


# ── run_diff ─────────────────────────────────────────────────────────────

def _ckpt(path, findings, failed=None, actions=None, target="10.0.0.1"):
    doc = {
        "schema": 1, "target": target, "goal": "deliver",
        "failed_caps": failed or {},
        "wm": {
            "target": target,
            "findings": findings,
            "actions": actions or [],
        },
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    return path


F = lambda kind, key, conf=0.8, src="scan": {
    "kind": kind, "key": key, "confidence": conf, "source": src}


def test_diff_reports_new_lost_changed(tmp_path):
    from phantom.core.run_diff import diff_files
    a = _ckpt(str(tmp_path / "a.json"),
              [F("service", "tcp/22"), F("os", "detected", 0.5)])
    b = _ckpt(str(tmp_path / "b.json"),
              [F("service", "tcp/22"), F("os", "detected", 0.9, "banner"),
               F("creds", "ssh:root")])
    d = diff_files(a, b)
    assert [(f["kind"], f["key"]) for f in d.new_findings] == \
        [("creds", "ssh:root")]
    assert [(f["kind"], f["key"]) for f in d.lost_findings] == []
    assert len(d.changed_findings) == 1 and d.changed_findings[0]["key"] == \
        "detected"
    assert d.progressed and not d.regressed


def test_diff_walls_resolved_and_new(tmp_path):
    from phantom.core.run_diff import diff_files
    a = _ckpt(str(tmp_path / "a.json"), [F("service", "tcp/22")],
              failed={"ssh_login": 1.0, "smb_login": 2.0})
    b = _ckpt(str(tmp_path / "b.json"), [F("service", "tcp/22")],
              failed={"smb_login": 2.0, "http_admin": 3.0})
    d = diff_files(a, b)
    assert d.resolved_failures == ["ssh_login"]
    assert d.new_failures == ["http_admin"]
    assert d.progressed and d.regressed     # mixed run


def test_verdict_lines(tmp_path):
    from phantom.core.run_diff import diff_files, format_report
    a = _ckpt(str(tmp_path / "a.json"), [], failed={"x": 1.0})
    b = _ckpt(str(tmp_path / "b.json"), [F("service", "tcp/80")])
    assert "FURTHER" in format_report(diff_files(a, b))
    a2 = _ckpt(str(tmp_path / "a2.json"), [F("service", "tcp/80")])
    b2 = _ckpt(str(tmp_path / "b2.json"), [])
    assert "REGRESSED" in format_report(diff_files(a2, b2))


def test_load_run_accepts_bare_wm_dump(tmp_path):
    from phantom.core.run_diff import load_run
    p = str(tmp_path / "wm.json")
    with open(p, "w", encoding="utf-8") as fh:
        json.dump({"target": "h", "findings": [F("service", "tcp/22")]}, fh)
    r = load_run(p)
    assert r["target"] == "h" and len(r["findings"]) == 1


def test_run_diff_command_registered_and_renders(tmp_path, monkeypatch):
    import phantom.core.shell as shell_mod
    from phantom.core.shell.commands import system
    a = _ckpt(str(tmp_path / "a.json"), [])
    b = _ckpt(str(tmp_path / "b.json"), [F("service", "tcp/80")])
    printed = []

    class _C:
        def print(self, *a, **k):
            printed.append(a)
    monkeypatch.setattr(shell_mod, "console", _C())

    assert "run_diff" in system.COMMANDS
    system.cmd_run_diff(None, f"{a} {b}")
    assert printed and "FURTHER" in str(printed[0][0])


def test_run_diff_usage_on_bad_args():
    from phantom.core.shell.commands import system
    msgs = []

    class _N:
        def usage(self, *a, **k):
            msgs.append(a)
    old = system.notifier
    system.notifier = _N()
    try:
        system.cmd_run_diff(None, "only-one")
    finally:
        system.notifier = old
    assert msgs


# ── why (decision trace) ─────────────────────────────────────────────────

def _trace_entry(seq=1, cap="ssh_login", driver="evidence"):
    return {
        "seq": seq, "capability": cap, "stage": "creds",
        "value": 1.4, "base": 1.0, "driver": driver,
        "runner_up": "opsec", "profile": "balanced",
        "search_policy": "greedy", "veto": "",
        "contributions": {"evidence": 0.4}, "signals": {}, "ts": 1.0,
    }


def test_why_reads_trace_from_checkpoint(tmp_path, monkeypatch):
    import phantom.core.shell as shell_mod
    from phantom.core.shell.commands import system
    doc = {"schema": 1, "wm": {"trace": {"entries": [_trace_entry()]}}}
    cp = str(tmp_path / "cp.json")
    with open(cp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    printed = []

    class _C:
        def print(self, *a, **k):
            printed.append(str(a[0]) if a else "")
    monkeypatch.setattr(shell_mod, "console", _C())

    system.cmd_why(None, f"--trace {cp}")
    assert printed and "#1 ssh_login" in printed[0]
    assert "evidence" in " ".join(printed)     # the driver lens is shown


def test_why_unknown_capability_suggests(tmp_path, monkeypatch):
    import phantom.core.shell as shell_mod
    from phantom.core.shell.commands import system
    doc = {"wm": {"trace": {"entries": [_trace_entry(cap="ssh_login")]}}}
    cp = str(tmp_path / "cp.json")
    with open(cp, "w", encoding="utf-8") as fh:
        json.dump(doc, fh)
    monkeypatch.setattr(shell_mod, "console",
                        type("_C", (), {"print": lambda self, *a, **k: None})())
    msgs = []

    class _N:
        def unknown(self, *a, **k):
            msgs.append(a)
    old = system.notifier
    system.notifier = _N()
    try:
        system.cmd_why(None, f"--trace {cp} smb_login")
    finally:
        system.notifier = old
    assert msgs and "ssh_login" in str(msgs[0])


def test_why_missing_checkpoint_is_a_clean_error(monkeypatch):
    from phantom.core.shell.commands import system
    msgs = []

    class _N:
        def error(self, *a, **k):
            msgs.append(a)
    old = system.notifier
    system.notifier = _N()
    try:
        system.cmd_why(None, "--trace /no/such/cp.json")
    finally:
        system.notifier = old
    assert msgs


def test_why_no_source_available(monkeypatch):
    from phantom.core.shell.commands import system
    msgs = []

    class _N:
        def error(self, *a, **k):
            msgs.append(a)
    old = system.notifier
    system.notifier = _N()
    try:
        monkeypatch.setattr(
            "phantom.core.session.session", type("S", (), {})(),
            raising=False)
        system.cmd_why(None, "")
    finally:
        system.notifier = old
    assert msgs
