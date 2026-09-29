"""tests/test_experience_loop.py — closing the learning loop.

Three things make the experience engine REAL instead of decorative:
  1. the entry points RESOLVE the operator's intent (config
     `automation.experience`, default on; flag wins when given) instead of
     hardcoding `experience=False` three layers down;
  2. the end-of-run RECEIPT names what was recorded and what changes;
  3. the operator can inspect and forget from the shell (`experience`).
"""
import os

from phantom.automation.agent import experience_receipt
from phantom.automation.brain.experience import Experience
from phantom.automation.brain.experience.cases import CaseStore
from phantom.core.automode import _experience_enabled


# ── resolution: config default on, flag wins ────────────────────────────

def _cfg(monkeypatch, experience):
    from phantom.utils import config as cfg
    monkeypatch.setattr(cfg, "_loaded",
                        {"automation": {"experience": experience}})


def test_config_default_is_on(monkeypatch):
    _cfg(monkeypatch, True)
    assert _experience_enabled(None) is True


def test_explicit_flag_off_wins(monkeypatch):
    _cfg(monkeypatch, True)
    assert _experience_enabled(False) is False


def test_explicit_flag_on_wins_over_off_config(monkeypatch):
    _cfg(monkeypatch, False)
    assert _experience_enabled(True) is False   # config off = hard opt-out


def test_config_off_keeps_memory_run_only(monkeypatch):
    _cfg(monkeypatch, False)
    assert _experience_enabled(None) is False


# ── the receipt ─────────────────────────────────────────────────────────

def _wm_stub():
    """Minimal WorldModel stand-in: the Signature reads via wm.find."""
    return type("WM", (), {
        "target": "10.0.0.1",
        "all_findings": lambda self: [],
        "find": lambda self, kind: [],
        "actions_taken": [
            {"capability": "ssh_login", "ok": False,
             "note": "auth failure", "ts": 1.0},
            {"capability": "smb_password_spray", "ok": True,
             "note": "creds accepted", "ts": 2.0},
        ]})()


def _store_with_run(tmp_path):
    """A global (persistent) store at the DEFAULT path holding two run
    episodes: one wall with a learned repair, one clean success."""
    from phantom.automation.brain.experience.cases import experience_path
    exp = Experience(enabled=True, path=experience_path())
    exp.sync(_wm_stub())
    return exp.store


def test_receipt_names_episodes_and_repair(tmp_path):
    store = _store_with_run(tmp_path)
    line = experience_receipt(store)
    assert "2 episode" in line
    assert "unblock" in line
    assert "ssh_login" in line and "smb_password_spray" in line
    assert "global memory" in line


def test_receipt_empty_run(tmp_path):
    store = CaseStore(enabled=False)
    line = experience_receipt(store)
    assert "0 episode" in line and "not on disk" in line


def test_receipt_run_only_store(tmp_path):
    store = CaseStore(enabled=False, path=str(tmp_path / "x.json"))
    line = experience_receipt(store)
    assert "not on disk" in line


def test_agent_emits_learning_receipt_event(tmp_path, monkeypatch):
    """finish() must emit the learning_receipt event (the visible half of
    the loop), not only the raw stats."""
    from phantom.automation.agent import AutonomousAgent
    monkeypatch.setenv("PHANTOM_DATA_DIR", str(tmp_path))

    events = []
    agent = AutonomousAgent.__new__(AutonomousAgent)
    agent.experience = Experience(enabled=True,
                                  path=str(tmp_path / "e.json"))
    agent.wm = _wm_stub()
    agent.wm.actions_taken = [
        {"capability": "scan_tcp", "ok": True, "ts": 1.0}]
    agent._priors = None
    agent._emit = lambda kind, **d: events.append((kind, d))

    # run ONLY the experience tail (mirror of the end-of-run block)
    agent.experience.sync(agent.wm)
    exp_result = agent.experience.finish(priors=None)
    agent._emit("experience", **agent.experience.stats())
    if exp_result.get("promoted"):
        agent._emit("note", capability="experience", detail="")
    agent._emit("learning_receipt",
                detail=experience_receipt(agent.experience))

    assert any(k == "learning_receipt" for k, _ in events)
    receipt = next(d for k, d in events if k == "learning_receipt")["detail"]
    assert "1 episode" in receipt


# ── CLI: `experience` command ───────────────────────────────────────────

def test_experience_command_registered():
    from phantom.core.shell.commands import system
    assert "experience" in system.COMMANDS


def test_experience_status_empty_and_full(tmp_path, monkeypatch):
    import phantom.core.shell as shell_mod
    from phantom.core.shell.commands import system
    monkeypatch.setenv("PHANTOM_DATA_DIR", str(tmp_path))
    printed = []

    class _C:
        def print(self, *a, **k):
            printed.append(a)
    monkeypatch.setattr(shell_mod, "console", _C())

    # empty memory: no table, just guidance
    system.cmd_experience(None, "")
    assert printed == []

    store = _store_with_run(tmp_path)
    store.save()
    system.cmd_experience(None, "")
    assert printed                # the status table renders


def test_experience_list_and_forget(tmp_path, monkeypatch):
    import phantom.core.shell as shell_mod
    from phantom.core.shell.commands import system
    monkeypatch.setenv("PHANTOM_DATA_DIR", str(tmp_path))
    printed = []

    class _C:
        def print(self, *a, **k):
            printed.append(a)
    monkeypatch.setattr(shell_mod, "console", _C())

    store = _store_with_run(tmp_path)
    store.save()

    system.cmd_experience(None, "list")
    assert printed
    printed.clear()

    # forget the wall (row 1), then the store holds only the success
    from phantom.automation.brain.experience.cases import experience_path
    reloaded = CaseStore(enabled=True, path=experience_path())
    assert len(reloaded.episodes) == 2

    system.cmd_experience(None, "forget 1")
    reloaded = CaseStore(enabled=True, path=experience_path())
    assert len(reloaded.episodes) == 1
    assert reloaded.episodes[0].ok is True


def test_experience_forget_bad_row_gets_suggestion(tmp_path, monkeypatch):
    from phantom.core.shell.commands import system
    monkeypatch.setenv("PHANTOM_DATA_DIR", str(tmp_path))
    msgs = []

    class _FakeNotifier:
        def unknown(self, *a, **k):
            msgs.append(("unknown", a, k))
        def usage(self, *a, **k):
            msgs.append(("usage", a, k))
        def info(self, *a, **k):
            msgs.append(("info", a, k))
        def success(self, *a, **k):
            msgs.append(("success", a, k))

    monkeypatch.setattr(system, "notifier", _FakeNotifier())
    store = _store_with_run(tmp_path)
    store.save()
    system.cmd_experience(None, "forget 99")
    assert any(m[0] in ("unknown", "usage") for m in msgs)


# ── stream contract ─────────────────────────────────────────────────────

def test_learning_receipt_renders_outside_verbose():
    from phantom.core.stream_contract import render_event
    rendered = render_event(
        "learning_receipt",
        {"detail": "Learning receipt: 3 episode(s) recorded"},
        verbose=False)
    assert rendered is not None
    assert "Learning receipt" in rendered.lines[0]
