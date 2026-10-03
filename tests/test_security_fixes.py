"""Regression tests for the security fixes from the audit (A/B/D).

Each test pins the INVARIANT that was broken, not an implementation detail:

* A-1  sshpass/ssh/scp argv is shell-quoted and the password never travels as
       an argv element (`sshpass -e` + SSHPASS) — a password harvested ON the
       target cannot inject a command on the operator box.
* A-6  auto-mode refuses to run against a remote target with NO engagement
       scope unless the operator explicitly opted out.
* B-1  `c2.ssl=false` actually disables TLS (bool("false") is True).
* B-2  the Python replay epoch map survives a restart.
* D-3  the state/registry files are hardened to the owner on every platform.
* D-4  the Go data plane and the Python control plane agree on the wire
       format (canonical HMAC string, envelope key, download token).
"""
from __future__ import annotations

import os
import shlex
import tempfile

from phantom.automation.agent import AutonomousAgent

USER = "root; touch /tmp/pwned_phantom_user"
PW = "pw'; touch /tmp/pwned_phantom_pw; #"


def _agent(scope_list=("10.0.0.0/8",)):
    agent = AutonomousAgent(target="10.0.0.5", scope_list=list(scope_list))
    agent.wm.add_finding(
        "creds", "ssh-1",
        {"username": USER, "password": PW, "service": "ssh", "valid": True},
        source="test")
    return agent


def _capture_runtime(bucket):
    class _Runtime:
        def runner(self, cmd, timeout=None):
            bucket.append(cmd)
            from unittest.mock import Mock
            res = Mock()
            res.ok = False
            res.stdout = ""
            res.stderr = ""
            return res
    return _Runtime()


# ── A-1: no shell injection from harvested credentials ──────────────────

def test_ssh_probe_quotes_credentials(monkeypatch):
    monkeypatch.setattr(
        "phantom.automation.guidance.kit._effective_target",
        lambda wm: "10.0.0.5")
    agent = _agent()
    bucket = []
    agent.runtime = _capture_runtime(bucket)
    assert agent._ssh_creds_ok(USER, PW) is False   # runner says "failed"
    assert bucket, "the probe must actually run"
    cmd = bucket[0]
    # the password is a SINGLE env assignment token, never split into shell
    # words; the metacharacters it carries stay inert.
    tokens = shlex.split(cmd)
    assert f"SSHPASS={PW}" in tokens, cmd
    assert "touch" not in tokens, cmd
    assert "/tmp/pwned_phantom_pw" not in tokens, cmd
    assert "sshpass" in tokens and "-e" in tokens, cmd


def test_remote_exec_quotes_credentials(monkeypatch):
    monkeypatch.setattr(
        "phantom.automation.guidance.kit._effective_target",
        lambda wm: "10.0.0.5")
    monkeypatch.setattr(
        "phantom.utils.network.get_c2_endpoint",
        lambda: ("203.0.113.9", 8443))
    agent = _agent()
    agent._target_platform = lambda: "linux"
    agent._ssh_creds_ok = lambda u, p: True
    fd, binary = tempfile.mkstemp(prefix="fake_beacon_", suffix=".bin")
    with os.fdopen(fd, "wb") as fh:
        fh.write(b"BEACON")
    agent._last_beacon_binary = binary

    cmd = agent._wrap_remote_exec("ignored")
    tokens = shlex.split(cmd)
    assert f"SSHPASS={PW}" in tokens, cmd
    assert "touch" not in tokens, cmd
    assert "/tmp/pwned_phantom_pw" not in tokens, cmd
    # user/target are one login token, not a split
    assert "root" not in tokens, cmd
    assert any(t.endswith("@10.0.0.5") for t in tokens), cmd
    # the beacon endpoint is still delivered
    assert "203.0.113.9" in cmd and "8443" in cmd
    os.unlink(binary)


def test_sshpass_env_password_is_redacted_and_not_persisted():
    """A-1 ships the password as `SSHPASS=<quoted>`, so it must be masked
    wherever commands are surfaced or stored (stream/redaction + session
    history, which is serialized into data/sessions/*.json)."""
    from phantom.utils.redact import redact_text
    out = redact_text("SSHPASS='p;w' sshpass -e ssh root@10.0.0.5 'id'")
    assert "p;w" not in out and "SSHPASS=[REDACTED]" in out
    assert "plainpw" not in redact_text("SSHPASS=plainpw sshpass -e scp a b")

    from phantom.core.session import session
    original = list(session.history)
    try:
        session.history = []
        session.add_history("sshpass -p hunter2 ssh root@10.0.0.5 'id'")
        session.add_history("SSHPASS='hunter2' sshpass -e ssh root@10.0.0.5 'id'")
        assert all("hunter2" not in line for line in session.history)
        assert any("sshpass" in line for line in session.history)
    finally:
        session.history = original


# ── A-6: unscoped auto-mode fails closed ────────────────────────────────

def test_unscoped_auto_mode_fails_closed(monkeypatch):
    import phantom.core.scope as scope
    agent = AutonomousAgent(target="10.0.0.5", scope_list=[])

    monkeypatch.setattr(scope, "unscoped_allowed", lambda: False)
    assert agent._scope_ok() is False, (
        "auto-mode must refuse a remote target when no scope is declared")

    monkeypatch.setattr(scope, "unscoped_allowed", lambda: True)
    assert agent._scope_ok() is True, (
        "an explicit opt-out must allow the lab path")


def test_identity_target_is_always_in_scope(monkeypatch):
    import phantom.core.scope as scope
    monkeypatch.setattr(scope, "unscoped_allowed", lambda: False)
    agent = AutonomousAgent(target="bob@corp.com", scope_list=[])
    assert agent._scope_ok() is True, (
        "the identity subject must stay in scope regardless of the machine "
        "scope list")


# ── B-1: c2.ssl=false is parsed canonically ─────────────────────────────

def test_c2_ssl_false_actually_disables_tls(monkeypatch):
    from phantom.utils.network import get_c2_front
    monkeypatch.setenv("PHANTOM_C2_FRONT", "front.example:8443")
    monkeypatch.setenv("PHANTOM_C2_SSL", "false")
    front = get_c2_front()
    assert front is not None
    assert front[2] is False, "PHANTOM_C2_SSL=false must disable TLS"
    monkeypatch.setenv("PHANTOM_C2_SSL", "true")
    assert get_c2_front()[2] is True


# ── B-2: the replay epoch map survives a restart ────────────────────────

def test_replay_epoch_persists_across_restart(monkeypatch, tmp_path):
    monkeypatch.setattr("phantom.utils.paths.data_dir", lambda: str(tmp_path))
    from phantom.core.c2_server import C2State

    st1 = C2State()
    st1._nonce_epoch = {"B-1": {"nonce-x": st1.auth_epoch}}
    st1._persist_replay_state()

    st2 = C2State()          # a "restart": fresh random epoch
    restored = st2._nonce_epoch.get("B-1", {})
    assert restored.get("nonce-x") == st1.auth_epoch, (
        "the nonce->epoch binding must be reloaded from disk")
    assert restored["nonce-x"] != st2.auth_epoch, (
        "and it must be a PREVIOUS epoch, so the stale-epoch check fires")


# ── D-3: state files are owner-only on every platform ───────────────────

def test_secret_store_hardens_and_reports(tmp_path):
    from phantom.utils.secret_store import harden_file, locked_down
    path = tmp_path / "secret.json"
    path.write_text("{}", encoding="utf-8")
    if os.name != "nt":
        os.chmod(path, 0o644)
        assert locked_down(str(path)) is False
    harden_file(str(path))
    assert locked_down(str(path)) is True
    if os.name != "nt":
        assert (os.stat(path).st_mode & 0o077) == 0


# ── D-4: Go <-> Python wire-format parity ───────────────────────────────

def test_wire_format_parity_with_go():
    """Vectors are pinned in c2d/c2d_test.go; if the three implementations
    (beacon, Python, Go) disagree the traffic silently never decrypts."""
    from phantom.utils.beacon_auth import canonical_request, sign_request
    from phantom.utils.c2_crypto import beacon_download_token, beacon_envelope_key

    secret = bytes(range(32))
    assert beacon_envelope_key(secret, "B-TEST").hex() == (
        "275c2265389eb7081752b239a2ab65fab82938b05e579d7937ded40bc33b5afc")
    assert beacon_envelope_key(secret, "").hex() == (
        "88170beeb2e2a92e1c5875050d69741b6d7384ed20e930ceaa366d2fa50ba182")
    assert beacon_envelope_key(secret, "B-\u00e8-t\u00e9st").hex() == (
        "7c6eb272b1b1478f38248badb802e48e71c5af45b8a74b6c68aa67aeff7b337e")
    assert beacon_download_token(secret, "B-TEST") == (
        "f8a955bf74dc5a93aa0407d58429898600aade9123bb3b23f5bb38dadcb608d6")
    assert beacon_download_token(b"", "B-TEST") == ""

    # canonical string: METHOD\nPATH\nTS\nCOUNTER\nNONCE\nBODY
    assert canonical_request("GET", "/api/v1/ping", "1759000000", "7",
                             "abc123", "") == (
        b"GET\n/api/v1/ping\n1759000000\n7\nabc123\n")

    hmac_secret = bytes(range(32))   # same vector secret as c2d_test.go
    assert sign_request(hmac_secret, "GET", "/api/v1/ping", "1759000000",
                        "7", "abc123", "") == (
        "fd9d0747fe8d1210778af9460e598447eb10cc13d43ec6d0d49e84466673ab4d")
    assert sign_request(hmac_secret, "POST", "/x.js", "1759000042", "19",
                        "n0nce", "Y2lwaGVy") == (
        "44f31f3cc0e878a0d31e985875e742db20ae2ea5f3e9042926334e69b849e955")


# ── redact: concatenated `-pSecret` must be masked (no flag false positives) ──

def test_redact_concatenated_short_password_flag():
    from phantom.utils.redact import redact_text
    # the classic `mysql -p<password>` shape (no separator) used to leak
    assert "S3cr3t" not in redact_text("mysql -pS3cr3t -h db")
    assert redact_text("mysql -pS3cr3t -h db") == "mysql -p[REDACTED] -h db"
    assert redact_text("mysql -p'hunter2' -h db") == "mysql -p[REDACTED] -h db"
    assert redact_text('mysqldump -p"pa$$wd" db') == "mysqldump -p[REDACTED] db"


def test_redact_does_not_mask_ordinary_p_flags_or_ports():
    from phantom.utils.redact import redact_text
    assert redact_text("ssh -p 2222 host") == "ssh -p 2222 host"
    assert redact_text("mysql -p3306") == "mysql -p3306"
    assert redact_text("curl -path /tmp/x") == "curl -path /tmp/x"
    assert redact_text("tool -port 80 host") == "tool -port 80 host"
    assert redact_text("cmd -proxy http://x") == "cmd -proxy http://x"
