"""Tests for the real-target simulation fixes.

Each test locks one fix that came out of the "simulate against real targets
on every profile/goal" pass, so the failure it prevents cannot silently
return:

- B1  callback plausibility (a beacon whose endpoint cannot be dialed)
- A3  impacket tool aliases (`impacket-secretsdump` == `secretsdump.py`)
- A2  `nmap -O` gated on raw-socket availability
- A1  the planner's rejected candidates surfaced on a halt
- A5  checkpoint schema mismatch reported on resume
- C1  a module's missing tools gated before it runs
- A4  profile/goal combinations that cannot succeed, warned up front
- A6  artifact disk usage measured (never auto-deleted)
- C2  C2 transport hardening (bind, TLS floor, required client cert)
"""
import json


# ── B1: callback plausibility ───────────────────────────────────────────

def test_callback_unroutable_host_is_implausible():
    from phantom.utils.network import callback_plausibility
    for host in ("", "0.0.0.0", "::"):
        ok, reason = callback_plausibility("8.8.8.8", host)
        assert not ok
        assert "c2.host" in reason


def test_callback_loopback_is_implausible_for_a_remote_target():
    from phantom.utils.network import callback_plausibility
    ok, reason = callback_plausibility("8.8.8.8", "127.0.0.1")
    assert not ok and "loopback" in reason.lower()


def test_callback_private_endpoint_against_external_target_is_implausible():
    from phantom.utils.network import callback_plausibility
    ok, reason = callback_plausibility("8.8.8.8", "192.168.1.10")
    assert not ok and "private" in reason.lower()
    # an external DOMAIN is external too
    ok, _ = callback_plausibility("example.com", "10.0.0.5")
    assert not ok


def test_callback_private_endpoint_on_a_lan_target_is_plausible():
    from phantom.utils.network import callback_plausibility
    ok, reason = callback_plausibility("192.168.1.50", "192.168.1.10")
    assert ok and "lan" in reason.lower()


def test_callback_internal_name_is_plausible_without_dns():
    from phantom.utils.network import callback_plausibility
    assert callback_plausibility("intranet.corp", "10.0.0.5")[0]
    assert callback_plausibility("dc01", "10.0.0.5")[0]


def test_callback_public_endpoint_is_plausible():
    from phantom.utils.network import callback_plausibility
    assert callback_plausibility("8.8.8.8", "1.2.3.4")[0]


def test_callback_identity_target_has_no_callback_yet():
    from phantom.utils.network import callback_plausibility
    assert callback_plausibility("analyst@example.com", "127.0.0.1")[0]


# ── C2 listener bind / plaintext guard ──────────────────────────────────

def test_listener_bind_defaults_to_all_interfaces(monkeypatch):
    from phantom.core import c2_server
    from phantom.utils import config as cfg
    monkeypatch.delenv("PHANTOM_C2_BIND", raising=False)
    monkeypatch.setattr(cfg, "_loaded", {})
    assert c2_server.listener_bind_host() == "0.0.0.0"


def test_listener_bind_respects_env_override(monkeypatch):
    from phantom.core import c2_server
    monkeypatch.setenv("PHANTOM_C2_BIND", "127.0.0.1")
    assert c2_server.listener_bind_host() == "127.0.0.1"


def test_plaintext_is_refused_by_default(monkeypatch):
    from phantom.core import c2_server
    from phantom.utils import config as cfg
    monkeypatch.delenv("PHANTOM_ALLOW_PLAINTEXT", raising=False)
    monkeypatch.setattr(cfg, "_loaded", {})
    assert c2_server._plaintext_allowed() is False
    monkeypatch.setenv("PHANTOM_ALLOW_PLAINTEXT", "1")
    assert c2_server._plaintext_allowed() is True


def test_required_client_cert_is_the_default(monkeypatch):
    from phantom.core import c2_server
    from phantom.utils import config as cfg
    monkeypatch.delenv("PHANTOM_MTLS_REQUIRE_CLIENT_CERT", raising=False)
    monkeypatch.setattr(cfg, "_loaded", {})
    assert c2_server._mtls_require_client_cert() is True
    monkeypatch.setenv("PHANTOM_MTLS_REQUIRE_CLIENT_CERT", "0")
    assert c2_server._mtls_require_client_cert() is False


# ── A3: impacket tool aliases ───────────────────────────────────────────

def test_tool_candidates_include_impacket_variants():
    from phantom.automation.runtime import toolchain as tc
    cands = tc.tool_candidates("secretsdump.py")
    assert "secretsdump.py" in cands and "impacket-secretsdump" in cands


def test_registry_has_is_alias_aware():
    from phantom.automation.runtime import toolchain as tc
    assert tc.ToolRegistry(installed={"impacket-secretsdump"}).has(
        "secretsdump.py")
    assert not tc.ToolRegistry(installed={"nmap"}).has("secretsdump.py")


def test_resolve_tool_prefers_an_installed_alias(monkeypatch):
    from phantom.automation.runtime import toolchain as tc
    monkeypatch.setattr(tc.shutil, "which", lambda n: None)
    assert tc.resolve_tool("secretsdump.py") == "secretsdump.py"
    monkeypatch.setattr(
        tc.shutil, "which",
        lambda n: "/usr/bin/x" if n == "impacket-secretsdump" else None)
    assert tc.resolve_tool("secretsdump.py") == "impacket-secretsdump"


def test_ad_commands_use_the_installed_impacket_alias(monkeypatch):
    from phantom.automation.runtime import toolchain as tc
    from phantom.automation.post import ad
    monkeypatch.setattr(tc, "resolve_tool", lambda n: "impacket-" + n[:-3])
    kerb = ad.kerberoast_command("corp.local", "u", "p", "10.0.0.1")
    assert kerb.startswith("impacket-GetUserSPNs ") and ".py" not in kerb
    asrep = ad.as_rep_roast_command("corp.local", "u", "p", "10.0.0.1")
    assert asrep.startswith("impacket-GetNPUsers ")
    dcsync = ad.dc_sync_command("corp.local", "u", "p", "10.0.0.1")
    assert dcsync.startswith("impacket-secretsdump ")


# ── A2: nmap -O needs raw sockets ───────────────────────────────────────

def test_os_adapter_degrades_without_raw_sockets(monkeypatch):
    from phantom.automation.guidance import kit
    monkeypatch.setattr(kit, "_raw_socket_ok", lambda: False)
    monkeypatch.setattr(kit, "_effective_target", lambda wm: "10.0.0.5")
    cmd = kit._os_adapter(None, {})
    assert "-O" not in cmd and "-sV" in cmd


def test_os_adapter_uses_O_when_raw_sockets_available(monkeypatch):
    from phantom.automation.guidance import kit
    monkeypatch.setattr(kit, "_raw_socket_ok", lambda: True)
    monkeypatch.setattr(kit, "_effective_target", lambda wm: "10.0.0.5")
    assert "-O" in kit._os_adapter(None, {})


# ── A1: rejected candidates on a halt ───────────────────────────────────

def test_halt_renders_rejected_reasons():
    from phantom.core.stream_contract import render_event
    r = render_event("halt", {
        "reason": "no affordable path to goal",
        "rejected": [{"capability": "cred_dump", "fact": "creds",
                      "reason": "tool missing"}],
        "rejected_total": 7,
    })
    text = "\n".join(r.lines)
    assert "cred_dump" in text and "creds" in text and "tool missing" in text
    assert "7 candidate" in text


def test_halt_ignores_malformed_rejected_entries():
    from phantom.core.stream_contract import render_event
    r = render_event("halt", {"reason": "stopped", "rejected": ["oops", None]})
    assert any("stopped" in line for line in r.lines)


def test_halt_carries_structured_rejected_for_the_ui():
    from phantom.core.stream_contract import render_event
    rejected = [{"capability": "cred_dump", "fact": "creds",
                 "reason": "tool missing"}]
    r = render_event("halt", {"reason": "no affordable path", "goal": "deep",
                              "rejected": rejected, "rejected_total": 3})
    assert r.fields["goal"] == "deep"
    assert r.fields["rejected"] == rejected
    assert r.fields["rejected_total"] == 3


# ── B1 wiring: the preflight speaks before the run ──────────────────────

class _RecordingNotifier:
    def __init__(self):
        self.calls = []

    def _add(self, level, msg, **kw):
        self.calls.append((level, msg))

    def warn(self, msg, **kw):
        self._add("warn", msg)

    def error(self, msg, **kw):
        self._add("error", msg)

    def info(self, msg, **kw):
        self._add("info", msg)

    def success(self, msg, **kw):
        self._add("success", msg)


def test_callback_preflight_errors_when_no_target_can_call_back(monkeypatch):
    from phantom.core import automode
    from phantom.utils import config as cfg
    monkeypatch.setattr(cfg, "_loaded", {"c2": {"host": "127.0.0.1"}})
    rec = _RecordingNotifier()
    monkeypatch.setattr(automode, "notifier", rec)
    automode._callback_preflight(["8.8.8.8"], "beacon")
    assert any(level == "error" for level, _ in rec.calls)


def test_callback_preflight_is_silent_for_a_lan_deploy(monkeypatch):
    from phantom.core import automode
    from phantom.utils import config as cfg
    monkeypatch.setattr(cfg, "_loaded", {"c2": {"host": "192.168.1.10"}})
    rec = _RecordingNotifier()
    monkeypatch.setattr(automode, "notifier", rec)
    automode._callback_preflight(["192.168.1.50"], "beacon")
    assert rec.calls == []


def test_callback_preflight_skipped_for_non_beacon_goals(monkeypatch):
    from phantom.core import automode
    from phantom.utils import config as cfg
    monkeypatch.setattr(cfg, "_loaded", {"c2": {"host": "127.0.0.1"}})
    rec = _RecordingNotifier()
    monkeypatch.setattr(automode, "notifier", rec)
    automode._callback_preflight(["8.8.8.8"], "recon")
    assert rec.calls == []


# ── A5: checkpoint schema mismatch ──────────────────────────────────────

def test_from_state_flags_schema_mismatch(tmp_path):
    from phantom.automation.agent import AutonomousAgent
    p = tmp_path / "cp.json"
    p.write_text(json.dumps({"schema": 999, "target": "10.0.0.5",
                             "goal": "beacon"}), encoding="utf-8")
    seen = []
    AutonomousAgent.from_state(str(p),
                               on_event=lambda k, d: seen.append((k, d)))
    assert any(k == "note" and d.get("capability") == "resume"
               for k, d in seen)


def test_from_state_is_quiet_on_matching_schema(tmp_path):
    from phantom.automation.agent import CHECKPOINT_SCHEMA, AutonomousAgent
    p = tmp_path / "cp.json"
    p.write_text(json.dumps({"schema": CHECKPOINT_SCHEMA,
                             "target": "10.0.0.5"}), encoding="utf-8")
    seen = []
    AutonomousAgent.from_state(str(p),
                               on_event=lambda k, d: seen.append((k, d)))
    assert not any(k == "note" for k, _ in seen)


# ── C1: module missing-tool gate ────────────────────────────────────────

class _FakeModule:
    def build_commands(self):
        return {"primary": ["phantom_missing_tool_abc --run",
                            "# a comment", "echo hello"]}

    def suggest_commands(self):
        return {"alt": ["phantom_missing_tool_abc -x"]}


def test_module_missing_tools_is_alias_aware(monkeypatch):
    from phantom.automation.runtime import toolchain as tc
    from phantom.core import executor

    class _Mod:
        def build_commands(self):
            return {"a": ["secretsdump.py -just-dc x"]}

        def suggest_commands(self):
            return {}

    real = tc.ToolRegistry
    monkeypatch.setattr(
        tc, "ToolRegistry",
        lambda *a, **k: real(installed={"impacket-secretsdump"}))
    assert executor.module_missing_tools(_Mod()) == []


def test_module_missing_tools_reports_only_real_binaries():
    from phantom.core.executor import module_missing_tools
    missing = module_missing_tools(_FakeModule())
    names = [t for t, _ in missing]
    assert "phantom_missing_tool_abc" in names
    assert "#" not in names and "echo" not in names
    assert all(hint for _t, hint in missing)


# ── A4: profile/goal feasibility warnings ───────────────────────────────

def test_mobile_profile_cannot_reach_beacon():
    from phantom.automation.swarm.coverage import feasibility_warnings
    assert feasibility_warnings("mobile", "beacon")
    assert feasibility_warnings("mobile", "deliver")
    # identity IS the honest goal for a phone
    assert not feasibility_warnings("mobile", "identity")


def test_smb_profile_warns_on_ad_goals():
    from phantom.automation.swarm.coverage import feasibility_warnings
    assert feasibility_warnings("smb", "ad")
    assert feasibility_warnings("smb", "crack")
    assert not feasibility_warnings("smb", "beacon")


def test_impact_warns_until_ransom_sim_is_allowed(monkeypatch):
    from phantom.automation.swarm.coverage import feasibility_warnings
    from phantom.utils import config as cfg
    monkeypatch.setattr(cfg, "_loaded", {})
    assert feasibility_warnings("enterprise", "impact")
    monkeypatch.setattr(cfg, "_loaded",
                        {"engagement": {"ransom_sim_allow": True}})
    assert not feasibility_warnings("enterprise", "impact")


# ── A6: artifact disk usage ─────────────────────────────────────────────

def test_usage_report_measures_every_class_recursively(tmp_path, monkeypatch):
    monkeypatch.delenv("PHANTOM_ARTIFACT_TTL_DAYS", raising=False)
    from phantom.core.artifact_policy import usage_report
    (tmp_path / "sessions" / "auto_2026").mkdir(parents=True)
    (tmp_path / "sessions" / "auto_2026" / "state.json").write_text("x" * 100)
    (tmp_path / "reports").mkdir()
    (tmp_path / "reports" / "r.md").write_text("y" * 50)
    rows = {r["dir"]: r for r in usage_report(str(tmp_path))}
    assert rows["sessions"]["bytes"] == 100
    assert rows["sessions"]["files"] == 1
    assert rows["sessions"]["ttl_days"] == 0      # never auto-deleted
    assert rows["reports"]["bytes"] == 50


# ── C2: doctor hardening checks ─────────────────────────────────────────

def test_doctor_fails_on_plaintext_non_loopback(monkeypatch):
    from phantom.core import doctor
    from phantom.utils import config as cfg
    monkeypatch.setattr(cfg, "_loaded",
                        {"c2": {"ssl": False, "bind": "0.0.0.0"}})
    c = doctor._c2_hardening_check()
    assert c.status == "fail" and c.hint
    assert "plaintext" in c.detail.lower()


def test_doctor_warns_when_client_cert_optional(monkeypatch):
    from phantom.core import doctor
    from phantom.utils import config as cfg
    monkeypatch.setattr(cfg, "_loaded",
                        {"c2": {"ssl": True, "bind": "0.0.0.0",
                                "mtls_require_client_cert": False}})
    assert doctor._c2_hardening_check().status == "warn"


def test_doctor_c2_transport_passes_by_default(monkeypatch):
    from phantom.core import doctor
    from phantom.utils import config as cfg
    monkeypatch.setattr(cfg, "_loaded", {})
    assert doctor._c2_hardening_check().status == "pass"


def test_doctor_ad_tools_check_flags_a_missing_logical_tool(monkeypatch):
    from phantom.core import doctor
    from phantom.automation.runtime import toolchain as tc

    class _Reg:
        def __init__(self, *a, **k):
            pass

        def has(self, name):
            return name != "GetNPUsers.py"

    monkeypatch.setattr(tc, "ToolRegistry", _Reg)
    c = doctor._ad_tools_check()
    assert c.status == "warn" and "GetNPUsers.py" in c.detail


def test_doctor_data_usage_check_is_offline_and_read_only(tmp_path, monkeypatch):
    from phantom.core import doctor
    from phantom.utils import paths
    monkeypatch.setattr(paths, "data_dir", lambda: str(tmp_path))
    (tmp_path / "screenshots").mkdir()
    (tmp_path / "screenshots" / "s.png").write_bytes(b"z" * 2048)
    c = doctor._data_usage_check()
    assert c.status == "pass" and "screenshots" in c.detail
    # read-only: nothing was deleted
    assert (tmp_path / "screenshots" / "s.png").exists()


def test_doctor_reports_buildable_platforms():
    from phantom.core import doctor
    platforms = doctor._buildable_platforms()
    assert isinstance(platforms, list)
    assert set(platforms) <= {"linux", "windows", "macos", "android"}
