"""Fase post-exploitation: internal recon (beacon snapshot + bounded probe)
and the manual-core post-exploitation chain goals.

Acceptance:
  * internal_recon parses a real-shaped snapshot into gateway/hosts
  * the probe interpreter parses one-line-joined marker output
  * peer candidates are scope-gated (an ARP neighbor is NOT authorization)
  * the manual chain planner now emits privesc/persistence/lateral plans
    from the same WorldModel the auto-mode reasons on
  * the composition projection speaks nmap's service dialect
    (microsoft-ds == SMB, port 445 == SMB)
"""
import pytest

from phantom.core.knowledge import reset_wm
from phantom.automation.post.internal_recon import (
    internal_probe_command,
    internal_probe_interpreter,
    internal_recon_interpreter,
    internal_peers_in_scope,
    internal_snapshot_command,
)

_LINUX_SNAPSHOT = (
    "__NET_BEGIN__\n"
    "default via 192.168.1.1 dev eth0\n"
    "inet 192.168.1.50/24 brd 192.168.1.255 dev eth0\n"
    "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
    "192.168.1.23 dev eth0 lladdr 11:22:33:44:55:66 REACHABLE\n"
    "192.168.1.99 dev eth0  INCOMPLETE\n"
    "__NET_END__"
)


class TestInternalSnapshot:
    def test_linux_command_shape(self):
        cmd = internal_snapshot_command("linux")
        assert "__NET_BEGIN__" in cmd and "ip route" in cmd and "ip neigh" in cmd

    def test_windows_command_shape(self):
        cmd = internal_snapshot_command("windows")
        assert "__NET_BEGIN__" in cmd and "arp -a" in cmd and "route print" in cmd

    def test_linux_snapshot_parses_gateway_and_hosts(self):
        findings = internal_recon_interpreter(_LINUX_SNAPSHOT, None, {})
        kinds = {f.kind: f.key for f in findings}
        assert kinds.get("internal_gateway") == "192.168.1.1"
        hosts = [f.key for f in findings if f.kind == "internal_host"]
        assert "192.168.1.23" in hosts
        # the gateway is our own infra, not a candidate peer
        assert "192.168.1.1" not in hosts
        # INCOMPLETE arp entries are noise, not hosts
        assert "192.168.1.99" not in hosts

    def test_garbage_output_yields_nothing(self):
        assert internal_recon_interpreter("no markers here", None, {}) == []


class TestInternalProbe:
    def test_probe_command_is_bounded(self):
        cmd = internal_probe_command(["10.0.0.%d" % i for i in range(1, 5)])
        assert "__SVC__" in cmd
        # only pivot ports are probed
        assert "22" in cmd and "445" in cmd and "5985" in cmd
        assert "1,4444" not in cmd

    def test_one_line_joined_output_parses(self):
        out = ("__PROBE_BEGIN__ ; __SVC__ 192.168.1.23 22 ; "
               "__SVC__ 192.168.1.23 445 ; __SVC__ 192.168.1.40 5985 ; "
               "__PROBE_END__")
        findings = internal_probe_interpreter(out, None, {})
        got = {(f.value["host"], f.value["service"]) for f in findings}
        assert got == {("192.168.1.23", "ssh"), ("192.168.1.23", "smb"),
                       ("192.168.1.40", "winrm")}

    def test_no_svc_markers_yields_nothing(self):
        assert internal_probe_interpreter("echo nothing", None, {}) == []


class TestScopeGate:
    def test_peers_respect_scope(self):
        wm = reset_wm("192.168.1.50")
        wm.add_finding("internal_host", "192.168.1.23",
                       {"ip": "192.168.1.23"}, confidence=0.7)
        wm.add_finding("internal_host", "172.30.99.99",
                       {"ip": "172.30.99.99"}, confidence=0.7)
        peers = internal_peers_in_scope(wm, ["192.168.1.0/24"])
        assert "192.168.1.23" in peers
        assert "172.30.99.99" not in peers  # out of scope: never a pivot target

    def test_no_scope_allows_all_neighbors(self):
        wm = reset_wm("192.168.1.50")
        wm.add_finding("internal_host", "192.168.1.23",
                       {"ip": "192.168.1.23"}, confidence=0.7)
        assert internal_peers_in_scope(wm, []) == ["192.168.1.23"]


class TestManualChainPostExploitation:
    """The manual core's chain planner now covers the full kill chain."""

    def _wm_with_beacon(self):
        wm = reset_wm("10.0.0.5")
        wm.add_finding("service", "10.0.0.5:445",
                       {"ip": "10.0.0.5", "port": 445, "service": "microsoft-ds"},
                       confidence=0.9)
        wm.add_finding("creds", "smb:admin",
                       {"username": "admin", "password": "P@ss", "valid": True,
                        "service": "smb"}, confidence=0.8)
        wm.add_finding("beacon", "b1", {"id": "b1", "status": "LIVE"},
                       confidence=0.95)
        return wm

    def test_all_post_exploitation_goals_plan(self):
        from phantom.core.chain import plan
        goals = {p["goal"] for p in plan(self._wm_with_beacon())}
        assert {"priv.system", "persist.installed", "pivot.smb",
                "pivot.winrm"} <= goals

    def test_steps_map_to_executable_capabilities(self):
        from phantom.core.chain import plan
        for p in plan(self._wm_with_beacon()):
            for s in p["steps"]:
                assert s["cap"], f"{p['goal']}: step {s['op']} has no capability"

    def test_satisfied_goals_are_not_replanned(self):
        from phantom.core.chain import plan
        wm = self._wm_with_beacon()
        wm.add_finding("persistence", "runkey", {"method": "runkey"},
                       confidence=0.9)
        goals = {p["goal"] for p in plan(wm)}
        assert "persist.installed" not in goals


class TestProjectionDialect:
    """facts_from_worldmodel must speak nmap's service dialect."""

    def test_microsoft_ds_is_smb(self):
        from phantom.automation.brain.composition import CompositionEngine
        from phantom.automation.brain.operators import default_operators
        wm = reset_wm("10.0.0.5")
        wm.add_finding("service", "10.0.0.5:445",
                       {"ip": "10.0.0.5", "port": 445, "service": "microsoft-ds"},
                       confidence=0.9)
        facts = CompositionEngine(default_operators()).facts_from_worldmodel(wm)
        assert "service.smb" in facts

    def test_port_445_alone_is_smb(self):
        from phantom.automation.brain.composition import CompositionEngine
        from phantom.automation.brain.operators import default_operators
        wm = reset_wm("10.0.0.5")
        wm.add_finding("service", "10.0.0.5:445",
                       {"ip": "10.0.0.5", "port": 445, "service": ""},
                       confidence=0.9)
        facts = CompositionEngine(default_operators()).facts_from_worldmodel(wm)
        assert "service.smb" in facts


class TestAutoModeWiring:
    """The capabilities exist, are beacon-gated and scope-gated."""

    def test_internal_recon_registered(self):
        from phantom.automation.guidance.commands import make_registry
        reg = make_registry()
        for cid in ("internal_recon", "internal_probe"):
            cap = reg.get(cid)
            assert cap is not None, f"{cid} missing from registry"
            assert cap.category == "post"
            assert any(getattr(p, "__name__", "").endswith("_requires_beacon")
                       for p in cap.preconditions)

    def test_planner_knows_the_new_facts(self):
        from phantom.automation.planner import _FACT_SOURCES
        assert _FACT_SOURCES.get("internal_host") == ["internal_recon"]
        assert _FACT_SOURCES.get("internal_service") == ["internal_probe"]

    def test_probe_adapter_refuses_without_inscope_hosts(self):
        from phantom.automation.guidance.kit import _internal_probe_adapter
        wm = reset_wm("10.0.0.5")
        wm.add_finding("beacon", "b1", {"id": "b1"}, confidence=0.9)
        with pytest.raises(ValueError):
            _internal_probe_adapter(wm, {})


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
