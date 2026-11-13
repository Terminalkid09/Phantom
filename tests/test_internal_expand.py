"""Fase 1 — internal expansion.

Covers:
  * the planner goals/facts that make internal recon reachable
    (`expand`, `evasion`, and `defensive_gap` as edr_disable's effect);
  * the deep ladder: `expand` is static, `evasion` is inserted ONLY for
    aggressive runs (edr_disable is aggressive-only);
  * the pivot `host` slot now comes from the engagement's OWN internal
    recon (internal_service), scope-gated through the target ledger, with
    the campaign share as fallback;
  * the edr_disable gate (aggressive + SYSTEM);
  * the manual core plans the internal expansion goals too.
"""
from unittest.mock import Mock

from phantom.automation.belief import Finding, WorldModel
from phantom.automation.guidance.stealth import StealthConfig, StealthEngine
from phantom.automation.planner import GOAL_FACTS, _FACT_SOURCES
from phantom.automation.runtime.stealth_runtime import (
    StealthRuntime,
    TimingGovernor,
)
from phantom.automation.runtime.toolchain import ToolRegistry


def _runner(_cmd, _timeout=None):
    res = Mock()
    res.ok = False
    res.stdout = ""
    res.stderr = ""
    return res


def _agent(target="10.0.0.5", scope_list=None, aggressive=False, wm=None):
    from phantom.automation.agent import AutonomousAgent
    wm = wm if wm is not None else WorldModel(target=target)
    return AutonomousAgent(
        target=target, target_type="ip", profile="enterprise",
        aggressive=aggressive, on_event=None, shared_wm=wm,
        scope_list=scope_list, cred_discoverer=lambda service: None,
        runtime=StealthRuntime(
            StealthEngine(wm, StealthConfig(aggressive=aggressive)),
            runner=_runner, cost_per_action=0.5,
            governor=TimingGovernor(base_delay=0.0, jitter=0.0)),
        toolchain=ToolRegistry(installed={"nmap", "sshpass", "curl", "nc"}),
    )


def _peer(host, port, service, kind="internal_service"):
    key = f"{host}:{port}" if kind == "internal_service" else host
    value = {"host": host, "port": port, "service": service} \
        if kind == "internal_service" else {"ip": host}
    return Finding(kind=kind, key=key, value=value, confidence=0.85,
                   source="internal_probe", evidence="test")


# ─────────────────────────────── planner wiring ─────────────────────────────

class TestPlannerWiring:
    def test_expand_and_evasion_goals(self):
        assert GOAL_FACTS["expand"] == ["internal_host", "internal_service"]
        assert GOAL_FACTS["evasion"] == ["defensive_gap"]

    def test_fact_sources_new_facts(self):
        assert _FACT_SOURCES["internal_host"] == ["internal_recon"]
        assert _FACT_SOURCES["internal_service"] == ["internal_probe"]
        assert _FACT_SOURCES["defensive_gap"] == ["edr_disable"]


# ─────────────────────────────── deep ladder ────────────────────────────────

class TestDeepLadder:
    def test_expand_is_static_evasion_is_not(self):
        from phantom.automation.agent import DEEP_STAGES
        assert "expand" in DEEP_STAGES
        # evasion is aggressive-only: never in the static tuple
        assert "evasion" not in DEEP_STAGES

    def test_evasion_inserted_only_when_aggressive(self):
        calm = _agent(aggressive=False)._deep_ladder()
        loud = _agent(aggressive=True)._deep_ladder()
        assert "evasion" not in calm
        assert "evasion" in loud
        # right after post_exploit -> the SYSTEM session it needs exists
        assert loud.index("evasion") == loud.index("post_exploit") + 1
        # evasion must come before the loud AD/pivot stages
        assert loud.index("evasion") < loud.index("ad")


# ─────────────────────── pivot host from internal recon ─────────────────────

class TestPivotHostFromInternalRecon:
    def test_ledger_registers_in_scope_peers_only(self):
        agent = _agent(scope_list=["10.0.0.0/24"])
        agent._register_findings("internal_recon", [
            Finding(kind="internal_host", key="10.0.0.9",
                    value={"ip": "10.0.0.9"}, confidence=0.7,
                    source="internal_recon"),
            Finding(kind="internal_host", key="172.20.0.5",
                    value={"ip": "172.20.0.5"}, confidence=0.7,
                    source="internal_recon"),
        ])
        assert agent.ledger.activatable("10.0.0.9")
        assert not agent.ledger.activatable("172.20.0.5")

    def test_host_slot_filled_from_internal_service(self):
        agent = _agent(scope_list=["10.0.0.0/24"])
        agent._register_findings("internal_probe", [
            _peer("10.0.0.9", 445, "smb"),
            _peer("10.0.0.9", 22, "ssh"),
        ])
        assert agent._internal_pivot_host("smb_pivot") == "10.0.0.9"
        assert agent._internal_pivot_host("lateral_pivot") == "10.0.0.9"

    def test_out_of_scope_peer_never_chosen(self):
        agent = _agent(scope_list=["10.0.0.0/24"])
        agent._register_findings("internal_probe", [
            _peer("172.20.0.5", 445, "smb"),
        ])
        assert agent._internal_pivot_host("smb_pivot") == ""

    def test_service_mismatch_does_not_pick_wrong_peer(self):
        agent = _agent()
        agent._register_findings("internal_probe", [
            _peer("10.0.0.9", 22, "ssh"),
        ])
        # an SMB pivot needs SMB: the ssh-only peer is not eligible
        assert agent._internal_pivot_host("smb_pivot") == ""
        assert agent._internal_pivot_host("lateral_pivot") == "10.0.0.9"

    def test_autofill_sets_host_slot(self):
        agent = _agent()
        agent._register_findings("internal_probe", [_peer("10.0.0.9", 22, "ssh")])
        cap = agent.registry.get("lateral_pivot")
        slots = agent._autofill_slots(cap, {})
        assert slots.get("host") == "10.0.0.9"

    def test_autofill_falls_back_to_campaign_peer(self):
        from phantom.automation.agent import ShareContext
        agent = _agent()
        agent.share = ShareContext(peers=["10.0.0.7"])
        cap = agent.registry.get("smb_pivot")
        slots = agent._autofill_slots(cap, {})
        assert slots.get("host") == "10.0.0.7"


# ───────────────────────────── edr_disable gate ─────────────────────────────

class TestEdrDisableGate:
    def test_blocked_without_aggressive(self):
        from phantom.automation.agent import _BeaconSession
        agent = _agent(aggressive=False)
        agent._session = _BeaconSession("b1")
        agent.wm.add_finding("system_privilege", "sp", {"level": "system"},
                             source="privesc_system")
        events = []
        agent._on_event = lambda k, d: events.append((k, d))
        cap = agent.registry.get("edr_disable")
        assert agent._execute_post_capability(cap, {}) is False
        assert any(k == "blocked" and "requires --aggressive" in d.get("reason", "")
                   for k, d in events)

    def test_gate_does_not_fire_when_aggressive(self):
        class _InstantSession:
            beacon_id = "b1"

            def task(self, command):
                return "t1"

            def wait_result(self, task_id, timeout=30.0):
                return "EDR_DISABLED"

        agent = _agent(aggressive=True)
        agent._session = _InstantSession()
        events = []
        agent._on_event = lambda k, d: events.append((k, d))
        cap = agent.registry.get("edr_disable")
        # may still fail elsewhere (no real beacon), but never via this gate
        agent._execute_post_capability(cap, {})
        assert not any(k == "blocked"
                       and "requires --aggressive" in d.get("reason", "")
                       for k, d in events)


# ─────────────────────── manual core internal goals ─────────────────────────

class TestCoreInternalGoals:
    def test_core_chain_plans_internal_expansion(self):
        from phantom.core.chain import GOALS, plan
        from phantom.core.knowledge import reset_wm
        assert "internal.host" in GOALS
        assert "internal.service" in GOALS
        wm = reset_wm("10.0.0.5")
        wm.add_finding("beacon", "b1", {"id": "b1", "status": "LIVE"},
                       confidence=0.95)
        goals = {p["goal"] for p in plan(wm)}
        assert {"internal.host", "internal.service"} <= goals

    def test_core_maps_internal_ops_to_real_capabilities(self):
        from phantom.core.chain import _OP_TO_CAP
        assert _OP_TO_CAP["recon.internal"][0] == "internal_recon"
        assert _OP_TO_CAP["probe.internal"][0] == "internal_probe"
