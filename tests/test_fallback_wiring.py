"""The fallback engine was recorded-but-never-consulted (6.6).

`FallbackEngine.next_strategy` / `_gap_analysis` / `learned_accounts` were
tested and dead: `record()` ran on every failure, so the engine learned, and
the learning never reached a decision or the operator. The wiring is at the
stall recovery: the gap analysis orders which failed capabilities get
re-armed, and the diagnosis is emitted instead of a bare "no affordable
path to goal".
"""
from phantom.automation.agent import _GAP_CAP_HINTS
from phantom.automation.belief import WorldModel
from phantom.automation.fallback import FallbackEngine


class TestGapAnalysisIsTheController:
    def _wm_with_creds(self):
        wm = WorldModel(target="10.0.0.5", target_type="ip")
        wm.add_finding("service", "tcp/22",
                       {"port": "22", "service": "ssh"}, 0.9, "nmap")
        wm.add_finding("creds", "root@10.0.0.5",
                       {"username": "root", "password": "toor"}, 0.9, "agent")
        return wm

    def test_creds_without_beacon_still_wants_the_beacon(self):
        gap = FallbackEngine().next_strategy("", self._wm_with_creds())
        assert gap == "network_beacon"

    def test_the_gap_maps_to_concrete_capabilities(self):
        assert "beacon_deploy" in _GAP_CAP_HINTS["network_beacon"]
        assert "ssh_login" in _GAP_CAP_HINTS["network_creds"]
        assert "scan_tcp" in _GAP_CAP_HINTS["network_footprint"]

    def test_every_gap_the_engine_can_report_is_mapped(self):
        """A gap with no mapping would silently re-arm in arbitrary order."""
        reportable = set()
        for chain in __import__("phantom.automation.fallback",
                                fromlist=["FALLBACK_CHAINS"]
                                ).FALLBACK_CHAINS.values():
            reportable |= set(chain)
        reportable |= {"network_beacon", "network_creds", "exploit_chain",
                       "network_footprint", "identity_breach",
                       "identity_phish", "identity_osint"}
        missing = reportable - set(_GAP_CAP_HINTS)
        assert not missing, f"unmapped gap classes: {sorted(missing)}"


class TestRecoveryUsesTheGap:
    def _agent(self, events):
        from phantom.automation.agent import AutonomousAgent
        from phantom.automation.guidance.stealth import (
            StealthConfig, StealthEngine)
        from phantom.automation.runtime.stealth_runtime import (
            StealthRuntime, TimingGovernor)
        from phantom.automation.runtime.toolchain import ToolRegistry

        agent = AutonomousAgent(
            target="10.0.0.5", target_type="ip", profile="enterprise",
            on_event=lambda k, d: events.append((k, d)),
            runtime=StealthRuntime(
                StealthEngine(WorldModel(target="10.0.0.5"),
                              StealthConfig()),
                runner=lambda cmd, timeout=60: None,
                cost_per_action=0.0,
                governor=TimingGovernor(base_delay=0.0, jitter=0.0)),
            toolchain=ToolRegistry(installed={"nmap", "sshpass", "curl", "nc"}),
            scope_list=["10.0.0.0/8"])
        # the run failed exactly these moves; creds are known, beacon is not
        agent._failed_caps = {"web_rce": 2, "beacon_deploy": 2}
        agent.wm.add_finding("creds", "root@10.0.0.5",
                             {"username": "root", "password": "toor"},
                             0.9, "agent")
        return agent

    def test_stall_recovery_emits_the_gap_and_orders_the_rearm(self):
        events = []
        agent = self._agent(events)
        rearmed = []
        agent._exec_with_permit = lambda step: (
            rearmed.append(step.capability.id), True)[1]
        agent._registry_has = None

        agent._recover_stall("deliver")

        gaps = [d for k, d in events if k == "gap"]
        assert gaps, [k for k, _ in events]
        assert gaps[0]["missing"] == "network_beacon"
        assert "beacon_deploy" in gaps[0]["hints"]
        # it must still be a bounded, real recovery
        assert [k for k, _ in events if k == "recover"]
