"""Gap/fallback tables and checkpoint completeness (7.7).

Two classes of silent rot, both closed here:

* TABLES THAT MATCH NOTHING. `_GAP_CAP_HINTS` named capabilities that do not
  exist ("smb_login"/"cred_dump", "phish"/"dm_stage1"), and
  `FALLBACK_CHAINS` had a key (`identity_phish`) that no strategy id can
  ever equal. A hint naming nothing degrades to an arbitrary order that
  LOOKS like a working priority, and an unreachable key reads like a
  safeguard while doing nothing.

* A CHECKPOINT THAT FORGETS THE SETTINGS. The reasoning objective
  (`--reason`) and the cell authority were dropped at save time, so a
  resumed run silently re-chose both.
"""
import pytest


class TestGapCapHints:
    def test_every_hinted_capability_exists(self):
        """A hint naming a capability that does not exist is a no-op."""
        from phantom.automation.agent import _GAP_CAP_HINTS
        from phantom.automation.guidance.commands import make_registry
        registry = make_registry()
        missing = sorted(f"{gap}:{cap}"
                         for gap, caps in _GAP_CAP_HINTS.items()
                         for cap in caps
                         if registry.get(cap) is None)
        assert missing == [], missing

    def test_the_two_rotten_entries_now_name_real_capabilities(self):
        from phantom.automation.agent import _GAP_CAP_HINTS
        # credential acquisition no longer names an SMB login or a dumper
        # that were never registered
        assert "smb_login" not in _GAP_CAP_HINTS["network_creds"]
        assert "cred_dump" not in _GAP_CAP_HINTS["network_creds"]
        # the identity delivery path names the real phish/poll capabilities
        assert "phish_identity" in _GAP_CAP_HINTS["identity_phish"]
        assert "phish" not in _GAP_CAP_HINTS["identity_phish"]

    def test_every_gap_class_the_engine_reports_is_mapped(self):
        from phantom.automation.agent import _GAP_CAP_HINTS
        from phantom.automation.fallback import FALLBACK_CHAINS
        reportable = {c for chain in FALLBACK_CHAINS.values() for c in chain}
        assert reportable
        assert not (reportable - set(_GAP_CAP_HINTS))


class TestFallbackChains:
    def _strategy_ids(self):
        from phantom.automation.guidance.strategy import STRATEGIES
        return {s.id for s in STRATEGIES}

    def test_every_key_is_a_real_strategy_id(self):
        """`_current_strategy` is a strategy id: any other key is dead."""
        from phantom.automation.fallback import FALLBACK_CHAINS
        ids = self._strategy_ids()
        dead = sorted(set(FALLBACK_CHAINS) - ids)
        assert dead == [], f"unreachable fallback keys: {dead}"

    def test_the_former_dead_key_is_gone(self):
        from phantom.automation.fallback import FALLBACK_CHAINS
        assert "identity_phish" not in FALLBACK_CHAINS
        assert "identity_beacon" in FALLBACK_CHAINS

    def test_every_value_is_a_strategy_id_or_a_gap_class(self):
        from phantom.automation.agent import _GAP_CAP_HINTS
        from phantom.automation.fallback import FALLBACK_CHAINS
        known = self._strategy_ids() | set(_GAP_CAP_HINTS)
        unknown = sorted({c for chain in FALLBACK_CHAINS.values()
                          for c in chain} - known)
        assert unknown == [], unknown

    def test_a_failed_identity_delivery_goes_back_to_the_identity_sources(
            self):
        from phantom.automation.belief import WorldModel
        from phantom.automation.fallback import FallbackEngine
        wm = WorldModel(target="bob@corp.com", target_type="email")
        wm.add_finding("identity", "handle", {"handle": "bob"})
        gap = FallbackEngine().next_strategy("identity_beacon", wm)
        assert gap in ("identity_beacon", "identity_breach", "identity_osint")


class TestCheckpointKeepsTheRunSettings:
    def _agent(self, **kw):
        from phantom.automation.agent import AutonomousAgent
        return AutonomousAgent(target="10.0.0.5", target_type="ip", **kw)

    def test_reason_profile_survives_a_resume(self, tmp_path):
        agent = self._agent(reason_profile="evidence_first")
        assert agent.reasoning_profile.name == "evidence_first"
        path = agent.save_state(str(tmp_path / "cp.json"))
        from phantom.automation.agent import AutonomousAgent
        clone = AutonomousAgent.from_state(path)
        assert clone.reason_profile == "evidence_first"
        # and the ARBITER was rebuilt with it, not just the label
        assert clone.reasoning_profile.name == "evidence_first"

    def test_cell_authority_survives_a_resume(self, tmp_path):
        agent = self._agent(cell_loop=True, cell_stages=["deliver",
                                                         "post_exploit"])
        path = agent.save_state(str(tmp_path / "cp.json"))
        from phantom.automation.agent import AutonomousAgent
        clone = AutonomousAgent.from_state(path)
        assert clone.cell_loop is True
        assert clone.cell_stages == ("deliver", "post_exploit")

    def test_an_old_checkpoint_without_the_new_fields_still_loads(
            self, tmp_path):
        """Backwards compatibility: a checkpoint written before 7.7 must
        resume on the legacy defaults instead of crashing."""
        import json
        legacy = {"schema": 1, "target": "10.0.0.5", "target_type": "ip",
                  "profile": "enterprise", "wm": {"target": "10.0.0.5"}}
        path = tmp_path / "legacy.json"
        path.write_text(json.dumps(legacy), encoding="utf-8")
        from phantom.automation.agent import AutonomousAgent
        clone = AutonomousAgent.from_state(str(path))
        assert clone.reason_profile == ""
        assert clone.cell_loop is False and clone.cell_stages == ()

    def test_belief_revisions_and_the_trace_are_in_the_checkpoint(
            self, tmp_path):
        from types import SimpleNamespace
        agent = self._agent()
        agent.wm.add_finding("os", "detected", {"name": "Linux"},
                             confidence=0.4)
        agent.wm.add_finding("os", "detected", {"name": "Windows"},
                             confidence=0.9)
        cap = agent.registry.get("scan_tcp")
        if cap is None:
            pytest.skip("scan_tcp not in the registry")
        agent._decision_for(SimpleNamespace(capability=cap, reason="probe"),
                            base=1.0)
        path = agent.save_state(str(tmp_path / "cp.json"))
        from phantom.automation.agent import AutonomousAgent
        clone = AutonomousAgent.from_state(path)
        assert len(clone.wm.revisions) == 1
        assert clone.wm.fingerprint_mismatch is True
        assert len(clone.trace) == 1

    def test_a_resume_keeps_the_dead_capability_discipline(self, tmp_path):
        agent = self._agent()
        agent._mark_failed("ssh_login")
        path = agent.save_state(str(tmp_path / "cp.json"))
        from phantom.automation.agent import AutonomousAgent
        clone = AutonomousAgent.from_state(path)
        assert "ssh_login" in clone._failed_caps
