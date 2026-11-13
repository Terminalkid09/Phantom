"""Profile policy: the environment profile decides the starting posture.

Before this module `--profile` was a label: it reached the threat model
and OPSEC but never changed the PLAN, so `--profile mobile` still opened
with a direct web chain. These tests pin the mapping and the wiring:
the profile picks the chain when the operator did not pick one, and an
explicit `--chain` always wins.
"""
import pytest


class TestPolicyTable:
    def test_every_profile_maps_to_a_real_chain(self):
        from phantom.automation.swarm.profile_policy import POLICY
        from phantom.automation.swarm.tasks import CHAIN_TEMPLATES
        for profile, policy in POLICY.items():
            assert policy.chain in CHAIN_TEMPLATES, (profile, policy.chain)

    def test_all_six_environment_profiles_are_covered(self):
        from phantom.automation.swarm.profile_policy import POLICY
        assert set(POLICY) == {"smb", "enterprise", "cloud", "financial",
                               "government", "mobile"}

    def test_unknown_profile_falls_back_to_enterprise(self):
        from phantom.automation.swarm.profile_policy import policy_for
        assert policy_for("nope").profile == "enterprise"
        assert policy_for("").profile == "enterprise"

    def test_mobile_does_not_open_with_a_direct_web_chain(self):
        from phantom.automation.swarm.profile_policy import chain_for_profile
        assert chain_for_profile("mobile") == "footprint"
        assert chain_for_profile("mobile") != "web"

    def test_cloud_is_identity_led(self):
        from phantom.automation.swarm.profile_policy import chain_for_profile
        assert chain_for_profile("cloud") == "identity"

    def test_difficulty_orders_hardened_classes_below_smb(self):
        from phantom.automation.swarm.profile_policy import difficulty_for
        assert (difficulty_for("mobile") < difficulty_for("cloud")
                < difficulty_for("enterprise") < difficulty_for("smb"))
        for profile in ("smb", "enterprise", "cloud", "financial",
                        "government", "mobile"):
            assert 0.0 <= difficulty_for(profile) <= 1.0

    def test_hints_are_members_of_their_vocabularies(self):
        from phantom.automation.swarm.profile_policy import (
            POLICY, _REASONS, THIN_CONTROL_PLANE, THIN_DEEPEN_ONE,
            THIN_IDENTITY)
        thin = {THIN_DEEPEN_ONE, THIN_IDENTITY, THIN_CONTROL_PLANE}
        for policy in POLICY.values():
            assert policy.reason_hint in _REASONS
            assert policy.thin_surface in thin

    def test_unknown_profile_chain_fallback_is_explicit(self):
        from phantom.automation.swarm.profile_policy import chain_for_profile
        # a known profile is never shadowed by the fallback
        assert chain_for_profile("smb", fallback="deep") == "creds"
        assert chain_for_profile("nope", fallback="deep") == "deep"


class TestSwarmWiring:
    """`chain=""` means \"the profile decides\"; an explicit chain wins."""

    def _captured_tasks(self, monkeypatch, **kwargs):
        import phantom.automation.swarm.scheduler as sched
        captured = {}

        def _fake_schedule(orchs, board, tasks, **kw):
            captured["tasks"] = list(tasks)
            return {"tasks": [], "board": {}, "added": 0, "skipped": 0,
                    "trail": [], "failures": [], "evolution_cases": [],
                    "actions_taken": 0}

        monkeypatch.setattr(sched, "schedule", _fake_schedule)
        from phantom.automation.swarm import run_swarm
        run_swarm(["10.0.0.5"], runner=lambda cmd, timeout=60: None,
                  **kwargs)
        return captured["tasks"]

    def test_profile_decides_the_chain_when_none_is_given(self, monkeypatch):
        goals = [t.goal for t in self._captured_tasks(
            monkeypatch, chain="", profile="mobile")]
        assert goals == ["footprint"]

    def test_explicit_chain_overrides_the_profile(self, monkeypatch):
        goals = [t.goal for t in self._captured_tasks(
            monkeypatch, chain="footprint", profile="enterprise")]
        assert goals == ["footprint"]

    def test_default_profile_enterprise_uses_full(self, monkeypatch):
        goals = [t.goal for t in self._captured_tasks(monkeypatch)]
        assert "complete_kill_chain" in goals  # the full chain


class TestCliWiring:
    def test_chain_flag_defaults_to_auto_and_shows_the_effective_one(
            self, monkeypatch):
        captured = {}
        import phantom.automation.swarm as swarm_pkg

        def _fake_run_swarm(targets, **kwargs):
            captured.update(kwargs)
            return {"ok": True, "tasks": [], "added": 0}

        monkeypatch.setattr(swarm_pkg, "run_swarm", _fake_run_swarm)

        class _Shell:
            auto_run = True

        from phantom.core.shell.commands.auto import cmd_auto
        # a PHONE target: the mobile profile is coherent with it (a host
        # target would trip the profile<->target coherence check and the
        # profile would be corrected to enterprise — see
        # tests/test_profile_target_check.py)
        cmd_auto(_Shell(), "+391234567890 --swarm --profile mobile")
        # mobile -> footprint chain, reached run_swarm explicitly
        assert captured.get("chain") == "footprint"

    def test_explicit_chain_still_wins_on_the_cli(self, monkeypatch):
        captured = {}
        import phantom.automation.swarm as swarm_pkg

        def _fake_run_swarm(targets, **kwargs):
            captured.update(kwargs)
            return {"ok": True, "tasks": [], "added": 0}

        monkeypatch.setattr(swarm_pkg, "run_swarm", _fake_run_swarm)

        class _Shell:
            auto_run = True

        from phantom.core.shell.commands.auto import cmd_auto
        cmd_auto(_Shell(), "+391234567890 --swarm --profile mobile --chain deep")
        assert captured.get("chain") == "deep"
