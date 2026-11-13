"""Profile<->target coherence: the profile must fit the target's class.

`--profile mobile` on a PC opened with the mobile posture (scan +
identity/MDM, difficulty 0.20) — the one posture that never opens a
machine — and nothing said so. The reverse (a machine profile on a phone
number) hid behind a one-way, default-only promotion.

`check_profile_target` owns the rule; these tests pin both the rule and
the wiring: the caller announces the correction and uses the effective
profile, and `--force-profile` keeps the operator's choice.
"""
import pytest


class TestCheckRule:
    def _kinds(self, *types):
        return list(types)

    def test_mobile_on_a_host_is_corrected_to_enterprise(self):
        from phantom.automation.swarm.profile_policy import (
            check_profile_target)
        check = check_profile_target("mobile", ["ip"])
        assert check.ok is False
        assert check.corrected is True
        assert check.effective == "enterprise"
        assert "mobile" in check.reason and "host" in check.reason

    @pytest.mark.parametrize("kind", ["ip", "domain", "url"])
    def test_every_machine_kind_trips_the_mobile_mismatch(self, kind):
        from phantom.automation.swarm.profile_policy import (
            check_profile_target)
        assert check_profile_target("mobile", [kind]).effective == "enterprise"

    def test_mobile_on_a_phone_is_coherent(self):
        from phantom.automation.swarm.profile_policy import (
            check_profile_target)
        check = check_profile_target("mobile", ["phone"])
        assert check.ok is True and check.corrected is False
        assert check.effective == "mobile" and check.reason == ""

    def test_a_mixed_target_set_is_not_flagged(self):
        # the engagement really is both a phone and a machine: neither
        # posture is contradicted, so the operator's pick stands
        from phantom.automation.swarm.profile_policy import (
            check_profile_target)
        check = check_profile_target("mobile", ["ip", "phone"])
        assert check.ok is True and check.effective == "mobile"

    def test_machine_profile_on_a_phone_moves_to_mobile(self):
        from phantom.automation.swarm.profile_policy import (
            check_profile_target)
        for profile in ("enterprise", "smb", "financial", "government"):
            check = check_profile_target(profile, ["phone"])
            assert check.ok is False, profile
            assert check.effective == "mobile", profile

    def test_cloud_on_a_host_is_not_flagged(self):
        # cloud is identity/control-plane led: a bare host IS a legitimate
        # cloud asset, so the check must not second-guess it
        from phantom.automation.swarm.profile_policy import (
            check_profile_target)
        check = check_profile_target("cloud", ["ip"])
        assert check.ok is True and check.effective == "cloud"

    def test_identity_subject_is_not_a_device_signal(self):
        # email/username are the engagement SUBJECT, not a device: a
        # machine profile on an email must not be rewritten
        from phantom.automation.swarm.profile_policy import (
            check_profile_target)
        check = check_profile_target("enterprise", ["email"],)
        assert check.ok is True and check.effective == "enterprise"

    def test_force_keeps_the_operator_choice(self):
        from phantom.automation.swarm.profile_policy import (
            check_profile_target)
        check = check_profile_target("mobile", ["ip"], force=True)
        assert check.ok is True and check.corrected is False
        assert check.effective == "mobile"

    def test_empty_targets_never_rewrite_the_profile(self):
        from phantom.automation.swarm.profile_policy import (
            check_profile_target)
        assert check_profile_target("mobile", []).effective == "mobile"

    def test_unknown_profile_is_normalised_to_enterprise(self):
        from phantom.automation.swarm.profile_policy import (
            check_profile_target)
        assert check_profile_target("", ["ip"]).effective == "enterprise"
        assert check_profile_target("NOPE", ["ip"]).effective == "enterprise"

    def test_result_is_a_frozen_check(self):
        from phantom.automation.swarm.profile_policy import (
            ProfileTargetCheck, check_profile_target)
        check = check_profile_target("mobile", ["domain"])
        assert isinstance(check, ProfileTargetCheck)
        assert check.target_kinds == ("domain",)


class _Shell:
    auto_run = True


class TestCliWiring:
    def _capture(self, monkeypatch):
        captured = {}
        import phantom.automation.swarm as swarm_pkg

        def _fake_run_swarm(targets, **kwargs):
            captured.update(kwargs)
            return {"ok": True, "tasks": [], "added": 0}

        monkeypatch.setattr(swarm_pkg, "run_swarm", _fake_run_swarm)
        return captured

    def test_swarm_mobile_on_a_pc_is_corrected_and_announced(
            self, monkeypatch):
        captured = self._capture(monkeypatch)
        from phantom.utils.notifier import notifier
        warns = []
        monkeypatch.setattr(notifier, "warn", lambda m, **k: warns.append(m))
        from phantom.core.shell.commands.auto import cmd_auto
        cmd_auto(_Shell(), "10.0.0.5 --swarm --profile mobile")
        assert captured.get("profile") == "enterprise"
        assert captured.get("chain") == "full"
        assert any("mobile" in w for w in warns), warns

    def test_force_profile_keeps_mobile_on_a_pc(self, monkeypatch):
        captured = self._capture(monkeypatch)
        from phantom.core.shell.commands.auto import cmd_auto
        cmd_auto(_Shell(), "10.0.0.5 --swarm --profile mobile "
                           "--force-profile")
        assert captured.get("profile") == "mobile"
        assert captured.get("chain") == "footprint"

    def test_phone_target_promotes_the_default_profile(self, monkeypatch):
        captured = self._capture(monkeypatch)
        from phantom.core.shell.commands.auto import cmd_auto
        cmd_auto(_Shell(), "+391234567890 --swarm")
        assert captured.get("profile") == "mobile"

    def test_explicit_chain_still_wins_over_the_correction(self, monkeypatch):
        captured = self._capture(monkeypatch)
        from phantom.core.shell.commands.auto import cmd_auto
        cmd_auto(_Shell(), "10.0.0.5 --swarm --profile mobile --chain deep")
        assert captured.get("chain") == "deep"
        # the profile is still corrected, only the chain is the operator's
        assert captured.get("profile") == "enterprise"


class TestAutoModeWiring:
    """`run_auto_mode` carries the same rule (plan + real runs)."""

    @pytest.fixture
    def _run(self, monkeypatch):
        def _go(arg, force=False):
            import phantom.core.automode as automode
            seen = {}

            def _fake_plan(target, goal, profile, aggressive, paranoid, speed):
                seen["profile"] = profile

                class _P:
                    steps = []
                return _P(), "ip", "full", []

            # stop the dry-run right after the check so nothing executes
            monkeypatch.setattr(automode, "_dry_run_plan", _fake_plan)
            monkeypatch.setattr(automode, "_ensure_c2_listener",
                                lambda *a, **k: None)
            from phantom.core.automode import run_auto_mode
            run_auto_mode(targets=[arg], plan=True, profile="mobile",
                          force_profile=force)
            return seen

        return _go

    def test_plan_uses_the_corrected_profile(self, _run):
        # --profile mobile on a PC: the plan runs on enterprise
        assert _run("10.0.0.5")["profile"] == "enterprise"

    def test_force_profile_reaches_the_plan(self, _run):
        assert _run("10.0.0.5", force=True)["profile"] == "mobile"

    def test_phone_target_keeps_the_mobile_plan(self, _run):
        assert _run("+391234567890")["profile"] == "mobile"
