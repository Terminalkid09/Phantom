"""Fase 2 — mobile surface in the auto-mode.

The mobile recon capabilities (`mobile_probe`, `mobile_mdm_fingerprint`)
existed but were ORPHANED: no strategy ever planned them. These tests pin
the wiring that makes a phone target and a service-bearing host actually
reach the mobile/MDM stage, plus the Android build target.
"""
from phantom.automation.belief import WorldModel
from phantom.automation.brain.targets import TargetLedger
from phantom.automation.guidance.commands import make_registry
from phantom.automation.guidance.stealth import StealthConfig, StealthEngine
from phantom.automation.guidance.strategy import (
    STRATEGIES,
    ProfileDetector,
    TargetModel,
    _mobile_device,
    _mobile_host,
    applicable_strategies,
)
from phantom.automation.planner import Planner


def _plan(wm):
    se = StealthEngine(wm, StealthConfig())
    pl = Planner(make_registry(), se)
    led = TargetLedger(wm.target, scope_list=[])
    return pl.plan_strategic(wm, goal="complete_kill_chain", ledger=led)


# ───────────────────────────── strategy library ─────────────────────────────

class TestStrategies:
    def test_two_mobile_strategies_with_goal_mobile(self):
        by_id = {s.id: s for s in STRATEGIES}
        assert by_id["mobile_surface_device"].goal == "mobile"
        assert by_id["mobile_surface_host"].goal == "mobile"

    def test_device_strategy_ranks_above_beacon(self):
        by_id = {s.id: s for s in STRATEGIES}
        beacon = [s for s in STRATEGIES
                  if s.id == "identity_beacon"][0]
        # the phone chain must include the mobile stage before the terminal
        assert by_id["mobile_surface_device"].weight > beacon.weight

    def test_host_strategy_ranks_below_footprint(self):
        by_id = {s.id: s for s in STRATEGIES}
        assert by_id["mobile_surface_device"].weight < \
            by_id["identity_osint"].weight


# ───────────────────────────── target model ─────────────────────────────────

class TestTargetModel:
    def test_phone_is_mobile(self):
        wm = WorldModel(target="+391234567890", target_type="phone")
        assert ProfileDetector.detect(wm).is_mobile

    def test_mobile_fact_marks_surface(self):
        wm = WorldModel(target="10.0.0.5", target_type="ip")
        wm.add_finding("mdm_vendor", "intune", {"vendor": "intune"},
                       source="mobile_mdm_fingerprint")
        assert ProfileDetector.detect(wm).has_mobile

    def test_predicates(self):
        phone = TargetModel(is_mobile=True)
        hint = TargetModel(is_network=True, mobile_hint=True)
        host = TargetModel(is_network=True, open_services=["tcp/443"])
        bare = TargetModel(is_network=True)
        assert _mobile_device(phone) and not _mobile_device(host)
        assert _mobile_host(hint)
        assert not _mobile_host(host)   # a plain port is NOT an MDM hint
        assert not _mobile_host(bare)

    def test_applicable_includes_mobile_for_phone(self):
        wm = WorldModel(target="+391234567890", target_type="phone")
        ids = {s.id for s in applicable_strategies(ProfileDetector.detect(wm))}
        assert "mobile_surface_device" in ids


# ───────────────────────────── planned chain ────────────────────────────────

class TestMobileChain:
    def test_phone_chain_includes_mobile_stage(self):
        wm = WorldModel(target="+391234567890", target_type="phone")
        plan = _plan(wm)
        assert "mobile_surface_device" in plan.strategy_chain
        # OSINT still leads (doctrine: person first, then device)
        assert plan.steps[0].capability.id == "osint_identity"

    def test_plain_web_host_does_not_plan_mobile_recon(self):
        """A generic tcp/443 must NOT trigger the MDM probe: the strategy
        must not hijack every scanned host."""
        wm = WorldModel(target="10.0.0.5", target_type="ip")
        wm.add_finding("service", "tcp/443",
                       {"port": 443, "service": "https"}, source="scan_tcp")
        wm.add_finding("os", "os", {"name": "Linux"}, source="os_detect")
        plan = _plan(wm)
        ids = [s.capability.id for s in plan.steps]
        assert "mobile_probe" not in ids
        assert "mobile_surface_host" not in plan.strategy_chain

    def test_mdm_hint_plans_mobile_recon(self):
        """Concrete mobile/MDM evidence triggers the mobile surface: the
        stage is in the chain and, when asked for it, plans the probe."""
        wm = WorldModel(target="10.0.0.5", target_type="ip")
        wm.add_finding("service", "tcp/443",
                       {"port": 443, "service": "https",
                        "version": "AirWatch MDM 9.1"}, source="scan_tcp")
        wm.add_finding("os", "os", {"name": "Linux"}, source="os_detect")
        plan = _plan(wm)
        assert "mobile_surface_host" in plan.strategy_chain
        # the mobile stage itself plans both capabilities
        se = StealthEngine(wm, StealthConfig())
        pl = Planner(make_registry(), se)
        led = TargetLedger(wm.target, scope_list=[])
        mobile_plan = pl.plan_strategic(wm, goal="mobile", ledger=led)
        ids = [s.capability.id for s in mobile_plan.steps]
        assert ids == ["mobile_probe", "mobile_mdm_fingerprint"]

    def test_mobile_host_sits_between_creds_and_beacon(self):
        """The MDM probe runs after credential acquisition but BEFORE the
        beacon stage, and only on a host with a concrete mobile hint (so it
        can never hijack every scanned host)."""
        by_id = {s.id: s for s in STRATEGIES}
        w_mobile = by_id["mobile_surface_host"].weight
        assert by_id["network_beacon"].weight < w_mobile \
            < by_id["network_creds"].weight

    def test_confirmed_mobile_surface_is_not_replanned(self):
        wm = WorldModel(target="10.0.0.5", target_type="ip")
        wm.add_finding("mobile", "mdm", {"vendor": "intune"},
                       source="mobile_probe")
        wm.add_finding("mdm_vendor", "intune", {"vendor": "intune"},
                       source="mobile_mdm_fingerprint")
        plan = _plan(wm)
        ids = [s.capability.id for s in plan.steps]
        assert "mobile_probe" not in ids
        assert "mobile_mdm_fingerprint" not in ids


# ───────────────────────── platform branch (android vs ios) ─────────────────

class TestPlatformBranch:
    PHONE = "+391234567890"

    def _device_wm(self, platforms, mdm=True):
        """A PHONE target (mobile doctrine) whose platform is known."""
        wm = WorldModel(target=self.PHONE, target_type="phone")
        wm.add_finding("mobile_platform", "mdm",
                       {"platforms": platforms, "mdm": mdm,
                        "vendor": "intune"},
                       source="mobile_mdm_fingerprint")
        if mdm:
            wm.add_finding("mdm_vendor", "fingerprint",
                           {"vendors": ["intune"], "open_paths": ["/enroll"],
                            "platforms": platforms},
                           source="mobile_mdm_fingerprint")
        return wm

    def test_phone_takes_mobile_class(self):
        from phantom.automation.brain.targets import TargetLedger
        led = TargetLedger(self.PHONE, scope_list=[])
        assert led.chain_class() == "mobile"

    def test_model_reads_platforms(self):
        model = ProfileDetector.detect(self._device_wm(["ios"]))
        assert model.mobile_platforms == ["ios"]
        assert model.mobile_managed

    def test_unmanaged_ios_never_gets_beacon(self):
        from phantom.automation.brain.doctrine import allows
        assert not allows("mobile", "beacon", platform="ios", managed=False)
        assert allows("mobile", "beacon", platform="ios", managed=True)
        assert allows("mobile", "beacon", platform="android", managed=False)

    def test_other_classes_unaffected_by_platform(self):
        from phantom.automation.brain.doctrine import allows
        assert allows("network", "beacon", platform="ios", managed=False)

    def test_planner_drops_beacon_for_unmanaged_ios(self):
        plan = _plan(self._device_wm(["ios"], mdm=False))
        # for a device target the beacon stage is identity_beacon
        assert "identity_beacon" not in plan.strategy_chain

    def test_planner_keeps_beacon_for_managed_ios(self):
        plan = _plan(self._device_wm(["ios"], mdm=True))
        assert "identity_beacon" in plan.strategy_chain

    def test_planner_keeps_beacon_for_android(self):
        plan = _plan(self._device_wm(["android"], mdm=False))
        assert "identity_beacon" in plan.strategy_chain


class TestMdmPlatformProbe:
    def test_dual_ua_output_yields_platform_fact(self):
        from phantom.automation.guidance.kit import _mdm_fingerprint_interp
        wm = WorldModel(target="10.0.0.5", target_type="ip")
        out = (
            "__MDM_START__\n"
            "PLAT:ios:PATH:/enroll:CODE:200\n"
            "intune enrollment portal\n"
            "PLAT:android:PATH:/enroll:CODE:200\n"
            "intune android\n"
            "PLAT:ios:PATH:/api/v1:CODE:404\n"
            "__MDM_END__\n"
        )
        findings = _mdm_fingerprint_interp(out, wm, {})
        kinds = {f.kind for f in findings}
        assert "mdm_vendor" in kinds and "mobile_platform" in kinds
        pf = [f for f in findings if f.kind == "mobile_platform"][0]
        assert set(pf.value["platforms"]) == {"ios", "android"}

    def test_legacy_single_ua_output_still_parsed(self):
        from phantom.automation.guidance.kit import _mdm_fingerprint_interp
        wm = WorldModel(target="10.0.0.5", target_type="ip")
        out = ("__MDM_START__\nPATH:/enroll:CODE:200\njamf pro\n"
               "__MDM_END__\n")
        findings = _mdm_fingerprint_interp(out, wm, {})
        assert any(f.kind == "mdm_vendor" for f in findings)


# ───────────────────────────── android build target ─────────────────────────

class TestIosTarget:
    def test_builder_registers_ios_outputs(self):
        from phantom.utils.builder import _PLATFORM_OUT, _REMOTE_OUT
        assert _PLATFORM_OUT["ios"] == "beacon_ios.dylib"
        assert _REMOTE_OUT["ios"] == "remote_ios.dylib"

    def test_ios_build_fails_honestly_off_macos(self):
        """No cross-toolchain: either we are on macOS, or the env check
        refuses with a clear message. Never a silent fake success."""
        import sys
        from phantom.utils.build_helper import check_build_env
        if sys.platform == "darwin":
            return  # a real Mac may legitimately have the toolchain
        assert check_build_env("ios") is False

    def test_ios_beacon_compile_returns_none_off_macos(self):
        import sys
        from phantom.utils.builder import compile_beacon
        if sys.platform == "darwin":
            return
        assert compile_beacon("ios", ".", force_rebuild=True) is None


class TestAndroidTarget:
    def test_builder_registers_android_output(self):
        from phantom.utils.builder import _PLATFORM_OUT
        assert _PLATFORM_OUT["android"] == "beacon_android"

    def test_android_remote_source_tree_present(self):
        import os
        root = os.path.join("phantom", "payloads", "remote", "android")
        assert os.path.exists(os.path.join(
            root, "app", "src", "main", "AndroidManifest.xml"))
