"""Thin-surface policy (7.6): the profile answers a barren surface.

`--profile` owns a thin-surface policy (deepen_one / identity /
control_plane) declared in 7.1 and consumed by nobody: a run on a surface
where enumeration found almost nothing still reached for the generic
escalation list, which meant a machine class DEFAULTED into active
OSINT/phishing and a mobile class did not reach for the identity surface.

The policy now orders what a recovery re-arms first, and only while the
surface really is thin (one lead and the plan works the lead instead).
"""
import pytest


def _wm(target="10.0.0.5", target_type="ip"):
    from phantom.automation.belief import WorldModel
    return WorldModel(target=target, target_type=target_type)


class TestSurfaceIsThin:
    def test_an_empty_world_is_thin(self):
        from phantom.automation.guidance.strategy import surface_is_thin
        assert surface_is_thin(_wm()) is True

    @pytest.mark.parametrize("kind", ["service", "web_app", "web_header",
                                      "creds", "ad_domain", "mobile",
                                      "mdm_vendor", "cloud_creds",
                                      "identity", "victim_ip", "beacon",
                                      "rce_foothold", "internal_host"])
    def test_one_lead_is_enough_to_stand_down(self, kind):
        from phantom.automation.guidance.strategy import surface_is_thin
        wm = _wm()
        wm.add_finding(kind, "k", {"v": 1})
        assert surface_is_thin(wm) is False, kind

    def test_a_platform_guess_is_not_a_surface(self):
        # an OS/banner guess is not something to build a plan on
        from phantom.automation.guidance.strategy import surface_is_thin
        wm = _wm()
        wm.add_finding("os", "detected", {"name": "Windows 10"})
        wm.add_finding("banner", "ssh", {"product": "OpenSSH_9"})
        assert surface_is_thin(wm) is True

    def test_a_broken_world_model_is_not_claimed_thin(self):
        from phantom.automation.guidance.strategy import surface_is_thin

        class _Broken:
            def has_any(self, kind):
                raise RuntimeError("boom")

        assert surface_is_thin(_Broken()) is False


class TestThinSurfaceCaps:
    def test_each_policy_names_a_family(self):
        from phantom.automation.guidance.strategy import (
            THIN_SURFACE_CAPS, thin_surface_caps)
        for policy in ("deepen_one", "identity", "control_plane"):
            assert THIN_SURFACE_CAPS[policy], policy
            assert thin_surface_caps(policy) == THIN_SURFACE_CAPS[policy]

    def test_unknown_policy_names_nothing(self):
        from phantom.automation.guidance.strategy import thin_surface_caps
        assert thin_surface_caps("") == ()
        assert thin_surface_caps("nope") == ()
        assert thin_surface_caps(None) == ()

    def test_every_mapped_capability_exists_in_the_registry(self):
        """A typo would silently disable a policy: pin the ids."""
        from phantom.automation.guidance.commands import make_registry
        from phantom.automation.guidance.strategy import THIN_SURFACE_CAPS
        registry = make_registry()
        missing = sorted(
            f"{policy}:{cap}"
            for policy, caps in THIN_SURFACE_CAPS.items()
            for cap in caps
            if registry.get(cap) is None)
        assert missing == [], missing

    def test_every_policy_is_a_real_thin_policy(self):
        """The policy vocabulary is owned by profile_policy: no drift."""
        from phantom.automation.guidance.strategy import THIN_SURFACE_CAPS
        from phantom.automation.swarm.profile_policy import (
            THIN_CONTROL_PLANE, THIN_DEEPEN_ONE, THIN_IDENTITY)
        assert set(THIN_SURFACE_CAPS) == {THIN_DEEPEN_ONE, THIN_IDENTITY,
                                          THIN_CONTROL_PLANE}

    def test_the_classes_differ_by_class_of_target(self):
        from phantom.automation.guidance.strategy import thin_surface_caps
        machine = set(thin_surface_caps("deepen_one"))
        identity = set(thin_surface_caps("identity"))
        cloud = set(thin_surface_caps("control_plane"))
        # a machine class does NOT reach for the person
        assert not machine & identity
        assert "beacon_deploy" not in machine
        # the identity class does exactly the opposite
        assert "osint_identity" in identity
        # the control plane is cloud identity, not ports
        assert "cloud_iam_enum" in cloud
        assert not any("scan" in c for c in cloud)


class _Agent:
    """Just enough agent to run the thin-surface half of a recovery."""

    def __init__(self, profile="enterprise", target_type="ip", thin=True):
        from phantom.automation.agent import AutonomousAgent
        self._agent = AutonomousAgent(target="10.0.0.5",
                                      target_type=target_type,
                                      profile=profile)
        if not thin:
            self._agent.wm.add_finding("service", "tcp/22", {"service": "ssh"})

    def __getattr__(self, name):
        return getattr(self._agent, name)


class TestRecoveryWiring:
    def _gap(self, agent, goal="deliver"):
        events = []
        agent._agent._on_event = lambda k, d: events.append((k, d))
        agent._agent._deep_scanned = True        # isolate the one-shot scan
        agent._recover_stall(goal)
        return [d for k, d in events if k == "gap"]

    def test_a_thin_machine_surface_follows_the_profile_policy(self):
        from phantom.automation.guidance.strategy import thin_surface_caps
        gaps = self._gap(_Agent(profile="smb"))
        assert gaps, "the policy must be announced"
        assert gaps[0]["policy"] == "deepen_one"
        assert list(gaps[0]["hints"]) == \
            [c for c in thin_surface_caps("deepen_one")][:4]

    def test_a_thin_mobile_surface_reaches_for_identity(self):
        gaps = self._gap(_Agent(profile="mobile", target_type="phone"))
        assert gaps[0]["policy"] == "identity"
        assert "osint_identity" in gaps[0]["hints"]

    def test_a_thin_cloud_surface_reaches_for_the_control_plane(self):
        gaps = self._gap(_Agent(profile="cloud"))
        assert gaps[0]["policy"] == "control_plane"
        assert "cloud_iam_enum" in gaps[0]["hints"]

    def test_a_surface_with_a_lead_keeps_the_learned_gap(self):
        # one open service: the plan works the service, so the class prior
        # must NOT override what the run actually knows
        gaps = self._gap(_Agent(profile="smb", thin=False))
        assert all(not g["policy"] for g in gaps)

    def test_the_profile_is_re_read_not_frozen(self):
        # the same target can become thin again after a failed wave
        agent = _Agent(profile="mobile", target_type="phone")
        assert self._gap(agent)[0]["policy"] == "identity"
        agent.wm.add_finding("service", "tcp/443", {"service": "https"})
        assert all(not g["policy"] for g in self._gap(agent))


class TestRendering:
    def test_the_policy_is_visible_on_the_gap_line(self):
        from phantom.core import stream_contract as sc
        rendered = sc.render_event("gap", {
            "goal": "deliver", "failed": 4, "policy": "control_plane",
            "hints": ["cloud_iam_enum"]}, verbose=False)
        text = rendered.head
        assert "thin surface: control_plane" in text
        assert "cloud_iam_enum" in text

    def test_a_thin_gap_without_a_missing_fact_still_reads(self):
        from phantom.core import stream_contract as sc
        rendered = sc.render_event("gap", {
            "goal": "deliver", "policy": "identity",
            "hints": ["osint_identity"]})
        assert "a surface" in rendered.head

    def test_a_gap_without_a_policy_is_unchanged(self):
        from phantom.core import stream_contract as sc
        rendered = sc.render_event("gap", {
            "goal": "deliver", "missing": "network_beacon",
            "hints": ["beacon_deploy"]})
        assert "network_beacon" in rendered.head
        assert "thin surface" not in rendered.head
