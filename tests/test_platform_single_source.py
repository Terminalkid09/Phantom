"""8.3 — ONE source for the artefact family, and no silent default.

Five call sites used to classify the target OS with five private string
sniffs, and the one that shipped the beacon returned "linux" IN SILENCE
when detection failed. These tests pin the shared source into every call
site (the agent, the payload module, the manual C2 `generate`, the network
map) and pin the loud default.
"""
import os
import re

import pytest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _source(rel):
    with open(os.path.join(_REPO, rel), encoding="utf-8",
              errors="replace") as handle:
        return handle.read()


class TestNoPrivateSniffing:
    """A private substring test for "windows"/"linux" is the bug's shape."""

    _SITES = ("phantom/automation/agent.py", "phantom/modules/payload.py",
              "phantom/core/netmap.py", "phantom/core/c2_shell.py")

    @pytest.mark.parametrize("rel", _SITES)
    def test_the_call_site_delegates_to_the_shared_source(self, rel):
        text = _source(rel)
        assert "target_platform" in text, rel

    @pytest.mark.parametrize("rel", _SITES)
    def test_no_call_site_classifies_the_os_itself(self, rel):
        """`\"windows\" in <something>.lower()` is what we removed."""
        text = _source(rel)
        offenders = re.findall(
            r'["\']windows["\']\s+in\s+[A-Za-z_][\w\.\[\]\(\)]*\.lower\(\)',
            text)
        assert offenders == [], (rel, offenders)

    def test_the_platform_module_is_the_only_os_token_table(self):
        text = _source("phantom/utils/target_platform.py")
        assert "_OS_TOKENS" in text
        for rel in self._SITES:
            assert "_OS_TOKENS" not in _source(rel), rel


class TestAgentPlatform:
    def _agent(self, **kw):
        from phantom.automation.agent import AutonomousAgent
        return AutonomousAgent(target="10.0.0.5", target_type="ip", **kw)

    def test_the_os_finding_decides(self):
        agent = self._agent()
        agent.wm.add_finding("os", "detected", {"name": "Windows 10"})
        assert agent._target_platform() == "windows"
        assert agent._target_platform_answer().known is True

    def test_a_linux_finding_decides(self):
        agent = self._agent()
        agent.wm.add_finding("os", "detected", {"name": "Ubuntu Linux 22.04"})
        assert agent._target_platform() == "linux"

    def test_the_inferred_os_is_used_when_nothing_is_confirmed(self):
        agent = self._agent()
        agent.wm.add_finding("os_inferred", "role", {"name": "Windows"})
        assert agent._target_platform() == "windows"

    def test_nothing_detected_is_the_linux_default_but_marked_assumed(self):
        agent = self._agent()
        answer = agent._target_platform_answer()
        assert answer.platform == "linux" and answer.assumed is True
        assert agent._target_platform() == "linux"

    def test_building_the_payload_announces_the_assumption(self):
        agent = self._agent()
        events = []
        agent._on_event = lambda k, d: events.append((k, d))
        agent._beacon_builder = lambda platform, host, port: "/tmp/beacon"
        agent._build_payload()
        notes = [d for k, d in events if k == "note"]
        assert notes, "shipping the default family must be said out loud"
        assert "not identified" in notes[0]["detail"]

    def test_a_detected_target_needs_no_such_note(self):
        agent = self._agent()
        agent.wm.add_finding("os", "detected", {"name": "Windows 10"})
        events = []
        agent._on_event = lambda k, d: events.append((k, d))
        agent._beacon_builder = lambda platform, host, port: "/tmp/beacon"
        agent._build_payload()
        notes = [d["detail"] for k, d in events if k == "note"]
        assert not any("not identified" in n for n in notes), notes

    def test_a_detected_windows_target_builds_the_windows_artefact(self):
        seen = []
        agent = self._agent()
        agent.wm.add_finding("os", "detected", {"name": "Windows 10"})
        agent._beacon_builder = (
            lambda platform, host, port: seen.append(platform) or "/tmp/b")
        agent._build_payload()
        assert seen == ["windows"]


class TestPayloadModulePlatform:
    def _module(self):
        from phantom.modules.payload import PayloadModule
        return PayloadModule()

    def test_the_shared_finding_is_used(self):
        from phantom.core.knowledge import reset_wm
        reset_wm("10.0.0.5")
        wm = reset_wm("10.0.0.5")
        wm.add_finding("os", "detected", {"name": "Windows Server 2019"})
        from phantom.core.session import session
        session.target = "10.0.0.5"
        os_string, arch, platform = self._module()._guess_os()
        assert platform == "windows"
        assert os_string == "Windows Server 2019"

    def test_nothing_detected_warns_and_marks_the_default(self):
        from phantom.core.knowledge import reset_wm
        reset_wm("10.0.0.5")
        from phantom.core.session import session
        session.target = "10.0.0.5"
        session.results.pop("scan", None)
        warns = []
        from phantom.utils.notifier import notifier
        original = notifier.warn

        def _capture(message, *a, **kw):
            warns.append(str(message))
            return original(message, *a, **kw)

        notifier.warn = _capture
        try:
            os_string, arch, platform = self._module()._guess_os()
        finally:
            notifier.warn = original
        assert platform == "linux" and arch == "x64"
        assert "non rilevato" in os_string or "Unknown" in os_string
        assert any("non rilevato" in w for w in warns), warns

    def test_the_hint_helper_shares_the_classification(self):
        from phantom.modules.payload import _os_to_payload_hint
        assert _os_to_payload_hint("Windows Server 2019 64-bit") == \
            ("x64", "windows")
        assert _os_to_payload_hint("Ubuntu Linux 22.04") == ("x64", "linux")
        assert _os_to_payload_hint("Darwin Kernel 23.4.0") == ("x64", "macos")

    def test_an_unknown_string_keeps_the_historical_linux_shape(self):
        from phantom.modules.payload import _os_to_payload_hint
        assert _os_to_payload_hint("mystery host") == ("x64", "linux")


class TestC2ShellPlatform:
    def test_the_beacon_id_prefix_is_read_by_the_shared_source(self):
        import inspect
        from phantom.core import c2_shell
        src = inspect.getsource(c2_shell.C2Shell._beacon_platform)
        assert "from_beacon_id" in src

    def test_the_generate_clue_uses_the_shared_classification(self):
        import inspect
        from phantom.core import c2_shell
        src = inspect.getsource(c2_shell.C2Shell.do_generate)
        assert "from_os_string" in src
        assert "is_kernel_compatible" in src


class TestNetmapPlatform:
    def test_the_banner_is_classified_by_the_shared_source(self):
        from phantom.core.netmap import _guess_os
        # the displayed wording is unchanged (the terrain view is unchanged),
        # but the family now comes from utils.target_platform
        assert _guess_os([], "OpenSSH_8.4") == "Linux"
        assert _guess_os([3389, 135, 445]) == "Windows (likely)"
        assert _guess_os([22, 111]) == "Linux (likely)"
        assert _guess_os([1900, 53]) == "Router/IoT firmware"
        assert _guess_os([], "mystery") == ""

    def test_a_mac_banner_is_macos_not_linux(self):
        from phantom.core.netmap import _guess_os
        assert _guess_os([], "Darwin Kernel Version 23.4.0") == "macOS"
