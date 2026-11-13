"""The single OS→artefact source (8.3).

Five sites used to answer "which family is this target" with five string
sniffs, and the one that shipped the beacon returned **linux, silently**
when detection failed — a Linux ELF for an unknown Windows box, with the
operator told nothing. These tests pin the classification rules (word
boundaries, most-specific token first), the priority order, and the
distinction between DETECTED and ASSUMED.
"""
import pytest

from phantom.utils.target_platform import (
    PLATFORMS,
    TargetPlatform,
    assumed_linux,
    from_banner,
    from_beacon_id,
    from_findings,
    from_os_string,
    is_kernel_compatible,
    resolve,
)


def _wm(*findings):
    """A minimal WorldModel stand-in: findings are (kind, key, value)."""
    class _F:
        def __init__(self, kind, key, value):
            self.kind, self.key, self.value = kind, key, value

    class _WM:
        def __init__(self, fs):
            self._fs = fs

        def find(self, kind):
            return [f for f in self._fs if f.kind == kind]

    return _WM([_F(k, key, value) for k, key, value in findings])


class TestOsString:
    @pytest.mark.parametrize("text,platform", [
        ("Microsoft Windows Server 2019", "windows"),
        ("Windows 10 19045", "windows"),
        ("Windows XP SP3", "windows"),
        ("Ubuntu Linux 22.04", "linux"),
        ("Debian GNU/Linux 12", "linux"),
        ("CentOS Linux 7", "linux"),
        ("FreeBSD 13.2-RELEASE", "linux"),
        ("macOS 14.5 Ventura", "macos"),
        ("Darwin Kernel Version 23.4.0", "macos"),
        ("Apple iPhone iOS 17.4", "ios"),
        ("iPadOS 16.1", "ios"),
        ("Android 13 (API 33)", "android"),
        ("Linux 5.15.0-91-generic", "linux"),
    ])
    def test_a_real_os_string_classifies(self, text, platform):
        answer = from_os_string(text)
        assert answer.platform == platform, (text, answer)
        assert answer.known is True

    def test_ios_does_not_match_bios(self):
        # the substring trap: "bios" contains "ios"
        answer = from_os_string("Phoenix BIOS 4.0")
        assert answer.platform != "ios"

    @pytest.mark.parametrize("text", ["", "   ", "unknown", "Nmap done"])
    def test_an_unclassifiable_string_is_not_forced_into_a_family(self, text):
        answer = from_os_string(text)
        assert answer.platform == ""
        assert answer.known is False

    def test_windows_is_found_before_the_generic_unix_tokens(self):
        # "windows" and "unix" can both appear ("Microsoft Windows ... POSIX
        # subsystem"); the specific family must win
        answer = from_os_string("Microsoft Windows Server 2022 with Unix "
                                "services")
        assert answer.platform == "windows"


class TestArch:
    def test_64_bit_is_the_default_when_unclear(self):
        assert from_os_string("Windows").arch == "x64"
        assert from_os_string("whatever").arch == "x64"

    @pytest.mark.parametrize("text", ["i686", "32-bit", "Win32", "armv7"])
    def test_positive_32_bit_evidence_downgrades(self, text):
        assert from_os_string(text).arch == "x86"

    @pytest.mark.parametrize("text", ["x86_64", "AMD64", "64-bit", "aarch64"])
    def test_64_bit_evidence_stays_x64(self, text):
        assert from_os_string(text).arch == "x64"

    def test_an_explicit_arch_argument_wins(self):
        assert from_os_string("Windows 32-bit", arch="x64").arch == "x64"


class TestFromFindings:
    def test_a_confirmed_os_finding_is_the_senior_source(self):
        wm = _wm(("os", "detected", {"name": "Windows Server 2019"}))
        answer = from_findings(wm)
        assert answer.platform == "windows" and answer.known
        assert answer.os_name == "Windows Server 2019"

    def test_the_inferred_os_is_used_when_nothing_is_confirmed(self):
        wm = _wm(("os_inferred", "role", {"name": "Ubuntu Linux"}))
        answer = from_findings(wm)
        assert answer.platform == "linux"
        assert "inferred" in answer.source

    def test_the_value_may_carry_os_or_name(self):
        assert from_findings(_wm(("os", "d", {"os": "Windows"}))).platform \
            == "windows"
        assert from_findings(_wm(("os", "d", {"name": "Windows"}))).platform \
            == "windows"

    def test_nothing_detected_is_an_empty_answer_not_a_default(self):
        answer = from_findings(_wm())
        assert answer.platform == "" and answer.known is False
        assert from_findings(None).platform == ""

    def test_a_finding_without_a_name_is_skipped(self):
        wm = _wm(("os", "detected", {"accuracy": 90}),
                 ("os_inferred", "role", {"name": "Windows 10"}))
        assert from_findings(wm).platform == "windows"

    def test_several_findings_say_which_one_answered(self):
        wm = _wm(("os", "host-a", {"name": "Linux"}),
                 ("os", "host-b", {"name": "Windows 10"}))
        answer = from_findings(wm)
        assert answer.platform == "linux"
        assert "host-a" in answer.source

    def test_a_broken_world_model_does_not_raise(self):
        class _Broken:
            def find(self, kind):
                raise RuntimeError("boom")

        assert from_findings(_Broken()).platform == ""


class TestFromBanner:
    def test_a_banner_beats_the_port_fingerprint(self):
        answer = from_banner("SSH-2.0-OpenSSH_9.6", open_ports=[445])
        assert answer.platform == "linux"
        assert answer.source == "banner"

    def test_the_port_fingerprint_decides_when_the_banner_says_nothing(self):
        answer = from_banner("", open_ports=[135, 445, 3389])
        assert answer.platform == "windows"
        assert answer.source == "ports"

    def test_ssh_ports_mean_linux(self):
        assert from_banner("", open_ports=[22]).platform == "linux"

    def test_windows_ports_outrank_unix_ports(self):
        assert from_banner("", open_ports=[22, 445]).platform == "windows"

    def test_nothing_known_stays_empty(self):
        assert from_banner("", open_ports=[8080, 8000]).platform == ""


class TestFromBeaconId:
    @pytest.mark.parametrize("beacon_id,platform", [
        ("WIN-4F2A", "windows"), ("LNX-9C11", "linux"),
        ("AND-77B2", "android"), ("MAC-1234", "macos"),
        ("IOS-9001", "ios"),
    ])
    def test_the_id_prefix_names_the_platform(self, beacon_id, platform):
        assert from_beacon_id(beacon_id).platform == platform

    @pytest.mark.parametrize("beacon_id", ["", "UNKNOWN-ID", "beacon-1"])
    def test_an_unrecognised_id_is_empty(self, beacon_id):
        assert from_beacon_id(beacon_id).platform == ""


class TestAssumedAndResolve:
    def test_the_default_is_marked_assumed(self):
        answer = assumed_linux()
        assert answer.platform == "linux" and answer.known is False
        assert answer.assumed is True
        assert "ASSUMED" in answer.label

    def test_resolve_prefers_a_detection_over_the_default(self):
        detected = from_os_string("Windows 10")
        assert resolve(assumed_linux(), detected).platform == "windows"
        assert resolve(detected, assumed_linux()).platform == "windows"

    def test_resolve_falls_back_to_the_default_when_nothing_detected(self):
        answer = resolve(TargetPlatform(), assumed_linux())
        assert answer.assumed is True

    def test_resolve_of_nothing_is_empty(self):
        assert resolve(None, TargetPlatform()).platform == ""

    def test_the_label_names_the_source(self):
        detected = from_os_string("Windows 10", source="nmap -O")
        assert "nmap -O" in detected.label
        assert "ASSUMED" not in detected.label


class TestKernelCompatibility:
    def test_the_same_family_always_fits(self):
        for platform in PLATFORMS:
            assert is_kernel_compatible(platform, platform) is True

    def test_pe_is_not_an_elf(self):
        assert is_kernel_compatible("windows", "linux") is False
        assert is_kernel_compatible("linux", "windows") is False
        assert is_kernel_compatible("macos", "linux") is False

    def test_android_runs_linux_artefacts(self):
        assert is_kernel_compatible("android", "linux") is True
        assert is_kernel_compatible("linux", "android") is True

    def test_an_unknown_family_is_never_compatible(self):
        assert is_kernel_compatible("", "linux") is False
        assert is_kernel_compatible("linux", "") is False
