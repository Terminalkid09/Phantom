"""The WSL probe must never hang a run.

Regression under test: `wsl.exe` on a Windows box with no usable distro BLOCKS
instead of failing, and the old resolver paid that timeout once PER TOOL — the
first toolbelt scan took ~4 minutes of dead time and looked like a broken
build. The contract now is: availability is checked once per process with a
short deadline, every resolution is cached, and a process-wide budget turns the
whole path off rather than paying another hang.
"""
import pytest

from phantom.automation.runtime import toolchain as tc


class _Completed:
    def __init__(self, returncode=1, stdout=""):
        self.returncode = returncode
        self.stdout = stdout


@pytest.fixture(autouse=True)
def _fresh_state():
    tc._reset_wsl_state()
    yield
    tc._reset_wsl_state()


class TestAHangingWslIsPaidOnce:
    def test_a_hanging_probe_does_not_get_called_for_every_tool(self, monkeypatch):
        calls = []

        def hanging(cmd, timeout):
            calls.append(cmd)
            return None          # the timeout path

        monkeypatch.setattr(tc, "_wsl_probe", hanging)
        registry = tc.ToolRegistry(detect=lambda name: False)
        for name in ("nmap", "hydra", "gobuster", "sqlmap", "whois"):
            assert registry.has(name) is False
        # ONE availability probe for the whole process, not one per tool
        assert len(calls) == 1
        assert calls[0][:2] == ["wsl", "-l"]

    def test_the_availability_answer_is_memoised(self, monkeypatch):
        calls = []
        monkeypatch.setattr(tc, "_wsl_probe",
                           lambda cmd, timeout: calls.append(cmd) or None)
        assert tc.wsl_available() is False
        assert tc.wsl_available() is False
        assert tc.wsl_available() is False
        assert len(calls) == 1

    def test_the_budget_disables_the_path_for_the_rest_of_the_process(
            self, monkeypatch):
        monkeypatch.setattr(tc, "_WSL_BUDGET_SECONDS", 0.0)
        calls = []
        monkeypatch.setattr(
            tc, "_wsl_probe",
            lambda cmd, timeout: calls.append(cmd) or _Completed(
                0, "/usr/bin/nmap\n"))
        registry = tc.ToolRegistry(detect=lambda name: False)
        assert registry.has("nmap") is False
        assert len(calls) == 1               # only the availability probe
        assert tc._wsl_budget_left() <= 0


class TestAWslThatWorksStillResolvesTools:
    def test_a_tool_in_the_default_distro_is_usable(self, monkeypatch):
        def probe(cmd, timeout):
            if cmd[:2] == ["wsl", "-l"]:
                return _Completed(0, "kali-linux\n")
            if cmd[:2] == ["wsl", "-e"]:
                return _Completed(0, "/usr/bin/nmap\n")
            return _Completed(1, "")

        monkeypatch.setattr(tc, "_wsl_probe", probe)
        registry = tc.ToolRegistry(detect=lambda name: False)
        assert registry.has("nmap") is True
        assert tc._wsl_which("nmap") == "wsl -e nmap"

    def test_a_missing_tool_is_reported_missing_not_wrapped(self, monkeypatch):
        def probe(cmd, timeout):
            return _Completed(1, "")

        monkeypatch.setattr(tc, "_wsl_probe", probe)
        monkeypatch.setattr(tc, "_wsl_distro_list", lambda: [])
        registry = tc.ToolRegistry(detect=lambda name: False)
        assert registry.has("nmap") is False

    def test_a_named_distro_is_used_when_the_default_has_nothing(
            self, monkeypatch):
        def probe(cmd, timeout):
            if cmd[:2] == ["wsl", "-l"]:
                return _Completed(0, "kali-linux\n")
            if cmd[:2] == ["wsl", "-e"]:
                return _Completed(1, "")
            if cmd[:3] == ["wsl", "-d", "kali-linux"]:
                return _Completed(0, "/usr/bin/hydra\n")
            return _Completed(1, "")

        monkeypatch.setattr(tc, "_wsl_probe", probe)
        monkeypatch.setattr(tc, "_wsl_distro_list", lambda: ["kali-linux"])
        registry = tc.ToolRegistry(detect=lambda name: False)
        assert registry.has("hydra") is True
        assert tc._wsl_which("hydra") == "wsl -d kali-linux hydra"

    def test_resolutions_are_cached(self, monkeypatch):
        calls = []

        def probe(cmd, timeout):
            calls.append(tuple(cmd))
            return _Completed(0, "/usr/bin/nmap\n") if cmd[:2] != ["wsl", "-l"] \
                else _Completed(0, "kali\n")

        monkeypatch.setattr(tc, "_wsl_probe", probe)
        registry = tc.ToolRegistry(detect=lambda name: False)
        assert registry.has("nmap") is True
        before = len(calls)
        assert registry.has("nmap") is True
        assert tc._wsl_which("nmap") == "wsl -e nmap"
        assert len(calls) == before, "a cached answer must not re-probe"


class TestTheDescriptorStillDegrades:
    def test_no_wsl_and_no_native_binary_means_missing_not_crashing(
            self, monkeypatch):
        monkeypatch.setattr(tc, "_wsl_probe", lambda cmd, timeout: None)
        registry = tc.ToolRegistry(detect=lambda name: False)
        assert registry.missing(["nmap", "whois"]) == ["nmap", "whois"]
        assert registry.resolve(["nmap", "whois"]) is None

    def test_a_native_binary_wins_before_wsl_is_consulted(self, monkeypatch):
        calls = []
        monkeypatch.setattr(tc, "_wsl_probe",
                           lambda cmd, timeout: calls.append(cmd))
        registry = tc.ToolRegistry(detect=lambda name: name == "nmap")
        assert registry.has("nmap") is True
        assert calls == [], "a native hit must not pay for a WSL probe"
