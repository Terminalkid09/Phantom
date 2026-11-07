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
def _fresh_state(monkeypatch):
    # a real `data/cache/wsl_inventory.json` on the operator's box must not
    # decide what these unit tests see
    monkeypatch.setattr(tc, "_inventory_file", lambda: "")
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


class TestAColdVmIsNotPermanent:
    """Measured 2026-11-07: one slow `wsl -l` hid every tool for the run.

    The first probe after `wsl --shutdown` exceeded 5 s, `ok` was memoised as
    0, and `execute_quiet('nmap …')` answered `rc=-1 "tool 'nmap' not
    installed"` while the distro printed `nmap --version` seconds later. A
    negative must expire; a positive stays.
    """

    def test_a_negative_expires_after_the_retry_delay(self, monkeypatch):
        calls = []
        monkeypatch.setattr(tc, "_WSL_RETRY_AFTER", 0.0)
        monkeypatch.setattr(tc, "_WSL_MAX_PROBES", 2)
        monkeypatch.setattr(tc, "_wsl_probe",
                           lambda cmd, timeout: calls.append(cmd) or None)
        assert tc.wsl_available() is False
        assert tc.wsl_available() is False
        assert tc.wsl_available() is False
        assert len(calls) == 2, "the retry must stop at the probe cap"

    def test_a_tool_missed_during_the_outage_is_found_after_it(self, monkeypatch):
        answers = {"n": 0}
        monkeypatch.setattr(tc, "_WSL_RETRY_AFTER", 0.0)

        def probe(cmd, timeout):
            if answers["n"] == 0:
                return None                     # the cold start
            if cmd[:2] == ["wsl", "-l"]:
                return _Completed(0, "kali-linux\n")
            return _Completed(0, "/usr/bin/nmap\n")

        monkeypatch.setattr(tc, "_wsl_probe", probe)
        monkeypatch.setattr(tc, "_wsl_distro_list", lambda: [])
        assert tc._wsl_which("nmap") is None    # honest during the outage
        answers["n"] = 1
        # the per-tool cache must not have poisoned the answer
        assert tc._wsl_which("nmap") == "wsl -e nmap"

    def test_a_failed_distro_listing_is_not_memoised(self, monkeypatch):
        import subprocess

        def boom(*a, **k):
            raise OSError("wsl.exe not ready")

        monkeypatch.setattr(subprocess, "run", boom)
        assert tc._wsl_distro_list() == []
        names = "kali-linux\n".encode("utf-16-le")
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **k: _Completed(0, names))
        assert tc._wsl_distro_list() == ["kali-linux"]


class TestTheToolsetDistroIsAskedFirst:
    """Measured 2026-11-07: the resolver spent the budget on the wrong VM.

    `wsl -e` from a Stopped Ubuntu paid a >10 s cold boot, and a probe of
    `docker-desktop` (Docker's own utility distro, no toolset) took 15.6 s of
    a 20 s budget — so Kali was never reached and auto-mode reported
    `tool unavailable: nmap, masscan, nc` on a box where `nmap --version`
    answers in about a second.
    """

    def test_docker_desktop_is_never_probed(self, monkeypatch):
        seen = []

        def probe(cmd, timeout):
            seen.append(tuple(cmd))
            if cmd[:3] == ["wsl", "-d", "kali-linux"]:
                return _Completed(0, "/usr/bin/nmap\n")
            return _Completed(1, "")

        monkeypatch.setattr(tc, "_wsl_probe", probe)
        monkeypatch.setattr(tc, "_wsl_distro_list",
                            lambda: ["Ubuntu", "docker-desktop", "kali-linux"])
        assert tc._wsl_which("nmap") == "wsl -d kali-linux nmap"
        assert not any("docker-desktop" in c for c in seen), seen

    def test_one_listing_answers_every_tool(self, monkeypatch):
        calls = []

        def probe(cmd, timeout):
            calls.append(tuple(cmd))
            if cmd[:2] == ["wsl", "-l"]:
                return _Completed(0, "kali-linux\n")
            return _Completed(0, "/usr/bin/nmap\n/usr/bin/hydra\n"
                                 "/usr/sbin/msfconsole\n")

        monkeypatch.setattr(tc, "_wsl_probe", probe)
        monkeypatch.setattr(tc, "_wsl_distro_list", lambda: ["kali-linux"])
        monkeypatch.setattr(tc, "_inventory_file", lambda: "")
        registry = tc.ToolRegistry(detect=lambda name: False)
        assert registry.has("nmap") and registry.has("hydra")
        assert registry.has("msfconsole")
        listings = [c for c in calls if "ls -1" in " ".join(c)]
        assert len(listings) == 1, calls

    def test_the_inventory_survives_the_process(self, monkeypatch, tmp_path):
        store = tmp_path / "wsl_inventory.json"
        calls = []

        def probe(cmd, timeout):
            calls.append(tuple(cmd))
            if cmd[:2] == ["wsl", "-l"]:
                return _Completed(0, "kali-linux\n")
            return _Completed(0, "/usr/bin/nmap\n")

        monkeypatch.setattr(tc, "_wsl_probe", probe)
        monkeypatch.setattr(tc, "_wsl_distro_list", lambda: ["kali-linux"])
        monkeypatch.setattr(tc, "_inventory_file", lambda: str(store))
        assert tc._wsl_which("nmap") == "wsl -d kali-linux nmap"
        # a NEW process: memory is gone, the file is not
        tc._wsl_which.__dict__.pop("_inventory", None)
        calls.clear()
        assert tc._wsl_which("hydra") is None      # not in the saved listing
        assert not [c for c in calls if "ls -1" in " ".join(c)], calls

    def test_the_security_distro_is_asked_before_plain_ubuntu(self, monkeypatch):
        seen = []

        def probe(cmd, timeout):
            seen.append(tuple(cmd))
            return _Completed(1, "")

        monkeypatch.setattr(tc, "_wsl_probe", probe)
        monkeypatch.setattr(tc, "_wsl_distro_list",
                            lambda: ["Ubuntu", "kali-linux"])
        assert tc._wsl_which("nmap") is None
        asked = [c[2] for c in seen if c[:2] == ("wsl", "-d")]
        assert asked[0] == "kali-linux", asked


class TestAWslThatWorksStillResolvesTools:
    def test_a_tool_in_the_default_distro_is_usable(self, monkeypatch):
        def probe(cmd, timeout):
            if cmd[:2] == ["wsl", "-l"]:
                return _Completed(0, "kali-linux\n")
            if cmd[:2] == ["wsl", "-e"]:
                return _Completed(0, "/usr/bin/nmap\n")
            return _Completed(1, "")

        monkeypatch.setattr(tc, "_wsl_probe", probe)
        monkeypatch.setattr(tc, "_wsl_distro_list", lambda: [])
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
        monkeypatch.setattr(tc, "_wsl_distro_list", lambda: [])
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
