"""A1: identity targets (email/username/phone) reach beacon + persistence.

The agent auto-classifies the target; for identity targets the planner
must chain OSINT -> breach -> persona/phish -> victim_ip and only then the
network chain (scan -> creds -> beacon -> persistence). The fake
SocialEngine simulates the marker output the real engine emits.
"""
import threading
import unittest
from unittest.mock import Mock

from phantom.automation.belief import WorldModel
from phantom.automation.guidance.commands import make_registry
from phantom.automation.guidance.stealth import StealthConfig, StealthEngine
from phantom.automation.guidance.threatmodel import BlueTeamModel
from phantom.automation.runtime.stealth_runtime import StealthRuntime
from phantom.automation.sandbox.sandbox import SandboxEngine, SandboxVerdict, SandboxResult
from phantom.automation.agent import AutonomousAgent, run_autonomous

VICTIM_IP = "10.0.0.5"


def _fake_builder(platform, host, port):
    """Fake compile-on-demand: no toolchain needed. Produces a real file
    (the deploy path checks the binary exists on disk)."""
    import os
    import tempfile
    fd, path = tempfile.mkstemp(prefix="fake_beacon_", suffix=".bin")
    with os.fdopen(fd, "wb") as f:
        f.write(b"PHANTOM-FAKE-BEACON")
    return path


def _reset_c2():
    from phantom.core.c2_server import c2_state
    c2_state.beacons.clear()
    c2_state.tasks.clear()
    c2_state.results.clear()


def _fake_runner(targets=(VICTIM_IP,)):
    """Scripted runner: network recon + creds + the C++ beacon check-in +
    target-side answers for the post commands (persistence markers)."""
    from phantom.core.c2_server import c2_state
    import threading as _t
    _idx = [0]
    _lock = _t.Lock()

    def _register():
        with _lock:
            _idx[0] += 1
            for target in targets:
                if not any(info.get("ip") == target
                           for info in c2_state.get_beacons().values()):
                    c2_state.update_beacon(f"beacon-{target}-{_idx[0]}",
                                           {"ip": target, "os": "Linux 5.15"})
                    return
            c2_state.update_beacon(f"beacon-{targets[0]}-{_idx[0]}",
                                   {"ip": targets[0], "os": "Linux 5.15"})

    def runner(cmd, timeout=None):
        res = Mock()
        res.ok = False
        res.stdout = ""
        res.stderr = ""
        if "phantom-beacon.service" in cmd or "crontab" in cmd:
            res.ok = True
            res.stdout = "PERSISTENCE_OK systemd"
        elif "api/v1/payload" in cmd:
            _register()
            res.ok = True
            res.stdout = "PHANTOM"
        elif "sshpass" in cmd and "scp" in cmd:
            # beacon deploy: scp the staged binary to the target, then the
            # beacon starts and checks in (the compiled beacon does exactly
            # this over the wire)
            _register()
            res.ok = True
        elif "nmap" in cmd:
            res.ok = True
            res.stdout = ("22/tcp open ssh OpenSSH 7.9p1\n"
                          "80/tcp open http Apache httpd 2.4.49")
        elif "nc -w" in cmd:
            res.ok = True
            res.stdout = "SSH-2.0-OpenSSH_7.9p1 Debian-10"
        elif "curl" in cmd:
            res.ok = True
            res.stdout = "Server: nginx/1.18.0\n<title>Login</title>"
        elif "sshpass" in cmd or "ssh_login" in cmd:
            res.ok = True
            res.stdout = "uid=0(root) gid=0(root)"
        else:
            res.ok = True
            res.stdout = "PHANTOM"
        return res
    return runner


def _c2_simulator(runner, stop):
    """Simulates the beacon side: pulls pending C2 tasks, executes them with
    the runner and posts the output back (the exact wire path of the C++
    beacon)."""
    from phantom.core.c2_server import c2_state
    while not stop.is_set():
        for bid in list(c2_state.get_beacons().keys()):
            for task in c2_state.get_pending_tasks(bid):
                res = runner(task["command"])
                c2_state.add_result(bid, task["task_id"], res.stdout)
        time_sleep(0.05)


def time_sleep(t):
    import time
    time.sleep(t)


def _approving_sandbox():
    class _ApproveSandbox(SandboxEngine):
        def preflight(self, sample_path):
            return SandboxVerdict(approved=True,
                                  results=[SandboxResult(backend="docker", ok=True)])
    return _ApproveSandbox()


class _FakeSocialEngine:
    """Deterministic stand-in for the real SocialEngine: emits exactly the
    marker lines the shared interpreter parses, and delivers a victim_ip
    after the phish is polled."""

    def __init__(self):
        self.calls = []

    def set_social_config(self, aggressive=False, speed=False):
        self.calls.append(("set_social_config", aggressive, speed))

    def osint(self, target, target_type):
        self.calls.append(("osint", target, target_type))
        return True, [f"IDENTITY: username={target} platform=github url=https://github.com/{target}"]

    def breach(self, target, target_type):
        self.calls.append(("breach", target, target_type))
        return True, [f"BREACH: email={target} password=leakpass123 source=demo"]

    def persona(self):
        self.calls.append(("persona",))
        return True, ["PERSONA: email=persona.x@grr.la mailbox=42"]

    def persona_profile(self, name=""):
        self.calls.append(("persona_profile", name))
        return True, [f"PERSONA_PROFILE: name={name or 'cover'} audience=professional"]

    def dossier(self):
        self.calls.append(("dossier",))
        return True, ["DOSSIER_RECOMMEND: pretext=security_alert"]

    def profile_recon(self, target, platform=""):
        self.calls.append(("profile_recon", target, platform))
        return True, [f"PROFILE: username={target} visibility=public platform={platform or 'github'}"]

    def phish(self, target, target_type, use_video=False, use_login_page=False):
        self.calls.append(("phish", target, target_type, use_video, use_login_page))
        return True, [f"PHISH_SENT: to={target} channel=email link=https://track.example/abc"]

    def campaign(self, targets=None, pretext=None, use_video=False, use_login_page=False):
        self.calls.append(("campaign", list(targets or []), pretext))
        return True, [f"PHISH_SENT: to={targets[0] if targets else self.calls[-1][1]} channel=email link=https://track.example/abc"]

    def dm(self, targets=None, pretext=None, use_video=False, use_login_page=False):
        self.calls.append(("dm", list(targets or []), pretext))
        return True, [f"DM_SENT: to={targets[0] if targets else ''} platform=telegram link=https://t.me/x/abc"]

    def dm_follow(self, targets=None, platform=""):
        self.calls.append(("dm_follow", list(targets or []), platform))
        return True, [f"FOLLOW_SENT: to={targets[0] if targets else ''} platform={platform or 'github'}"]

    def wait_follow(self, timeout=5.0):
        self.calls.append(("wait_follow", timeout))
        return True, [f"FOLLOW_ACCEPTED: to={self.calls[-1][1][0] if self.calls and isinstance(self.calls[-1][1], list) else ''}"]

    def harvest(self, timeout=5.0):
        self.calls.append(("harvest", timeout))
        return True, [f"VICTIM_IP: ip={VICTIM_IP} ua=Mozilla when=now"]

    def poll(self, timeout=90.0):
        self.calls.append(("poll", timeout))
        return True, [f"VICTIM_IP: ip={VICTIM_IP} ua=Mozilla when=now"]


def _identity_agent(target, events, social=None, runner=None):
    from phantom.automation.runtime.stealth_runtime import TimingGovernor
    from phantom.automation.runtime.toolchain import ToolRegistry
    return AutonomousAgent(
        target=target, target_type="auto", profile="enterprise",
        on_event=lambda k, d: events.append((k, d)),
        runtime=StealthRuntime(
            StealthEngine(WorldModel(target=target),
                          StealthConfig()),
            runner=runner or _fake_runner(),
            cost_per_action=0.5,
            governor=TimingGovernor(base_delay=0.0, jitter=0.0),
        ),
        cred_discoverer=lambda service: ("root", "toor"),
        sandbox=_approving_sandbox(),
        toolchain=ToolRegistry(installed={"nmap", "sshpass", "curl", "nc",
                                          "redis-cli", "smbmap"}),
        beacon_builder=_fake_builder,
        social_engine=social or _FakeSocialEngine(),
    )


class TestIdentityChainDeliver(unittest.TestCase):

    def setUp(self):
        self.events = []
        _reset_c2()

    def _run_with_simulator(self, agent, max_iterations=15):
        stop = threading.Event()
        sim = threading.Thread(target=_c2_simulator,
                               args=(agent.runtime.runner, stop), daemon=True)
        sim.start()
        try:
            return agent.run(goal="deliver", max_iterations=max_iterations)
        finally:
            stop.set()
            sim.join(timeout=3)

    def test_email_target_auto_classified_and_reaches_deliver(self):
        social = _FakeSocialEngine()
        agent = _identity_agent("bob@corp.com", self.events, social)
        self.assertEqual(agent.target_type, "email")
        result = self._run_with_simulator(agent)
        # full deliver: beacon + persistence on the harvested victim IP
        self.assertTrue(result["beacon_established"], result)
        self.assertTrue(result["persistence_installed"], result)
        self.assertEqual(result["victim_ips"], 1)
        # the social chain ran: osint, breach, phish, poll
        kinds = [c[0] for c in social.calls]
        self.assertIn("osint", kinds)
        self.assertIn("phish", kinds)
        self.assertIn("poll", kinds)
        # findings in the world model
        victim_ips = agent.wm.find("victim_ip")
        self.assertTrue(victim_ips)
        self.assertEqual(victim_ips[0].value["ip"], VICTIM_IP)
        self.assertTrue(agent.wm.find("identity"))
        self.assertTrue(agent.wm.find("phish"))

    def test_username_target_auto_classified(self):
        social = _FakeSocialEngine()
        agent = _identity_agent("bob_smith", self.events, social)
        self.assertEqual(agent.target_type, "username")
        result = self._run_with_simulator(agent)
        self.assertTrue(result["beacon_established"], result)
        self.assertTrue(result["persistence_installed"], result)

    def test_phone_target_auto_classified(self):
        social = _FakeSocialEngine()
        agent = _identity_agent("+391234567890", self.events, social)
        self.assertEqual(agent.target_type, "phone")
        result = self._run_with_simulator(agent)
        self.assertTrue(result["beacon_established"], result)
        self.assertTrue(result["persistence_installed"], result)

    def test_run_autonomous_auto_classifies_and_delivers(self):
        from phantom.automation.runtime.toolchain import ToolRegistry
        social = _FakeSocialEngine()
        stop = threading.Event()
        runner = _fake_runner()
        sim = threading.Thread(target=_c2_simulator, args=(runner, stop),
                               daemon=True)
        sim.start()
        try:
            result = run_autonomous(
                target="bob@corp.com",
                runner=runner,
                beacon_builder=_fake_builder,
                sandbox=_approving_sandbox(),
                cred_discoverer=lambda service: ("root", "toor"),
                toolchain=ToolRegistry(installed={"nmap", "sshpass", "curl", "nc",
                                                  "redis-cli", "smbmap"}),
                social_engine=social,
                goal="deliver",
                max_iterations=15,
                on_event=lambda k, d: None)
        finally:
            stop.set()
            sim.join(timeout=3)
        self.assertTrue(result["beacon_established"], result)
        self.assertTrue(result["persistence_installed"], result)

    def test_network_target_skips_social_chain(self):
        # a plain IP target must NOT drag the social chain in
        social = _FakeSocialEngine()
        agent = _identity_agent("10.0.0.9", self.events, social,
                                runner=_fake_runner(targets=("10.0.0.9",)))
        self.assertEqual(agent.target_type, "ip")
        result = self._run_with_simulator(agent)
        self.assertTrue(result["beacon_established"], result)
        self.assertEqual(social.calls, [], "network target must not use the "
                                           "social engine")


if __name__ == "__main__":
    unittest.main()
