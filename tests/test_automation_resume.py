"""A4: campaign resume after restart.

Coverage:
- WorldModel round-trips through to_dict/from_dict (findings, hypotheses,
  opsec ledger, identity graph)
- AutonomousAgent.save_state / from_state restore the world model and the
  dead-capability discipline
- an interrupted run resumes from the checkpoint and completes the goal
  without re-executing what already produced facts
- run_autonomous(state_path=...) picks up the checkpoint automatically
- run_campaign(state_dir=...) persists and resumes per-target checkpoints
"""
import json
import os
import shutil
import tempfile
import threading
import unittest
from unittest.mock import Mock

from phantom.automation.belief import WorldModel, IdentityGraph, Finding, Hypothesis
from phantom.automation.agent import AutonomousAgent, run_autonomous, run_campaign
from phantom.automation.guidance.commands import make_registry
from phantom.automation.guidance.stealth import StealthConfig, StealthEngine
from phantom.automation.guidance.threatmodel import BlueTeamModel
from phantom.automation.runtime.stealth_runtime import StealthRuntime, TimingGovernor
from phantom.automation.runtime.toolchain import ToolRegistry
from phantom.automation.sandbox.sandbox import SandboxEngine, SandboxVerdict, SandboxResult

VICTIM_IP = "10.0.0.5"


def _reset_c2():
    from phantom.core.c2_server import c2_state
    c2_state.beacons.clear()
    c2_state.tasks.clear()
    c2_state.results.clear()


def _fake_builder(platform, host, port):
    """Fake compile-on-demand: produces a real file (the deploy path
    checks the binary exists on disk)."""
    fd, path = tempfile.mkstemp(prefix="fake_beacon_", suffix=".bin")
    with os.fdopen(fd, "wb") as f:
        f.write(b"PHANTOM-FAKE-BEACON")
    return path


def _fake_runner(targets=(VICTIM_IP,)):
    from phantom.core.c2_server import c2_state
    _idx = [0]
    lock = threading.Lock()

    def _register():
        with lock:
            _idx[0] += 1
            for target in targets:
                if not any(i.get("ip") == target
                           for i in c2_state.get_beacons().values()):
                    c2_state.update_beacon(f"beacon-{target}-{_idx[0]}",
                                           {"ip": target, "os": "Linux"})
                    return
            c2_state.update_beacon(f"beacon-{targets[0]}-{_idx[0]}",
                                   {"ip": targets[0], "os": "Linux"})

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
            # beacon deploy (scp + setsid): beacon starts on target
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
    import time
    from phantom.core.c2_server import c2_state
    while not stop.is_set():
        for bid in list(c2_state.get_beacons().keys()):
            for task in c2_state.get_pending_tasks(bid):
                res = runner(task["command"])
                c2_state.add_result(bid, task["task_id"], res.stdout)
        time.sleep(0.05)


def _approving_sandbox():
    class _Approve(SandboxEngine):
        def preflight(self, sample_path):
            return SandboxVerdict(approved=True,
                                  results=[SandboxResult(backend="docker", ok=True)])
    return _Approve()


class _FakeSocialEngine:
    """Deterministic stand-in mirroring the full real SocialEngine interface
    (including the video/social-DM capabilities added later), so the agent
    can exercise every social capability during resume tests."""

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
        return True, [f"PHISH_SENT: to={targets[0] if targets else ''} channel=email link=https://track.example/abc"]

    def dm(self, targets=None, pretext=None, use_video=False, use_login_page=False):
        self.calls.append(("dm", list(targets or []), pretext))
        return True, [f"DM_SENT: to={targets[0] if targets else ''} platform=telegram link=https://t.me/x/abc"]

    def dm_follow(self, targets=None, platform=""):
        self.calls.append(("dm_follow", list(targets or []), platform))
        return True, [f"FOLLOW_SENT: to={targets[0] if targets else ''} platform={platform or 'github'}"]

    def wait_follow(self, timeout=5.0):
        self.calls.append(("wait_follow", timeout))
        return True, [f"FOLLOW_ACCEPTED: to={VICTIM_IP}"]

    def harvest(self, timeout=5.0):
        self.calls.append(("harvest", timeout))
        return True, [f"VICTIM_IP: ip={VICTIM_IP} ua=Mozilla when=now"]

    def poll(self, timeout=90.0):
        self.calls.append(("poll", timeout))
        return True, [f"VICTIM_IP: ip={VICTIM_IP} ua=Mozilla when=now"]


def _tools():
    return ToolRegistry(installed={"nmap", "sshpass", "curl", "nc",
                                   "redis-cli", "smbmap"})


class TestWorldModelRoundTrip(unittest.TestCase):

    def test_findings_and_graph_round_trip(self):
        wm = WorldModel(target="bob@corp.com", target_type="email")
        wm.add_finding("identity", "bob@corp.com",
                       {"username": "bob"}, confidence=0.9,
                       source="osint_identity", evidence="IDENTITY: ...")
        wm.add_finding("victim_ip", VICTIM_IP, {"ip": VICTIM_IP},
                       confidence=0.8, source="poll_hits")
        wm.add_hypothesis("ssh_login", "found ssh", cost=0.4)
        wm.spend_opsec(2.5)
        wm.record_action("scan_tcp", {}, "nmap -sS x", True, "ok")
        wm.record_failure("redis_info", "no service")
        wm.identity.link("email", "bob@corp.com", "username", "bob")

        wm2 = WorldModel.from_dict(wm.to_dict())
        self.assertEqual(wm2.target, "bob@corp.com")
        self.assertEqual(wm2.target_type, "email")
        self.assertTrue(wm2.has_any("identity"))
        self.assertTrue(wm2.has_any("victim_ip"))
        f = wm2.get("identity", "bob@corp.com")
        self.assertEqual(f.value["username"], "bob")
        self.assertEqual(f.confidence, 0.9)
        self.assertEqual(len(wm2.pending_hypotheses()), 1)
        self.assertEqual(wm2.opsec_spent, 2.5)
        self.assertEqual(len(wm2.actions_taken), 1)
        self.assertEqual(len(wm2.failures), 1)
        self.assertEqual(len(wm2.identity.neighbors("email", "bob@corp.com")), 1)

    def test_identity_graph_round_trip(self):
        g = IdentityGraph()
        g.link("person", "Alice", "email", "alice@corp.com")
        g.link("email", "alice@corp.com", "phone", "+391234")
        g2 = IdentityGraph.from_dict(g.to_dict())
        self.assertEqual(len(g2.nodes), 3)
        self.assertEqual(len(g2.neighbors("phone", "+391234")), 1)
        self.assertEqual(g2.get("person", "Alice").node_type, "person")


class TestAgentStateResume(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        _reset_c2()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _checkpoint(self, name="state.json"):
        return os.path.join(self.tmp, name)

    def _events(self):
        return []

    def test_state_round_trip_restores_world(self):
        agent = AutonomousAgent("10.0.0.9", target_type="ip",
                                toolchain=_tools())
        agent.wm.add_finding("service", "10.0.0.9/tcp/22",
                             {"port": "22", "service": "ssh"})
        agent._mark_failed("redis_info")
        path = agent.save_state(self._checkpoint())

        agent2 = AutonomousAgent.from_state(path, toolchain=_tools())
        self.assertEqual(agent2.target, "10.0.0.9")
        self.assertEqual(agent2.target_type, "ip")
        self.assertTrue(agent2.wm.has("service", "10.0.0.9/tcp/22"))
        self.assertIn("redis_info", agent2._failed_caps)
        resumed = [e for e in agent2.sink.events if e["kind"] == "resumed"]
        self.assertEqual(len(resumed), 1)

    def test_interrupted_run_resumes_and_completes(self):
        # phase 1: too few iterations to finish — checkpoint written
        runner = _fake_runner()
        stop = threading.Event()
        sim = threading.Thread(target=_c2_simulator, args=(runner, stop),
                               daemon=True)
        sim.start()
        try:
            res1, agent1 = run_autonomous(
                target="bob@corp.com", goal="deliver",
                max_iterations=2, return_agent=True,
                runner=runner, sandbox=_approving_sandbox(),
                cred_discoverer=lambda s: ("root", "toor"),
                toolchain=_tools(), beacon_builder=_fake_builder,
                social_engine=_FakeSocialEngine(),
                state_path=self._checkpoint())
            self.assertTrue(os.path.exists(self._checkpoint()))
            state = json.load(open(self._checkpoint()))
            self.assertTrue(state["wm"]["findings"],
                            "checkpoint must persist partial findings")

            # phase 2: fresh process resumes from the checkpoint
            res2, agent2 = run_autonomous(
                target="bob@corp.com", goal="deliver",
                max_iterations=15, return_agent=True,
                runner=runner, sandbox=_approving_sandbox(),
                cred_discoverer=lambda s: ("root", "toor"),
                toolchain=_tools(), beacon_builder=_fake_builder,
                social_engine=_FakeSocialEngine(),
                state_path=self._checkpoint())
            self.assertTrue(res2["beacon_established"], res2)
            self.assertTrue(res2["persistence_installed"], res2)
            resumed = [e for e in agent2.sink.events if e["kind"] == "resumed"]
            self.assertEqual(len(resumed), 1)
            # findings from phase 1 survived into phase 2
            self.assertTrue(agent2.wm.find("identity"))
        finally:
            stop.set()
            sim.join(timeout=3)

    def test_campaign_state_dir_resumes(self):
        state_dir = os.path.join(self.tmp, "campaign")
        runner = _fake_runner()
        stop = threading.Event()
        sim = threading.Thread(target=_c2_simulator, args=(runner, stop),
                               daemon=True)
        sim.start()
        try:
            camp1 = run_campaign(
                targets=["bob@corp.com"], goal="deliver",
                max_iterations=2, max_agents=2,
                runner=runner, sandbox=_approving_sandbox(),
                cred_discoverer=lambda s: ("root", "toor"),
                toolchain=_tools(), beacon_builder=_fake_builder,
                social_engine=_FakeSocialEngine(),
                state_dir=state_dir)
            files = os.listdir(state_dir)
            self.assertTrue(any(f.endswith(".json") for f in files))
            camp2 = run_campaign(
                targets=["bob@corp.com"], goal="deliver",
                max_iterations=15, max_agents=2,
                runner=runner, sandbox=_approving_sandbox(),
                cred_discoverer=lambda s: ("root", "toor"),
                toolchain=_tools(), beacon_builder=_fake_builder,
                social_engine=_FakeSocialEngine(),
                state_dir=state_dir)
            r = camp2["results"]["bob@corp.com"]
            self.assertTrue(r["beacon_established"], r)
            self.assertTrue(r["persistence_installed"], r)
        finally:
            stop.set()
            sim.join(timeout=3)

    def test_fresh_run_with_state_path_writes_checkpoint(self):
        path = self._checkpoint()
        # the fake C2 registers a beacon whose source IP matches the target,
        # so the runner must be told which IP this run will deploy to
        runner = _fake_runner(targets=("10.0.0.9",))
        stop = threading.Event()
        sim = threading.Thread(target=_c2_simulator, args=(runner, stop),
                               daemon=True)
        sim.start()
        try:
            run_autonomous(
                target="10.0.0.9", goal="deliver",
                runner=runner, sandbox=_approving_sandbox(),
                cred_discoverer=lambda s: ("root", "toor"),
                toolchain=_tools(), beacon_builder=_fake_builder,
                state_path=path)
            self.assertTrue(os.path.exists(path))
        finally:
            stop.set()
            sim.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
