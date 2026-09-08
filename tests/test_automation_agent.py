"""End-to-end tests of the autonomous agent (fake runner, real logic)."""
import os
import re
import threading
import time
import unittest
from unittest.mock import Mock

from phantom.automation.belief import WorldModel
from phantom.automation.guidance.commands import make_registry
from phantom.automation.guidance.stealth import StealthConfig, StealthEngine
from phantom.automation.guidance.threatmodel import BlueTeamModel
from phantom.automation.runtime.stealth_runtime import StealthRuntime
from phantom.automation.sandbox.sandbox import SandboxEngine, SandboxVerdict, SandboxResult
from phantom.automation.agent import AutonomousAgent, run_autonomous

TARGET = "10.0.0.5"


def _fake_builder(platform, host, port):
    """Fake compile-on-demand: no toolchain needed. Produces a real file
    (the deploy path checks the binary exists on disk — a guard added
    after a lab run showed a missing build silently skipping deploy)."""
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


def _fake_runner(targets=(TARGET,)):
    """A scripted runner that simulates tool responses per command prefix.

    When the dropper executes (our own C++ beacon staged from the C2), the
    compiled beacon checks in to the REAL c2_state with the engagement
    target's IP — exactly what the C++ beacon does over the wire. The
    registration is matched by the agent's `_await_beacon`.
    """
    from phantom.core.c2_server import c2_state
    import threading as _t
    _idx = [0]
    _lock = _t.Lock()

    def _register():
        with _lock:
            _idx[0] += 1
            # deterministic in campaigns: pick the first target that has no
            # beacon yet, regardless of sub-agent execution order
            for target in targets:
                if not any(info.get("ip") == target
                           for info in c2_state.get_beacons().values()):
                    beacon_id = f"beacon-{target}-{_idx[0]}"
                    c2_state.update_beacon(beacon_id,
                                           {"ip": target, "os": "Linux 5.15"})
                    return beacon_id
            target = targets[0]
            beacon_id = f"beacon-{target}-{_idx[0]}"
            c2_state.update_beacon(beacon_id,
                                   {"ip": target, "os": "Linux 5.15"})
            return beacon_id

    def runner(cmd, timeout=None):
        res = Mock()
        res.ok = False
        res.stdout = ""
        res.stderr = ""
        if "api/v1/payload" in cmd:
            _register()
            res.ok = True
            res.stdout = "PHANTOM"
        elif "sshpass" in cmd and "scp" in cmd:
            # deploy path: scp the staged binary to the target, then the
            # beacon starts there and checks in (what really happens)
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


def _approving_sandbox():
    class _ApproveSandbox(SandboxEngine):
        def preflight(self, sample_path):
            return SandboxVerdict(approved=True,
                                  results=[SandboxResult(backend="docker", ok=True)])
    return _ApproveSandbox()


def _quiet_hunt_runner(method, url, body="", timeout=8.0):
    """Behavioural-hunt runner for tests: the fake target never answers
    (offline-safe), so the hunt capability stays silent and fails cleanly."""
    from phantom.automation.exploit.anomaly import ProbeResult
    return ProbeResult()


class TestAutonomousAgent(unittest.TestCase):

    def setUp(self):
        self.events = []
        _reset_c2()

    def _agent(self, aggressive=False, sandbox=None, scope_list=None):
        from phantom.automation.runtime.stealth_runtime import TimingGovernor
        from phantom.automation.runtime.toolchain import ToolRegistry
        return AutonomousAgent(
            target=TARGET, target_type="ip", profile="enterprise",
            aggressive=aggressive,
            on_event=lambda k, d: self.events.append((k, d)),
            runtime=StealthRuntime(
                StealthEngine(WorldModel(target=TARGET),
                              StealthConfig(aggressive=aggressive)),
                runner=_fake_runner(),
                cost_per_action=0.5,
                governor=TimingGovernor(base_delay=0.0, jitter=0.0),
            ),
            cred_discoverer=lambda service: ("root", "toor"),
            sandbox=_approving_sandbox() if sandbox is None else sandbox,
            scope_list=scope_list,
            toolchain=ToolRegistry(installed={"nmap", "sshpass", "curl", "nc",
                                              "redis-cli", "smbmap"}),
            beacon_builder=_fake_builder,
            hunt_runner=_quiet_hunt_runner,
        )

    def test_full_kill_chain_to_beacon(self):
        agent = self._agent()
        result = agent.run(goal="complete_kill_chain")
        self.assertTrue(result["beacon_established"], result)
        self.assertGreater(result["services_enumerated"], 0)
        kinds = [k for k, _ in self.events]
        self.assertIn("beacon_up", kinds)

    def test_operator_handoff_after_beacon_no_auto_cleanup(self):
        """The run stops at the beacon and hands it to the operator:
        a handoff event carries the beacon_id, the result reports it, and
        NO cleanup capability ever runs automatically."""
        agent = self._agent()
        result = agent.run(goal="complete_kill_chain")
        self.assertTrue(result["beacon_id"], result)
        handoffs = [d for k, d in self.events if k == "handoff"]
        self.assertEqual(len(handoffs), 1)
        self.assertEqual(handoffs[0]["beacon_id"], result["beacon_id"])
        # no cleanup planned/executed by the auto-mode
        self.assertFalse(result["cleanup_done"], result)
        runs = [d for k, d in self.events if k == "run"]
        self.assertNotIn("cleanup", [r["capability"] for r in runs])

    def test_goal_footprint_only_services(self):
        agent = self._agent()
        result = agent.run(goal="footprint", max_iterations=5)
        self.assertGreaterEqual(result["services_enumerated"], 1)

    def test_aggressive_flag_flows(self):
        agent = self._agent(aggressive=True)
        self.assertTrue(agent.aggressive)
        result = agent.run(goal="complete_kill_chain", max_iterations=10)
        self.assertTrue(result["beacon_established"])

    def test_event_stream_captures_planning(self):
        agent = self._agent()
        agent.run(goal="footprint", max_iterations=5)
        plans = [d for k, d in self.events if k == "plan"]
        self.assertGreaterEqual(len(plans), 1)
        self.assertTrue(any("scan_tcp" in p["steps"] for p in plans))

    def test_run_autonomous_function_entry(self):
        # Hermetic smoke of the public entry point: quiet hunt runner (no
        # real curl probes), no credential discovery, short iteration cap.
        # Without these the smoke would spend its real 90s web-hunt budget
        # per host and blow the test timeout — production behavior stays.
        from phantom.automation.runtime.toolchain import ToolRegistry
        result = run_autonomous(
            target=TARGET,
            runner=_fake_runner(),
            cred_discoverer=lambda service: ("root", "toor"),
            sandbox=_approving_sandbox(),
            beacon_builder=_fake_builder,
            hunt_runner=_quiet_hunt_runner,
            max_iterations=4,
            toolchain=ToolRegistry(installed={"nmap", "sshpass", "curl", "nc"}),
            on_event=lambda k, d: None)
        self.assertIsInstance(result, dict)
        self.assertIn("beacon_established", result)

    def test_no_budget_concept_no_halt_for_budget(self):
        agent = self._agent()
        result = agent.run(goal="complete_kill_chain", max_iterations=20)
        self.assertTrue(result["beacon_established"], result)
        halts = [d for k, d in self.events if k == "halt"]
        reasons = " ".join(h.get("reason", "") for h in halts)
        self.assertNotIn("budget", reasons)
        self.assertIn("opsec_spent", result)
        self.assertNotIn("opsec_budget_left", result)

    def test_failed_move_recovered_on_stall(self):
        # the agent no longer gives up on the first dead-end: bounded stall
        # recovery re-arms a failed move and keeps pushing toward the beacon
        agent = self._agent()
        agent.run(goal="footprint", max_iterations=5)  # service facts known
        agent._mark_failed("ssh_login")  # ssh failed; nothing changed since
        result = agent.run(goal="complete_kill_chain", max_iterations=10)
        self.assertTrue(result["beacon_established"], result)
        executed = [a["capability"] for a in agent.wm.actions_taken
                    if a["capability"] == "ssh_login"]
        self.assertTrue(executed)  # retried after recovery
        recovers = [d for k, d in self.events if k == "recover"]
        self.assertTrue(recovers, "expected a recover event")

    def test_failed_move_retried_when_new_facts_make_it_viable(self):
        agent = self._agent()
        agent.run(goal="footprint", max_iterations=5)
        agent._mark_failed("ssh_login")
        time.sleep(0.02)  # ensure the new finding is strictly after the failure
        # the world changed: a NEW service finding (re-scan) is useful for
        # ssh_login's preconditions -> the failed move becomes viable again
        agent.wm.add_finding("service", "tcp/2222",
                             {"port": 2222, "protocol": "tcp"},
                             confidence=0.6, source="re_scan")
        result = agent.run(goal="complete_kill_chain", max_iterations=10)
        self.assertTrue(result["beacon_established"], result)
        executed = [a["capability"] for a in agent.wm.actions_taken]
        self.assertIn("ssh_login", executed)

    def test_sandbox_denies_beacon_in_quiet_mode(self):
        class _DenySandbox(SandboxEngine):
            def preflight(self, sample_path):
                return SandboxVerdict(
                    approved=False,
                    results=[SandboxResult(backend="defender", ok=False, detected=True,
                                           error="Trojan:Win32/Phantom")],
                    reason="defender: Trojan:Win32/Phantom")

        agent = self._agent(sandbox=_DenySandbox())
        result = agent.run(goal="complete_kill_chain", max_iterations=10)
        self.assertFalse(result["beacon_established"])
        blocked = [d for k, d in self.events if k == "blocked"]
        self.assertTrue(any("defender" in d.get("reason", "") for d in blocked))

    def test_sandbox_denial_overridden_in_aggressive(self):
        class _DenySandbox(SandboxEngine):
            def preflight(self, sample_path):
                return SandboxVerdict(
                    approved=False,
                    results=[SandboxResult(backend="defender", ok=False, detected=True,
                                           error="Trojan:Win32/Phantom")],
                    reason="defender: Trojan:Win32/Phantom")

        agent = self._agent(aggressive=True, sandbox=_DenySandbox())
        result = agent.run(goal="complete_kill_chain", max_iterations=10)
        self.assertTrue(result["beacon_established"])

    def test_finalize_contains_campaign_trail(self):
        agent = self._agent()
        result = agent.run(goal="footprint", max_iterations=5)
        self.assertGreater(len(result["campaign_trail"]), 0)
        self.assertIn("actions_taken", result)

    # ------------------------------------------------------------------ scope

    def test_in_scope_target_runs_normally(self):
        agent = self._agent(scope_list=["10.0.0.0/24"])
        result = agent.run(goal="complete_kill_chain", max_iterations=10)
        self.assertTrue(result["beacon_established"], result)

    def test_out_of_scope_target_halts_immediately(self):
        agent = self._agent(scope_list=["192.168.0.0/16"])
        result = agent.run(goal="complete_kill_chain", max_iterations=10)
        self.assertFalse(result["beacon_established"])
        self.assertEqual(result["actions_taken"], 0)
        halts = [d for k, d in self.events if k == "halt"]
        self.assertTrue(any("out of scope" in h.get("reason", "") for h in halts))

    # ------------------------------------------------------------- multi-target

    def test_run_campaign_fans_out_to_sub_agents(self):
        from phantom.automation.agent import run_campaign
        from phantom.automation.runtime.toolchain import ToolRegistry
        campaign = run_campaign(
            targets=[TARGET, "10.0.0.6"],
            goal="complete_kill_chain", max_agents=2,
            runner=_fake_runner(targets=(TARGET, "10.0.0.6")),
            cred_discoverer=lambda service: ("root", "toor"),
            sandbox=_approving_sandbox(),
            beacon_builder=_fake_builder,
            hunt_runner=_quiet_hunt_runner,
            toolchain=ToolRegistry(installed={"nmap", "sshpass", "curl", "nc",
                                              "redis-cli", "smbmap"}))
        self.assertEqual(set(campaign["results"].keys()),
                         {TARGET, "10.0.0.6"})
        self.assertEqual(campaign["beacons"], 2)
        self.assertGreater(campaign["services"], 0)
        self.assertGreater(campaign["compromised_creds"], 0)
        self.assertEqual(len(campaign["_agents"]), 2)

    # ------------------------------------------- same-target phase workers

    def test_same_target_workers_share_worldmodel_and_report(self):
        from phantom.automation.agent import run_campaign
        from phantom.automation.runtime.toolchain import ToolRegistry
        _reset_c2()
        campaign = run_campaign(
            targets=[TARGET],
            goal="complete_kill_chain", max_agents=1,
            workers_per_target=2,
            runner=_fake_runner(targets=(TARGET,)),
            cred_discoverer=lambda service: ("root", "toor"),
            sandbox=_approving_sandbox(),
            beacon_builder=_fake_builder,
            hunt_runner=_quiet_hunt_runner,
            toolchain=ToolRegistry(installed={"nmap", "sshpass", "curl", "nc",
                                              "redis-cli", "smbmap"}))
        res = campaign["results"][TARGET]
        self.assertEqual(campaign["beacons"], 1)
        workers = res.get("workers", {})
        self.assertIn("exploit", workers)
        self.assertNotIn("error", workers["exploit"])

    def test_phase_gate_keeps_worker_quiet_without_facts(self):
        """A phase worker without its gate facts stays silent and halts
        cleanly instead of firing tools before its phase."""
        _reset_c2()
        sink = []

        def on_event(kind, data):
            sink.append((kind, data))

        def runner(cmd, timeout=None):
            res = Mock()
            res.ok = False
            res.stdout = ""
            res.stderr = ""
            return res

        from phantom.automation.agent import AutonomousAgent
        from phantom.automation.runtime.toolchain import ToolRegistry
        agent = AutonomousAgent(
            target=TARGET, profile="enterprise",
            on_event=on_event,
            toolchain=ToolRegistry(installed={"nmap"}),
            shared_wm=WorldModel(target=TARGET))
        agent.runtime = StealthRuntime(
            agent.stealth_engine, runner=runner,
            cost_per_action=0.5)
        result = agent.run(goal="exploit", max_iterations=3,
                           phase_wait="service", phase_wait_timeout=5.0)
        self.assertTrue(any(
            k == "halt" and "phase gate timeout" in str(d.get("reason"))
            for k, d in sink))
        self.assertFalse(any(
            k == "run" for k, d in sink))

    def test_deepen_worker_is_passive_and_never_launches_lures(self):
        """The deepen sub-agent (goal 'enrich') digs OSINT/breach/profile
        and polls the grabber, but NEVER launches new lures — the lead is
        the only one that sends, the deepen worker only enriches + waits."""
        from unittest.mock import Mock as _Mock

        class _DeepenEngine:
            def __init__(self):
                self.calls = []

            def set_social_config(self, **kw):
                pass

            def osint(self, target, target_type):
                self.calls.append("osint")
                return True, [
                    f"IDENTITY: username={target} platform=instagram "
                    f"url=https://instagram.com/{target}"]

            def breach(self, target, target_type):
                self.calls.append("breach")
                return True, [
                    f"BREACH_EXPOSURE: email={target} breach=Acme2023 date=2023"]

            def persona_profile(self, **kw):
                self.calls.append("persona_profile")
                return True, ["PERSONA_PROFILE: name=Leo_Rossi age=24 "
                              "job=Developer location=Milano avatar="]

            def dossier(self):
                self.calls.append("dossier")
                return True, ["DOSSIER_RECOMMEND: pretext=security_alert "
                              "score=0.55"]

            def profile_recon(self, username, platform=""):
                self.calls.append("profile_recon")
                return True, ["PROFILE: username=leo platform=instagram "
                              "private=0 bio= link="]

            def dm_follow(self, handles, platform=""):
                self.calls.append("dm_follow")  # MUST never fire
                return True, ["FOLLOW_SENT: handle=x platform=ig delivered=0"]

            def harvest(self, timeout=15.0):
                self.calls.append("harvest")
                return True, []

            def wait_follow(self, timeout=300.0):
                return True, []

            def poll(self, timeout=90.0):
                self.calls.append("poll")
                return True, []

        from phantom.automation.agent import AutonomousAgent
        from phantom.automation.runtime.stealth_runtime import (
            StealthRuntime,
            TimingGovernor,
        )
        _reset_c2()
        eng = _DeepenEngine()
        sink = []
        agent = AutonomousAgent(
            target="mario.rossi", target_type="username",
            on_event=lambda k, d: sink.append(k),
            social_engine=eng,
            runtime=StealthRuntime(
                StealthEngine(WorldModel(target="mario.rossi"),
                              StealthConfig(aggressive=False)),
                runner=_fake_runner(),
                cost_per_action=0.5,
                governor=TimingGovernor(base_delay=0.0, jitter=0.0)))
        result = agent.run(goal="enrich", max_iterations=4)
        self.assertIn("osint", eng.calls)
        self.assertIn("dossier", eng.calls)
        self.assertIn("profile_recon", eng.calls)
        self.assertNotIn("dm_follow", eng.calls)   # never sends
        self.assertNotIn("poll", eng.calls)        # harvest covers polling
        self.assertGreaterEqual(result.get("identity_profiles", 0), 1)

    def test_three_workers_include_post_phase(self):
        from phantom.automation.agent import run_campaign
        from phantom.automation.runtime.toolchain import ToolRegistry
        _reset_c2()
        campaign = run_campaign(
            targets=[TARGET],
            goal="complete_kill_chain", max_agents=1,
            workers_per_target=3,
            runner=_fake_runner(targets=(TARGET,)),
            cred_discoverer=lambda service: ("root", "toor"),
            sandbox=_approving_sandbox(),
            beacon_builder=_fake_builder,
            hunt_runner=_quiet_hunt_runner,
            toolchain=ToolRegistry(installed={"nmap", "sshpass", "curl", "nc",
                                              "redis-cli", "smbmap"}))
        workers = campaign["results"][TARGET].get("workers", {})
        self.assertIn("exploit", workers)
        self.assertIn("post", workers)
        for w in workers.values():
            self.assertNotIn("error", w)

    # ---------------------------------------------------- sandbox materialization

    def test_beacon_payload_materialized_for_sandbox(self):
        import os
        import tempfile

        class _CapturingSandbox(SandboxEngine):
            def __init__(self):
                self.samples = []
            def preflight(self, sample_path):
                self.samples.append(sample_path)
                return SandboxVerdict(
                    approved=True,
                    results=[SandboxResult(backend="docker", ok=True)])

        sb = _CapturingSandbox()
        agent = self._agent(sandbox=sb)
        result = agent.run(goal="complete_kill_chain", max_iterations=10)
        self.assertTrue(result["beacon_established"], result)
        real_samples = [p for p in sb.samples if p]
        self.assertTrue(real_samples, "no payload materialized for pre-flight")
        for p in real_samples:
            self.assertTrue(p.startswith(tempfile.gettempdir()), p)
            with open(p, "rb") as f:
                content = f.read()
            # The sandbox pre-flights the ACTUAL artifact shipped to the
            # target (the compiled beacon binary), not the deployment
            # one-liner: a scp/ssh or curl dropper cannot run inside the
            # networkless sandbox container (no sshpass, no curl), so it
            # always "crashed" with EXIT:127 and validated nothing. The
            # binary is what AV/EDR would ever see on the target.
            self.assertEqual(content, b"PHANTOM-FAKE-BEACON", p)
        # the materialized artifact is the one handed to the sandbox gate
        self.assertTrue(os.path.exists(agent._deploy_sample_path()))
        sandbox_events = [d for k, d in self.events if k == "sandbox"]
        self.assertTrue(any(d.get("sample") for d in sandbox_events))

    # ---------------------------------------------------- ShareContext (campaign)

    def test_share_adds_and_finds_creds(self):
        from phantom.automation.agent import ShareContext
        share = ShareContext(peers=["10.0.0.6", "10.0.0.7"])
        share.add_creds("ssh", "root", "toor", "10.0.0.5")
        share.add_creds("ssh", "root", "toor", "10.0.0.6")  # duplicate is ignored
        self.assertEqual(share.find("ssh"), ("root", "toor"))
        self.assertIsNone(share.find("smb"))
        self.assertEqual(share.find(None), ("root", "toor"))  # any-service fallback

    def test_share_first_peer(self):
        from phantom.automation.agent import ShareContext
        share = ShareContext(peers=["10.0.0.6", "10.0.0.7"])
        self.assertEqual(share.first_peer("10.0.0.5"), "10.0.0.6")
        self.assertEqual(share.first_peer("10.0.0.6"), "10.0.0.7")
        self.assertIsNone(ShareContext(peers=["10.0.0.6"]).first_peer("10.0.0.6"))

    def test_shared_creds_used_without_local_discovery(self):
        from phantom.automation.agent import ShareContext, AutonomousAgent
        from phantom.automation.runtime.stealth_runtime import TimingGovernor
        from phantom.automation.runtime.toolchain import ToolRegistry
        share = ShareContext()
        share.add_creds("ssh", "admin", "s3cr3t", TARGET)
        agent = AutonomousAgent(
            target=TARGET, target_type="ip", profile="enterprise",
            on_event=lambda k, d: None,
            runtime=StealthRuntime(
                StealthEngine(WorldModel(target=TARGET),
                              StealthConfig()),
                runner=_fake_runner(),
                cost_per_action=0.5,
                governor=TimingGovernor(base_delay=0.0, jitter=0.0),
            ),
            cred_discoverer=lambda service: None,  # local discovery finds nothing
            sandbox=_approving_sandbox(),
            toolchain=ToolRegistry(installed={"nmap", "sshpass", "curl", "nc",
                                              "redis-cli", "smbmap"}),
            share=share,
            beacon_builder=_fake_builder,
            hunt_runner=_quiet_hunt_runner,
        )
        result = agent.run(goal="complete_kill_chain", max_iterations=10)
        self.assertTrue(result["beacon_established"], result)
        creds = [f for f in agent.wm.all_findings()
                 if f.kind == "creds" and f.value.get("valid")]
        self.assertTrue(creds, "no creds finding despite shared pool")
        self.assertEqual(creds[0].value.get("password"), "s3cr3t")

    def test_campaign_creds_published_back_to_share(self):
        from phantom.automation.agent import ShareContext, run_campaign
        from phantom.automation.runtime.toolchain import ToolRegistry
        share = ShareContext(peers=[TARGET, "10.0.0.6"])
        campaign = run_campaign(
            targets=[TARGET, "10.0.0.6"],
            on_event=lambda k, d: None,
            runner=_fake_runner(targets=(TARGET, "10.0.0.6")),
            cred_discoverer=lambda service: ("root", "toor"),
            sandbox=_approving_sandbox(),
            beacon_builder=_fake_builder,
            toolchain=ToolRegistry(installed={"nmap", "sshpass", "curl", "nc",
                                              "redis-cli", "smbmap"}),
            share=share,
            hunt_runner=_quiet_hunt_runner,
        )
        self.assertEqual(campaign["beacons"], 2)
        self.assertEqual(share.find("ssh"), ("root", "toor"))


if __name__ == "__main__":
    unittest.main()
