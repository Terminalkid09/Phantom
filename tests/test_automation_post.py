"""Post-exploitation tests: interpreters, planner sequencing, and the full
persistence -> SYSTEM -> injection chain executed THROUGH the C2 beacon channel."""
import re
import threading
import time
import unittest
from unittest.mock import Mock, patch

from phantom.automation.belief import WorldModel
from phantom.automation.guidance.commands import make_registry
from phantom.automation.guidance.stealth import StealthConfig, StealthEngine
from phantom.automation.planner import Planner
from phantom.automation.runtime.stealth_runtime import StealthRuntime, TimingGovernor
from phantom.automation.runtime.toolchain import ToolRegistry
from phantom.automation.sandbox.sandbox import SandboxEngine, SandboxVerdict, SandboxResult
from phantom.automation.agent import AutonomousAgent

from phantom.automation.post.persistence import persistence_interpreter
from phantom.automation.post.privesc import privesc_interpreter
from phantom.automation.post.inject import inject_interpreter
from phantom.automation.post.ad import (ad_enum_interpreter, kerberoast_interpreter,
                                        as_rep_interpreter, dc_sync_interpreter,
                                        hash_crack_interpreter, resolve_dc)
from phantom.automation.post.lateral import (lateral_interpreter,
                                             smb_pivot_interpreter,
                                             winrm_pivot_interpreter)
from phantom.automation.post.cleanup import cleanup_interpreter

TARGET = "10.0.0.5"
PEER = "10.0.0.6"


def _fake_builder(platform, host, port):
    """Fake compile-on-demand: produces a real file (the deploy path
    checks the binary exists on disk)."""
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


def _fake_runner(targets=(TARGET,)):
    """Scripted runner: recon + creds, the C++ beacon check-in (dropper ->
    c2_state registration, exactly what the compiled beacon does over the
    wire) and target-side answers for the post commands."""
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
        # NOTE: post commands EMBED the dropper payload (persistence, pivots,
        # privesc all carry the beacon command) — their markers MUST be
        # checked before the generic "api/v1/payload" dropper branch.
        if "echo CLEANUP_OK" in cmd:
            res.ok = True
            res.stdout = "CLEANUP_OK\n[+] persistence removed, beacon killed"
        elif "sshpass" in cmd and "scp" in cmd:
            # beacon deploy (scp + setsid): the staged beacon starts on the
            # target and checks in — matched before the sshpass+nohup pivot
            # branch because the deploy command embeds both
            _register()
            res.ok = True
            res.stdout = "PHANTOM"
        elif "sshpass" in cmd and "nohup" in cmd:
            # lateral_pivot (ssh) — the payload itself also contains "nohup",
            # so match the sshpass+nohup pivot BEFORE the dropper branch
            res.ok = True
            res.stdout = f"PIVOT_OK host={PEER}"
        elif "psexec.py" in cmd:
            res.ok = True
            res.stdout = f"PIVOT_OK host={PEER}"
        elif "evil-winrm" in cmd:
            res.ok = True
            res.stdout = f"PIVOT_OK host={PEER}"
        elif "phantom-priv" in cmd:
            res.ok = True
            res.stdout = "uid=0(root) gid=0(root)\nPRIVESC_OK"
        elif "sudo -S" in cmd:
            res.ok = True
            res.stdout = "uid=0(root) gid=0(root)\nPRIVESC_OK"
        elif "ldapsearch" in cmd:
            res.ok = True
            res.stdout = ("dn: DC=corp,DC=local\n"
                          "namingContexts: dc=corp,dc=local\n"
                          "AD_ENUM_OK")
        elif "GetUserSPNs" in cmd:
            res.ok = True
            res.stdout = ("ServicePrincipalName    Name\n"
                          "HTTP/svc.corp.local     svc\n"
                          "$krb5tgs$23$svc$CORP.LOCAL/user:deadbeef\n"
                          "KERBEROAST_OK")
        elif "GetNPUsers" in cmd:
            res.ok = True
            res.stdout = ("$krb5asrep$17$svc@CORP.LOCAL:deadbeef\n"
                          "ASREP_ROAST_OK")
        elif "secretsdump" in cmd:
            res.ok = True
            res.stdout = ("CORP\\admin:500:aad3b435b51404eeaad3b435b51404ee:"
                          "31d6cfe0d16ae931b73c59d7e0c089c0:::\nDCSYNC_OK")
        elif "john" in cmd:
            res.ok = True
            res.stdout = "svc:Winter2024!\nHASH_CRACK_OK"
        elif "crontab" in cmd:
            res.ok = True
            res.stdout = "PERSISTENCE_OK cron"
        elif "phantom-beacon.service" in cmd:
            res.ok = True
            res.stdout = "PERSISTENCE_OK systemd"
        elif "phantom-inject" in cmd:
            res.ok = True
            res.stdout = "INJECT_OK systemd"
        elif "api/v1/payload" in cmd:  # the pure dropper -> beacon check-in
            _register()
            res.ok = True
            res.stdout = "PHANTOM"
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
    """Simulates the beacon side: continuously pulls pending tasks from
    c2_state, executes them with the runner and posts the output back."""
    from phantom.core.c2_server import c2_state
    while not stop.is_set():
        for bid in list(c2_state.get_beacons().keys()):
            for task in c2_state.get_pending_tasks(bid):
                res = runner(task["command"])
                c2_state.add_result(bid, task["task_id"], res.stdout)
        time.sleep(0.05)


class TestPostInterpreters(unittest.TestCase):

    def setUp(self):
        self.wm = WorldModel(target="10.0.0.5")

    def test_persistence_interpreter_marker(self):
        f = persistence_interpreter("PERSISTENCE_OK runkey", self.wm, {"os": "windows"})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].kind, "persistence")
        self.assertEqual(f[0].value["method"], "runkey")

    def test_persistence_interpreter_ignores_plain_output(self):
        self.assertEqual(persistence_interpreter("Access denied", self.wm, {}), [])

    def test_privesc_interpreter_system(self):
        f = privesc_interpreter("nt authority\\system\nPRIVESC_OK", self.wm, {})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].value["identity"], "SYSTEM")

    def test_privesc_interpreter_root(self):
        f = privesc_interpreter("uid=0(root) gid=0(root)\nPRIVESC_OK", self.wm, {})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].value["identity"], "root")

    def test_privesc_interpreter_requires_marker(self):
        self.assertEqual(privesc_interpreter("uid=0(root)", self.wm, {}), [])

    def test_inject_interpreter_pid(self):
        f = inject_interpreter("INJECT_OK pid=1234", self.wm, {})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].value["target_process"], "1234")
        self.assertEqual(f[0].kind, "injection")

    def test_ad_enum_interpreter_discovers_domain(self):
        out = ("dn: DC=corp,DC=local\n"
               "namingContexts: dc=corp,dc=local\n"
               "AD_ENUM_OK")
        f = ad_enum_interpreter(out, self.wm, {})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].kind, "ad_domain")
        self.assertEqual(f[0].value["domain"], "corp.local")

    def test_ad_enum_interpreter_prefers_slot_domain(self):
        f = ad_enum_interpreter("AD_ENUM_OK", self.wm, {"domain": "ad.foo"})
        self.assertEqual(f[0].value["domain"], "ad.foo")

    def test_ad_enum_interpreter_requires_marker(self):
        self.assertEqual(ad_enum_interpreter("dc=corp,dc=local", self.wm, {}), [])

    def test_kerberoast_interpreter_extracts_ticket(self):
        out = ("$krb5tgs$23$svc$CORP.LOCAL/user:deadbeef\nKERBEROAST_OK")
        f = kerberoast_interpreter(out, self.wm, {})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].kind, "ad_creds")
        self.assertIn("deadbeef", f[0].value["hash"])

    def test_kerberoast_interpreter_requires_marker_or_hash(self):
        self.assertEqual(kerberoast_interpreter("GetUserSPNs.py: Error", self.wm, {}), [])

    def test_lateral_interpreter_pivot_fact(self):
        f = lateral_interpreter("PIVOT_OK host=10.0.0.6", self.wm, {})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].kind, "pivot")
        self.assertEqual(f[0].value["host"], "10.0.0.6")

    def test_lateral_interpreter_requires_marker(self):
        self.assertEqual(lateral_interpreter("Connection refused", self.wm, {}), [])

    def test_smb_pivot_interpreter_fact(self):
        f = smb_pivot_interpreter("PIVOT_OK host=10.0.0.6",
                                  self.wm, {"host": "10.0.0.6"})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].source, "smb_pivot")
        self.assertEqual(f[0].value["host"], "10.0.0.6")

    def test_winrm_pivot_interpreter_fact(self):
        f = winrm_pivot_interpreter("PIVOT_OK host=10.0.0.6", self.wm, {})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].source, "winrm_pivot")

    def test_as_rep_interpreter_extracts_ticket(self):
        out = ("$krb5asrep$17$svc@CORP.LOCAL:deadbeef\nASREP_ROAST_OK")
        f = as_rep_interpreter(out, self.wm, {})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].kind, "ad_creds")
        self.assertIn("$krb5asrep$", f[0].value["hash"])

    def test_as_rep_interpreter_requires_marker_or_hash(self):
        self.assertEqual(as_rep_interpreter("GetNPUsers.py: Error", self.wm, {}), [])

    def test_dc_sync_interpreter_extracts_hashes(self):
        out = ("CORP\\admin:500:aad3b435b51404eeaad3b435b51404ee:"
               "31d6cfe0d16ae931b73c59d7e0c089c0:::\nDCSYNC_OK")
        f = dc_sync_interpreter(out, self.wm, {})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].kind, "ad_creds")
        self.assertTrue(f[0].value["privileged"])
        self.assertIn("31d6cfe0", f[0].value["hash"])

    def test_dc_sync_interpreter_requires_marker(self):
        self.assertEqual(dc_sync_interpreter("Access denied", self.wm, {}), [])

    def test_hash_crack_interpreter_extracts_plaintext(self):
        out = "svc:Winter2024!\nHASH_CRACK_OK"
        f = hash_crack_interpreter(out, self.wm, {"hash": "$krb5tgs$abc"})
        self.assertEqual(len(f), 2)
        cracked = [x for x in f if x.kind == "cracked"]
        creds = [x for x in f if x.kind == "creds"]
        self.assertEqual(len(cracked), 1)
        self.assertEqual(cracked[0].value["password"], "Winter2024!")
        self.assertEqual(cracked[0].value["username"], "svc")
        self.assertEqual(creds[0].value["service"], "domain")

    def test_hash_crack_interpreter_requires_marker(self):
        self.assertEqual(hash_crack_interpreter("0g 0:00:00 john", self.wm, {}), [])

    def test_cleanup_interpreter(self):
        f = cleanup_interpreter("CLEANUP_OK\n[+] removed", self.wm, {"os": "linux"})
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0].kind, "cleanup")

    def test_cleanup_interpreter_requires_marker(self):
        self.assertEqual(cleanup_interpreter("Access denied", self.wm, {}), [])


class TestPostPlannerSequencing(unittest.TestCase):

    def setUp(self):
        self.wm = WorldModel(target="10.0.0.5")
        self.registry = make_registry()
        self.planner = Planner(self.registry, StealthEngine(self.wm, StealthConfig()))

    def test_inject_planned_with_privesc_chain(self):
        # inject_beacon is planned together with privesc_system, which
        # produces the system_privilege fact it needs — the EXECUTION gate
        # (not the planner) enforces the SYSTEM-first ordering
        self.wm.add_finding("beacon", "established", {"ok": True})
        plan = self.planner.plan(self.wm, goal="post_exploit")
        ids = [s.capability.id for s in plan.steps]
        self.assertIn("persistence_install", ids)
        self.assertIn("privesc_system", ids)
        self.assertIn("inject_beacon", ids)

    def test_inject_planned_after_system_privilege(self):
        self.wm.add_finding("beacon", "established", {"ok": True})
        self.wm.add_finding("system_privilege", "escalated", {"identity": "root"})
        plan = self.planner.plan(self.wm, goal="post_exploit")
        ids = [s.capability.id for s in plan.steps]
        self.assertIn("inject_beacon", ids)
        self.assertNotIn("privesc_system", ids)  # fact already present

    def test_post_exploit_goal_reached(self):
        for kind in ("beacon", "persistence", "system_privilege", "injection"):
            self.wm.add_finding(kind, f"{kind}:1", {"ok": True})
        plan = self.planner.plan(self.wm, goal="post_exploit")
        self.assertTrue(plan.complete)
        self.assertEqual(plan.steps, [])


def _make_agent(runner=None, share=None, events=None, tools=None,
                beacon_builder=None, cred_discoverer=None, hunt_runner=None):
    return AutonomousAgent(
        target=TARGET, target_type="ip", profile="enterprise",
        on_event=lambda k, d: events.append((k, d)) if events is not None else None,
        runtime=StealthRuntime(
            StealthEngine(WorldModel(target=TARGET),
                          StealthConfig()),
            runner=runner or _fake_runner(),
            cost_per_action=0.5,
            governor=TimingGovernor(base_delay=0.0, jitter=0.0),
        ),
        cred_discoverer=cred_discoverer or (lambda service: ("root", "toor")),
        sandbox=_ApprovingSandbox(),
        toolchain=ToolRegistry(installed=tools or {"nmap", "sshpass", "curl", "nc",
                                                   "redis-cli", "smbmap",
                                                   "ldapsearch", "GetUserSPNs.py",
                                                   "sudo"}),
        share=share,
        beacon_builder=beacon_builder or _fake_builder,
        hunt_runner=hunt_runner,
    )


class TestPostExploitationChainE2E(unittest.TestCase):

    def setUp(self):
        from phantom.core.c2_server import c2_state
        c2_state.beacons.clear()
        c2_state.tasks.clear()
        c2_state.results.clear()
        self.events = []

    def _agent(self):
        return _make_agent(events=self.events)

    def test_persistence_system_and_injection_via_beacon(self):
        from phantom.core.c2_server import c2_state
        agent = self._agent()
        stop = threading.Event()
        sim = threading.Thread(target=_c2_simulator,
                               args=(_fake_runner(), stop), daemon=True)
        sim.start()
        try:
            result = agent.run(goal="post_exploit", max_iterations=60)
        finally:
            stop.set()
            sim.join(timeout=3)

        self.assertTrue(result["beacon_established"], result)
        self.assertTrue(result["persistence_installed"], result)
        self.assertTrue(result["system_privilege"], result)
        self.assertTrue(result["beacon_injected"], result)

        actions = [a["capability"] for a in agent.wm.actions_taken]
        self.assertIn("persistence_install", actions)
        self.assertIn("privesc_system", actions)
        self.assertIn("inject_beacon", actions)

        kinds = {f.kind for f in agent.wm.all_findings()}
        self.assertTrue({"persistence", "system_privilege", "injection"} <= kinds)

        # the beacon really registered in the C2 and the tasks really flowed
        self.assertTrue(c2_state.get_beacons(), "beacon not registered in C2")
        self.assertTrue(c2_state.get_results(list(c2_state.get_beacons())[0]))

    def test_post_steps_blocked_without_beacon_session(self):
        # no C2 session -> post capabilities are blocked fast (never run,
        # never timed out): the session gate is the first thing checked
        agent = _make_agent(events=self.events)
        cap = agent.registry.get("persistence_install")
        self.assertIsNotNone(cap)
        ok = agent._execute_post_capability(cap, {})
        self.assertFalse(ok)
        blocked = [d for k, d in self.events if k == "blocked"]
        self.assertTrue(any("no beacon session" in d.get("reason", "")
                            for d in blocked))


class TestAdEnumerationE2E(unittest.TestCase):
    """Goal 'ad': the agent enums the domain and kerberoasts SPN tickets
    through the beacon, producing ad_domain and ad_creds facts."""

    def setUp(self):
        from phantom.core.c2_server import c2_state
        c2_state.beacons.clear()
        c2_state.tasks.clear()
        c2_state.results.clear()
        self.events = []

    def test_ad_enum_then_kerberoast_via_beacon(self):
        agent = _make_agent(events=self.events)
        stop = threading.Event()
        sim = threading.Thread(target=_c2_simulator,
                               args=(_fake_runner(), stop), daemon=True)
        sim.start()
        try:
            result = agent.run(goal="ad", max_iterations=20)
        finally:
            stop.set()
            sim.join(timeout=3)

        actions = [a["capability"] for a in agent.wm.actions_taken]
        self.assertIn("ad_enum", actions)
        self.assertIn("kerberoast", actions)

        self.assertEqual(result["ad_domains"], 1)
        kinds = {f.kind for f in agent.wm.all_findings()}
        self.assertTrue({"ad_domain", "ad_creds"} <= kinds)

        ad_facts = [f for f in agent.wm.all_findings() if f.kind == "ad_domain"]
        self.assertEqual(ad_facts[0].value["domain"], "corp.local")
        ad_creds = [f for f in agent.wm.all_findings() if f.kind == "ad_creds"]
        self.assertTrue(any(f.value.get("hash", "").startswith("$krb5tgs$")
                            for f in ad_creds))


class TestLateralMovementE2E(unittest.TestCase):
    """Goal 'lateral': with a campaign share holding a peer host, the agent
    pivots a new beacon to it using shared credentials."""

    def setUp(self):
        from phantom.core.c2_server import c2_state
        c2_state.beacons.clear()
        c2_state.tasks.clear()
        c2_state.results.clear()
        self.events = []

    def test_lateral_pivot_to_peer_with_shared_creds(self):
        from phantom.automation.agent import ShareContext
        share = ShareContext(peers=["10.0.0.6"])
        share.add_creds("ssh", "root", "toor", "10.0.0.5")
        agent = _make_agent(share=share, events=self.events)

        stop = threading.Event()
        sim = threading.Thread(target=_c2_simulator,
                               args=(_fake_runner(), stop), daemon=True)
        sim.start()
        try:
            result = agent.run(goal="lateral", max_iterations=20)
        finally:
            stop.set()
            sim.join(timeout=3)

        self.assertTrue(result["lateral_movements"], result)
        pivots = [f for f in agent.wm.all_findings() if f.kind == "pivot"]
        self.assertTrue(pivots, "no pivot finding")
        self.assertEqual(pivots[0].value["host"], "10.0.0.6")

        actions = [a["capability"] for a in agent.wm.actions_taken]
        self.assertIn("lateral_pivot", actions)
        kinds = {f.kind for f in agent.wm.all_findings()}
        self.assertIn("pivot", kinds)


class TestPrivescAlternateVectorE2E(unittest.TestCase):
    """When the first privesc vector fails, the OTHER one is still attempted
    (sudo and the SYSTEM exploit are both planned; neither failing stops the
    agent from trying the other vector)."""

    def setUp(self):
        from phantom.core.c2_server import c2_state
        c2_state.beacons.clear()
        c2_state.tasks.clear()
        c2_state.results.clear()
        self.events = []

    def test_alternate_privesc_vector_attempted(self):
        base = _fake_runner()

        def denied_runner(cmd, timeout=None):
            # goal post_exploit REQUIRES system_privilege: BOTH privesc
            # vectors get planned; the first failing must not stop the
            # other from being attempted (deterministic)
            if "phantom-priv" in cmd or "sudo -S" in cmd:
                res = Mock()
                res.ok = False
                res.stdout = "Access denied"
                res.stderr = "Access denied"
                return res
            return base(cmd)

        agent = _make_agent(runner=denied_runner, events=self.events)
        stop = threading.Event()
        sim = threading.Thread(target=_c2_simulator,
                               args=(denied_runner, stop), daemon=True)
        sim.start()
        try:
            result = agent.run(goal="post_exploit", max_iterations=60)
        finally:
            stop.set()
            sim.join(timeout=3)

        actions = [a["capability"] for a in agent.wm.actions_taken]
        self.assertIn("privesc_system", actions)
        self.assertIn("privesc_sudo", actions)
        self.assertFalse(result["system_privilege"], result)
        # all escalation vectors exhausted -> the run terminates (stale
        # discipline / no affordable path)
        halts = [d for k, d in self.events if k == "halt"]
        self.assertTrue(any("no new move" in h.get("reason", "")
                            or "no affordable path" in h.get("reason", "")
                            for h in halts), halts)


class TestAdDepthE2E(unittest.TestCase):
    """Goal 'ad'/'crack' with the FIRST AD vectors failing: the planner must
    fall back to the next source (kerberoast -> as_rep_roast -> dc_sync) and
    finally crack the captured hashes — the full deep-AD chain."""

    def setUp(self):
        _reset_c2()
        self.events = []

    def _ad_failing_runner(self):
        """Blocks kerberoast AND as_rep -> the chain must fall through to
        dc_sync (used by the crack test)."""
        base = _fake_runner()

        def runner(cmd, timeout=None):
            if "GetUserSPNs" in cmd:
                res = Mock()
                res.ok = True
                res.stdout = "No SPNs found for user"
                res.stderr = ""
                return res
            if "GetNPUsers" in cmd:
                res = Mock()
                res.ok = True
                res.stdout = "Pre-authentication enabled for all accounts"
                res.stderr = ""
                return res
            return base(cmd)
        return runner

    def _kerberoast_failing_runner(self):
        """Blocks ONLY kerberoast -> as_rep_roast is the fallback."""
        base = _fake_runner()

        def runner(cmd, timeout=None):
            if "GetUserSPNs" in cmd:
                res = Mock()
                res.ok = True
                res.stdout = "No SPNs found for user"
                res.stderr = ""
                return res
            return base(cmd)
        return runner

    _TOOLS = {"nmap", "sshpass", "curl", "nc", "ldapsearch",
              "GetUserSPNs.py", "GetNPUsers.py", "secretsdump.py",
              "john", "sudo"}

    def test_as_rep_fallback_when_kerberoast_has_no_spns(self):
        runner = self._kerberoast_failing_runner()
        agent = _make_agent(runner=runner, events=self.events, tools=self._TOOLS)
        stop = threading.Event()
        sim = threading.Thread(target=_c2_simulator,
                               args=(runner, stop), daemon=True)
        sim.start()
        try:
            result = agent.run(goal="ad", max_iterations=20)
        finally:
            stop.set()
            sim.join(timeout=3)

        actions = [a["capability"] for a in agent.wm.actions_taken]
        self.assertIn("kerberoast", actions)      # tried first...
        self.assertIn("as_rep_roast", actions)    # ...then the fallback
        ad_creds = [f for f in agent.wm.all_findings() if f.kind == "ad_creds"]
        self.assertTrue(any(f.value.get("hash", "").startswith("$krb5asrep$")
                            for f in ad_creds))
        self.assertEqual(result["ad_creds"], 1)

    def test_dc_sync_and_hash_crack_full_chain(self):
        runner = self._ad_failing_runner()
        agent = _make_agent(runner=runner, events=self.events, tools=self._TOOLS)
        stop = threading.Event()
        sim = threading.Thread(target=_c2_simulator,
                               args=(runner, stop), daemon=True)
        sim.start()
        try:
            result = agent.run(goal="crack", max_iterations=60)
        finally:
            stop.set()
            sim.join(timeout=3)

        actions = [a["capability"] for a in agent.wm.actions_taken]
        self.assertIn("privesc_system", actions)  # SYSTEM needed for DCSync
        self.assertIn("dc_sync", actions)
        self.assertIn("hash_crack", actions)
        self.assertEqual(result["cracked_hashes"], 1, result)
        cracked = [f for f in agent.wm.all_findings() if f.kind == "cracked"]
        self.assertTrue(cracked, "no cracked finding")
        self.assertEqual(cracked[0].value["password"], "Winter2024!")
        # the cracked plaintext is reusable as domain credentials
        creds = [f for f in agent.wm.all_findings()
                 if f.kind == "creds" and f.value.get("service") == "domain"]
        self.assertTrue(creds)


class TestSmbWinrmPivotE2E(unittest.TestCase):
    """Goal 'lateral' with the SSH pivot failing: the agent falls back to
    smb_pivot and winrm_pivot for Windows peers."""

    def setUp(self):
        _reset_c2()
        self.events = []

    def _ssh_pivot_failing_runner(self):
        base = _fake_runner()

        def runner(cmd, timeout=None):
            # the ssh pivot to the WINDOWS PEER fails. Restrict to the peer
            # host, NOT the generic sshpass+nohup pair: the scp beacon deploy
            # also embeds "sshpass" (chmod && nohup <beacon>), so matching the
            # pair alone would block the deploy and the beacon would never
            # check in.
            if ("sshpass" in cmd and "nohup" in cmd and "10.0.0.6" in cmd
                    and "scp" not in cmd):
                res = Mock()
                res.ok = True
                res.stdout = "ssh: connect to host 10.0.0.6 port 22: Connection refused"
                res.stderr = ""
                return res
            return base(cmd)
        return runner

    def _smb_pivot_failing_runner(self):
        """Blocks the ssh pivot AND the smb pivot -> winrm_pivot is the
        last fallback standing."""
        base = _fake_runner()

        def runner(cmd, timeout=None):
            if ("sshpass" in cmd and "nohup" in cmd and "10.0.0.6" in cmd
                    and "scp" not in cmd):
                res = Mock()
                res.ok = True
                res.stdout = "ssh: connect to host 10.0.0.6 port 22: Connection refused"
                res.stderr = ""
                return res
            if "psexec.py" in cmd:
                res = Mock()
                res.ok = True
                res.stdout = "[-] ERROR_ACCESS_DENIED"
                res.stderr = ""
                return res
            return base(cmd)
        return runner

    def test_smb_pivot_to_windows_peer(self):
        from phantom.automation.agent import ShareContext
        share = ShareContext(peers=[PEER])
        share.add_creds("smb", "admin", "Passw0rd!", TARGET)
        runner = self._ssh_pivot_failing_runner()
        agent = _make_agent(runner=runner, share=share, events=self.events,
                            tools={"nmap", "sshpass", "curl", "nc",
                                   "ldapsearch", "psexec.py"})
        stop = threading.Event()
        sim = threading.Thread(target=_c2_simulator,
                               args=(runner, stop), daemon=True)
        sim.start()
        try:
            result = agent.run(goal="lateral", max_iterations=20)
        finally:
            stop.set()
            sim.join(timeout=3)

        actions = [a["capability"] for a in agent.wm.actions_taken]
        self.assertIn("lateral_pivot", actions)   # ssh tried first...
        self.assertIn("smb_pivot", actions)       # ...then the SMB fallback
        pivots = [f for f in agent.wm.all_findings() if f.kind == "pivot"]
        self.assertTrue(pivots, "no pivot finding")
        self.assertEqual(pivots[0].value["host"], PEER)
        self.assertTrue(result["lateral_movements"], result)

    def test_winrm_pivot_to_windows_peer(self):
        from phantom.automation.agent import ShareContext
        share = ShareContext(peers=[PEER])
        share.add_creds("winrm", "admin", "Passw0rd!", TARGET)
        runner = self._smb_pivot_failing_runner()
        agent = _make_agent(runner=runner, share=share, events=self.events,
                            tools={"nmap", "sshpass", "curl", "nc",
                                   "ldapsearch", "psexec.py", "evil-winrm"})
        stop = threading.Event()
        sim = threading.Thread(target=_c2_simulator,
                               args=(runner, stop), daemon=True)
        sim.start()
        try:
            result = agent.run(goal="lateral", max_iterations=20)
        finally:
            stop.set()
            sim.join(timeout=3)

        actions = [a["capability"] for a in agent.wm.actions_taken]
        self.assertIn("smb_pivot", actions)
        self.assertIn("winrm_pivot", actions)
        self.assertTrue(result["lateral_movements"], result)


class TestCleanupE2E(unittest.TestCase):
    """Goal 'cleanup': re-establish the beacon, remove persistence and kill
    the beacon process through the C2 channel."""

    def setUp(self):
        _reset_c2()
        self.events = []

    def test_cleanup_goal_removes_persistence_and_kills_beacon(self):
        agent = _make_agent(events=self.events)
        stop = threading.Event()
        sim = threading.Thread(target=_c2_simulator,
                               args=(_fake_runner(), stop), daemon=True)
        sim.start()
        try:
            result = agent.run(goal="cleanup", max_iterations=20)
        finally:
            stop.set()
            sim.join(timeout=3)

        self.assertTrue(result["cleanup_done"], result)
        actions = [a["capability"] for a in agent.wm.actions_taken]
        self.assertIn("cleanup", actions)
        self.assertTrue(any(f.kind == "cleanup"
                            for f in agent.wm.all_findings()))


class TestDcDiscovery(unittest.TestCase):
    """ad_enum resolves the domain controller and downstream AD attacks
    (kerberoast / as_rep / dc_sync) aim at the DC, not the foothold host."""

    def test_resolve_dc_empty_domain(self):
        self.assertEqual(resolve_dc(""), "")

    def test_ad_enum_interpreter_parses_dc_host_marker(self):
        wm = WorldModel(target="10.0.0.5")
        out = ("dn: DC=corp,DC=local\n"
               "namingContexts: dc=corp,dc=local\n"
               "AD_ENUM_OK\nDC_HOST=dc1.corp.local")
        with patch("phantom.automation.post.ad.resolve_dc", return_value=""):
            f = ad_enum_interpreter(out, wm, {})
        self.assertEqual(f[0].value["dc_host"], "dc1.corp.local")

    def test_ad_enum_interpreter_resolves_dc_from_domain(self):
        wm = WorldModel(target="10.0.0.5")
        out = ("dn: DC=corp,DC=local\n"
               "namingContexts: dc=corp,dc=local\nAD_ENUM_OK")
        with patch("phantom.automation.post.ad.resolve_dc",
                   return_value="dc1.corp.local"):
            f = ad_enum_interpreter(out, wm, {})
        self.assertEqual(f[0].value["dc_host"], "dc1.corp.local")

    def test_kerberoast_adapter_uses_dc_host(self):
        from phantom.automation.guidance.kit import _kerberoast_adapter
        wm = WorldModel(target="10.0.0.5")
        wm.add_finding("ad_domain", "corp.local",
                       {"domain": "corp.local", "dc_host": "dc1.corp.local"},
                       confidence=0.9, source="ad_enum")
        cmd = _kerberoast_adapter(wm, {"username": "svc", "password": "pw"})
        self.assertIn("-dc-ip dc1.corp.local", cmd)
        self.assertNotIn("10.0.0.5", cmd)

    def test_kerberoast_adapter_falls_back_to_target(self):
        from phantom.automation.guidance.kit import _kerberoast_adapter
        wm = WorldModel(target="10.0.0.5")
        wm.add_finding("ad_domain", "corp.local",
                       {"domain": "corp.local"},
                       confidence=0.9, source="ad_enum")
        cmd = _kerberoast_adapter(wm, {"username": "svc", "password": "pw"})
        self.assertIn("-dc-ip 10.0.0.5", cmd)


class TestCredentialReuse(unittest.TestCase):
    """The AD chain (kerberoast / as_rep / dc_sync) needs a domain account;
    there is no offline 'domain' verifier, so it must reuse an already-
    VALIDATED credential from the WorldModel (foothold reuse)."""

    def test_discover_credentials_reuses_worldmodel_creds(self):
        agent = _make_agent(cred_discoverer=lambda service: None)
        agent.wm.add_finding(
            "creds", "ssh:admin",
            {"username": "corp\\admin", "password": "P@ss!",
             "valid": True, "service": "ssh"},
            confidence=0.9, source="ssh_login")
        found = agent._discover_credentials("domain")
        self.assertEqual(found, ("corp\\admin", "P@ss!"))

    def test_discover_credentials_prefers_matching_service(self):
        agent = _make_agent(cred_discoverer=lambda service: None)
        agent.wm.add_finding(
            "creds", "domain:svc",
            {"username": "svc", "password": "Winter2024!",
             "valid": True, "service": "domain"},
            confidence=0.95, source="hash_crack")
        agent.wm.add_finding(
            "creds", "ssh:admin",
            {"username": "corp\\admin", "password": "P@ss!",
             "valid": True, "service": "ssh"},
            confidence=0.9, source="ssh_login")
        self.assertEqual(agent._discover_credentials("domain"),
                         ("svc", "Winter2024!"))

    def test_discover_credentials_ignores_invalid_creds(self):
        agent = _make_agent(cred_discoverer=lambda service: None)
        agent.wm.add_finding(
            "creds", "leak:user",
            {"username": "user@example.com", "password": "leaked",
             "valid": False, "service": "leak"},
            confidence=0.6, source="breach_check")
        self.assertIsNone(agent._discover_credentials("domain"))


class TestStallRecovery(unittest.TestCase):
    """When the planner finds no path/move, the agent escalates (bounded)
    instead of halting on the first dead-end — it keeps pushing toward the
    beacon."""

    def test_recover_stall_rearms_failed_caps(self):
        agent = _make_agent()
        agent._mark_failed("ssh_login")
        self.assertIn("ssh_login", agent._failed_caps)
        self.assertTrue(agent._recover_stall("deliver"))
        self.assertNotIn("ssh_login", agent._failed_caps)
        self.assertEqual(agent._recoveries, 1)

    def test_recover_stall_is_bounded(self):
        agent = _make_agent()
        # Distinct failure reasons per round: identical reasons twice would
        # poison the capability (deterministic dead end — recovery correctly
        # refuses to re-arm it) and mask the budget bound under test.
        for i in range(agent._max_recoveries):
            agent.wm.record_failure("ssh_login", f"transient-{i}")
            agent._mark_failed("ssh_login")  # re-fail before each recovery
            self.assertTrue(agent._recover_stall("deliver"))
        self.assertFalse(agent._recover_stall("deliver"))  # budget exhausted

    def test_recover_stall_refuses_poisoned_cap(self):
        # A capability that failed 3x with the SAME reason is a deterministic
        # dead end: recovery must NOT burn budget re-arming it.
        agent = _make_agent()
        agent._deep_scanned = True  # isolate: no one-shot scan escalation
        for _ in range(3):
            agent.wm.record_failure("ssh_login", "auth rejected")
            agent._mark_failed("ssh_login")
        self.assertIn("ssh_login", agent._poisoned)
        self.assertFalse(agent._recover_stall("deliver"))

    def test_recover_stall_skips_post_caps(self):
        agent = _make_agent()
        agent._mark_failed("persistence_install")  # category "post"
        agent._mark_failed("ssh_login")
        agent._recover_stall("deliver")
        self.assertIn("persistence_install", agent._failed_caps)  # untouched
        self.assertNotIn("ssh_login", agent._failed_caps)

    def test_recover_stall_noop_when_nothing_failed(self):
        agent = _make_agent()
        # nothing failed AND already deep-scanned (no access service known is
        # what triggers the one-shot full-range escalation; with that already
        # done there is nothing left to do and the recovery is a no-op).
        agent._deep_scanned = True
        self.assertFalse(agent._recover_stall("deliver"))


class _ApprovingSandbox(SandboxEngine):
    def preflight(self, sample_path):
        return SandboxVerdict(approved=True,
                              results=[SandboxResult(backend="docker", ok=True)])


if __name__ == "__main__":
    unittest.main()
