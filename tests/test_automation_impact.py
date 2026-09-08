"""B4+: ransomware simulation (real reversible AES-GCM) and trojan bundles."""
import hashlib
import json
import os
import tempfile


def _temp_beacon():
    """Fake compile-on-demand: produces a real file (the deploy path
    checks the binary exists on disk)."""
    fd, path = tempfile.mkstemp(prefix="fake_beacon_", suffix=".bin")
    with os.fdopen(fd, "wb") as f:
        f.write(b"PHANTOM-FAKE-BEACON")
    return path
import unittest

from phantom.automation.post.ransom_sim import (
    RansomSimulator,
    ransom_sim_command,
    ransom_sim_interpreter,
)
from phantom.automation.belief import WorldModel
from phantom.automation.guidance.commands import make_registry
from phantom.automation.planner import Planner, GOAL_FACTS
from phantom.automation.guidance.stealth import StealthEngine, StealthConfig
from phantom.utils.trojan_bundle import (
    build_trojan_bundle,
    extract_payload,
    bundle_info,
    verify_legit,
)


def _approving_sandbox():
    from phantom.automation.sandbox.sandbox import (SandboxEngine,
                                                    SandboxVerdict,
                                                    SandboxResult)

    class _Approve(SandboxEngine):
        def preflight(self, sample_path):
            return SandboxVerdict(approved=True,
                                  results=[SandboxResult(backend="docker",
                                                         ok=True)])
    return _Approve()


class TestRansomSimulator(unittest.TestCase):

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.vault = os.path.join(self.base, "vault")
        self.victim = os.path.join(self.base, "victim")
        os.makedirs(self.victim)
        self.files = {}
        for name, content in (("invoice.pdf", b"%PDF-1.7 fake"),
                              ("report.docx", b"PK\x03\x04 fake docx"),
                              ("backup.bin", os.urandom(4096))):
            path = os.path.join(self.victim, name)
            with open(path, "wb") as f:
                f.write(content)
            self.files[name] = (path, content)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.base, ignore_errors=True)

    def test_encrypt_replaces_files_with_ciphertext(self):
        sim = RansomSimulator(self.vault)
        manifest = sim.encrypt(self.victim, run_id="rs-test-1")
        self.assertEqual(len(manifest["entries"]), 3)
        self.assertEqual(manifest["cipher"], "aes-256-gcm")
        for e in manifest["entries"]:
            # the original file is gone, replaced by a .phnt artifact
            self.assertFalse(os.path.exists(e["orig_abspath"]))
            self.assertTrue(os.path.exists(e["encrypted"]))
            # real encryption: ciphertext is never the plaintext
            with open(e["encrypted"], "rb") as f:
                self.assertNotEqual(f.read(), self.files[e["orig_rel"]][1])
        self.assertTrue(os.path.exists(
            os.path.join(self.vault, "rs-test-1", "manifest.json")))

    def test_encrypt_records_plaintext_sha256(self):
        sim = RansomSimulator(self.vault)
        manifest = sim.encrypt(self.victim, run_id="rs-test-2")
        for e in manifest["entries"]:
            orig = self.files[e["orig_rel"]][1]
            self.assertEqual(e["sha256"], hashlib.sha256(orig).hexdigest())
            self.assertEqual(e["size"], len(orig))

    def test_rollback_restores_everything_byte_identical(self):
        sim = RansomSimulator(self.vault)
        sim.encrypt(self.victim, run_id="rs-test-3")
        manifest_path = os.path.join(self.vault, "rs-test-3", "manifest.json")
        restored = sim.rollback(manifest_path)
        self.assertEqual(restored, 3)
        # files are back byte-identical and nothing is left behind
        for name, (path, content) in self.files.items():
            with open(path, "rb") as f:
                self.assertEqual(f.read(), content)
            self.assertFalse(os.path.exists(path + ".phnt"))
        self.assertFalse(os.path.exists(
            os.path.join(self.vault, "rs-test-3")))

    def test_rollback_refuses_tampered_entry(self):
        sim = RansomSimulator(self.vault)
        sim.encrypt(self.victim, run_id="rs-test-3b")
        manifest_path = os.path.join(self.vault, "rs-test-3b",
                                     "manifest.json")
        # corrupt one encrypted file: its entry must NOT be restored
        entry = json.load(open(manifest_path, encoding="utf-8"))[
            "entries"][0]
        with open(entry["encrypted"], "r+b") as f:
            f.seek(13)
            f.write(b"\x00")
        restored = sim.rollback(manifest_path)
        self.assertEqual(restored, 2)
        self.assertFalse(os.path.exists(entry["orig_abspath"]))
        # the other two came back byte-identical
        for name, (path, content) in self.files.items():
            if path == entry["orig_abspath"]:
                continue
            with open(path, "rb") as f:
                self.assertEqual(f.read(), content)

    def test_marker_and_interpreter(self):
        sim = RansomSimulator(self.vault)
        manifest = sim.encrypt(self.victim, run_id="rs-test-4")
        marker = sim.marker_from_manifest(manifest)
        self.assertTrue(marker.startswith("RANSOM_SIM:"))
        wm = WorldModel(target="10.0.0.5")
        findings = ransom_sim_interpreter(marker, wm, {})
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.kind, "ransom_sim")
        self.assertEqual(f.value["encrypted"], 3)
        self.assertTrue(f.value["rollback_ready"])

    def test_nested_dirs_and_links_untouched(self):
        sub = os.path.join(self.victim, "nested")
        os.makedirs(sub)
        nested_file = os.path.join(sub, "keep.txt")
        open(nested_file, "w").write("untouched")
        sim = RansomSimulator(self.vault)
        manifest = sim.encrypt(self.victim, run_id="rs-test-5")
        # only the 3 flat files are encrypted; nested file stays in place
        self.assertEqual(len(manifest["entries"]), 3)
        self.assertTrue(os.path.exists(nested_file))

    def test_non_directory_raises(self):
        with self.assertRaises(NotADirectoryError):
            RansomSimulator(self.vault).encrypt(
                os.path.join(self.base, "missing"), run_id="x")

    def test_command_shape(self):
        self.assertEqual(ransom_sim_command("/tmp/victims"),
                         "ransom-sim /tmp/victims")


class TestTrojanBundle(unittest.TestCase):

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.legit = os.path.join(self.base, "clean_app.bin")
        with open(self.legit, "wb") as f:
            f.write(b"\x7fELF" + os.urandom(512))
        self.payload = os.path.join(self.base, "payload.bin")
        with open(self.payload, "wb") as f:
            f.write(b"\x90" * 128 + b"PAYLOAD")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.base, ignore_errors=True)

    def test_build_and_extract_roundtrip(self):
        out = os.path.join(self.base, "app.bundle")
        info = build_trojan_bundle(self.legit, self.payload, out)
        legit, payload = self._parse(out)
        self.assertEqual(legit, open(self.legit, "rb").read())
        self.assertEqual(payload, open(self.payload, "rb").read())
        self.assertEqual(info.payload_offset, info.legit_size)

    def _parse(self, path):
        from phantom.utils.trojan_bundle import parse_bundle
        return parse_bundle(path)

    def test_extract_payload_only(self):
        out = os.path.join(self.base, "app.bundle")
        build_trojan_bundle(self.legit, self.payload, out)
        self.assertEqual(extract_payload(out),
                         open(self.payload, "rb").read())

    def test_info_hashes(self):
        out = os.path.join(self.base, "app.bundle")
        build_trojan_bundle(self.legit, self.payload, out)
        info = bundle_info(out)
        legit_bytes = open(self.legit, "rb").read()
        self.assertEqual(info.legit_sha256,
                         hashlib.sha256(legit_bytes).hexdigest())
        self.assertTrue(verify_legit(out, info.legit_sha256))
        self.assertFalse(verify_legit(out, "0" * 64))

    def test_tampered_footer_rejected(self):
        out = os.path.join(self.base, "app.bundle")
        build_trojan_bundle(self.legit, self.payload, out)
        with open(out, "r+b") as f:
            f.seek(-16, os.SEEK_END)  # corrupt the footer magic
            f.write(b"XXXXXXXX")
        with self.assertRaises(ValueError):
            self._parse(out)

    def test_tampered_carrier_detected_by_verify(self):
        out = os.path.join(self.base, "app.bundle")
        orig_sha = hashlib.sha256(open(self.legit, "rb").read()).hexdigest()
        build_trojan_bundle(self.legit, self.payload, out)
        self.assertTrue(verify_legit(out, orig_sha))
        with open(out, "r+b") as f:
            f.seek(4)  # mutate the legit carrier bytes
            f.write(b"\x00\x00")
        # structure still parses (footer intact) but the carrier is no
        # longer the signed original
        legit, payload = self._parse(out)
        self.assertNotEqual(legit, open(self.legit, "rb").read())
        self.assertFalse(verify_legit(out, orig_sha))

    def test_non_bundle_rejected(self):
        junk = os.path.join(self.base, "junk.bin")
        open(junk, "wb").write(b"just some data")
        with self.assertRaises(ValueError):
            self._parse(junk)

    def test_empty_parts_rejected(self):
        empty = os.path.join(self.base, "empty.bin")
        open(empty, "wb").write(b"")
        with self.assertRaises(ValueError):
            build_trojan_bundle(empty, self.payload, os.path.join(self.base, "x"))

    def _make_apk(self, name="app.apk"):
        """Build a tiny but valid APK-shaped ZIP (dex + resources)."""
        import zipfile
        path = os.path.join(self.base, name)
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("classes.dex", b"\x00" * 64)
            z.writestr("AndroidManifest.xml", b"<manifest/>" * 3)
            z.writestr("res/values/strings.xml", b"<string>hi</string>")
        return path

    def test_zip_carrier_auto_detected_and_still_opens(self):
        """A ZIP/APK carrier must be re-archived (hidden entry before the
        EOCD) so the result is still a valid archive, not a broken one."""
        apk = self._make_apk()
        out = os.path.join(self.base, "evil.apk")
        info = build_trojan_bundle(apk, self.payload, out)
        self.assertEqual(info.layout, "zip")
        self.assertTrue(info.payload_offset < info.legit_size,
                        "payload must live inside the re-archived container")
        # the bundle still parses as a normal ZIP archive
        import zipfile
        with zipfile.ZipFile(out) as z:
            names = z.namelist()
            self.assertIn("classes.dex", names)
            self.assertIn("AndroidManifest.xml", names)
            self.assertIn(".phantom/beacon", names)
            self.assertEqual(z.read(".phantom/beacon"),
                             open(self.payload, "rb").read())
            # original entries byte-identical
            self.assertEqual(z.read("classes.dex"), b"\x00" * 64)

    def test_zip_roundtrip_preserves_original_archive(self):
        apk = self._make_apk()
        out = os.path.join(self.base, "evil.apk")
        build_trojan_bundle(apk, self.payload, out)
        orig_sha = hashlib.sha256(open(apk, "rb").read()).hexdigest()
        self.assertTrue(verify_legit(out, orig_sha), "carrier unchanged")
        self.assertFalse(verify_legit(out, "0" * 64))
        legit, payload = self._parse(out)
        self.assertEqual(legit, open(apk, "rb").read())
        self.assertEqual(payload, open(self.payload, "rb").read())
        self.assertEqual(extract_payload(out), open(self.payload, "rb").read())

    def test_zip_rejects_non_archive_with_zip_magic(self):
        """A file whose name is .zip but is not an archive must fail."""
        fake = os.path.join(self.base, "fake.apk")
        with open(fake, "wb") as f:
            f.write(b"PK\x03\x04" + b"not really a zip" * 10)
        out = os.path.join(self.base, "evil.apk")
        with self.assertRaises(ValueError):
            build_trojan_bundle(fake, self.payload, out)

    def test_zip_multi_entry_and_subdirectory_carrier(self):
        """Rebundling keeps every original entry (nested dirs included)."""
        import zipfile
        apk = os.path.join(self.base, "deep.apk")
        with zipfile.ZipFile(apk, "w") as z:
            z.writestr("lib/arm64-v8a/libnative.so", b"\x7fELFnative")
            z.writestr("assets/a/b/c.bin", bytes(range(20)))
        out = os.path.join(self.base, "deep_evil.apk")
        build_trojan_bundle(apk, self.payload, out)
        import zipfile as zf
        with zf.ZipFile(out) as z:
            self.assertEqual(z.namelist()[:2],
                             ["lib/arm64-v8a/libnative.so", "assets/a/b/c.bin"])
            self.assertEqual(z.read("lib/arm64-v8a/libnative.so"),
                             b"\x7fELFnative")


class TestRansomCapability(unittest.TestCase):

    def test_registered_in_kit(self):
        registry = make_registry()
        cap = registry.get("ransom_sim")
        self.assertIsNotNone(cap)
        self.assertIn("ransom_sim", cap.effects)
        self.assertEqual(cap.category, "post")

    def test_command_shape_via_adapter(self):
        from phantom.automation.belief import WorldModel
        from phantom.automation.guidance.kit import _ransom_sim_adapter
        wm = WorldModel(target="10.0.0.5")
        self.assertEqual(_ransom_sim_adapter(wm, {"dir": "/opt"}),
                         "ransom-sim /opt")

    def test_planner_impact_goal(self):
        self.assertIn("ransom_sim", GOAL_FACTS["impact"])
        wm = WorldModel(target="10.0.0.5")
        wm.add_finding("beacon", "established", {"payload": "true"},
                       confidence=0.95)
        plan = Planner(make_registry(), StealthEngine(wm, StealthConfig())).plan(
            wm, goal="impact")
        ids = [s.capability.id for s in plan.steps]
        self.assertIn("ransom_sim", ids)
        self.assertTrue(plan.complete)


class TestTrojanDeliverCapability(unittest.TestCase):

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.carrier = os.path.join(self.base, "clean_app.bin")
        with open(self.carrier, "wb") as f:
            f.write(b"\x7fELF" + os.urandom(512))
        self.payload = os.path.join(self.base, "stage.bin")
        with open(self.payload, "wb") as f:
            f.write(b"\x90" * 64 + b"STAGE2")
        self.staging = os.path.join(self.base, "staging")
        os.makedirs(self.staging)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.base, ignore_errors=True)

    def test_registered_in_kit(self):
        registry = make_registry()
        cap = registry.get("trojan_deliver")
        self.assertIsNotNone(cap)
        self.assertIn("trojan_bundle", cap.effects)
        self.assertEqual(cap.category, "post")

    def test_precondition_requires_beacon(self):
        registry = make_registry()
        cap = registry.get("trojan_deliver")
        wm = WorldModel(target="10.0.0.5")
        self.assertFalse(all(p(wm) for p in cap.preconditions))
        wm.add_finding("beacon", "established", {"payload": "true"},
                       confidence=0.95)
        self.assertTrue(all(p(wm) for p in cap.preconditions))

    def test_adapter_stages_bundle_and_returns_command(self):
        from phantom.automation.belief import WorldModel
        from phantom.automation.guidance.kit import _trojan_deliver_adapter
        from phantom.utils.trojan_bundle import parse_bundle
        wm = WorldModel(target="10.0.0.5")
        cmd = _trojan_deliver_adapter(wm, {
            "carrier": self.carrier, "payload": self.payload,
            "staging": self.staging, "dir": "/opt/app"})
        self.assertTrue(cmd.startswith("trojan-deliver /opt/app "))
        bundle = cmd.split()[-1]
        self.assertTrue(os.path.exists(bundle), bundle)
        legit, payload = parse_bundle(bundle)
        self.assertEqual(legit, open(self.carrier, "rb").read())
        self.assertEqual(payload, open(self.payload, "rb").read())

    def test_adapter_without_assets_is_plain_drop(self):
        from phantom.automation.belief import WorldModel
        from phantom.automation.guidance.kit import _trojan_deliver_adapter
        wm = WorldModel(target="10.0.0.5")
        self.assertEqual(_trojan_deliver_adapter(wm, {"dir": "/tmp"}),
                         "trojan-deliver /tmp")

    def test_interpreter_parses_marker(self):
        from phantom.automation.post.trojan import trojan_deliver_interpreter
        wm = WorldModel(target="10.0.0.5")
        marker = ("TROJAN: delivered=true carrier=/opt/app/app.bundle "
                  "sha256=" + "ab" * 32 + " payload_offset=512")
        findings = trojan_deliver_interpreter(marker, wm, {})
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.kind, "trojan_bundle")
        self.assertEqual(f.value["carrier"], "/opt/app/app.bundle")
        self.assertEqual(f.value["payload_offset"], 512)
        self.assertTrue(f.value["verified"])
        self.assertEqual(
            trojan_deliver_interpreter("delivery failed", wm, {}), [])

    def test_planner_trojan_goal(self):
        self.assertIn("trojan_bundle", GOAL_FACTS["trojan"])
        wm = WorldModel(target="10.0.0.5")
        wm.add_finding("beacon", "established", {"payload": "true"},
                       confidence=0.95)
        plan = Planner(make_registry(), StealthEngine(wm, StealthConfig())).plan(
            wm, goal="trojan")
        ids = [s.capability.id for s in plan.steps]
        self.assertIn("trojan_deliver", ids)
        self.assertTrue(plan.complete)


class TestTrojanDeliverEndToEnd(unittest.TestCase):
    """The trojan bundle is consumed by the auto-mode: staged on the
    operator host, dropped through the beacon channel, verified."""

    def setUp(self):
        from phantom.core.c2_server import c2_state
        c2_state.beacons.clear()
        c2_state.tasks.clear()
        c2_state.results.clear()
        self.base = tempfile.mkdtemp()
        self.carrier = os.path.join(self.base, "app.bin")
        with open(self.carrier, "wb") as f:
            f.write(b"\x7fELF" + os.urandom(512))
        self.payload = os.path.join(self.base, "stage.bin")
        with open(self.payload, "wb") as f:
            f.write(b"\x90" * 64 + b"STAGE2")
        self.staging = os.path.join(self.base, "staging")
        os.makedirs(self.staging)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.base, ignore_errors=True)

    def test_run_reaches_trojan_goal_through_beacon(self):
        import threading
        from unittest.mock import Mock
        from phantom.automation.agent import run_autonomous
        from phantom.automation.runtime.toolchain import ToolRegistry
        from phantom.core.c2_server import c2_state

        def runner(cmd, timeout=None):
            res = Mock()
            res.ok = True
            res.stdout = ""
            res.stderr = ""
            if "api/v1/payload" in cmd:
                c2_state.update_beacon("beacon-t1", {"ip": "10.0.0.5",
                                                     "os": "Linux"})
                res.stdout = "PHANTOM"
            elif "sshpass" in cmd and "scp" in cmd:
                # beacon deploy (scp + setsid): beacon starts on target
                c2_state.update_beacon("beacon-t1", {"ip": "10.0.0.5",
                                                     "os": "Linux"})
                res.stdout = "PHANTOM"
            elif "trojan-deliver" in cmd:
                res.stdout = ("TROJAN: delivered=true carrier=/opt/app.bundle "
                              "sha256=" + "ab" * 32 + " payload_offset=512")
            elif "nmap" in cmd:
                res.stdout = "22/tcp open ssh OpenSSH 7.9p1"
            elif "sshpass" in cmd:
                res.stdout = "uid=0(root) gid=0(root)"
            else:
                res.stdout = "PHANTOM"
            return res

        stop = threading.Event()

        def sim():
            import time
            while not stop.is_set():
                for bid in list(c2_state.get_beacons().keys()):
                    for task in c2_state.get_pending_tasks(bid):
                        res = runner(task["command"])
                        c2_state.add_result(bid, task["task_id"], res.stdout)
                time.sleep(0.05)

        t = threading.Thread(target=sim, daemon=True)
        t.start()
        try:
            result = run_autonomous(
                target="10.0.0.5", goal="trojan", max_iterations=20,
                runner=runner,
                cred_discoverer=lambda s: ("root", "toor"),
                sandbox=_approving_sandbox(),
                toolchain=ToolRegistry(
                    installed={"nmap", "sshpass", "curl", "nc"}),
                beacon_builder=lambda p, h, pt: _temp_beacon(),
                trojan_assets={"carrier": self.carrier,
                               "payload": self.payload,
                               "staging": self.staging},
                on_event=lambda k, d: None)
        finally:
            stop.set()
            t.join(timeout=3)

        self.assertTrue(result["beacon_established"], result)
        self.assertEqual(result["trojan_bundles"], 1, result)
        bundles = [f for f in os.listdir(self.staging)
                   if f.endswith(".bundle")]
        self.assertEqual(len(bundles), 1)
        self.assertTrue(os.path.getsize(
            os.path.join(self.staging, bundles[0])) > 0)


if __name__ == "__main__":
    unittest.main()
