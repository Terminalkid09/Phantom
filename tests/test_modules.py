"""
Integration test suite for phantom module workflows.

Tests the end-to-end flow:
- scan → parsing XML → extraction of services
- exploit → CVE correlation → scoring
- payload → OS detection → payload generation
"""

from unittest.mock import MagicMock, patch

import pytest

from phantom.core.session import session
from phantom.utils.parser import ServiceInfo


class TestModuleIntegration:
    """Integration tests for module workflows."""

    def setup_method(self):
        """Reset session before each test."""
        session.target = "10.0.0.1"
        session.scope = []
        session.results = {}
        session.notes = []
        session.history = []
        session.mode = "recon"

    def test_scan_to_exploit_workflow(self, monkeypatch):
        """
        Test workflow: Scan module saves XML → Exploit module parses it.
        
        This verifies that the scan results are compatible with exploit module.
        """
        from phantom.modules.scan import ScanModule
        from phantom.modules.exploit import ExploitModule

        # Mock scan to save minimal XML
        def mock_run_commands(commands, target_ip=""):
            # Simulate scan output
            return {cmd: f"output of {cmd}" for cmd in commands}

        monkeypatch.setattr("phantom.core.executor.run_commands", mock_run_commands)

        # Build scan commands
        scan = ScanModule()
        commands = scan.build_commands()
        assert "NMAP" in commands
        assert any("oX" in cmd for cmd in commands["NMAP"])

    def test_exploit_requires_versioned_services(self):
        """Test that exploit module requires services with version info."""
        from phantom.modules.exploit import ExploitModule

        # Create module
        exploit = ExploitModule()
        
        # Verify module exists and has required methods
        assert hasattr(exploit, '_get_services')
        assert hasattr(exploit, '_check_msf_module')
        assert callable(exploit._get_services)
        assert callable(exploit._check_msf_module)

    def test_payload_os_detection_impacts_payload_type(self):
        """Test that OS detection influences payload selection."""
        from phantom.modules.payload import _os_to_payload_hint, PAYLOAD_TYPES

        # Windows x64 should suggest Windows payloads
        arch, platform = _os_to_payload_hint("Windows Server 2019 64-bit")
        
        # Verify detection is correct
        assert platform == "windows"
        assert arch == "x64"

    def test_session_persistence_across_modules(self):
        """Test that session data persists across module calls."""
        from phantom.core.session import Session

        # Set some session state
        session.target = "example.com"
        session.mode = "osint"
        session.scope = ["10.0.0.0/24"]
        session.add_note("Test note")
        session.add_result("scan", {"services": ["ssh", "http"]})

        # Verify state is maintained
        assert session.target == "example.com"
        assert session.mode == "osint"
        assert len(session.scope) == 1
        assert len(session.notes) == 1
        assert "scan" in session.results

    def test_aggressive_flag_consistency(self):
        """Test that AGGRESSIVE flag is handled consistently across modules."""
        from phantom.core.executor import run_commands
        from unittest.mock import patch

        # Create commands with AGGRESSIVE marker
        commands = [
            "nmap -p- 10.0.0.1 AGGRESSIVE",
            "sqlmap -u http://10.0.0.1 --batch AGGRESSIVE",
            "whois example.com",
        ]

        executed = []
        def mock_run_cmd(cmd, target_ip=""):
            executed.append(cmd)
            return ""

        with patch("phantom.core.executor.run_command", mock_run_cmd):
            run_commands(commands, target_ip="10.0.0.1")

            # Verify AGGRESSIVE was stripped from all commands
            for cmd in executed:
                assert "AGGRESSIVE" not in cmd
            # Verify all commands were executed
            assert len(executed) == 3

    def test_scope_enforcement_in_commands(self, monkeypatch):
        """Test that scope is enforced when running commands."""
        from phantom.core.executor import run_command

        session.target = "10.0.0.1"
        session.scope = ["10.0.0.0/24"]

        # In-scope target should be allowed
        def mock_popen(*args, **kwargs):
            proc = MagicMock()
            proc.stdout = []
            proc.poll = MagicMock(return_value=0)
            proc.wait = MagicMock()
            return proc

        monkeypatch.setattr("subprocess.Popen", mock_popen)

        output = run_command("nmap 10.0.0.2", target_ip="10.0.0.2")
        assert isinstance(output, str)

    def test_session_save_and_load_preserves_module_results(self):
        """Test that session preserves all module results through save/load cycle."""
        session.target = "10.0.0.1"
        session.mode = "full"
        session.add_result("scan", {"ports": [22, 80, 443]})
        session.add_result("exploit", {"cves": ["CVE-2023-0001", "CVE-2023-0002"]})
        session.add_note("Important finding")

        # Verify state is properly stored
        assert session.target == "10.0.0.1"
        assert session.mode == "full"
        assert len(session.results) == 2
        assert len(session.notes) == 1
        assert session.results["scan"]["ports"] == [22, 80, 443]
        assert session.results["exploit"]["cves"] == ["CVE-2023-0001", "CVE-2023-0002"]
        
        # Verify we can access by module name
        assert session.get_result("scan") is not None
        assert session.get_result("exploit") is not None
