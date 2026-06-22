"""
test_c2.py — Tests for the C2 Server and Shell components.
"""
import pytest
from unittest.mock import patch, MagicMock


class TestC2ServerCrypto:
    """Verify AES encrypt/decrypt round-trip."""

    def test_encrypt_decrypt_roundtrip(self):
        from phantom.core.c2_server import encrypt_data, decrypt_data
        original = '{"tasks": [{"task_id": "123", "command": "recon"}]}'
        encrypted = encrypt_data(original)
        assert encrypted != original
        assert len(encrypted) > 0
        decrypted = decrypt_data(encrypted)
        assert decrypted == original

    def test_encrypt_produces_base64(self):
        from phantom.core.c2_server import encrypt_data
        import base64
        encrypted = encrypt_data("test message")
        # Should be valid base64
        decoded = base64.b64decode(encrypted)
        assert len(decoded) > 0

    def test_decrypt_invalid_data_returns_empty(self):
        from phantom.core.c2_server import decrypt_data
        result = decrypt_data("this_is_not_valid_base64_!@#$")
        assert result == ""

    def test_encrypt_empty_string(self):
        from phantom.core.c2_server import encrypt_data, decrypt_data
        encrypted = encrypt_data("")
        assert len(encrypted) > 0
        decrypted = decrypt_data(encrypted)
        assert decrypted == ""


class TestC2State:
    """Verify shared state management."""

    def test_register_beacon(self):
        from phantom.core.c2_server import C2State
        state = C2State()
        state.update_beacon("PHANTOM-TEST-001", {"ip": "10.0.0.5"})
        beacons = state.get_beacons()
        assert "PHANTOM-TEST-001" in beacons
        assert beacons["PHANTOM-TEST-001"]["ip"] == "10.0.0.5"
        assert "last_seen" in beacons["PHANTOM-TEST-001"]

    def test_queue_and_retrieve_tasks(self):
        from phantom.core.c2_server import C2State
        state = C2State()
        state.update_beacon("B1", {"ip": "10.0.0.1"})
        task_id = state.queue_task("B1", "recon C:\\")
        assert task_id is not None

        pending = state.get_pending_tasks("B1")
        assert len(pending) == 1
        assert pending[0]["command"] == "recon C:\\"

        # Tasks should be cleared after retrieval
        pending2 = state.get_pending_tasks("B1")
        assert len(pending2) == 0

    def test_add_and_retrieve_results(self):
        from phantom.core.c2_server import C2State
        state = C2State()
        state.update_beacon("B2", {"ip": "10.0.0.2"})
        state.add_result("B2", "task-001", "=== DRIVES ===\nC:\\ Fixed")
        results = state.get_results("B2")
        assert len(results) == 1
        assert results[0]["output"] == "=== DRIVES ===\nC:\\ Fixed"

    def test_multiple_beacons_isolation(self):
        from phantom.core.c2_server import C2State
        state = C2State()
        state.update_beacon("B-A", {"ip": "10.0.0.1"})
        state.update_beacon("B-B", {"ip": "10.0.0.2"})
        state.queue_task("B-A", "whoami")
        state.queue_task("B-B", "drives")

        tasks_a = state.get_pending_tasks("B-A")
        tasks_b = state.get_pending_tasks("B-B")
        assert len(tasks_a) == 1 and tasks_a[0]["command"] == "whoami"
        assert len(tasks_b) == 1 and tasks_b[0]["command"] == "drives"


class TestC2ShellImport:
    """Verify C2 Shell can be imported without errors."""

    def test_c2_shell_import(self):
        from phantom.core.c2_shell import C2Shell
        assert C2Shell is not None

    def test_c2_shell_instantiation(self):
        from phantom.core.c2_shell import C2Shell
        shell = C2Shell()
        assert shell.active_beacon is None

    def test_run_c2_function_exists(self):
        from phantom.core.c2_shell import run_c2
        assert callable(run_c2)


class TestC2ServerInstance:
    """Verify C2 Server lifecycle."""

    def test_server_instance_exists(self):
        from phantom.core.c2_server import server_instance
        assert server_instance is not None
        assert server_instance.port == 8080

    def test_server_can_change_port(self):
        from phantom.core.c2_server import C2Server
        s = C2Server(port=8443)
        assert s.port == 8443
