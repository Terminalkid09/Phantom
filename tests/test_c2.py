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
        # First task is auto-persist from update_beacon: `persist` with no
        # argument so the beacon uses its default unit name (PhantomBeacon)
        # instead of creating a unit literally called "systemd"/"runkey".
        assert len(pending) == 2
        assert pending[0]["command"] == "persist"
        assert pending[1]["command"] == "recon C:\\"

        # Tasks should be cleared after retrieval
        pending2 = state.get_pending_tasks("B1")
        assert len(pending2) == 0

    def test_result_acknowledges_leased_task(self):
        from phantom.core.c2_server import C2State
        state = C2State()
        state.update_beacon("B2", {"ip": "10.0.0.2"})
        task_id = state.queue_task("B2", "sysinfo")
        pending = state.get_pending_tasks("B2")
        assert any(task["task_id"] == task_id for task in pending)
        state.add_result("B2", task_id, "SYSINFO_OK")
        assert not any(task["task_id"] == task_id
                       for task in state.tasks["B2"])

    def test_duplicate_result_is_idempotent(self):
        from phantom.core.c2_server import C2State
        state = C2State()
        state.update_beacon("B2", {"ip": "10.0.0.2"})
        state.add_result("B2", "task-001", "OK")
        state.add_result("B2", "task-001", "OK")
        results = state.get_results("B2")
        assert len(results) == 1
        assert results[0]["output"] == "OK"

    def test_multiple_beacons_isolation(self):
        from phantom.core.c2_server import C2State
        state = C2State()
        state.update_beacon("B-A", {"ip": "10.0.0.1"})
        state.update_beacon("B-B", {"ip": "10.0.0.2"})
        state.queue_task("B-A", "whoami")
        state.queue_task("B-B", "drives")

        tasks_a = state.get_pending_tasks("B-A")
        tasks_b = state.get_pending_tasks("B-B")
        # First task is auto-persist from update_beacon
        assert len(tasks_a) == 2 and tasks_a[1]["command"] == "whoami"
        assert len(tasks_b) == 2 and tasks_b[1]["command"] == "drives"


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


@pytest.mark.asyncio
async def test_pic_payload_requires_authentication():
    from phantom.core.c2_server import handle_payload_pic
    request = MagicMock()
    request.query = {}
    request.headers = {}
    request.remote = "127.0.0.1"
    response = await handle_payload_pic(request)
    assert response.status == 403
