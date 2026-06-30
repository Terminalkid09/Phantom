import pytest
import os
import json
import time
from unittest.mock import MagicMock, AsyncMock
from phantom.core.c2_server import handle_payload, PAYLOAD_AUTH_TOKEN, c2_state, decrypt_data, encrypt_data
from phantom.utils.payload_manager import add_custom_beacon, get_custom_beacons, clear_payload_history

@pytest.fixture
def clean_payload_history():
    clear_payload_history()
    yield
    clear_payload_history()

class TestPayloadManager:
    def test_add_custom_beacon_deduplication(self, clean_payload_history):
        add_custom_beacon("windows", "echo 1", "test")
        add_custom_beacon("windows", "echo 1", "test")
        beacons = get_custom_beacons()
        assert len(beacons) == 1

    def test_add_custom_beacon_fields(self, clean_payload_history):
        add_custom_beacon("linux", "echo 2", "desc", source="test_source")
        beacons = get_custom_beacons()
        assert len(beacons) == 1
        assert beacons[0]["platform"] == "linux"
        assert beacons[0]["command"] == "echo 2"
        assert beacons[0]["source"] == "test_source"
        assert "created_at" in beacons[0]
        assert "id" in beacons[0]

@pytest.mark.asyncio
async def test_handle_payload_unauthorized():
    # Mock aiohttp request
    request = MagicMock()
    request.query = {}
    request.headers = {}
    request.remote = "127.0.0.1"
    
    resp = await handle_payload(request)
    assert resp.status == 403
    assert "Forbidden" in resp.text

@pytest.mark.asyncio
async def test_handle_payload_authorized_not_found():
    # Mock aiohttp request
    request = MagicMock()
    request.query = {"auth": PAYLOAD_AUTH_TOKEN}
    request.headers = {}
    request.path = "/api/v1/payload_nonexistent"
    
    resp = await handle_payload(request)
    assert resp.status == 404

def test_crypto_roundtrip():
    original = "Hello C2 World!"
    encrypted = encrypt_data(original)
    assert encrypted != original
    decrypted = decrypt_data(encrypted)
    assert decrypted == original
