import builtins

def test_is_defender_present_monkeypatched(monkeypatch):
    """Simulate the presence of the Defender registry key.

    The test replaces ``winreg.OpenKey`` with a dummy that pretends the key
    exists, ensuring the function returns ``True`` without touching the real
    registry. A second scenario forces an exception to verify ``False``.
    """
    # Simulate success
    class DummyKey:
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_open_key_success(*args, **kwargs):
        return DummyKey()

    import sys
    fake_mod = type("winreg", (), {"OpenKey": fake_open_key_success, "HKEY_LOCAL_MACHINE": None})
    sys.modules["winreg"] = fake_mod
    from phantom.utils.defender_check import is_defender_present
    assert is_defender_present() is True

    # Simulate failure (ImportError or key missing)
    def fake_open_key_fail(*args, **kwargs):
        raise OSError("key not found")

    fake_mod_fail = type("winreg", (), {"OpenKey": fake_open_key_fail, "HKEY_LOCAL_MACHINE": None})
    sys.modules["winreg"] = fake_mod_fail
    assert is_defender_present() is False
