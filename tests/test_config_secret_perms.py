"""F-06: the config file (API keys, breach creds) must be owner-only at rest.

`save_config` now routes the freshly written file through the shared
`secret_store.harden_file` helper (chmod 0600 on POSIX, an owner-only ACL via
`icacls` on Windows), matching the state files. Hardening stays best-effort.
"""
import os

from phantom.utils import config as cfg


def test_save_config_hardens_the_written_file(monkeypatch, tmp_path):
    target = tmp_path / "data" / "config.json"
    monkeypatch.setattr(cfg, "_CONFIG_PATH", str(target))

    calls = []
    import phantom.utils.secret_store as ss
    monkeypatch.setattr(ss, "harden_file",
                        lambda path, mode=0o600: calls.append((path, mode)))

    cfg.save_config({"api_keys": {"shodan": "X"}})

    # hardened both the temp file (before replace) and the final path
    hardened = {os.path.basename(p) for p, _m in calls}
    assert "config.json" in hardened
    assert all(m == 0o600 for _p, m in calls)


def test_save_config_sets_owner_only_mode_on_posix(monkeypatch, tmp_path):
    if os.name == "nt":
        import pytest
        pytest.skip("POSIX permission bits (Windows uses an ACL)")
    target = tmp_path / "data" / "config.json"
    monkeypatch.setattr(cfg, "_CONFIG_PATH", str(target))

    cfg.save_config({"api_keys": {"shodan": "X"}})

    assert (os.stat(target).st_mode & 0o077) == 0
