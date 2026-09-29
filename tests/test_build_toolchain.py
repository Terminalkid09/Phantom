"""Build-toolchain selection: every supported target needs a REAL build path.

The cross-platform promise is only as good as the toolchain branch behind it.
These tests pin the pieces that are easy to silently lose: the native macOS
build (osxcross is not installed on a Mac, so a Mac operator had no way to
produce a macOS payload) and the honest readiness probe the smoke test uses
before compiling.
"""
import importlib.util
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_smoke():
    path = os.path.join(ROOT, "scripts", "ci_beacon_smoke.py")
    spec = importlib.util.spec_from_file_location("ci_beacon_smoke", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def fake_pkg(tmp_path, monkeypatch):
    """A throwaway package root with the beacon sources in place."""
    src = tmp_path / "payloads" / "beacon" / "src"
    src.mkdir(parents=True)
    (src / "main.cpp").write_text("int main() { return 0; }\n")
    monkeypatch.setenv("PHANTOM_BEACON_REGISTRY",
                       str(tmp_path / "registry.json"))
    monkeypatch.setenv("PHANTOM_DATA_DIR", str(tmp_path / "data"))
    return str(tmp_path)


def test_macos_uses_native_clang_when_osxcross_is_absent(fake_pkg, monkeypatch,
                                                          tmp_path):
    from phantom.utils import builder

    monkeypatch.setattr(builder.sys, "platform", "darwin")
    monkeypatch.setattr(builder, "_mark_built", lambda *a, **k: None)
    monkeypatch.delenv("OSXCROSS_ROOT", raising=False)
    monkeypatch.delenv("CXX", raising=False)
    # A real (existing) prefix, so the keg-only include/lib flags are added.
    brew = tmp_path / "openssl@3"
    brew.mkdir()
    monkeypatch.setenv("OPENSSL_PREFIX", str(brew))
    monkeypatch.setattr(builder.shutil, "which", lambda name: "/usr/bin/" + name)

    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return type("R", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(builder.subprocess, "run", fake_run)

    result = builder.compile_beacon("macos", fake_pkg, force_rebuild=True)
    assert result, "the native macOS path must produce an artefact"
    assert calls, "no compiler was invoked"
    cmd = calls[-1]
    assert cmd[0] == "clang++", cmd
    assert "src/main.cpp" in cmd
    assert f"-I{brew}/include" in cmd
    assert f"-L{brew}/lib" in cmd


def test_macos_still_prefers_osxcross_when_present(fake_pkg, monkeypatch, tmp_path):
    from phantom.utils import builder

    monkeypatch.setattr(builder.sys, "platform", "darwin")
    monkeypatch.setattr(builder, "_mark_built", lambda *a, **k: None)
    monkeypatch.setattr(builder.shutil, "which", lambda name: "/usr/bin/" + name)
    osxcross = tmp_path / "osxcross"
    (osxcross / "bin").mkdir(parents=True)
    (osxcross / "bin" / "o32-clang++").write_text("#!/bin/sh\n")
    monkeypatch.setenv("OSXCROSS_ROOT", str(osxcross))

    calls = []
    monkeypatch.setattr(builder.subprocess, "run",
                        lambda cmd, **kw: calls.append(cmd) or type(
                            "R", (), {"returncode": 0, "stdout": "", "stderr": ""})())

    assert builder.compile_beacon("macos", fake_pkg, force_rebuild=True)
    assert calls[-1][0].endswith("o32-clang++"), calls[-1]


def test_macos_without_any_toolchain_reports_instead_of_guessing(
        fake_pkg, monkeypatch):
    from phantom.utils import builder

    # A Linux host with no osxcross: there is no honest way to build macOS.
    monkeypatch.setattr(builder.sys, "platform", "linux")
    monkeypatch.delenv("OSXCROSS_ROOT", raising=False)
    assert builder.compile_beacon("macos", fake_pkg, force_rebuild=True) is None


def test_smoke_readiness_probe_is_honest(monkeypatch):
    smoke = _load_smoke()

    # linux is always buildable on a Linux runner
    assert smoke._toolchain_ready("linux")[0]

    monkeypatch.delenv("ANDROID_NDK_HOME", raising=False)
    monkeypatch.delenv("ANDROID_NDK_LATEST_HOME", raising=False)
    ready, reason = smoke._toolchain_ready("android")
    assert not ready and "NDK compiler" in reason

    # The NDK compiler is the real gate; OpenSSL is bootstrapped by the build
    # helper, so its absence alone must NOT report the target as unbuildable.
    monkeypatch.setenv("ANDROID_NDK_HOME", "/opt/android-ndk")
    monkeypatch.setattr(smoke.os.path, "exists", lambda p: True)
    monkeypatch.delenv("OPENSSL_ANDROID_ROOT", raising=False)
    assert smoke._toolchain_ready("android")[0]


def test_smoke_magic_tables_cover_the_real_formats():
    smoke = _load_smoke()
    assert smoke.MAGIC["linux"][0][0] == b"\x7fELF"
    assert smoke.MAGIC["windows"][0][0] == b"MZ"
    assert any(magic == b"\xcf\xfa\xed\xfe" for magic, _ in smoke.MAGIC["macos"])
