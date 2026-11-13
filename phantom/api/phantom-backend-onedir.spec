# -*- mode: python ; coding: utf-8 -*-
"""OneDIR variant of phantom-backend.spec.

onedir is used instead of onefile because onefile's self-extracting
bootloader is a well-known heuristic trigger for AV false positives.
The onedir layout (exe + DLLs + _internal/) starts faster too.
"""
from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules

root = Path(SPECPATH).resolve().parents[1]
phantom_root = root / "phantom"

hiddenimports = []
for package in (
    "phantom.core", "phantom.modules", "phantom.utils", "phantom.automation",
):
    hiddenimports.extend(collect_submodules(package))

analysis = Analysis(
    [str(phantom_root / "api" / "launcher.py")],
    pathex=[str(root)],
    binaries=[],
    datas=[(str(phantom_root), "phantom")],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter"],
    noarchive=False,
)
pyz = PYZ(analysis.pure)
exe = EXE(
    pyz,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="phantom-backend",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
)
coll = COLLECT(
    exe,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="phantom-backend",
)
