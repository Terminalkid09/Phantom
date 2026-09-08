# -*- mode: python ; coding: utf-8 -*-
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
    analysis.binaries,
    analysis.datas,
    [],
    name="phantom-backend",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
)
