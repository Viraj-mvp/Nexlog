# -*- mode: python ; coding: utf-8 -*-
"""Reference PyInstaller spec for NexLog.

The preferred build path is `python scripts/package_release.py --binary`,
which generates an OS-appropriate command from the current checkout. This spec
is kept as a readable template for maintainers.
"""

from pathlib import Path

from PyInstaller.utils.hooks import collect_all

ROOT = Path.cwd()

datas = [
    (str(ROOT / "nexlog"), "nexlog"),
    (str(ROOT / "examples" / "logs"), "examples/logs"),
    (str(ROOT / ".env.example"), ".env.example"),
    (str(ROOT / "README.md"), "README.md"),
    (str(ROOT / "docs"), "docs"),
    (str(ROOT / "LICENSE"), "LICENSE"),
]
binaries = []
hiddenimports = ["yaml", "defusedxml", "ijson", "Evtx"]

for package in [
    "PySide6",
    "sentence_transformers",
    "chromadb",
    "sklearn",
    "transformers",
    "torch",
    "tokenizers",
    "numpy",
    "reportlab",
]:
    collected = collect_all(package)
    datas += collected[0]
    binaries += collected[1]
    hiddenimports += collected[2]

a = Analysis(
    [str(ROOT / "main_gui.py")],
    pathex=[str(ROOT), str(ROOT / "nexlog")],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["PyQt6", "PyQt5", "PySide2"],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="NexLog",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ROOT / "nexlog" / "interface" / "gui" / "assets" / "nexlog-icon.ico"),
)
