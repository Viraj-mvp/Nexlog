# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules

ROOT = Path.cwd()

hiddenimports = ['yaml', 'defusedxml', 'ijson', 'Evtx', 'reportlab', 'reportlab.lib', 'reportlab.platypus', 'reportlab.graphics', 'networkx', 'PIL']
hiddenimports += collect_submodules('reportlab')
hiddenimports += collect_submodules('maxminddb')

a = Analysis(
    [str(ROOT / 'main.py')],
    pathex=[
        str(ROOT),
        str(ROOT / "nexlog"),
        str(ROOT / "nexlog" / "core"),
        str(ROOT / "nexlog" / "detection"),
        str(ROOT / "nexlog" / "storage"),
        str(ROOT / "nexlog" / "intelligence"),
        str(ROOT / "nexlog" / "output"),
        str(ROOT / "nexlog" / "utils"),
        str(ROOT / "nexlog" / "ai"),
        str(ROOT / "nexlog" / "interface" / "web"),
        str(ROOT / "nexlog" / "interface" / "gui"),
    ],
    binaries=[],
    datas=[
        (str(ROOT / "nexlog"), "nexlog"),
        (str(ROOT / "examples" / "logs"), "examples/logs"),
        (str(ROOT / ".env.example"), ".env.example"),
        (str(ROOT / "README.md"), "README.md"),
        (str(ROOT / "docs"), "docs"),
        (str(ROOT / "LICENSE"), "LICENSE"),
    ],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[str(ROOT / 'packaging/pyinstaller/rthook_nexlog.py')],
    excludes=['torch', 'torchvision', 'torchaudio', 'tensorflow', 'keras', 'chromadb', 'sentence_transformers', 'PyQt5', 'PyQt6', 'PySide2', 'tkinter', '_tkinter', 'wx', 'PySide6.QtWebEngineCore', 'PySide6.QtWebEngineQuick', 'PySide6.QtWebEngineWidgets', 'pytest', 'IPython', 'jupyter', 'notebook', 'matplotlib', 'scipy'],
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
    name='nexlog',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=['vcruntime140.dll', 'qwindows.dll'],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ROOT / 'nexlog/interface/gui/assets/nexlog-icon.ico'),
)
