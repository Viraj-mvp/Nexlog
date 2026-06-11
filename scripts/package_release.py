#!/usr/bin/env python3
"""Build NexLog source archives, native app bundles, and installer releases."""

from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import zipfile


ROOT = Path(__file__).resolve().parents[1]
RELEASE_DIR = ROOT / "release"
BUILD_DIR = ROOT / "build" / "release"
APP_DISPLAY_NAME = "NexLog"
LINUX_DEPENDS = (
    "libc6, libegl1, libgl1, libxkbcommon-x11-0, libxcb-cursor0, "
    "libxcb-icccm4, libxcb-image0, libxcb-keysyms1, libxcb-randr0, "
    "libxcb-render-util0, libxcb-shape0, libxcb-xinerama0"
)


def _project_version() -> str:
    pyproject = ROOT / "pyproject.toml"
    in_project = False
    for line in pyproject.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped == "[project]":
            in_project = True
            continue
        if in_project and stripped.startswith("["):
            break
        if in_project:
            match = re.match(r'version\s*=\s*"([^"]+)"', stripped)
            if match:
                return match.group(1)
    return "0.0.0"


VERSION = os.environ.get("NEXLOG_VERSION", _project_version()).lstrip("vV")

EXCLUDE_DIRS = {
    ".git",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "workspace",
    "test.ai",
    "build",
    "dist",
    "release",
    "node_modules",
}

EXCLUDE_DIR_PREFIXES = (
    "pytest-cache-files-",
)

EXCLUDE_FILE_SUFFIXES = {
    ".pyc",
    ".pyo",
}

EXCLUDE_FILE_NAMES = {
    ".env",
    ".nexlog_write_check",
    "pytest_error.log",
    "pip_err.txt",
    ".abuseipdb_cache.db",
    ".abuseipdb_cache.db-journal",
}

EXCLUDE_GLOBS = [
    "*.facase",
    "*.facase-journal",
    "*.sqlite",
    "*.sqlite-journal",
    "*.sqlite-wal",
    "*.sqlite-shm",
    "*.db",
    "*.db-journal",
    "*.db-wal",
    "*.db-shm",
    ".nexlog_write_check*",
]


def _skip(path: Path) -> bool:
    rel = path.relative_to(ROOT)
    if any(part in EXCLUDE_DIRS for part in rel.parts):
        return True
    if any(part.startswith(prefix) for part in rel.parts for prefix in EXCLUDE_DIR_PREFIXES):
        return True
    if path.name in EXCLUDE_FILE_NAMES:
        return True
    if path.suffix in EXCLUDE_FILE_SUFFIXES:
        return True
    return any(path.match(glob) for glob in EXCLUDE_GLOBS)


def build_source_zip() -> Path:
    RELEASE_DIR.mkdir(parents=True, exist_ok=True)
    zip_path = RELEASE_DIR / f"NexLog-v{VERSION}-source.zip"
    if zip_path.exists():
        try:
            zip_path.unlink()
        except PermissionError:
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            zip_path = RELEASE_DIR / f"NexLog-v{VERSION}-source-{stamp}.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in ROOT.rglob("*"):
            if path.is_dir() or _skip(path):
                continue
            zf.write(path, path.relative_to(ROOT).as_posix())
    print(f"Created {zip_path}")
    return zip_path


def _add_data_arg(source: Path, dest: str) -> str:
    return f"{source}{os.pathsep}{dest}"


def _machine() -> str:
    machine = platform.machine().lower()
    if machine in {"amd64", "x86_64"}:
        return "x64"
    if machine == "aarch64":
        return "arm64"
    return machine


def _deb_architecture() -> str:
    machine = _machine()
    if machine == "x64":
        return "amd64"
    if machine == "arm64":
        return "arm64"
    return machine


def _system() -> str:
    return platform.system().lower()


def _exe_suffix() -> str:
    return ".exe" if _system() == "windows" else ""


# ── Targeted hidden imports (no collect_all bloat) ───────────────────────
_PYSIDE6_HIDDEN = [
    "PySide6.QtCore",
    "PySide6.QtGui",
    "PySide6.QtWidgets",
    "PySide6.QtQml",
    "PySide6.QtQuick",
    "PySide6.QtQuickControls2",
    "PySide6.QtSvg",
    "PySide6.QtCharts",
    "PySide6.QtOpenGL",
    "PySide6.QtPrintSupport",
    "PySide6.QtNetwork",
]

_CORE_HIDDEN = [
    "yaml",
    "defusedxml",
    "ijson",
    "Evtx",
    "reportlab",
    "reportlab.lib",
    "reportlab.platypus",
    "reportlab.graphics",
    "networkx",
    "PIL",
]

# ── Excluded modules (keep installer payload lean) ───────────────────────
_EXCLUDES = [
    # Heavy ML / AI — not needed for the packaged installer
    "torch", "torchvision", "torchaudio",
    "tensorflow", "keras",
    "chromadb", "sentence_transformers",
    # Unused GUI frameworks
    "PyQt5", "PyQt6", "PySide2",
    "tkinter", "_tkinter", "wx",
    # PySide6 web engine (huge, unused)
    "PySide6.QtWebEngineCore",
    "PySide6.QtWebEngineQuick",
    "PySide6.QtWebEngineWidgets",
    # Dev / test
    "pytest", "IPython", "jupyter", "notebook",
    "matplotlib", "scipy",
]


def _pyinstaller_command(entrypoint: Path, name: str, *, windowed: bool, onefile: bool = True) -> list[str]:
    icon = ROOT / "nexlog" / "interface" / "gui" / "assets" / "nexlog-icon.ico"
    rthook = ROOT / "packaging" / "pyinstaller" / "rthook_nexlog.py"
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--windowed" if windowed else "--console",
        "--name",
        name,
        "--distpath",
        str(RELEASE_DIR),
        "--workpath",
        str(ROOT / "build" / "pyinstaller"),
        "--specpath",
        str(ROOT / "build" / "pyinstaller" / "specs"),
    ]
    if onefile:
        cmd.append("--onefile")
    if icon.exists():
        cmd.extend(["--icon", str(icon)])

    # Add app subdirectories to PyInstaller search path so it resolves flat imports
    paths = [
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
    ]
    for p in paths:
        cmd.extend(["--paths", p])

    # Runtime hook for frozen path resolution
    if rthook.exists():
        cmd.extend(["--runtime-hook", str(rthook)])

    # Strip on Linux (not Windows — breaks PySide6 DLLs)
    if _system() != "windows":
        cmd.append("--strip")

    # ── Excludes ──────────────────────────────────────────────────────
    for module in _EXCLUDES:
        cmd.extend(["--exclude-module", module])

    # ── Data bundles ──────────────────────────────────────────────────
    data_items = [
        (ROOT / "nexlog",                                  "nexlog"),
        (ROOT / "examples" / "logs",                       "examples/logs"),
        (ROOT / ".env.example",                            ".env.example"),
        (ROOT / "README.md",                               "README.md"),
        (ROOT / "docs",                                    "docs"),
        (ROOT / "LICENSE",                                 "LICENSE"),
    ]
    for source, dest in data_items:
        if source.exists():
            cmd.extend(["--add-data", _add_data_arg(source, dest)])

    # ── Hidden imports (targeted, not collect_all) ────────────────────
    hidden_imports = list(_CORE_HIDDEN)
    if windowed:
        hidden_imports.extend(_PYSIDE6_HIDDEN)

    for imp in hidden_imports:
        cmd.extend(["--hidden-import", imp])

    # ── Collect submodules for packages with dynamic imports ──────────
    for package in ["reportlab", "maxminddb"]:
        cmd.extend(["--collect-submodules", package])

    # UPX exclusions for Windows
    if _system() == "windows":
        for dll in ["vcruntime140.dll", "qwindows.dll"]:
            cmd.extend(["--upx-exclude", dll])

    cmd.append(str(entrypoint))
    return cmd


def _run_pyinstaller(entrypoint: Path, name: str, *, windowed: bool, onefile: bool) -> int:
    build_kind = "one-file" if onefile else "app-directory"
    cmd = _pyinstaller_command(entrypoint, name, windowed=windowed, onefile=onefile)
    (ROOT / "build" / "pyinstaller" / "specs").mkdir(parents=True, exist_ok=True)
    print(f"Running PyInstaller {build_kind} build for {name}...")
    proc = subprocess.run(cmd, cwd=ROOT)
    if proc.returncode != 0:
        print(f"PyInstaller {build_kind} build failed for {name}.")
    return proc.returncode


def _built_path(name: str) -> Path:
    ext = _exe_suffix()
    onefile = RELEASE_DIR / f"{name}{ext}"
    if onefile.exists():
        return onefile
    folder = RELEASE_DIR / name
    if folder.exists():
        return folder
    return onefile


def build_app_binaries(*, onefile: bool = True) -> int:
    RELEASE_DIR.mkdir(parents=True, exist_ok=True)
    if shutil.which("pyinstaller") is None:
        print("PyInstaller command not found; trying python -m PyInstaller.")

    builds = [
        (ROOT / "main_gui.py", "NexLog", True),
        (ROOT / "main.py", "nexlog", False),
    ]
    for entrypoint, name, windowed in builds:
        rc = _run_pyinstaller(entrypoint, name, windowed=windowed, onefile=onefile)
        if rc != 0:
            return rc
    return 0


def _copy_any(src: Path, dest: Path) -> None:
    if src.is_dir():
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(src, dest)
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)


def _stage_app_bundle() -> Path:
    stage = BUILD_DIR / "bundle" / "NexLog"
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True, exist_ok=True)

    for binary_name in ["NexLog", "nexlog"]:
        src = _built_path(binary_name)
        if not src.exists():
            raise FileNotFoundError(f"Missing built binary: {src}")
        _copy_any(src, stage / src.name)
        if src.is_file() and _system() != "windows":
            (stage / src.name).chmod(0o755)

    for src_name in [".env.example", "README.md", "LICENSE"]:
        src = ROOT / src_name
        if src.exists():
            shutil.copy2(src, stage / src_name)

    examples_logs = ROOT / "examples" / "logs"
    if examples_logs.exists():
        shutil.copytree(examples_logs, stage / "examples" / "logs")

    icon = ROOT / "nexlog" / "interface" / "gui" / "assets" / "nexlog-icon.png"
    if icon.exists():
        assets = stage / "assets"
        assets.mkdir(exist_ok=True)
        shutil.copy2(icon, assets / "nexlog-icon.png")
    return stage


def _staged_executable(stage: Path, name: str) -> Path:
    direct = stage / f"{name}{_exe_suffix()}"
    if direct.exists():
        return direct
    nested = stage / name / f"{name}{_exe_suffix()}"
    if nested.exists():
        return nested
    raise FileNotFoundError(f"Missing staged executable for {name}")


def _ensure_app_binaries(*, onefile: bool = True) -> int:
    if _built_path("NexLog").exists() and _built_path("nexlog").exists():
        return 0
    return build_app_binaries(onefile=onefile)


def build_binary(exe_only: bool = False) -> int:
    if exe_only and platform.system() != "Windows":
        print("Windows .exe builds must be run on Windows.", file=sys.stderr)
        return 2
    rc = build_app_binaries(onefile=True)
    if rc != 0:
        return rc

    stage = _stage_app_bundle()
    zip_name = f"NexLog-v{VERSION}-{_system()}-{_machine()}.zip"
    zip_path = RELEASE_DIR / zip_name
    print(f"Packaging app bundle into {zip_name}...")
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path in stage.rglob("*"):
            if path.is_file():
                zf.write(path, Path("NexLog") / path.relative_to(stage))
    print(f"Created app zip release at: {zip_path}")
    return 0


def _inno_path() -> str | None:
    found = shutil.which("ISCC") or shutil.which("ISCC.exe")
    if found:
        return found
    for candidate in [
        Path(os.environ.get("ProgramFiles(x86)", "")) / "Inno Setup 6" / "ISCC.exe",
        Path(os.environ.get("ProgramFiles", "")) / "Inno Setup 6" / "ISCC.exe",
    ]:
        if candidate.exists():
            return str(candidate)
    return None


def build_windows_installer() -> int:
    if _system() != "windows":
        print("Windows installer builds must be run on Windows.", file=sys.stderr)
        return 2
    rc = build_app_binaries(onefile=False)
    if rc != 0:
        return rc
    stage = _stage_app_bundle()
    iscc = _inno_path()
    if not iscc:
        print("Inno Setup compiler ISCC.exe not found.", file=sys.stderr)
        return 2

    script_dir = BUILD_DIR / "installer"
    script_dir.mkdir(parents=True, exist_ok=True)
    script = script_dir / "NexLog.iss"
    output_base = f"NexLog-v{VERSION}-windows-{_machine()}-setup"
    icon = ROOT / "nexlog" / "interface" / "gui" / "assets" / "nexlog-icon.ico"
    license_file = ROOT / "LICENSE"
    gui_exe = str(_staged_executable(stage, "NexLog").relative_to(stage)).replace("/", "\\")
    cli_exe = str(_staged_executable(stage, "nexlog").relative_to(stage)).replace("/", "\\")
    script.write_text(
        f"""
[Setup]
AppId={{{{7C4B926F-80B7-48E8-8EB8-FB3AF2C18A10}}}}
AppName={APP_DISPLAY_NAME}
AppVersion={VERSION}
AppPublisher=NexLog Contributors
DefaultDirName={{autopf}}\\NexLog
DefaultGroupName=NexLog
OutputDir={RELEASE_DIR}
OutputBaseFilename={output_base}
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
DisableProgramGroupPage=yes
SetupIconFile={icon}
LicenseFile={license_file}

[Files]
Source: "{stage}\\*"; DestDir: "{{app}}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{{group}}\\NexLog"; Filename: "{{app}}\\{gui_exe}"; WorkingDir: "{{app}}"
Name: "{{group}}\\NexLog CLI"; Filename: "{{app}}\\{cli_exe}"; WorkingDir: "{{app}}"
Name: "{{autodesktop}}\\NexLog"; Filename: "{{app}}\\{gui_exe}"; WorkingDir: "{{app}}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked
""".lstrip(),
        encoding="utf-8",
    )
    proc = subprocess.run([iscc, str(script)], cwd=ROOT)
    return proc.returncode


def _tar_add(tf, path: Path, arcname: Path) -> None:
    import tarfile

    info = tf.gettarinfo(str(path), arcname.as_posix())
    if path.name in {"NexLog", "nexlog"}:
        info.mode = 0o755
    if path.is_file():
        with path.open("rb") as fh:
            tf.addfile(info, fh)
    else:
        tf.addfile(info)


def build_linux_tarball() -> Path:
    import tarfile

    stage = _stage_app_bundle()
    tar_path = RELEASE_DIR / f"NexLog-v{VERSION}-linux-{_machine()}.tar.gz"
    if tar_path.exists():
        tar_path.unlink()
    with tarfile.open(tar_path, "w:gz") as tf:
        for path in stage.rglob("*"):
            _tar_add(tf, path, Path("NexLog") / path.relative_to(stage))
    print(f"Created Linux portable tarball: {tar_path}")
    return tar_path


def build_linux_deb() -> Path:
    if _system() != "linux":
        raise RuntimeError("Linux .deb builds must be run on Linux.")
    stage = _stage_app_bundle()
    package_root = BUILD_DIR / "deb" / f"nexlog_{VERSION}_{_machine()}"
    if package_root.exists():
        shutil.rmtree(package_root)

    app_dir = package_root / "opt" / "nexlog"
    shutil.copytree(stage, app_dir)
    for binary in [_staged_executable(app_dir, "NexLog"), _staged_executable(app_dir, "nexlog")]:
        if binary.exists():
            binary.chmod(0o755)

    bin_dir = package_root / "usr" / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    cli_rel = _staged_executable(app_dir, "nexlog").relative_to(app_dir).as_posix()
    gui_rel = _staged_executable(app_dir, "NexLog").relative_to(app_dir).as_posix()
    (bin_dir / "nexlog").write_text(f"#!/bin/sh\nexec /opt/nexlog/{cli_rel} \"$@\"\n", encoding="utf-8")
    (bin_dir / "nexlog-gui").write_text(f"#!/bin/sh\nexec /opt/nexlog/{gui_rel} \"$@\"\n", encoding="utf-8")
    (bin_dir / "nexlog").chmod(0o755)
    (bin_dir / "nexlog-gui").chmod(0o755)

    icon_dir = package_root / "usr" / "share" / "icons" / "hicolor" / "256x256" / "apps"
    icon_dir.mkdir(parents=True, exist_ok=True)
    icon_src = ROOT / "nexlog" / "interface" / "gui" / "assets" / "nexlog-icon.png"
    if icon_src.exists():
        shutil.copy2(icon_src, icon_dir / "nexlog.png")

    desktop_dir = package_root / "usr" / "share" / "applications"
    desktop_dir.mkdir(parents=True, exist_ok=True)
    (desktop_dir / "nexlog.desktop").write_text(
        """[Desktop Entry]
Type=Application
Name=NexLog
Comment=Local-first DFIR log analyzer
Exec=nexlog-gui
Icon=nexlog
Terminal=false
Categories=Security;Utility;
""",
        encoding="utf-8",
    )

    debian = package_root / "DEBIAN"
    debian.mkdir(parents=True, exist_ok=True)
    installed_size = sum(path.stat().st_size for path in package_root.rglob("*") if path.is_file()) // 1024
    (debian / "control").write_text(
        f"""Package: nexlog
Version: {VERSION}
Section: utils
Priority: optional
Architecture: {_deb_architecture()}
Maintainer: NexLog Contributors
Depends: {LINUX_DEPENDS}
Installed-Size: {installed_size}
Description: Local-first DFIR log analyzer
 NexLog is a desktop GUI and CLI tool for analyzing security logs.
""",
        encoding="utf-8",
    )

    deb_path = RELEASE_DIR / f"NexLog-v{VERSION}-linux-{_machine()}.deb"
    proc = subprocess.run(["dpkg-deb", "--build", str(package_root), str(deb_path)], cwd=ROOT)
    if proc.returncode != 0:
        raise RuntimeError("dpkg-deb failed")
    print(f"Created Linux deb package: {deb_path}")
    return deb_path


def build_linux_packages() -> int:
    if _system() != "linux":
        print("Linux packages must be built on Linux.", file=sys.stderr)
        return 2
    rc = build_app_binaries(onefile=False)
    if rc != 0:
        return rc
    build_linux_tarball()
    build_linux_deb()
    return 0


def write_checksums() -> Path:
    checksum_path = RELEASE_DIR / f"NexLog-v{VERSION}-checksums.txt"
    candidates = sorted(
        path for path in RELEASE_DIR.iterdir()
        if path.is_file()
        and path.name.startswith(f"NexLog-v{VERSION}-")
        and path.name != checksum_path.name
        and path.suffix not in {".spec"}
    )
    with checksum_path.open("w", encoding="utf-8", newline="\n") as fh:
        for path in candidates:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            fh.write(f"{digest}  {path.name}\n")
    print(f"Created checksums: {checksum_path}")
    return checksum_path



def run_release_check() -> int:
    return subprocess.run([sys.executable, "scripts/release_check.py"], cwd=ROOT).returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="Package NexLog releases.")
    parser.add_argument("--source-zip", action="store_true", help="Create clean source ZIP.")
    parser.add_argument("--binary", action="store_true", help="Build native PyInstaller binary for this OS.")
    parser.add_argument("--exe", action="store_true", help="Build Windows NexLog.exe; requires Windows.")
    parser.add_argument("--windows-installer", action="store_true", help="Build Windows setup installer; requires Windows and Inno Setup.")
    parser.add_argument("--linux-packages", action="store_true", help="Build Linux .deb and portable .tar.gz packages.")
    parser.add_argument("--checksums", action="store_true", help="Write SHA-256 checksums for release assets.")
    parser.add_argument("--all", action="store_true", help="Run checks, build ZIP, and build native binary.")
    parser.add_argument("--skip-check", action="store_true", help="Do not run release_check before building.")
    args = parser.parse_args()

    if not any((args.source_zip, args.binary, args.exe, args.windows_installer, args.linux_packages, args.checksums, args.all)):
        parser.print_help()
        return 0
    if not args.skip_check and (args.all or args.binary or args.exe or args.windows_installer or args.linux_packages):
        rc = run_release_check()
        if rc != 0:
            return rc
    if args.source_zip or args.all:
        build_source_zip()
    if args.windows_installer:
        rc = build_windows_installer()
        if rc != 0:
            return rc
    if args.linux_packages:
        rc = build_linux_packages()
        if rc != 0:
            return rc
    if args.exe:
        rc = build_binary(exe_only=True)
        if rc != 0:
            return rc
    if args.binary or args.all:
        rc = build_binary(exe_only=False)
        if rc != 0:
            return rc
    if args.checksums:
        write_checksums()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
