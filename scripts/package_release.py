#!/usr/bin/env python3
"""Build clean NexLog source ZIPs and native PyInstaller binaries."""

from __future__ import annotations

import argparse
from datetime import datetime
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


def _pyinstaller_command(onefile: bool = True) -> list[str]:
    icon = ROOT / "nexlog" / "interface" / "gui" / "assets" / "nexlog-icon.ico"
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--windowed",
        "--name",
        "NexLog",
        "--distpath",
        str(RELEASE_DIR),
        "--workpath",
        str(ROOT / "build" / "pyinstaller"),
        "--specpath",
        str(ROOT / "packaging" / "pyinstaller"),
    ]
    if onefile:
        cmd.append("--onefile")
    if icon.exists():
        cmd.extend(["--icon", str(icon)])
    for module in ["PyQt6", "PyQt5", "PySide2"]:
        cmd.extend(["--exclude-module", module])
    data_items = [
        (ROOT / "nexlog", "nexlog"),
        (ROOT / "examples" / "logs", "examples/logs"),
        (ROOT / ".env.example", ".env.example"),
        (ROOT / "README.md", "README.md"),
        (ROOT / "docs", "docs"),
        (ROOT / "LICENSE", "LICENSE"),
    ]
    for source, dest in data_items:
        if source.exists():
            cmd.extend(["--add-data", _add_data_arg(source, dest)])
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
        cmd.extend(["--collect-all", package])
    cmd.extend(
        [
            "--hidden-import",
            "yaml",
            "--hidden-import",
            "defusedxml",
            "--hidden-import",
            "ijson",
            "--hidden-import",
            "Evtx",
            str(ROOT / "main_gui.py"),
        ]
    )
    return cmd


def build_binary(exe_only: bool = False) -> int:
    if exe_only and platform.system() != "Windows":
        print("Windows .exe builds must be run on Windows.", file=sys.stderr)
        return 2
    RELEASE_DIR.mkdir(parents=True, exist_ok=True)
    if shutil.which("pyinstaller") is None:
        print("PyInstaller command not found; trying python -m PyInstaller.")
    cmd = _pyinstaller_command(onefile=True)
    print("Running PyInstaller one-file build...")
    proc = subprocess.run(cmd, cwd=ROOT)
    
    if proc.returncode != 0:
        print("One-file build failed; trying portable folder build...")
        cmd = _pyinstaller_command(onefile=False)
        proc = subprocess.run(cmd, cwd=ROOT)
        if proc.returncode != 0:
            print("PyInstaller build failed.")
            return proc.returncode

    # If build succeeded, package it into a neat release ZIP with accessories
    sys_name = platform.system().lower()
    machine = platform.machine().lower()
    if machine in {"amd64", "x86_64"}:
        machine = "x64"
    elif machine == "aarch64":
        machine = "arm64"
        
    ext = ".exe" if sys_name == "windows" else ""
    binary_path = RELEASE_DIR / f"NexLog{ext}"
    
    if not binary_path.exists():
        # Check if portable folder was built instead
        dist_dir = RELEASE_DIR / "NexLog"
        if dist_dir.exists() and dist_dir.is_dir():
            print(f"Portable folder built at {dist_dir}. Packaging folder...")
            zip_name = f"NexLog-v{VERSION}-{sys_name}-{machine}.zip"
            zip_path = RELEASE_DIR / zip_name
            with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                # Add portable folder contents
                for path in dist_dir.rglob("*"):
                    if path.is_file():
                        zf.write(path, Path("NexLog") / path.relative_to(dist_dir))
                # Add other resources
                for src_name in [".env.example", "README.md", "LICENSE"]:
                    src = ROOT / src_name
                    if src.exists():
                        zf.write(src, Path("NexLog") / src_name)
                # Add examples/logs
                examples_logs = ROOT / "examples" / "logs"
                if examples_logs.exists():
                    for path in examples_logs.rglob("*"):
                        if path.is_file():
                            zf.write(path, Path("NexLog") / "examples" / "logs" / path.relative_to(examples_logs))
            print(f"Created portable zip release at: {zip_path}")
            return 0
        else:
            print(f"Error: Could not locate built binary or directory at {binary_path}.", file=sys.stderr)
            return 1

    # Package one-file executable into a neat release ZIP
    zip_name = f"NexLog-v{VERSION}-{sys_name}-{machine}.zip"
    zip_path = RELEASE_DIR / zip_name
    print(f"Packaging executable and assets into {zip_name}...")
    
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # Add the binary
        zf.write(binary_path, Path("NexLog") / binary_path.name)
        # Add other resources
        for src_name in [".env.example", "README.md", "LICENSE"]:
            src = ROOT / src_name
            if src.exists():
                zf.write(src, Path("NexLog") / src_name)
        # Add examples/logs
        examples_logs = ROOT / "examples" / "logs"
        if examples_logs.exists():
            for path in examples_logs.rglob("*"):
                if path.is_file():
                    zf.write(path, Path("NexLog") / "examples" / "logs" / path.relative_to(examples_logs))
                    
    print(f"Created executable zip release at: {zip_path}")
    return 0



def run_release_check() -> int:
    return subprocess.run([sys.executable, "scripts/release_check.py"], cwd=ROOT).returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="Package NexLog releases.")
    parser.add_argument("--source-zip", action="store_true", help="Create clean source ZIP.")
    parser.add_argument("--binary", action="store_true", help="Build native PyInstaller binary for this OS.")
    parser.add_argument("--exe", action="store_true", help="Build Windows NexLog.exe; requires Windows.")
    parser.add_argument("--all", action="store_true", help="Run checks, build ZIP, and build native binary.")
    parser.add_argument("--skip-check", action="store_true", help="Do not run release_check before building.")
    args = parser.parse_args()

    if not any((args.source_zip, args.binary, args.exe, args.all)):
        parser.print_help()
        return 0
    if not args.skip_check and (args.all or args.binary or args.exe):
        rc = run_release_check()
        if rc != 0:
            return rc
    if args.source_zip or args.all:
        build_source_zip()
    if args.exe:
        return build_binary(exe_only=True)
    if args.binary or args.all:
        return build_binary(exe_only=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
