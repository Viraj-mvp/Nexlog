#!/usr/bin/env python3
"""Release readiness checks for NexLog."""

from __future__ import annotations

import ast
import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]

SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "workspace",
    "build",
    "dist",
    "release",
    "node_modules",
}

GENERATED_DIR_PREFIXES = (
    "pytest-cache-files-",
)

REQUIRED_IMPORTS = {
    "yaml": "pyyaml",
    "defusedxml": "defusedxml",
    "ijson": "ijson",
    "Evtx": "python-evtx",
    "PySide6": "PySide6",
    "reportlab": "reportlab",
    "fastapi": "fastapi",
    "uvicorn": "uvicorn",
    "PyInstaller": "pyinstaller",
}

GENERATED_PATTERNS = [
    ".env",
    ".abuseipdb_cache.db*",
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
    "pytest_error.log",
    "pip_err.txt",
]

SECRET_PATTERNS = [
    "9544594b" + "a4a33e34" + "b45d8769" + "6342129b54d3076f61cb14a3d098c7b4a6bb428e616421470054aa3f",
    "BEGIN " + "PRIVATE KEY",
    "BEGIN " + "RSA PRIVATE KEY",
]

STALE_BRANDING_PATTERNS = [
    "Forensic-Amp",
    "Forensic Amp",
    "FORENSIC_AMP",
    "forensic_amp",
    "forensic-amp",
    "ForensicAmp",
    "forensicamp",
]

PUBLIC_DOCS = [
    "README.md",
    "docs/roadmap.md",
    "docs/security.md",
    "docs/setup.md",
    "docs/quick-setup.md",
    "docs/changelog.md",
    "docs/legal/privacy.md",
    "docs/legal/terms.md",
    "docs/legal/third-party-notices.md",
    "CONTRIBUTING.md",
]


def _skip(path: Path) -> bool:
    rel_parts = path.relative_to(ROOT).parts
    return any(part in SKIP_DIRS for part in rel_parts) or any(
        part.startswith(prefix) for part in rel_parts for prefix in GENERATED_DIR_PREFIXES
    )


def _is_startup_cache(path: Path) -> bool:
    if path.name != "__pycache__" or not path.is_dir():
        return False
    files = [child for child in path.iterdir() if child.is_file()]
    if not files:
        return False
    return all(child.name.startswith("sitecustomize.") and ".pyc" in child.name for child in files)


def _run(cmd: list[str]) -> tuple[bool, str]:
    env = os.environ.copy()
    env.setdefault(
        "NEXLOG_WORKSPACE_DIR",
        str(Path(tempfile.gettempdir()) / "nexlog-release-check-workspace"),
    )
    proc = subprocess.run(
        cmd,
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=120,
    )
    return proc.returncode == 0, proc.stdout.strip()


def check_imports() -> list[str]:
    failures: list[str] = []
    for module, package in REQUIRED_IMPORTS.items():
        if importlib.util.find_spec(module) is None:
            failures.append(f"Missing package {package} (import {module})")
    return failures


def check_ast() -> list[str]:
    failures: list[str] = []
    for path in ROOT.rglob("*.py"):
        if _skip(path):
            continue
        try:
            ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        except Exception as exc:
            failures.append(f"Syntax error in {path.relative_to(ROOT)}: {exc}")
    return failures


def check_generated(allow_local_env: bool = False) -> list[str]:
    failures: list[str] = []
    for pattern in GENERATED_PATTERNS:
        if allow_local_env and pattern == ".env":
            continue
        for path in ROOT.glob(pattern):
            if path.exists() and not _skip(path):
                failures.append(f"Generated/local artifact present: {path.relative_to(ROOT)}")
    for name in ("__pycache__", ".pytest_cache", ".ruff_cache", "workspace", "node_modules"):
        for path in ROOT.rglob(name):
            if path.exists() and not _skip(path.parent):
                if _is_startup_cache(path):
                    continue
                failures.append(f"Generated directory present: {path.relative_to(ROOT)}")
    for path in ROOT.rglob("*"):
        if path.is_dir() and any(path.name.startswith(prefix) for prefix in GENERATED_DIR_PREFIXES):
            if not _skip(path.parent):
                failures.append(f"Generated directory present: {path.relative_to(ROOT)}")
    return sorted(set(failures))


def check_branding() -> list[str]:
    failures: list[str] = []
    for rel in PUBLIC_DOCS:
        path = ROOT / rel
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for pattern in STALE_BRANDING_PATTERNS:
            if pattern in text:
                failures.append(f"Stale public branding in {rel}: {pattern}")
                break
    return failures


def check_secrets() -> list[str]:
    failures: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or _skip(path):
            continue
        if path.suffix.lower() not in {".py", ".qml", ".md", ".txt", ".yml", ".yaml", ".json", ".env", ".example"}:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for pattern in SECRET_PATTERNS:
            if pattern in text:
                failures.append(f"Secret-like pattern in {path.relative_to(ROOT)}")
    return failures


def check_package_exclusions() -> list[str]:
    failures: list[str] = []
    try:
        spec = importlib.util.spec_from_file_location("nexlog_package_release", ROOT / "scripts" / "package_release.py")
        if spec is None or spec.loader is None:
            raise RuntimeError("could not load scripts/package_release.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        package_skip = module._skip
    except Exception as exc:
        return [f"Could not load package exclusion rules: {exc}"]

    forbidden = [
        ROOT / ".env",
        ROOT / ".venv" / "pyvenv.cfg",
        ROOT / "workspace" / "case.facase",
        ROOT / "nexlog" / "workspace" / "case.facase",
        ROOT / "release" / "NexLog.zip",
        ROOT / "website" / "node_modules" / "vite" / "index.js",
        ROOT / "__pycache__" / "main.cpython-312.pyc",
        ROOT / "nexlog" / "core" / "__pycache__" / "models.cpython-312.pyc",
        ROOT / "case.facase",
        ROOT / "vectors.db",
    ]
    for path in forbidden:
        if not package_skip(path):
            failures.append(f"Package exclusion missing: {path.relative_to(ROOT)}")
    return failures


def check_smoke() -> list[str]:
    commands = [
        [sys.executable, "-B", "main.py", "--help"],
        [sys.executable, "-B", "main_gui.py", "--help"],
        [sys.executable, "-B", "main_gui.py", "--packaged-check"],
        [sys.executable, "-B", "-m", "interface.web.serve", "--help"],
    ]
    failures: list[str] = []
    for cmd in commands:
        ok, output = _run(cmd)
        if not ok:
            failures.append(f"Command failed: {' '.join(cmd)}\n{output}")
    return failures


def check_launch_deep() -> list[str]:
    ok, output = _run([sys.executable, "-B", "scripts/launch_check.py"])
    return [] if ok else [f"Deep launch gate failed:\n{output}"]


def main() -> int:
    parser = argparse.ArgumentParser(description="Release readiness checks for NexLog.")
    parser.add_argument(
        "--allow-local-env",
        action="store_true",
        help="Allow a local .env during development checks. Release/package builds should not use this.",
    )
    parser.add_argument(
        "--launch-deep",
        action="store_true",
        help="Also run scripts/launch_check.py for full GUI/backend launch smoke verification.",
    )
    args = parser.parse_args()
    checks = [
        ("imports", check_imports),
        ("syntax", check_ast),
        ("generated artifacts", lambda: check_generated(allow_local_env=args.allow_local_env)),
        ("public branding", check_branding),
        ("secrets", check_secrets),
        ("package exclusions", check_package_exclusions),
        ("smoke commands", check_smoke),
    ]
    if args.launch_deep:
        checks.append(("deep launch gate", check_launch_deep))
    failed: list[str] = []
    for name, fn in checks:
        issues = fn()
        if issues:
            print(f"FAIL: {name} ({len(issues)})")
            for issue in issues[:25]:
                print(f"  - {issue}")
            failed.extend(issues)
        else:
            print(f"OK: {name}")
    if failed:
        print(f"Release check failed with {len(failed)} issue(s).")
        return 1
    print("Release check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
