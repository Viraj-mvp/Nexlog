#!/usr/bin/env python3
"""
Safe generated-artifact cleaner for NexLog.

Dry run:
    python scripts/clean_project.py

Apply cleanup:
    python scripts/clean_project.py --apply
"""

from __future__ import annotations

import argparse
import os
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

DIR_NAMES = {
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".dist",
    ".pytest-tmp-local",
    "build",
    "dist",
    "release",
    "workspace",
    "test.ai",
    "node_modules",
    "%SystemDrive%",
}

DIR_PREFIXES = (
    "pytest-cache-files-",
)

FILE_PATTERNS = {
    "*.pyc",
    "*.pyo",
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
    ".abuseipdb_cache.db",
    ".abuseipdb_cache.db-journal",
    ".abuseipdb_cache.db-wal",
    ".abuseipdb_cache.db-shm",
    ".nexlog_write_check*",
    "pytest_error.log",
    "pip_err.txt",
}

GENERATED_REPORT_PATTERNS = {
    "reports/**/*.pdf",
    "reports/**/*.json",
    "reports/**/*.md",
    "reports/**/*.txt",
    "reports/**/*.csv",
    "reports/**/*.stix",
    "nexlog/output/*.pdf",
    "nexlog/output/*.json",
    "nexlog/output/*.md",
    "nexlog/output/*.txt",
    "nexlog/output/*.csv",
    "nexlog/output/*.stix",
}

WORKSPACE_PATTERNS = {
    "pytest-tmp*",
    "test-security",
    "manual-security-check",
}

SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "env",
    "examples",
}


def _inside_root(path: Path) -> bool:
    try:
        path.resolve().relative_to(ROOT)
        return True
    except ValueError:
        return False


def _iter_targets(include_sensitive: bool = False) -> list[Path]:
    targets: set[Path] = set()

    for path in ROOT.rglob("*"):
        rel_parts = path.relative_to(ROOT).parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if path.is_dir() and (path.name in DIR_NAMES or any(path.name.startswith(prefix) for prefix in DIR_PREFIXES)):
            targets.add(path)

    for pattern in FILE_PATTERNS:
        targets.update(ROOT.glob(pattern))

    for pattern in GENERATED_REPORT_PATTERNS:
        targets.update(ROOT.glob(pattern))

    workspace = ROOT / "workspace"
    if workspace.exists():
        for pattern in WORKSPACE_PATTERNS:
            targets.update(workspace.glob(pattern))

    if include_sensitive:
        env_file = ROOT / ".env"
        if env_file.exists():
            targets.add(env_file)

    return sorted(
        (path for path in targets if path.exists() and _inside_root(path)),
        key=lambda p: (len(p.parts), str(p).lower()),
        reverse=True,
    )


def clean(apply: bool = False, include_sensitive: bool = False) -> int:
    targets = _iter_targets(include_sensitive=include_sensitive)
    action = "Removing" if apply else "Would remove"

    if not targets:
        print("No generated cleanup targets found.")
        return 0

    def _on_remove_error(func, path, exc_info):
        try:
            os.chmod(path, 0o700)
            func(path)
        except OSError as exc:
            print(f"  skipped: {exc}")

    removed = 0
    for path in targets:
        rel = path.relative_to(ROOT)
        print(f"{action}: {rel}")
        if not apply:
            continue
        try:
            if path.is_dir():
                shutil.rmtree(path, onerror=_on_remove_error)
            else:
                try:
                    os.chmod(path, 0o600)
                except OSError:
                    pass
                path.unlink()
            if not path.exists():
                removed += 1
        except OSError as exc:
            print(f"  skipped: {exc}")

    if apply:
        print(f"Removed {removed}/{len(targets)} generated targets.")
    else:
        print("Dry run only. Re-run with --apply to delete these files.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Safely clean generated NexLog artifacts.")
    parser.add_argument("--apply", action="store_true", help="Actually delete generated files.")
    parser.add_argument(
        "--include-sensitive",
        action="store_true",
        help="Also remove local .env. This is off by default.",
    )
    args = parser.parse_args()
    return clean(apply=args.apply, include_sensitive=args.include_sensitive)


if __name__ == "__main__":
    raise SystemExit(main())
