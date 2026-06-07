#!/usr/bin/env python3
"""Deep launch gate for NexLog GUI/backend release readiness."""

from __future__ import annotations

import argparse
import ast
import os
from pathlib import Path
import importlib.util
import subprocess
import sys
import tempfile
import time


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
    "release",
    "build",
    "dist",
    "node_modules",
}


def _env() -> dict[str, str]:
    env = os.environ.copy()
    env.setdefault("QT_QPA_PLATFORM", "offscreen")
    env.setdefault("QT_QUICK_BACKEND", "software")
    env.setdefault("QSG_RHI_BACKEND", "software")
    env.setdefault("NEXLOG_HARDWARE_MODE", "conservative")
    env.setdefault("NEXLOG_REDUCED_MOTION", "1")
    env.setdefault("NEXLOG_WORKSPACE_DIR", str(Path(tempfile.gettempdir()) / "nexlog-launch-check"))
    return env


def _run(name: str, cmd: list[str], timeout: int = 120) -> tuple[bool, str]:
    started = time.time()
    proc = subprocess.run(
        cmd,
        cwd=ROOT,
        env=_env(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    elapsed = time.time() - started
    output = proc.stdout.strip()
    ok = proc.returncode == 0
    print(f"{'OK' if ok else 'FAIL'}: {name} ({elapsed:.1f}s)")
    if not ok and output:
        print(output[-4000:])
    return ok, output


def check_ast() -> bool:
    failures: list[str] = []
    for path in ROOT.rglob("*.py"):
        rel = path.relative_to(ROOT)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        try:
            ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        except Exception as exc:
            failures.append(f"{rel}: {exc}")
    if failures:
        print("FAIL: syntax")
        for failure in failures[:25]:
            print(f"  - {failure}")
        return False
    print("OK: syntax")
    return True


def check_bridge_analysis() -> bool:
    script = r"""
import os
import time
from pathlib import Path
from PySide6.QtWidgets import QApplication
from nexlog.interface.gui.cyber_bridge import CyberBridge

app = QApplication.instance() or QApplication([])
workspace = Path(os.environ.get('NEXLOG_WORKSPACE_DIR', 'workspace'))
workspace.mkdir(parents=True, exist_ok=True)
case = workspace / 'launch_check_android.facase'
if case.exists():
    try:
        case.unlink()
    except PermissionError:
        case = workspace / f'launch_check_android_{int(time.time() * 1000)}.facase'
bridge = CyberBridge(str(case))
bridge.bootstrap()
bridge.analyseLog(str(Path('examples/logs/Android_2k.log').resolve()))
deadline = time.time() + 90
while bridge.busy and time.time() < deadline:
    app.processEvents()
    time.sleep(0.05)
app.processEvents()
if bridge.busy:
    raise SystemExit('analysis did not finish')
total = int(bridge.dashboardSnapshot().get('totalFindings') or 0)
rows = len(bridge.findingsSnapshot())
if total < 1 or rows < 1:
    raise SystemExit(f'analysis not visible in GUI snapshots: total={total} rows={rows}')
print(f'bridge analysis visible: total={total} rows={rows}')
"""
    return _run("bridge analysis smoke", [sys.executable, "-B", "-c", script], timeout=120)[0]


def check_zip_exclusions() -> bool:
    try:
        spec = importlib.util.spec_from_file_location("nexlog_package_release", ROOT / "scripts" / "package_release.py")
        if spec is None or spec.loader is None:
            raise RuntimeError("could not load scripts/package_release.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _skip = module._skip
    except Exception as exc:
        print(f"FAIL: source ZIP exclusion import ({exc})")
        return False
    forbidden = [
        ROOT / ".env",
        ROOT / "workspace" / "case.facase",
        ROOT / "website" / "node_modules" / "x.js",
        ROOT / "__pycache__" / "x.pyc",
        ROOT / "release" / "NexLog.zip",
        ROOT / "build" / "tmp",
    ]
    failures = [str(path.relative_to(ROOT)) for path in forbidden if not _skip(path)]
    if failures:
        print("FAIL: source ZIP exclusions")
        for failure in failures:
            print(f"  - not excluded: {failure}")
        return False
    print("OK: source ZIP exclusions")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Run NexLog professional launch gate checks.")
    parser.add_argument("--skip-tests", action="store_true", help="Skip pytest suites for a faster smoke run.")
    args = parser.parse_args()

    checks: list[bool] = []
    checks.append(check_ast())
    checks.append(_run("CLI help", [sys.executable, "-B", "main.py", "--help"], timeout=60)[0])
    checks.append(_run("GUI help", [sys.executable, "-B", "main_gui.py", "--help"], timeout=60)[0])
    checks.append(_run("GUI preflight", [sys.executable, "-B", "main_gui.py", "--preflight"], timeout=90)[0])
    checks.append(check_bridge_analysis())
    checks.append(check_zip_exclusions())
    if not args.skip_tests:
        checks.append(
            _run(
                "GUI unit tests",
                [sys.executable, "-B", "-m", "pytest", "tests/unit/test_layer5_gui.py", "-q", "-p", "no:cacheprovider"],
                timeout=180,
            )[0]
        )
        checks.append(
            _run(
                "security unit tests",
                [sys.executable, "-B", "-m", "pytest", "tests/unit/test_security.py", "-q", "-p", "no:cacheprovider"],
                timeout=180,
            )[0]
        )
        checks.append(
            _run(
                "AI unit tests",
                [sys.executable, "-B", "-m", "pytest", "tests/unit/test_ai.py", "-q", "-p", "no:cacheprovider"],
                timeout=240,
            )[0]
        )
    if all(checks):
        print("NexLog launch gate passed.")
        return 0
    print("NexLog launch gate failed.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
