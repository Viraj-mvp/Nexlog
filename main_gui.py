#!/usr/bin/env python3
"""
NexLog desktop GUI launcher.

Usage:
    python main_gui.py
    python main_gui.py --case workspace/nexlog.facase
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from pathconfig import ROOT_PATH, WORKSPACE_DIR, add_root, load_env_profile

load_env_profile("gui")


def _workspace_writable(path: Path) -> tuple[bool, str]:
    try:
        path.mkdir(parents=True, exist_ok=True)
        try:
            from interface.gui.crash_guard import clean_stale_write_checks

            clean_stale_write_checks(path)
        except Exception:
            pass
        probe = path / f".nexlog_write_check_{os.getpid()}"
        probe.write_text("ok", encoding="utf-8")
        try:
            probe.unlink(missing_ok=True)
        except OSError:
            pass
        return True, str(path)
    except OSError as exc:
        return False, f"{path}: {exc}"


def _case_openable(case_path: Path) -> tuple[bool, str]:
    try:
        from storage.case_db import CaseDB

        case_path.parent.mkdir(parents=True, exist_ok=True)
        with CaseDB(str(case_path)) as db:
            db.get_findings_summary()
        return True, str(case_path)
    except Exception as exc:
        return False, f"{case_path}: {exc}"


def packaged_check(case_path: Path | None = None) -> int:
    """Verify bundled GUI/runtime resources without opening an interactive window."""
    add_root()
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    os.environ.setdefault("QT_QUICK_BACKEND", "software")
    os.environ.setdefault("QSG_RHI_BACKEND", "software")
    os.environ.setdefault("NEXLOG_HARDWARE_MODE", "conservative")
    os.environ.setdefault("NEXLOG_REDUCED_MOTION", "1")
    checks: list[tuple[str, bool, str]] = []

    try:
        from interface.gui.cyber_app import ICON_PNG_PATH, LOGO_PATH, QML_DIR, preflight
    except Exception as exc:
        print(f"FAIL import GUI launcher: {exc}", file=sys.stderr)
        return 1

    checks.append(("QML directory", QML_DIR.exists(), str(QML_DIR)))
    checks.append(("Main.qml", (QML_DIR / "Main.qml").exists(), str(QML_DIR / "Main.qml")))
    checks.append(("Logo", LOGO_PATH.exists(), str(LOGO_PATH)))
    checks.append(("Icon", ICON_PNG_PATH.exists(), str(ICON_PNG_PATH)))
    rules_dir = ROOT_PATH / "detection" / "rules"
    checks.append(("Rules", rules_dir.exists() and any(rules_dir.glob("*.yaml")), str(rules_dir)))

    workspace_ok, workspace_detail = _workspace_writable(Path(WORKSPACE_DIR))
    checks.append(("Workspace writable", workspace_ok, workspace_detail))

    resolved_case = case_path or (Path(WORKSPACE_DIR) / "nexlog.facase")
    case_ok, case_detail = _case_openable(resolved_case)
    checks.append(("Case database openable", case_ok, case_detail))

    try:
        from main import analyse  # noqa: F401
        from storage.case_db import CaseDB  # noqa: F401
        from detection.rule_engine import RuleEngine  # noqa: F401

        imports_ok = True
        import_msg = "core imports"
    except Exception as exc:
        imports_ok = False
        import_msg = str(exc)
    checks.append(("Core imports", imports_ok, import_msg))
    if case_ok:
        checks.extend(preflight(case_db_path=str(resolved_case), screen_smoke=True))

    failed = 0
    for name, ok, detail in checks:
        status = "OK" if ok else "FAIL"
        print(f"{status}: {name} - {detail}")
        failed += 0 if ok else 1
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="NexLog desktop GUI"
    )
    parser.add_argument("--case", default="", help="Open a specific .facase database")
    parser.add_argument(
        "--hardware-mode",
        choices=["adaptive", "performance", "conservative"],
        default=None,
        help="GUI/runtime hardware profile override",
    )
    parser.add_argument(
        "--safe-mode",
        action="store_true",
        help="Launch with conservative software rendering and reduced motion",
    )
    parser.add_argument(
        "--packaged-check",
        action="store_true",
        help="Verify bundled QML/assets/rules/imports without opening the GUI",
    )
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="Run full launch preflight, including offscreen QML and bridge smoke checks",
    )
    parser.add_argument(
        "--_gui-child",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args()

    add_root()
    if args.safe_mode:
        os.environ["NEXLOG_HARDWARE_MODE"] = "conservative"
        os.environ["NEXLOG_GPU_GUI"] = "off"
        os.environ["NEXLOG_REDUCED_MOTION"] = "1"
        os.environ.setdefault("QT_QUICK_BACKEND", "software")
        os.environ.setdefault("QSG_RHI_BACKEND", "software")
    if args.hardware_mode:
        os.environ["NEXLOG_HARDWARE_MODE"] = args.hardware_mode
    try:
        from utils.runtime_config import load_runtime_config

        load_runtime_config().apply_gui_environment()
    except Exception:
        pass
    case_path = Path(args.case) if args.case else Path(WORKSPACE_DIR) / "nexlog.facase"
    if not case_path.is_absolute():
        case_path = Path(WORKSPACE_DIR) / case_path
    try:
        case_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print(f"ERROR: Could not create case directory: {case_path.parent}", file=sys.stderr)
        print(f"DETAIL: {exc}", file=sys.stderr)
        return 1

    if args.packaged_check or args.preflight:
        return packaged_check(case_path)

    if not args._gui_child:
        base_cmd = [sys.executable, "-B", str(Path(__file__).resolve()), "--_gui-child", "--case", str(case_path)]
        if args.hardware_mode:
            base_cmd.extend(["--hardware-mode", args.hardware_mode])
        if args.safe_mode:
            base_cmd.append("--safe-mode")
        first = subprocess.run(base_cmd, cwd=str(_ROOT), check=False)
        if first.returncode == 0:
            return 0

        print(
            f"WARNING: QML GUI exited unexpectedly with code {first.returncode}. Retrying safe mode...",
            file=sys.stderr,
        )
        safe_cmd = [sys.executable, "-B", str(Path(__file__).resolve()), "--_gui-child", "--safe-mode", "--case", str(case_path)]
        safe = subprocess.run(safe_cmd, cwd=str(_ROOT), check=False)
        if safe.returncode == 0:
            return 0

        print(
            f"ERROR: Safe QML GUI exited unexpectedly with code {safe.returncode}.",
            file=sys.stderr,
        )
        print("Run `python -B main_gui.py --preflight` for diagnostics.", file=sys.stderr)
        return safe.returncode or 1

    try:
        from interface.gui.cyber_app import launch
    except ImportError as exc:
        print(f"ERROR: Could not import GUI: {exc}", file=sys.stderr)
        print("Install GUI dependencies with: pip install PySide6", file=sys.stderr)
        return 1

    try:
        launch(case_db_path=str(case_path))
    except SystemExit as exc:
        code = int(exc.code or 0)
        if code == 0:
            return 0
        print(f"WARNING: QML GUI exited during startup with code {code}. Retrying safely...", file=sys.stderr)
    except Exception as exc:
        print(f"WARNING: QML GUI failed to start: {exc}", file=sys.stderr)

    print("INFO: Retrying QML in conservative software-rendering mode.", file=sys.stderr)
    os.environ["NEXLOG_HARDWARE_MODE"] = "conservative"
    os.environ["NEXLOG_REDUCED_MOTION"] = "1"
    os.environ.setdefault("QT_QUICK_BACKEND", "software")
    os.environ.setdefault("QSG_RHI_BACKEND", "software")
    try:
        from interface.gui.cyber_app import launch as safe_launch

        safe_launch(case_db_path=str(case_path))
    except SystemExit as exc:
        code = int(exc.code or 0)
        if code == 0:
            return 0
        print(f"WARNING: Conservative QML launch exited with code {code}.", file=sys.stderr)
    except Exception as exc:
        print(f"WARNING: Conservative QML launch failed: {exc}", file=sys.stderr)

    print("ERROR: QML GUI could not start. Run `python -B main_gui.py --preflight` for diagnostics.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
