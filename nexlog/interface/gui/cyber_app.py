"""NexLog animated QML desktop launcher."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import PySide6

if hasattr(os, "add_dll_directory"):
    _pyside_dir = Path(PySide6.__file__).resolve().parent
    for _dll_dir in (_pyside_dir, _pyside_dir / "plugins", _pyside_dir / "qml"):
        if _dll_dir.exists():
            os.add_dll_directory(str(_dll_dir))

from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QGuiApplication, QIcon
from PySide6.QtQml import QQmlApplicationEngine
from PySide6.QtQuick import QQuickWindow
from PySide6.QtWidgets import QApplication

from interface.gui.cyber_bridge import CyberBridge
from interface.gui.crash_guard import install_crash_logging, log_event
from pathconfig import ROOT_PATH
from utils.runtime_config import load_runtime_config


GUI_DIR = ROOT_PATH / "interface" / "gui"
ASSETS_DIR = GUI_DIR / "assets"
QML_DIR = GUI_DIR / "qml"
LOGO_PATH = ASSETS_DIR / "nexlog-logo.png"
ICON_PATH = ASSETS_DIR / "nexlog-icon.ico"
ICON_PNG_PATH = ASSETS_DIR / "nexlog-icon.png"


def _qt_application() -> QApplication:
    if QApplication.instance() is None:
        QGuiApplication.setHighDpiScaleFactorRoundingPolicy(
            Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
        )
    return QApplication.instance() or QApplication(sys.argv)


def app_icon() -> QIcon:
    icon = QIcon(str(ICON_PNG_PATH))
    if icon.isNull() and ICON_PATH.exists():
        icon = QIcon(str(ICON_PATH))
    return icon


def _load_qml_engine(bridge: CyberBridge) -> QQmlApplicationEngine:
    engine = QQmlApplicationEngine()
    engine.rootContext().setContextProperty("bridge", bridge)
    engine.rootContext().setContextProperty("appBridge", bridge)
    engine.rootContext().setContextProperty(
        "logoPath", QUrl.fromLocalFile(str(LOGO_PATH)).toString()
    )
    engine.rootContext().setContextProperty(
        "iconPath", QUrl.fromLocalFile(str(ICON_PNG_PATH)).toString()
    )
    engine.addImportPath(str(QML_DIR))
    main_qml = QML_DIR / "Main.qml"
    engine.load(QUrl.fromLocalFile(str(main_qml)))
    if not engine.rootObjects():
        raise RuntimeError(
            "QML interface failed to load. "
            f"Checked Main.qml at {main_qml}. "
            "Run `python -B main_gui.py --preflight` for diagnostics."
        )
    return engine


def preflight(case_db_path: str = "nexlog.facase", screen_smoke: bool = True) -> list[tuple[str, bool, str]]:
    """Run GUI launch checks without opening an interactive window."""
    install_crash_logging()
    checks: list[tuple[str, bool, str]] = []
    checks.append(("QML directory", QML_DIR.exists(), str(QML_DIR)))
    checks.append(("Main.qml", (QML_DIR / "Main.qml").exists(), str(QML_DIR / "Main.qml")))
    checks.append(("Logo", LOGO_PATH.exists(), str(LOGO_PATH)))
    checks.append(("Icon", ICON_PNG_PATH.exists() or ICON_PATH.exists(), str(ICON_PNG_PATH)))
    checks.append(
        (
            "Rules",
            (_rules := (ROOT_PATH / "detection" / "rules")).exists()
            and any(_rules.glob("*.yaml")),
            str(ROOT_PATH / "detection" / "rules"),
        )
    )
    try:
        runtime = load_runtime_config()
        runtime.apply_gui_environment()
        app = _qt_application()
        app.setApplicationName("NexLog")
        bridge = CyberBridge(case_db_path=case_db_path)
        engine = _load_qml_engine(bridge)
        bridge.bootstrap()
        dashboard = bridge.dashboardSnapshot()
        findings = bridge.findingsSnapshot()
        checks.append(("QML offscreen load", bool(engine.rootObjects()), str(QML_DIR / "Main.qml")))
        checks.append(("Bridge bootstrap", bool(dashboard), bridge.statusText))
        checks.append(("Dashboard snapshot", isinstance(dashboard, dict), f"{len(dashboard)} keys"))
        checks.append(("Findings snapshot", isinstance(findings, list), f"{len(findings)} rows"))
        if screen_smoke:
            root = engine.rootObjects()[0]
            for screen in ("dashboard", "findings", "timeline", "graph", "mitre", "ai", "tools"):
                root.setProperty("activeScreen", screen)
                bridge.setActiveScreen(screen)
                app.processEvents()
            checks.append(("QML screen smoke", True, "dashboard/findings/timeline/graph/mitre/ai/tools"))
        engine.deleteLater()
    except Exception as exc:
        checks.append(("QML/bridge preflight", False, str(exc)))
    return checks


def launch(case_db_path: str = "nexlog.facase") -> None:
    install_crash_logging()
    runtime = load_runtime_config()
    runtime.apply_gui_environment()
    log_event(
        "GUI_LAUNCH",
        case_db_path=case_db_path,
        hardware_mode=runtime.hardware_mode,
        gpu_gui=runtime.gpu_gui,
        qt_quick_backend=os.environ.get("QT_QUICK_BACKEND", ""),
        qsg_rhi_backend=os.environ.get("QSG_RHI_BACKEND", ""),
    )
    app = _qt_application()
    app.setApplicationName("NexLog")
    app.setApplicationDisplayName("NexLog")
    app.setApplicationVersion("1.0.0")
    QQuickWindow.setDefaultAlphaBuffer(True)

    icon = app_icon()
    if not icon.isNull():
        app.setWindowIcon(icon)

    bridge = CyberBridge(case_db_path=case_db_path)
    engine = _load_qml_engine(bridge)

    root = engine.rootObjects()[0]
    if hasattr(root, "setIcon") and not icon.isNull():
        root.setIcon(icon)

    bridge.bootstrap()
    sys.exit(app.exec())
