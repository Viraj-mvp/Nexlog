# -*- coding: utf-8 -*-
"""
NexLog PyInstaller runtime hook.

Executed before the main script in frozen (PyInstaller) builds.
Sets up Qt plugin paths, asset directories, and platform overrides
so that both the GUI and CLI binaries find their bundled resources.
"""

import os
import sys

if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    _MEIPASS = sys._MEIPASS

    # ── Qt plugin and QML paths ────────────────────────────────────────
    _qt_plugins = os.path.join(_MEIPASS, "PySide6", "Qt", "plugins")
    if os.path.isdir(_qt_plugins):
        os.environ["QT_PLUGIN_PATH"] = _qt_plugins

    _qml_dir = os.path.join(_MEIPASS, "PySide6", "Qt", "qml")
    if os.path.isdir(_qml_dir):
        os.environ["QML2_IMPORT_PATH"] = _qml_dir

    # ── Bundled asset directories ──────────────────────────────────────
    _rules_dir = os.path.join(_MEIPASS, "nexlog", "detection", "rules")
    if os.path.isdir(_rules_dir):
        os.environ["NEXLOG_RULES_DIR"] = _rules_dir

    _assets_dir = os.path.join(_MEIPASS, "nexlog", "interface", "gui", "assets")
    if os.path.isdir(_assets_dir):
        os.environ["NEXLOG_ASSETS_DIR"] = _assets_dir

    _qml_app_dir = os.path.join(_MEIPASS, "nexlog", "interface", "gui", "qml")
    if os.path.isdir(_qml_app_dir):
        os.environ["NEXLOG_QML_DIR"] = _qml_app_dir

    # ── Platform-specific Qt backend ───────────────────────────────────
    if sys.platform == "win32":
        # Never force offscreen on Windows — let Qt auto-detect the
        # native 'windows' platform plugin for end-user machines.
        pass
    elif sys.platform.startswith("linux"):
        # Only force offscreen when genuinely headless (CI runners).
        # End-user Linux desktops have DISPLAY or WAYLAND_DISPLAY set.
        if "DISPLAY" not in os.environ and "WAYLAND_DISPLAY" not in os.environ:
            os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
