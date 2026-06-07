"""GUI stability helpers for NexLog.

These helpers keep risky native UI actions and Qt diagnostics in one place so
QML slots can fail closed instead of taking the whole app down.
"""

from __future__ import annotations

import os
import sys
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable, TypeVar

from .qt_compat import QApplication, QFileDialog, Qt, QWidget, qInstallMessageHandler

try:
    from pathconfig import WORKSPACE_DIR
except Exception:  # pragma: no cover - startup fallback only
    WORKSPACE_DIR = str(Path(__file__).resolve().parents[3] / "workspace")

_LOG_DIR = Path(WORKSPACE_DIR) / "logs"
_LOG_PATH = _LOG_DIR / "nexlog_gui.log"
_MESSAGE_HANDLER_INSTALLED = False
_T = TypeVar("_T")


def log_event(message: str, **fields: Any) -> None:
    """Append a compact GUI diagnostic line."""
    try:
        _LOG_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().isoformat(timespec="seconds")
        detail = " ".join(f"{key}={value!r}" for key, value in fields.items())
        line = f"{stamp} {message}"
        if detail:
            line += f" | {detail}"
        _LOG_PATH.open("a", encoding="utf-8").write(line + "\n")
    except Exception:
        pass


def install_crash_logging() -> None:
    """Install Python and Qt message logging once per process."""
    global _MESSAGE_HANDLER_INSTALLED

    def excepthook(exc_type: type[BaseException], exc: BaseException, tb: Any) -> None:
        log_event(
            "UNHANDLED_EXCEPTION",
            error=f"{exc_type.__name__}: {exc}",
            traceback="".join(traceback.format_exception(exc_type, exc, tb))[-6000:],
        )
        sys.__excepthook__(exc_type, exc, tb)

    sys.excepthook = excepthook
    if _MESSAGE_HANDLER_INSTALLED:
        return

    def qt_message_handler(mode: QtMsgTypeLike, context: Any, message: str) -> None:
        try:
            log_event(
                "QT_MESSAGE",
                level=str(mode),
                file=getattr(context, "file", "") or "",
                line=getattr(context, "line", 0) or 0,
                message=message,
            )
        except Exception:
            pass

    qInstallMessageHandler(qt_message_handler)
    _MESSAGE_HANDLER_INSTALLED = True


QtMsgTypeLike = Any


def active_parent_widget() -> QWidget | None:
    app = QApplication.instance()
    if app is None:
        return None
    widget = app.activeModalWidget() or app.activeWindow()
    return widget if isinstance(widget, QWidget) else None


def dialog_options() -> QFileDialog.Option:
    """Use safer Qt dialogs on Windows unless explicitly disabled."""
    use_native = os.environ.get("NEXLOG_NATIVE_DIALOGS", "").strip().lower() in {"1", "true", "yes", "on"}
    if os.name == "nt" and not use_native:
        return QFileDialog.Option.DontUseNativeDialog
    return QFileDialog.Option(0)


def clean_stale_write_checks(workspace: str | Path = WORKSPACE_DIR) -> int:
    """Remove old write probes left by interrupted launch checks."""
    count = 0
    try:
        root = Path(workspace)
        for probe in root.glob(".nexlog_write_check*"):
            try:
                probe.unlink()
                count += 1
            except OSError:
                pass
    except Exception:
        pass
    return count


def safe_slot(action: str, fallback: _T, callback: Callable[[], _T]) -> _T:
    """Run a GUI action with logging and a safe fallback."""
    log_event("ACTION_START", action=action)
    try:
        result = callback()
        log_event("ACTION_OK", action=action)
        return result
    except Exception as exc:
        log_event(
            "ACTION_FAILED",
            action=action,
            error=str(exc),
            traceback=traceback.format_exc()[-4000:],
        )
        return fallback


def get_open_file_names(title: str, directory: str, file_filter: str) -> list[str]:
    paths, _ = QFileDialog.getOpenFileNames(
        active_parent_widget(),
        title,
        directory,
        file_filter,
        options=dialog_options(),
    )
    return list(paths or [])


def get_open_file_name(title: str, directory: str, file_filter: str) -> str:
    path, _ = QFileDialog.getOpenFileName(
        active_parent_widget(),
        title,
        directory,
        file_filter,
        options=dialog_options(),
    )
    return str(path or "")


def get_save_file_name(title: str, default_path: str, file_filter: str) -> str:
    path, _ = QFileDialog.getSaveFileName(
        active_parent_widget(),
        title,
        default_path,
        file_filter,
        options=dialog_options(),
    )
    return str(path or "")


def get_existing_directory(title: str, directory: str) -> str:
    return str(
        QFileDialog.getExistingDirectory(
            active_parent_widget(),
            title,
            directory,
            options=dialog_options(),
        )
        or ""
    )


def validate_log_paths(paths: Iterable[str], max_line_bytes: int) -> tuple[list[str], list[str]]:
    """Validate selected evidence without reading full files."""
    valid: list[str] = []
    errors: list[str] = []
    allowed = {
        ".log",
        ".txt",
        ".json",
        ".jsonl",
        ".evtx",
        ".csv",
        ".xml",
        ".gz",
        ".zip",
    }
    for raw in paths:
        try:
            path = Path(raw).expanduser()
            if not path.exists():
                errors.append(f"Missing: {raw}")
                continue
            if path.is_dir():
                errors.append(f"Directory skipped: {raw}")
                continue
            if path.suffix.lower() not in allowed:
                log_event("LOG_EXTENSION_WARNING", path=str(path), suffix=path.suffix)
            with path.open("rb") as fh:
                sample = fh.readline(max_line_bytes + 1)
                if len(sample) > max_line_bytes:
                    errors.append(f"Line too large for current safety limit: {path.name}")
                    continue
            valid.append(str(path))
        except Exception as exc:
            errors.append(f"{raw}: {exc}")
    return valid, errors
