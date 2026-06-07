"""Qt imports with an explicit lightweight test stub mode.

Set ``NEXLOG_GUI_STUBS=1`` for logic tests that exercise the QML bridge
without loading native PySide6 display libraries.
"""

from __future__ import annotations

import os
from typing import Any, Callable


_USE_STUBS = os.environ.get("NEXLOG_GUI_STUBS", "").strip().lower() in {"1", "true", "yes", "on"}


if not _USE_STUBS:
    try:
        from PySide6.QtCore import QObject, Property, QThread, Qt, Signal, Slot, qInstallMessageHandler
        from PySide6.QtGui import QGuiApplication
        from PySide6.QtWidgets import QApplication, QFileDialog, QWidget
    except ImportError as exc:  # pragma: no cover - depends on host GUI runtime
        raise RuntimeError(
            "PySide6 is required for the NexLog desktop GUI. "
            "Set NEXLOG_GUI_STUBS=1 only for headless bridge tests."
        ) from exc
else:

    class _BoundSignal:
        def __init__(self) -> None:
            self._callbacks: list[Callable[..., Any]] = []

        def connect(self, callback: Callable[..., Any]) -> None:
            self._callbacks.append(callback)

        def emit(self, *args: Any, **kwargs: Any) -> None:
            for callback in list(self._callbacks):
                callback(*args, **kwargs)


    class Signal:
        def __init__(self, *signature: Any, **kwargs: Any) -> None:
            del signature, kwargs
            self._storage_name = ""
            self._class_signal = _BoundSignal()

        def __set_name__(self, owner: type, name: str) -> None:
            self._storage_name = f"__qt_stub_signal_{name}"

        def __get__(self, instance: Any, owner: type | None = None) -> _BoundSignal:
            del owner
            if instance is None or not self._storage_name:
                return self._class_signal
            signal = instance.__dict__.get(self._storage_name)
            if signal is None:
                signal = _BoundSignal()
                instance.__dict__[self._storage_name] = signal
            return signal


    def Slot(*signature: Any, **kwargs: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        del signature, kwargs

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            return func

        return decorator


    def Property(type_: Any = None, fget: Callable[..., Any] | None = None, **kwargs: Any) -> property:
        del type_, kwargs
        if fget is not None:
            return property(fget)

        def decorator(func: Callable[..., Any]) -> property:
            return property(func)

        return decorator  # type: ignore[return-value]


    class QObject:
        def __init__(self, parent: Any | None = None) -> None:
            self._qt_parent = parent

        def deleteLater(self) -> None:
            return None


    class QThread(QObject):
        def start(self) -> None:
            self.run()

        def run(self) -> None:
            return None

        def isInterruptionRequested(self) -> bool:
            return False

        def requestInterruption(self) -> None:
            return None


    class QGuiApplication:
        @staticmethod
        def clipboard() -> Any | None:
            return None


    class QWidget:
        pass


    class QApplication:
        @staticmethod
        def instance() -> Any | None:
            return None


    class QFileDialog:
        class Option(int):
            DontUseNativeDialog = 1

        @staticmethod
        def getOpenFileNames(*args: Any, **kwargs: Any) -> tuple[list[str], str]:
            del args, kwargs
            return [], ""

        @staticmethod
        def getOpenFileName(*args: Any, **kwargs: Any) -> tuple[str, str]:
            del args, kwargs
            return "", ""

        @staticmethod
        def getSaveFileName(*args: Any, **kwargs: Any) -> tuple[str, str]:
            del args, kwargs
            return "", ""

        @staticmethod
        def getExistingDirectory(*args: Any, **kwargs: Any) -> str:
            del args, kwargs
            return ""


    class Qt:
        pass


    def qInstallMessageHandler(handler: Callable[..., Any] | None) -> Callable[..., Any] | None:
        del handler
        return None
