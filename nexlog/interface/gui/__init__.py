"""Active NexLog desktop GUI package.

The production desktop app is QML-only. The previous PySide6 Widgets GUI is
archived under ``docs/archive/legacy-widgets-gui`` for reference and is not
imported by runtime package initialization.
"""

from .cyber_bridge import CyberBridge


def launch(*args, **kwargs):
    """Launch the real QML desktop app, importing QtQuick only on demand."""
    from .cyber_app import launch as _launch

    return _launch(*args, **kwargs)


__all__ = ["CyberBridge", "launch"]
