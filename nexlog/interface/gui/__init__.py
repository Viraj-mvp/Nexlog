"""Active NexLog desktop GUI package.

The production desktop app is QML-only. Retired PySide6 Widgets modules are
kept out of the runtime package and public source tree.
"""

from .cyber_bridge import CyberBridge


def launch(*args, **kwargs):
    """Launch the real QML desktop app, importing QtQuick only on demand."""
    from .cyber_app import launch as _launch

    return _launch(*args, **kwargs)


__all__ = ["CyberBridge", "launch"]
