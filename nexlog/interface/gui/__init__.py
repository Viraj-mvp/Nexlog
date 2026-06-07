"""Active NexLog desktop GUI package.

The production desktop app is QML-only. The previous PySide6 Widgets GUI is
archived under ``docs/archive/legacy-widgets-gui`` for reference and is not
imported by runtime package initialization.
"""

from .cyber_app import launch
from .cyber_bridge import CyberBridge

__all__ = ["CyberBridge", "launch"]
