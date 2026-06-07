"""Keep legacy top-level imports working after moving source into nexlog/."""

from __future__ import annotations

from pathlib import Path
import sys

sys.dont_write_bytecode = True

_ROOT = Path(__file__).resolve().parent
_APP_ROOT = _ROOT / "nexlog"
if _APP_ROOT.exists() and str(_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(_APP_ROOT))
