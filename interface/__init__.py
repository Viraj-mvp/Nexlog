"""Compatibility namespace for ``python -m interface...`` commands."""

from __future__ import annotations

from pathlib import Path

_REAL_INTERFACE = Path(__file__).resolve().parents[1] / "nexlog" / "interface"
__path__ = [str(_REAL_INTERFACE)]
