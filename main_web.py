#!/usr/bin/env python3
"""
NexLog web cockpit launcher.

Usage:
    python main_web.py [options]
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from pathconfig import ROOT_PATH, add_root, load_env_profile

load_env_profile("web")


def main() -> int:
    try:
        from interface.web.serve import _cli_main
    except ImportError as exc:
        print(f"ERROR: Could not import web server: {exc}", file=sys.stderr)
        return 1

    try:
        _cli_main()
        return 0
    except SystemExit as exc:
        return int(exc.code or 0)
    except Exception as exc:
        print(f"ERROR: Web server failed to start: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
