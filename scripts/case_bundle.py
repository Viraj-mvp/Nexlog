#!/usr/bin/env python3
"""Export a NexLog .nexlogcase bundle."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
from pathconfig import WORKSPACE_DIR, add_root

add_root()

from output.case_bundle import CaseBundleExporter  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Export a portable NexLog case bundle.")
    parser.add_argument("--case", default=str(Path(WORKSPACE_DIR) / "nexlog.facase"))
    parser.add_argument("--output", default=str(Path(WORKSPACE_DIR) / "case_bundle.nexlogcase"))
    parser.add_argument("--session-id", default="")
    parser.add_argument("--no-db", action="store_true", help="Do not include the SQLite case DB file.")
    args = parser.parse_args()

    result = CaseBundleExporter(args.case).export(
        args.output,
        session_id=args.session_id or None,
        include_db=not args.no_db,
    )
    print(json.dumps(result, indent=2, default=str))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
