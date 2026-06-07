#!/usr/bin/env python3
"""Run a safe parameterized NexLog hunt query."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
from pathconfig import add_root

add_root()

from storage.case_db import CaseDB  # noqa: E402
from storage.hunt import hunt_findings  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Query NexLog findings using safe filters.")
    parser.add_argument("--case", default="workspace/nexlog.facase")
    parser.add_argument("--session-id", default="")
    parser.add_argument("--severity", default="")
    parser.add_argument("--min-severity", default="")
    parser.add_argument("--source-ip", default="")
    parser.add_argument("--hostname", default="")
    parser.add_argument("--username", default="")
    parser.add_argument("--category", default="")
    parser.add_argument("--rule-id", default="")
    parser.add_argument("--mitre-id", default="")
    parser.add_argument("--text", default="")
    parser.add_argument("--limit", type=int, default=100)
    args = parser.parse_args()

    filters = {k: v for k, v in vars(args).items() if k not in {"case", "limit"} and v}
    with CaseDB(args.case) as db:
        result = hunt_findings(db._conn, filters, limit=args.limit)
    print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
