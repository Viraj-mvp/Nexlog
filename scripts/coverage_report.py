#!/usr/bin/env python3
"""Print NexLog rule coverage and maturity report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
from pathconfig import ROOT, add_root

add_root()

from rule_coverage import RuleCoverage  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate NexLog rule coverage report.")
    parser.add_argument("--rules-dir", default=str(Path(ROOT) / "detection" / "rules"))
    parser.add_argument("--output", "-o", help="Optional JSON output path.")
    args = parser.parse_args()

    report = RuleCoverage(args.rules_dir).build()
    text = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
