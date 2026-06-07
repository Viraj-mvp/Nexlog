#!/usr/bin/env python3
"""Run NexLog rule test manifests."""

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

from rule_tester import RuleTestHarness  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Run NexLog rule tests from a manifest.")
    parser.add_argument("manifest", help="YAML or JSON rule-test manifest.")
    parser.add_argument("--rules-dir", default="", help="Optional rules directory.")
    args = parser.parse_args()

    harness = RuleTestHarness(args.rules_dir or None)
    result = harness.run_manifest_file(args.manifest)
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
