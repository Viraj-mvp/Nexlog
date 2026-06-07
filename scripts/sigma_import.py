#!/usr/bin/env python3
"""Convert Sigma YAML into NexLog rule YAML."""

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

from sigma_importer import SigmaImporter  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Import a safe Sigma subset as NexLog YAML.")
    parser.add_argument("sigma_file", help="Sigma YAML file to import.")
    parser.add_argument("--output", "-o", help="Optional output NexLog YAML file.")
    parser.add_argument("--json", action="store_true", help="Print structured JSON result.")
    args = parser.parse_args()

    importer = SigmaImporter()
    result = importer.from_file(args.sigma_file)
    if args.output and result.ok:
        Path(args.output).write_text(importer.to_yaml(result), encoding="utf-8")
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(importer.to_yaml(result) if result.ok else "\n".join(result.errors))
        if result.warnings:
            print("# Warnings:")
            for warning in result.warnings:
                print(f"# - {warning}")
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
