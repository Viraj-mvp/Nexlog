#!/usr/bin/env python3
"""Generate or install a NexLog web/API key."""

from __future__ import annotations

import argparse
import secrets
from pathlib import Path


def generate_key(length: int = 48) -> str:
    return "nxl_" + secrets.token_urlsafe(max(32, int(length)))[:max(32, int(length))]


def write_env(path: Path, key: str, *, force: bool = False) -> bool:
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    lines = existing.splitlines()
    out = []
    replaced = False
    for line in lines:
        if line.startswith("NEXLOG_API_KEY=") or line.startswith("NEXLOG_WEB_API_KEY="):
            if not force:
                out.append(line)
                continue
            out.append(f"NEXLOG_WEB_API_KEY={key}")
            replaced = True
        else:
            out.append(line)
    if not replaced and not any(line.startswith("NEXLOG_WEB_API_KEY=") for line in out):
        if out and out[-1].strip():
            out.append("")
        out.append(f"NEXLOG_WEB_API_KEY={key}")
    path.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a NexLog API key.")
    parser.add_argument("--length", type=int, default=48, help="Token entropy length, default 48.")
    parser.add_argument("--print", action="store_true", dest="print_key", help="Print the generated key.")
    parser.add_argument("--write-env-web", action="store_true", help="Write NEXLOG_WEB_API_KEY to .env.web.")
    parser.add_argument("--env-file", default=".env.web", help="Env file to update when writing.")
    parser.add_argument("--force", action="store_true", help="Replace existing NEXLOG_WEB_API_KEY line.")
    args = parser.parse_args()

    key = generate_key(args.length)
    if args.write_env_web:
        write_env(Path(args.env_file), key, force=args.force)
        print(f"Wrote NEXLOG_WEB_API_KEY to {args.env_file}")
    if args.print_key or not args.write_env_web:
        print(key)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
