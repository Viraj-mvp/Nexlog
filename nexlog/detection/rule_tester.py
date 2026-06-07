"""
NexLog rule test harness.

Runs manifest-defined sample logs against the parser and rule engine, then
checks expected/forbidden rule IDs and performance budgets. This is the start
of a Sigma-style detection lifecycle: rules become testable, not just loaded.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import yaml

from engine import Engine
from rule_engine import RuleEngine


class RuleTestHarness:
    """Execute rule tests from an inline manifest or YAML/JSON manifest file."""

    def __init__(self, rules_dir: str | Path | None = None):
        self.rules_dir = Path(rules_dir) if rules_dir else None

    def run_manifest_file(self, manifest_path: str | Path) -> dict:
        path = Path(manifest_path)
        if not path.exists():
            return {"ok": False, "error": f"manifest not found: {path}", "tests": []}
        text = path.read_text(encoding="utf-8")
        data = json.loads(text) if path.suffix.lower() == ".json" else yaml.safe_load(text)
        return self.run_manifest(data or {}, base_dir=path.parent)

    def run_manifest(self, manifest: dict[str, Any], *, base_dir: str | Path | None = None) -> dict:
        tests = manifest.get("tests", [])
        if not isinstance(tests, list):
            return {"ok": False, "error": "manifest.tests must be a list", "tests": []}
        base = Path(base_dir or ".")
        results = [self._run_one(test, base) for test in tests if isinstance(test, dict)]
        return {
            "ok": all(item.get("ok") for item in results),
            "total": len(results),
            "passed": sum(1 for item in results if item.get("ok")),
            "failed": sum(1 for item in results if not item.get("ok")),
            "tests": results,
        }

    def _run_one(self, test: dict[str, Any], base_dir: Path) -> dict:
        name = str(test.get("name") or test.get("log_path") or "rule-test")
        log_path = Path(str(test.get("log_path", "")))
        if not log_path.is_absolute():
            log_path = base_dir / log_path
        if not log_path.exists():
            return {"name": name, "ok": False, "error": f"log not found: {log_path}"}

        expected = {str(x) for x in test.get("expected_rules", [])}
        forbidden = {str(x) for x in test.get("forbidden_rules", [])}
        min_findings = int(test.get("min_findings", 0))
        max_ms = float(test.get("max_ms", 0) or 0)
        limit_entries = int(test.get("limit_entries", 250_000))

        started = time.perf_counter()
        engine = Engine()
        rules = RuleEngine(self.rules_dir) if self.rules_dir else RuleEngine()
        findings = []
        entries_seen = 0
        try:
            for entry in engine.parse(log_path, fast_meta=True):
                entries_seen += 1
                findings.extend(rules.evaluate(entry))
                if entries_seen >= limit_entries:
                    break
        except Exception as exc:
            return {"name": name, "ok": False, "error": str(exc), "log_path": str(log_path)}

        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        matched = {getattr(f, "rule_id", "") for f in findings}
        failures: list[str] = []
        missing = sorted(expected - matched)
        blocked = sorted(forbidden & matched)
        if missing:
            failures.append("missing expected rules: " + ", ".join(missing))
        if blocked:
            failures.append("forbidden rules matched: " + ", ".join(blocked))
        if len(findings) < min_findings:
            failures.append(f"expected at least {min_findings} findings, got {len(findings)}")
        if max_ms > 0 and elapsed_ms > max_ms:
            failures.append(f"performance budget exceeded: {elapsed_ms} ms > {max_ms} ms")

        return {
            "name": name,
            "ok": not failures,
            "failures": failures,
            "log_path": str(log_path),
            "entries_seen": entries_seen,
            "findings": len(findings),
            "matched_rules": sorted(matched),
            "elapsed_ms": elapsed_ms,
        }
