"""
Rule coverage reporting for NexLog.

Builds a maturity snapshot from loaded YAML rules: severity, category,
formats, MITRE techniques, lifecycle status, and test coverage metadata.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml


class RuleCoverage:
    """Read NexLog rule YAML files and produce coverage matrices."""

    def __init__(self, rules_dir: str | Path):
        self.rules_dir = Path(rules_dir)

    def build(self) -> dict:
        rules = self._load_rules()
        by_severity = Counter(str(r.get("severity", "MEDIUM")).upper() for r in rules)
        by_category = Counter(str(r.get("category", "unknown")) for r in rules)
        by_status = Counter(str(r.get("status", "active")) for r in rules)
        by_format = Counter()
        by_source = Counter(str(r.get("source", "nexlog")) for r in rules)
        mitre_rules: dict[str, list[dict]] = defaultdict(list)
        tested = 0

        for rule in rules:
            formats = rule.get("supported_formats") or ["unspecified"]
            if isinstance(formats, str):
                formats = [formats]
            by_format.update(str(fmt) for fmt in formats)
            if rule.get("test_cases"):
                tested += 1
            for tid in self._mitre_ids(rule.get("mitre")):
                mitre_rules[tid].append({
                    "id": rule.get("id"),
                    "name": rule.get("name"),
                    "severity": rule.get("severity", "MEDIUM"),
                    "category": rule.get("category", "unknown"),
                })

        missing_metadata = [
            {
                "id": r.get("id", ""),
                "missing": [
                    field for field in (
                        "version", "status", "source", "references",
                        "false_positive_guidance", "supported_formats", "test_cases"
                    )
                    if field not in r
                ],
            }
            for r in rules
            if any(field not in r for field in (
                "version", "status", "source", "references",
                "false_positive_guidance", "supported_formats", "test_cases"
            ))
        ]

        return {
            "rules_dir": str(self.rules_dir),
            "total_rules": len(rules),
            "tested_rules": tested,
            "untested_rules": max(0, len(rules) - tested),
            "by_severity": dict(by_severity),
            "by_category": dict(by_category),
            "by_status": dict(by_status),
            "by_source": dict(by_source),
            "by_format": dict(by_format),
            "mitre": {
                tid: {"count": len(items), "rules": items}
                for tid, items in sorted(mitre_rules.items())
            },
            "missing_metadata": missing_metadata[:500],
            "metadata_completion": round(
                1.0 - (len(missing_metadata) / len(rules)) if rules else 1.0, 3
            ),
            "rules": [self._rule_summary(r) for r in rules],
        }

    def _load_rules(self) -> list[dict[str, Any]]:
        if not self.rules_dir.exists():
            return []
        out: list[dict[str, Any]] = []
        for path in sorted(self.rules_dir.glob("*.yaml")):
            try:
                doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
                for rule in doc.get("rules", []) or []:
                    if isinstance(rule, dict):
                        item = dict(rule)
                        item["_file"] = str(path)
                        out.append(item)
            except Exception:
                continue
        return out

    def _mitre_ids(self, mitre: Any) -> list[str]:
        out: list[str] = []
        if isinstance(mitre, list):
            for item in mitre:
                if isinstance(item, str) and item.upper().startswith("T"):
                    out.append(item.upper())
                elif isinstance(item, dict):
                    for key in ("technique_id", "id", "technique"):
                        value = item.get(key)
                        if isinstance(value, str) and value.upper().startswith("T"):
                            out.append(value.upper())
        return sorted(set(out))

    def _rule_summary(self, rule: dict[str, Any]) -> dict:
        return {
            "id": rule.get("id", ""),
            "name": rule.get("name", ""),
            "severity": rule.get("severity", "MEDIUM"),
            "category": rule.get("category", "unknown"),
            "type": rule.get("type", "regex"),
            "status": rule.get("status", "active"),
            "source": rule.get("source", "nexlog"),
            "version": rule.get("version", ""),
            "supported_formats": rule.get("supported_formats", []),
            "mitre_ids": self._mitre_ids(rule.get("mitre")),
            "has_tests": bool(rule.get("test_cases")),
            "file": rule.get("_file", ""),
        }
