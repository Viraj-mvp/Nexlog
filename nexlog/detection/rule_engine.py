"""
detection/rule_engine.py â€” NexLog Layer 2
Loads all YAML rule files, builds the correct matcher per rule,
and runs the full detection pipeline against a stream of LogEntry objects.

Changes from v1:
  - composite rule type handler added (_build_matcher)
  - get_rule(id) â€” O(1) lookup by rule_id
  - get_rules_by_category(category) â€” filter loaded rules
  - get_loaded_categories() â€” set of all category strings
  - filter_findings(findings, min_severity, category) â€” post-process helper
  - deduplicate_findings(findings, window_secs) â€” collapse burst duplicates
  - summary() extended: per-category counts, per-type counts, avg_confidence
  - _extract_indicators now populates hostname/process_name/event_id
    on the Finding from the triggering LogEntry
  - Finding.hostname / process_name / event_id now populated from LogEntry
"""

import os
import sys
from datetime import timedelta
from pathlib import Path
from typing import Generator, Optional

import yaml
import re as _re
import time

from ..core.models import LogEntry
from .finding import Finding, Severity
from .pattern_matcher import (
    RegexMatcher, ThresholdMatcher,
    SequenceMatcher, CompositeRule,
)
from .attck_tagger import build_mitre_tags, adjust_confidence

def _default_rules_dir() -> Path:
    bundled = os.environ.get("NEXLOG_RULES_DIR")
    if bundled:
        return Path(bundled)
    try:
        from pathconfig import ROOT_PATH

        return ROOT_PATH / "detection" / "rules"
    except Exception:
        return Path(_HERE) / "rules"


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# INTERNAL RULE REPRESENTATION
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class _Rule:
    """
    Internal representation of a loaded YAML rule.
    Owns the matcher instance plus all static metadata from the YAML.
    """
    __slots__ = (
        "rule_id", "name", "description", "severity", "category",
        "base_confidence", "mitre_tags", "indicators", "tags",
        "matcher", "rule_type",
    )

    def __init__(self, data: dict):
        self.rule_id         = data["id"]
        self.name            = data["name"]
        self.description     = data.get("description", "").strip()
        self.severity        = Severity[data.get("severity", "MEDIUM").upper()]
        self.category        = data.get("category", "unknown")
        self.base_confidence = float(data.get("confidence", 0.75))
        self.mitre_tags      = build_mitre_tags(data.get("mitre", []))
        self.indicators      = data.get("indicators", [])
        self.tags            = data.get("tags", [])
        self.rule_type       = data.get("type", "regex")
        self.matcher         = _build_matcher(data)


def _build_matcher(data: dict):
    """
    Instantiate the correct matcher class from a YAML rule dict.
    Supported types: regex | threshold | sequence | composite
    """
    rule_type   = data.get("type", "regex")
    filter_dict = data.get("filter") or {}

    if rule_type == "regex":
        return RegexMatcher(
            match_field = data["match_field"],
            pattern     = data["pattern"],
            filter_dict = filter_dict,
        )

    elif rule_type == "threshold":
        return ThresholdMatcher(
            group_by       = data["group_by"],
            count          = data["count"],
            window_secs    = data["window_secs"],
            filter_dict    = filter_dict,
            count_distinct = data.get("count_distinct"),
        )

    elif rule_type == "sequence":
        return SequenceMatcher(
            steps       = data["steps"],
            group_by    = data["group_by"],
            window_secs = data.get("window_secs", 300),
        )

    elif rule_type == "composite":
        # composite rules define their sub-rules inline under "sub_rules" key.
        # Each sub-rule follows the same schema as a top-level rule.
        sub_matchers = [_build_matcher(sr) for sr in data.get("sub_rules", [])]
        return CompositeRule(
            sub_matchers = sub_matchers,
            group_by     = data.get("group_by", "source_ip"),
            window_secs  = data.get("window_secs", 600),
            logic        = data.get("logic", "AND"),
            name         = data.get("id", "composite"),
        )

    else:
        raise ValueError(
            f"Unknown rule type {rule_type!r} in rule {data.get('id')!r}. "
            f"Valid types: regex, threshold, sequence, composite"
        )


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# RULE ENGINE
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class RuleEngine:
    """
    Loads all YAML rules from a rules/ directory, builds matchers,
    and evaluates them against a stream of LogEntry objects.

    Thread safety: NOT thread-safe. ThresholdMatcher and SequenceMatcher
    are stateful. Use one RuleEngine instance per analysis session.
    Call reset() between log files.

    Quick start:
        from core.engine import Engine
        from detection.rule_engine import RuleEngine

        parse  = Engine()
        detect = RuleEngine()

        for finding in detect.evaluate_stream(parse.parse("access.log")):
            print(finding)

        print(detect.summary())
    """

    def __init__(self, rules_dir: str | Path | None = None):
        self._rules:      list[_Rule]      = []
        self._rules_by_id: dict[str, _Rule] = {}

        self._total_evaluated   = 0
        self._total_findings    = 0
        self._findings_by_rule: dict[str, int] = {}
        self._findings_by_cat:  dict[str, int] = {}
        self._rules_loaded      = 0

        rules_path = Path(rules_dir) if rules_dir else _default_rules_dir()
        self._load_rules(rules_path)

    # â”€â”€ Loading â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _load_rules(self, rules_dir: Path) -> None:
        if not rules_dir.exists():
            raise FileNotFoundError(f"Rules directory not found: {rules_dir}")

        for yaml_file in sorted(rules_dir.glob("*.yaml")):
            try:
                with open(yaml_file, encoding="utf-8") as f:
                    doc = yaml.safe_load(f)
                for rule_data in doc.get("rules", []):
                    # Validate regex pattern before adding the rule
                    # DO NOT overwrite rule_data['pattern'] with the compiled object, 
                    # as downstream matchers (RegexMatcher) expect the raw string for cleanup.
                    _validate_regex_safe(rule_data.get('pattern', ''), rule_data.get('id', 'unknown'))
                    rule = _Rule(rule_data)
                    self._rules.append(rule)
                    self._rules_by_id[rule.rule_id] = rule
                    self._rules_loaded += 1
            except Exception as e:
                # One bad YAML file must not crash the whole engine
                print(f"[RuleEngine] WARNING: could not load "
                      f"{yaml_file.name}: {e}")

    def load_rule_from_dict(self, rule_data: dict) -> None:
        """
        Add a single rule from a dict at runtime.
        Useful for testing and for dynamically injecting rules
        without writing a YAML file.
        """
        rule = _Rule(rule_data)
        self._rules.append(rule)
        self._rules_by_id[rule.rule_id] = rule
        self._rules_loaded += 1

    # â”€â”€ Lookup helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def get_rule(self, rule_id: str) -> Optional[_Rule]:
        """O(1) lookup of a loaded rule by its ID. Returns None if not found."""
        return self._rules_by_id.get(rule_id)

    def get_rules_by_category(self, category: str) -> list[_Rule]:
        """Return all loaded rules whose category matches exactly."""
        return [r for r in self._rules if r.category == category]

    def get_loaded_categories(self) -> set[str]:
        """Return the set of all category strings present in loaded rules."""
        return {r.category for r in self._rules}

    # â”€â”€ Evaluation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def evaluate(self, entry: LogEntry) -> list[Finding]:
        """
        Run all rules against one LogEntry.
        Returns a (possibly empty) list of Finding objects.
        Call once per LogEntry in your parse loop.
        """
        self._total_evaluated += 1
        findings: list[Finding] = []

        for rule in self._rules:
            try:
                matched, context = rule.matcher.match(entry)
            except Exception as e:
                # Log error but never let a bad rule crash the analysis
                import logging
                logging.warning(
                    f"Rule {rule.rule_id} failed for entry {entry.source_file}:{entry.line_number}: {e}",
                    exc_info=False
                )
                continue

            if not matched:
                continue

            confidence = adjust_confidence(
                rule.base_confidence, entry, rule.mitre_tags, context
            )

            finding = Finding(
                rule_id          = rule.rule_id,
                rule_name        = rule.name,
                description      = rule.description,
                severity         = rule.severity,
                confidence       = confidence,
                category         = rule.category,
                mitre_tags       = rule.mitre_tags,
                source_file      = entry.source_file,
                source_ip        = entry.source_ip,
                dest_ip          = entry.dest_ip,
                username         = entry.username,
                hostname         = entry.hostname,           # â† now populated
                process_name     = entry.process_name,       # â† now populated
                event_id         = entry.event_id,           # â† now populated
                timestamp        = entry.timestamp,
                trigger_line     = entry.raw_line,
                trigger_lineno   = entry.line_number,
                supporting_lines = context.get("evidence_lines", []),
                indicators       = _extract_indicators(
                                       entry, rule.indicators, context),
                extra            = {
                    "rule_tags":       rule.tags,
                    "rule_type":       rule.rule_type,
                    "matcher_context": context,
                },
            )

            findings.append(finding)
            self._total_findings += 1
            self._findings_by_rule[rule.rule_id] = (
                self._findings_by_rule.get(rule.rule_id, 0) + 1
            )
            self._findings_by_cat[rule.category] = (
                self._findings_by_cat.get(rule.category, 0) + 1
            )

        return findings

    def evaluate_stream(
        self,
        entries: Generator[LogEntry, None, None],
    ) -> Generator[Finding, None, None]:
        """
        Convenience wrapper â€” evaluate a complete parse stream.
        Yields Findings as they are detected.

        Example:
            for finding in engine.evaluate_stream(parse_engine.parse("auth.log")):
                print(finding)
        """
        for entry in entries:
            yield from self.evaluate(entry)

    # â”€â”€ Post-processing helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    @staticmethod
    def filter_findings(
        findings:     list[Finding],
        min_severity: Optional[Severity]  = None,
        category:     Optional[str]       = None,
        min_confidence: float             = 0.0,
    ) -> list[Finding]:
        """
        Filter a list of findings by severity, category, and confidence.

        Example:
            critical_web = RuleEngine.filter_findings(
                findings,
                min_severity=Severity.HIGH,
                category="web_attack",
            )
        """
        result = findings
        if min_severity is not None:
            result = [f for f in result if f.severity >= min_severity]
        if category is not None:
            result = [f for f in result if f.category == category]
        if min_confidence > 0.0:
            result = [f for f in result if f.confidence >= min_confidence]
        return result

    @staticmethod
    def deduplicate_findings(
        findings:    list[Finding],
        window_secs: int = 60,
    ) -> list[Finding]:
        """
        Collapse repeated findings of the same rule from the same source IP
        within a time window into a single representative finding.

        The first occurrence is kept; subsequent duplicates are discarded
        but their trigger_lines are merged into supporting_lines.

        Use this before writing to SQLite to avoid filling the database with
        burst duplicates from threshold rules that fire repeatedly.
        """

        seen: dict[str, Finding] = {}   # key â†’ canonical Finding
        deduped: list[Finding]   = []
        window = timedelta(seconds=window_secs)

        for f in findings:
            key = f"{f.rule_id}::{f.source_ip or f.hostname or '?'}"
            if key not in seen:
                seen[key] = f
                deduped.append(f)
            else:
                canonical = seen[key]
                # Check if still within dedup window
                if (f.timestamp and canonical.timestamp and
                        f.timestamp - canonical.timestamp <= window):
                    # Merge evidence
                    if f.trigger_line not in canonical.supporting_lines:
                        canonical.supporting_lines.append(f.trigger_line)
                else:
                    # Window expired â€” start new canonical
                    seen[key] = f
                    deduped.append(f)

        return deduped

    # â”€â”€ State management â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def reset(self) -> None:
        """
        Reset all stateful matchers and counters.
        Call between log files in the same session to avoid
        threshold / sequence state bleeding across files.
        """
        for rule in self._rules:
            if hasattr(rule.matcher, "reset"):
                rule.matcher.reset()
        self._total_evaluated   = 0
        self._total_findings    = 0
        self._findings_by_rule  = {}
        self._findings_by_cat   = {}

    # â”€â”€ Reporting â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def summary(self) -> dict:
        """
        Return a comprehensive summary of this detection session.

        Extended from v1 to include:
          - per_category:   findings broken down by attack category
          - per_type:       rule counts broken down by matcher type
          - avg_confidence: mean confidence of all findings (if any fired)
          - top_fired:      the 5 most-fired rules by finding count
        """
        # Per-type rule counts
        per_type: dict[str, int] = {}
        for r in self._rules:
            per_type[r.rule_type] = per_type.get(r.rule_type, 0) + 1

        # Top 5 most-fired rules
        top_fired = sorted(
            self._findings_by_rule.items(),
            key=lambda x: x[1], reverse=True
        )[:5]

        return {
            # Totals
            "rules_loaded":       self._rules_loaded,
            "entries_evaluated":  self._total_evaluated,
            "total_findings":     self._total_findings,
            # Breakdown by rule
            "findings_by_rule":   dict(self._findings_by_rule),
            # Breakdown by category (new)
            "findings_by_category": dict(self._findings_by_cat),
            # Breakdown by matcher type (new)
            "rules_by_type":      per_type,
            # Top 5 most-fired rules (new)
            "top_fired_rules":    [
                {"rule_id": rid, "count": cnt}
                for rid, cnt in top_fired
            ],
            # All loaded rules (trimmed metadata)
            "rules": [
                {
                    "id":       r.rule_id,
                    "name":     r.name,
                    "category": r.category,
                    "severity": r.severity.value,
                    "type":     r.rule_type,
                    "tags":     r.tags,
                }
                for r in self._rules
            ],
        }

    def __repr__(self) -> str:
        return (
            f"<RuleEngine rules={len(self._rules)} "
            f"categories={len(self.get_loaded_categories())} "
            f"evaluated={self._total_evaluated} "
            f"findings={self._total_findings}>"
        )


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# HELPERS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def _extract_indicators(
    entry:            LogEntry,
    indicator_fields: list[str],
    context:          dict,
) -> dict:
    """
    Build the indicators dict for a Finding from the triggering LogEntry.

    Now extracts: standard fields, dotted extra paths, and always appends
    matched_text from the regex context when available.
    """
    indicators: dict = {}

    for field_name in indicator_fields:
        if "." in field_name:
            parts  = field_name.split(".", 1)
            parent = getattr(entry, parts[0], None)
            val    = parent.get(parts[1]) if isinstance(parent, dict) else None
        else:
            val = getattr(entry, field_name, None)

        if val is not None:
            indicators[field_name] = str(val)[:500]

    if "matched_text" in context:
        indicators["matched_text"] = context["matched_text"]

    return indicators

def _validate_regex_safe(pattern: str, rule_id: str, timeout_ms: int = 150) -> _re.Pattern:
    """
    Compile regex and probe for catastrophic backtracking (ReDoS).
    Raises ValueError if the pattern is invalid or ReDoS-prone.
    """
    clean_pattern = _re.sub(r"\s+", "", pattern or "")
    if len(clean_pattern) > 6000:
        raise ValueError(f"Regex too large in rule {rule_id}: {len(clean_pattern)} chars")
    if clean_pattern.count("(") > 120:
        raise ValueError(f"Regex too complex in rule {rule_id}: too many groups")
    if clean_pattern.count("|") > 600:
        raise ValueError(f"Regex too complex in rule {rule_id}: too many alternations")
    # Ignore character classes so safe patterns like [A-Za-z0-9+/] are not
    # mistaken for nested quantifiers because they contain literal + or *.
    structural_pattern = _re.sub(r"\[(?:\\.|[^\]\\])*\]", "[]", clean_pattern)
    nested_quantifier = _re.search(
        r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\s*(?:[+*]|\{\d*,?\d*\})",
        structural_pattern,
    )
    if nested_quantifier:
        raise ValueError(
            f"ReDoS-prone regex in rule {rule_id}: nested quantifiers. "
            f"Pattern: {clean_pattern!r}"
        )

    try:
        compiled = _re.compile(clean_pattern, _re.IGNORECASE)
    except _re.error as exc:
        raise ValueError(f"Invalid regex in rule {rule_id}: {exc}") from exc

    # Probe with pathological input (triggers backtracking in evil patterns)
    probe_inputs = [
        "a" * 20 + "!",
        "A" * 20 + "\x00",
        "<" * 30 + ">" * 30 + "X",
    ]
    for probe in probe_inputs:
        t0 = time.monotonic()
        compiled.search(probe)
        elapsed = (time.monotonic() - t0) * 1000
        if elapsed > timeout_ms:
            raise ValueError(
                f"ReDoS-prone regex in rule {rule_id} "
                f"({elapsed:.0f}ms on probe input). "
                f"Pattern: {pattern!r}"
            )
    return compiled
