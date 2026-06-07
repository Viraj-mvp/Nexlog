"""
NexLog Sigma Importer

Converts a safe, auditable subset of Sigma rules into NexLog YAML rules.
Unsupported Sigma features are reported as warnings instead of being silently
misinterpreted. This gives analysts a practical import studio foundation while
keeping conversion deterministic and reviewable.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


_FIELD_MAP = {
    "commandline": "raw_line",
    "cmdline": "raw_line",
    "message": "raw_line",
    "image": "process_name",
    "processname": "process_name",
    "process_name": "process_name",
    "sourceip": "source_ip",
    "src_ip": "source_ip",
    "source_ip": "source_ip",
    "destinationip": "dest_ip",
    "dst_ip": "dest_ip",
    "dest_ip": "dest_ip",
    "user": "username",
    "username": "username",
    "hostname": "hostname",
    "computer": "hostname",
    "eventid": "event_id",
    "event_id": "event_id",
}

_LEVEL_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "informational": "INFO",
    "info": "INFO",
}

_LOGSOURCE_FORMATS = {
    "windows": ["windows_evtx", "sysmon_json", "sysmon_xml"],
    "sysmon": ["windows_evtx", "sysmon_json", "sysmon_xml"],
    "apache": ["apache_access", "apache_error"],
    "nginx": ["nginx_access", "nginx_error"],
    "linux": ["syslog", "auth_log"],
    "cloudtrail": ["aws_cloudtrail"],
    "zeek": ["zeek_conn", "zeek_dns", "zeek_http"],
    "suricata": ["suricata_eve"],
}


@dataclass
class SigmaImportResult:
    """Structured result returned by SigmaImporter."""

    ok: bool
    rules: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    source_id: str = ""

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "rules": self.rules,
            "warnings": self.warnings,
            "errors": self.errors,
            "source_id": self.source_id,
            "count": len(self.rules),
        }


class SigmaImporter:
    """Convert safe Sigma YAML into NexLog rule dictionaries."""

    def from_file(self, path: str | Path) -> SigmaImportResult:
        p = Path(path)
        try:
            return self.from_text(p.read_text(encoding="utf-8"), source_id=str(p))
        except Exception as exc:
            return SigmaImportResult(ok=False, errors=[str(exc)], source_id=str(p))

    def from_text(self, text: str, *, source_id: str = "") -> SigmaImportResult:
        try:
            doc = yaml.safe_load(text) or {}
        except Exception as exc:
            return SigmaImportResult(ok=False, errors=[f"invalid YAML: {exc}"], source_id=source_id)
        return self.from_dict(doc, source_id=source_id)

    def from_dict(self, doc: dict[str, Any], *, source_id: str = "") -> SigmaImportResult:
        warnings: list[str] = []
        errors: list[str] = []

        if not isinstance(doc, dict):
            return SigmaImportResult(ok=False, errors=["Sigma document must be a mapping"], source_id=source_id)
        detection = doc.get("detection")
        if not isinstance(detection, dict):
            return SigmaImportResult(ok=False, errors=["Sigma rule missing detection mapping"], source_id=source_id)

        condition = str(detection.get("condition", "")).strip()
        selectors = {k: v for k, v in detection.items() if k != "condition"}
        selected_names = self._selected_conditions(condition, selectors, warnings)
        if not selected_names:
            selected_names = list(selectors)
            warnings.append("condition unsupported or empty; importing all simple selections")

        terms: list[tuple[str, str]] = []
        for name in selected_names:
            value = selectors.get(name)
            terms.extend(self._selection_terms(name, value, warnings))

        if not terms:
            errors.append("no importable string or numeric match terms found")
            return SigmaImportResult(ok=False, warnings=warnings, errors=errors, source_id=source_id)

        fields = {field for field, _ in terms}
        match_field = fields.pop() if len(fields) == 1 else "raw_line"
        if fields:
            warnings.append("multiple Sigma fields detected; converted to raw_line keyword match")

        pattern = self._terms_to_regex(terms)
        sigma_id = str(doc.get("id") or uuid.uuid4())
        rule_id = "SIGMA-" + re.sub(r"[^A-Za-z0-9_-]+", "-", sigma_id).strip("-")[:48]
        tags = [str(t) for t in doc.get("tags", []) if isinstance(t, (str, int, float))]
        mitre = [t.upper() for t in tags if str(t).lower().startswith("attack.t")]

        rule = {
            "id": rule_id,
            "name": str(doc.get("title") or "Imported Sigma Rule")[:160],
            "description": str(doc.get("description") or "Imported from Sigma."),
            "severity": _LEVEL_MAP.get(str(doc.get("level", "medium")).lower(), "MEDIUM"),
            "confidence": 0.72,
            "category": self._category(doc, tags),
            "type": "regex",
            "match_field": match_field,
            "pattern": pattern,
            "tags": ["sigma", *tags],
            "mitre": mitre,
            "version": "1.0.0",
            "status": str(doc.get("status") or "imported"),
            "source": "sigma",
            "references": [str(r) for r in doc.get("references", []) if r],
            "false_positive_guidance": doc.get("falsepositives", []),
            "supported_formats": self._supported_formats(doc.get("logsource") or {}),
            "test_cases": [],
        }
        return SigmaImportResult(ok=True, rules=[rule], warnings=warnings, source_id=source_id)

    def to_yaml(self, result: SigmaImportResult) -> str:
        return yaml.safe_dump({"rules": result.rules}, sort_keys=False, allow_unicode=False)

    def _selected_conditions(self, condition: str, selectors: dict[str, Any], warnings: list[str]) -> list[str]:
        if not condition:
            return []
        condition_l = condition.lower()
        if re.fullmatch(r"[a-zA-Z0-9_* -]+", condition_l):
            names = [name for name in selectors if name.lower() in condition_l or condition_l == name.lower()]
            if " or " in condition_l or " and " in condition_l or condition_l in selectors:
                return names
        warnings.append(f"unsupported Sigma condition syntax: {condition}")
        return []

    def _selection_terms(self, name: str, value: Any, warnings: list[str]) -> list[tuple[str, str]]:
        terms: list[tuple[str, str]] = []
        if isinstance(value, dict):
            for raw_field, raw_value in value.items():
                field = self._map_field(str(raw_field), warnings)
                values = raw_value if isinstance(raw_value, list) else [raw_value]
                for item in values:
                    if isinstance(item, (str, int, float)):
                        terms.append((field, str(item)))
                    else:
                        warnings.append(f"selection {name}.{raw_field} has unsupported value type")
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    terms.extend(self._selection_terms(name, item, warnings))
                elif isinstance(item, (str, int, float)):
                    terms.append(("raw_line", str(item)))
        elif isinstance(value, (str, int, float)):
            terms.append(("raw_line", str(value)))
        else:
            warnings.append(f"selection {name} has unsupported type")
        return terms

    def _map_field(self, raw_field: str, warnings: list[str]) -> str:
        normalized = re.sub(r"[^a-z0-9_]+", "", raw_field.lower().split("|", 1)[0])
        field = _FIELD_MAP.get(normalized)
        if not field:
            warnings.append(f"unsupported Sigma field {raw_field!r}; matching against raw_line")
            return "raw_line"
        return field

    def _terms_to_regex(self, terms: list[tuple[str, str]]) -> str:
        literals = []
        for _, value in terms:
            escaped = re.escape(value).replace(r"\*", ".*").replace(r"\?", ".")
            if escaped:
                literals.append(escaped)
        literals = sorted(set(literals), key=len, reverse=True)
        return "(?i)(" + "|".join(literals[:64]) + ")"

    def _supported_formats(self, logsource: dict[str, Any]) -> list[str]:
        if not isinstance(logsource, dict):
            return []
        haystack = " ".join(str(v).lower() for v in logsource.values() if v)
        out: list[str] = []
        for key, formats in _LOGSOURCE_FORMATS.items():
            if key in haystack:
                out.extend(formats)
        return sorted(set(out))

    def _category(self, doc: dict[str, Any], tags: list[str]) -> str:
        text = " ".join([str(doc.get("title", "")), str(doc.get("description", "")), " ".join(tags)]).lower()
        if any(k in text for k in ("brute", "login", "credential", "password")):
            return "auth_attack"
        if any(k in text for k in ("web", "sql", "xss", "http", "exploit")):
            return "web_attack"
        if any(k in text for k in ("persistence", "scheduled task", "run key")):
            return "persistence"
        if any(k in text for k in ("exfil", "upload", "archive")):
            return "exfiltration"
        if any(k in text for k in ("lateral", "rdp", "smb", "winrm")):
            return "lateral_movement"
        if any(k in text for k in ("privilege", "token", "uac", "sudo")):
            return "privilege_escalation"
        return "sigma_import"
