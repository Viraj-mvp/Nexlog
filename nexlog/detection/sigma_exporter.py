"""
detection/sigma_exporter.py â€” NexLog v2
=============================================
Converts NexLog findings and internal rule definitions to
industry-standard Sigma YAML format.

Sigma is the universal SIEM rule language. Rules exported here can be
deployed to Splunk, ELK, QRadar, Wazuh, and 30+ other platforms using
the sigma CLI converter (https://github.com/SigmaHQ/sigma).

Usage:
    from detection.sigma_exporter import SigmaExporter
    from detection.finding import Finding

    exporter = SigmaExporter()
    yaml_str = exporter.finding_to_sigma(finding)
    exporter.export_bundle(findings, "output/sigma_rules/")
"""

import os
import re
import sys
import uuid
from datetime import datetime, timezone
from typing import Optional

_root = os.path.dirname(os.path.abspath(__file__))
for _ in range(8):
    if os.path.isfile(os.path.join(_root, "pathconfig.py")):
        break
    _root = os.path.dirname(_root)
if _root not in sys.path:
    sys.path.insert(0, _root)
from pathconfig import ROOT, add_root
add_root()

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


# â”€â”€ Category â†’ Sigma logsource mapping â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_LOGSOURCE_MAP = {
    "web_attack":           {"category": "webserver"},
    "auth_attack":          {"category": "authentication"},
    "privilege_escalation": {"product": "windows", "category": "process_creation"},
    "lateral_movement":     {"product": "windows", "category": "network_connection"},
    "persistence":          {"product": "windows", "category": "registry_set"},
    "exfiltration":         {"category": "network_connection"},
    "malware":              {"product": "windows", "category": "process_creation"},
    "recon":                {"category": "network_connection"},
    "discovery":            {"product": "windows", "category": "process_creation"},
    "defense_evasion":      {"product": "windows", "category": "process_creation"},
    "impact":               {"category": "application"},
    "insider_threat":       {"category": "authentication"},
    "api_security":         {"category": "webserver"},
    "cloud_attack":         {"product": "aws", "category": "cloudtrail"},
    "bot_activity":         {"category": "webserver"},
    "default":              {"category": "application"},
}

_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "LOW":      "low",
    "INFO":     "informational",
}


def _safe_str(val) -> str:
    return str(val) if val is not None else ""


def _extract_sigma_detection(trigger_line: str, category: str) -> dict:
    """
    Parse a trigger line and extract key-value pairs for the Sigma
    detection block. Uses heuristics based on log category.
    """
    detection: dict = {}

    if not trigger_line:
        return {"keywords": ["nexlog_finding"]}

    # Extract IP addresses
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', trigger_line)
    # Extract URLs/paths
    paths = re.findall(r'(?:GET|POST|PUT|DELETE|HEAD)\s+(\S+)', trigger_line)
    # Extract quoted strings
    quoted = re.findall(r'"([^"]{3,80})"', trigger_line)
    # Extract event IDs
    event_ids = re.findall(r'EventID[=:\s]+(\d+)', trigger_line, re.IGNORECASE)
    # Extract usernames
    users = re.findall(r'(?:user|username|account)[=:\s]+(\S+)', trigger_line, re.IGNORECASE)
    # Extract processes
    procs = re.findall(r'(?:process|image|commandline)[=:\s]+([^\s,;]+)', trigger_line, re.IGNORECASE)
    # Extract keywords (non-trivial words)
    keywords = [w for w in re.findall(r'\b[a-z_\-]{4,}\b', trigger_line.lower())
                if w not in {"from", "with", "that", "this", "have", "been",
                              "were", "they", "into", "http", "https"}]

    selection: dict = {}

    if category in ("web_attack", "api_security", "bot_activity"):
        if paths:
            selection["cs-uri-query|contains"] = paths[0][:200]
        elif quoted:
            selection["cs-uri-query|contains"] = quoted[0][:200]
        if ips:
            selection["c-ip"] = ips[0]

    elif category in ("auth_attack",):
        if event_ids:
            selection["EventID"] = [int(e) for e in event_ids[:5]]
        else:
            selection["EventID"] = [4625, 4648]
        if users:
            selection["TargetUserName|contains"] = users[0][:80]

    elif category in ("privilege_escalation", "persistence", "defense_evasion",
                      "lateral_movement", "discovery"):
        if event_ids:
            selection["EventID"] = [int(e) for e in event_ids[:5]]
        if procs:
            selection["Image|endswith"] = procs[0][:80]
        elif keywords:
            selection["CommandLine|contains|all"] = keywords[:4]

    elif category in ("exfiltration",):
        if ips:
            selection["DestinationIp"] = ips[0]
        if keywords:
            selection["CommandLine|contains"] = keywords[0]

    else:
        # Generic keyword fallback
        if keywords:
            selection["keywords"] = keywords[:6]
        elif trigger_line:
            selection["keywords"] = [trigger_line[:120]]

    if not selection:
        selection["keywords"] = keywords[:4] or [trigger_line[:120]]

    return {"selection": selection, "condition": "selection"}


def _to_yaml_str(data: dict) -> str:
    """Safe YAML serialisation with or without the yaml package."""
    if _HAS_YAML:
        return yaml.dump(data, default_flow_style=False,
                         allow_unicode=True, sort_keys=False)
    # Minimal fallback serialiser for simple dicts/lists
    lines = []
    def _emit(obj, indent=0):
        prefix = "  " * indent
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    lines.append(f"{prefix}{k}:")
                    _emit(v, indent + 1)
                else:
                    lines.append(f"{prefix}{k}: {v!r}")
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    lines.append(f"{prefix}-")
                    _emit(item, indent + 1)
                else:
                    lines.append(f"{prefix}- {item!r}")
        else:
            lines.append(f"{prefix}{obj!r}")
    _emit(data)
    return "\n".join(lines)


class SigmaExporter:
    """Export NexLog findings to Sigma YAML rules."""

    def __init__(self, author: str = "NexLog v2"):
        self._author = author

    def finding_to_sigma(self, finding) -> str:
        """
        Convert a single Finding object or dict to a Sigma YAML string.

        Returns a complete, valid Sigma rule ready to paste into any SIEM.
        """
        # â”€â”€ Extract fields â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if isinstance(finding, dict):
            rule_id   = finding.get("rule_id", "CUSTOM-001")
            rule_name = finding.get("rule_name", "Custom Detection")
            desc      = finding.get("description", "")
            sev       = finding.get("severity", "MEDIUM")
            category  = finding.get("category", "default")
            trigger   = finding.get("trigger_line", "") or ""
            tags_raw  = finding.get("mitre_tags", [])
        else:
            rule_id   = _safe_str(getattr(finding, "rule_id", "CUSTOM-001"))
            rule_name = _safe_str(getattr(finding, "rule_name", "Custom Detection"))
            desc      = _safe_str(getattr(finding, "description", ""))
            sev_obj   = getattr(finding, "severity", None)
            sev       = getattr(sev_obj, "value", str(sev_obj)) if sev_obj else "MEDIUM"
            category  = _safe_str(getattr(finding, "category", "default"))
            trigger   = _safe_str(getattr(finding, "trigger_line", "")) or ""
            tags_raw  = getattr(finding, "mitre_tags", [])

        # â”€â”€ MITRE tags â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        sigma_tags = []
        for t in tags_raw:
            if isinstance(t, dict):
                tactic = t.get("tactic_name", "").lower().replace(" ", "_")
                tid    = t.get("full_id", t.get("technique_id", ""))
            else:
                tactic = _safe_str(getattr(t, "tactic_name", "")).lower().replace(" ", "_")
                tid    = _safe_str(getattr(t, "full_id", ""))
            if tactic:
                sigma_tags.append(f"attack.{tactic}")
            if tid:
                sigma_tags.append(f"attack.{tid.lower()}")

        # â”€â”€ Logsource â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        logsource = _LOGSOURCE_MAP.get(category.lower(),
                                       _LOGSOURCE_MAP["default"]).copy()

        # â”€â”€ Detection block â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        detection = _extract_sigma_detection(trigger, category.lower())

        # â”€â”€ Assemble rule â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        rule = {
            "title":       f"NexLog - {rule_name}",
            "id":          str(uuid.uuid4()),
            "status":      "experimental",
            "description": desc or f"NexLog detection: {rule_name}",
            "references":  ["https://github.com/nexlog/nexlog"],
            "author":      self._author,
            "date":        datetime.now(timezone.utc).strftime("%Y/%m/%d"),
            "modified":    datetime.now(timezone.utc).strftime("%Y/%m/%d"),
            "tags":        sigma_tags or ["attack.discovery"],
            "logsource":   logsource,
            "detection":   detection,
            "falsepositives": ["Legitimate administrative activity"],
            "level":       _SEVERITY_MAP.get(sev.upper(), "medium"),
        }

        return f"# Exported from NexLog v2 â€” Rule {rule_id}\n" + _to_yaml_str(rule)

    def export_bundle(self, findings: list, output_dir: str) -> list[str]:
        """
        Export all findings as individual Sigma YAML files.

        Args:
            findings:   List of Finding objects or dicts.
            output_dir: Directory to write .yml files into.

        Returns:
            List of written file paths.
        """
        os.makedirs(output_dir, exist_ok=True)
        written = []
        seen_rules: set = set()

        for f in findings:
            if isinstance(f, dict):
                rid = f.get("rule_id", "UNKNOWN")
            else:
                rid = _safe_str(getattr(f, "rule_id", "UNKNOWN"))

            if rid in seen_rules:
                continue  # one Sigma rule per rule_id, not per finding
            seen_rules.add(rid)

            yaml_str = self.finding_to_sigma(f)
            fname    = re.sub(r'[^a-zA-Z0-9_\-]', '_', rid).lower() + ".yml"
            fpath    = os.path.join(output_dir, fname)
            with open(fpath, "w", encoding="utf-8") as fh:
                fh.write(yaml_str)
            written.append(fpath)

        return written

    def export_single_bundle(self, findings: list) -> str:
        """
        Merge all unique rules into a single YAML string (multi-document).
        Each rule separated by --- (standard YAML multi-doc separator).
        """
        seen: set = set()
        parts: list[str] = []
        for f in findings:
            if isinstance(f, dict):
                rid = f.get("rule_id", "")
            else:
                rid = _safe_str(getattr(f, "rule_id", ""))
            if rid in seen:
                continue
            seen.add(rid)
            parts.append(self.finding_to_sigma(f))

        return "\n---\n".join(parts)
