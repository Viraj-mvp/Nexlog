"""
detection/finding.py â€” NexLog Layer 2
Finding is to Layer 2 what LogEntry is to Layer 1.
Every detection produces a Finding. Nothing else leaves this layer.

Changes from v1:
  - Added hostname, process_name, event_id fields (referenced by 40+ rules)
  - supporting_lines now included in to_dict()
  - Added from_dict() classmethod for deserialisation from SQLite/JSON
  - Added risk_score cached property
  - Added tactic_names / technique_ids convenience properties on Finding
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# SEVERITY
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class Severity(Enum):
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

    def score(self) -> int:
        """Numeric score for sorting / comparison."""
        return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]

    # Rich comparison â€” lets you do: Severity.HIGH > Severity.MEDIUM
    def __lt__(self, other: "Severity") -> bool: return self.score() <  other.score()
    def __le__(self, other: "Severity") -> bool: return self.score() <= other.score()
    def __gt__(self, other: "Severity") -> bool: return self.score() >  other.score()
    def __ge__(self, other: "Severity") -> bool: return self.score() >= other.score()


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# MITRE TAG
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@dataclass
class MitreTag:
    """One MITRE ATT&CK technique reference attached to a Finding."""
    tactic_id:      str            # e.g. "TA0001"
    tactic_name:    str            # e.g. "Initial Access"
    technique_id:   str            # e.g. "T1190"
    technique_name: str            # e.g. "Exploit Public-Facing Application"
    sub_technique:  Optional[str] = None   # e.g. ".001"

    @property
    def full_id(self) -> str:
        """T1190 or T1190.001 if sub-technique is set."""
        if self.sub_technique:
            return f"{self.technique_id}{self.sub_technique}"
        return self.technique_id

    def to_dict(self) -> dict:
        return {
            "tactic_id":      self.tactic_id,
            "tactic_name":    self.tactic_name,
            "technique_id":   self.technique_id,
            "technique_name": self.technique_name,
            "sub_technique":  self.sub_technique,
            "full_id":        self.full_id,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "MitreTag":
        return cls(
            tactic_id      = d.get("tactic_id", ""),
            tactic_name    = d.get("tactic_name", ""),
            technique_id   = d.get("technique_id", ""),
            technique_name = d.get("technique_name", ""),
            sub_technique  = d.get("sub_technique"),
        )

    def __str__(self) -> str:
        return f"{self.full_id} â€” {self.technique_name} [{self.tactic_name}]"


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# FINDING
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

@dataclass
class Finding:
    """
    A confirmed or suspected attack event produced by the detection engine.
    Consumed by: storage layer (SQLite), output layer (PDF/STIX), GUI/API.

    Design rules:
      - One Finding per detected event, not per log line.
      - confidence is always float 0.0â€“1.0. Never a string like "high".
      - supporting_lines holds ALL evidence lines; trigger_line is the one
        that caused the rule to fire.
      - hostname / process_name / event_id mirror the source LogEntry fields
        that many Windows/Linux rules reference as indicators.
    """

    # â”€â”€ Core identity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    rule_id:        str      # "WEB-001"
    rule_name:      str      # "SQL Injection Attempt"
    description:    str      # what happened, human-readable

    # â”€â”€ Classification â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    severity:       Severity
    confidence:     float    # 0.0â€“1.0
    category:       str      # "web_attack" | "auth" | "malware" | etc.

    # â”€â”€ MITRE ATT&CK â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    mitre_tags: list[MitreTag] = field(default_factory=list)

    # â”€â”€ Source identity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    source_file:    str           = ""
    source_ip:      Optional[str] = None
    dest_ip:        Optional[str] = None
    username:       Optional[str] = None
    hostname:       Optional[str] = None    # â† was missing; used by 40+ rules
    process_name:   Optional[str] = None    # â† was missing; malware/lolbin rules
    event_id:       Optional[str] = None    # â† was missing; Windows EVTX rules
    timestamp:      Optional[datetime] = None

    # â”€â”€ Evidence â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    trigger_line:     str      = ""   # the exact line that fired the rule
    trigger_lineno:   int      = 0
    supporting_lines: list[str] = field(default_factory=list)  # all related lines

    # â”€â”€ Extracted indicators â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    indicators: dict = field(default_factory=dict)
    # e.g. {"payload": "' OR 1=1--", "matched_text": "union select"}

    # â”€â”€ Extra â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    extra: dict = field(default_factory=dict)
    # e.g. {"rule_tags": ["sqli", "owasp-a03"], "matcher_context": {...}}

    # â”€â”€ Computed â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    @property
    def risk_score(self) -> float:
        """
        CVSS-inspired composite score: severity_weight Ã— confidence.
        Range 0.0â€“10.0. Use compute_risk_score(finding, asset_value)
        from attck_tagger.py for asset-adjusted scoring.
        """
        weights = {
            "CRITICAL": 10.0, "HIGH": 7.0,
            "MEDIUM":    4.0, "LOW":  2.0, "INFO": 1.0,
        }
        w = weights.get(self.severity.value, 4.0)
        return round(min(w * self.confidence, 10.0), 2)

    @property
    def tactic_names(self) -> list[str]:
        """Unique tactic names from all MITRE tags."""
        seen, out = set(), []
        for t in self.mitre_tags:
            if t.tactic_name not in seen:
                seen.add(t.tactic_name)
                out.append(t.tactic_name)
        return out

    @property
    def technique_ids(self) -> list[str]:
        """All full technique IDs (including sub-techniques)."""
        return [t.full_id for t in self.mitre_tags]

    # â”€â”€ Serialisation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    def to_dict(self) -> dict:
        """
        Full serialisation to plain dict.
        Every value is a JSON primitive â€” safe for SQLite storage and
        JSON export with no further transformation.

        Previously missing: supporting_lines, hostname, process_name, event_id.
        """
        return {
            # identity
            "rule_id":          self.rule_id,
            "rule_name":        self.rule_name,
            "description":      self.description,
            # classification
            "severity":         self.severity.value,
            "confidence":       round(self.confidence, 3),
            "risk_score":       self.risk_score,
            "category":         self.category,
            # MITRE
            "mitre_tags":       [t.to_dict() for t in self.mitre_tags],
            "mitre_ids":        self.technique_ids,
            "tactic_names":     self.tactic_names,
            # source identity â€” all four fields now included
            "source_file":      self.source_file,
            "source_ip":        self.source_ip,
            "dest_ip":          self.dest_ip,
            "username":         self.username,
            "hostname":         self.hostname,
            "process_name":     self.process_name,
            "event_id":         self.event_id,
            "timestamp":        self.timestamp.isoformat() if self.timestamp else None,
            # evidence â€” supporting_lines now included
            "trigger_line":     self.trigger_line,
            "trigger_lineno":   self.trigger_lineno,
            "supporting_lines": self.supporting_lines,
            # indicators / extra
            "indicators":       self.indicators,
            "extra":            self.extra,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        """
        Reconstruct a Finding from a to_dict() output.
        Needed by the storage layer when reading findings back from SQLite.
        """
        # Parse timestamp
        ts = None
        if d.get("timestamp"):
            try:
                ts = datetime.fromisoformat(d["timestamp"])
            except (ValueError, TypeError):
                pass

        # Parse MITRE tags â€” handle both old format (list of str) and new (list of dict)
        mitre_tags = []
        for t in d.get("mitre_tags", []):
            if isinstance(t, dict):
                mitre_tags.append(MitreTag.from_dict(t))
            # old format was plain strings â€” skip gracefully

        return cls(
            rule_id          = d.get("rule_id", ""),
            rule_name        = d.get("rule_name", ""),
            description      = d.get("description", ""),
            severity         = Severity[d.get("severity", "MEDIUM").upper()],
            confidence       = float(d.get("confidence", 0.0)),
            category         = d.get("category", "unknown"),
            mitre_tags       = mitre_tags,
            source_file      = d.get("source_file", ""),
            source_ip        = d.get("source_ip"),
            dest_ip          = d.get("dest_ip"),
            username         = d.get("username"),
            hostname         = d.get("hostname"),
            process_name     = d.get("process_name"),
            event_id         = d.get("event_id"),
            timestamp        = ts,
            trigger_line     = d.get("trigger_line", ""),
            trigger_lineno   = int(d.get("trigger_lineno", 0)),
            supporting_lines = d.get("supporting_lines", []),
            indicators       = d.get("indicators", {}),
            extra            = d.get("extra", {}),
        )

    def __repr__(self) -> str:
        ids = ", ".join(self.technique_ids)
        return (
            f"<Finding [{self.severity.value}] {self.rule_id} "
            f"conf={self.confidence:.0%} risk={self.risk_score} "
            f"src={self.source_ip or self.hostname or '?'} "
            f"mitre=[{ids}]>"
        )
