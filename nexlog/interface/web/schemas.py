"""
interface/web/schemas.py - NexLog web schemas
Request / response schemas for the FastAPI web interface.

Design: written as stdlib dataclasses with to_dict() / from_dict()
so they work with or without Pydantic installed. When FastAPI is
available, each class can be used directly as a Pydantic BaseModel
because the field types and defaults are compatible.

If Pydantic IS installed, subclasses automatically become BaseModel
instances via the _pydantic_compat mixin below. This gives you:
  - Full OpenAPI schema generation in FastAPI
  - Request body validation
  - Response serialisation

If Pydantic is NOT installed, the dataclasses still work as plain
Python objects for testing and offline use.

Schema groups:
  Analysis        — AnalyseRequest, AnalyseResponse, SessionSummary
  Findings        — FindingSchema, FindingListResponse
  IOC             — IOCSchema, IOCListResponse
  Report          — ReportRequest, ReportResponse
  System          — HealthResponse, StatsResponse
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field, asdict
from typing import Optional

# ── Self-locating path ────────────────────────────────────────────────────

_root = os.path.dirname(os.path.abspath(__file__))
for _ in range(8):
    if os.path.isfile(os.path.join(_root, 'pathconfig.py')):
        break
    _root = os.path.dirname(_root)
if _root not in sys.path:
    sys.path.insert(0, _root)
from pathconfig import ROOT, add_root
add_root()
_ROOT = ROOT

# ── Optional Pydantic compatibility ──────────────────────────────────────
try:
    from pydantic import BaseModel, Field
    _HAS_PYDANTIC = True
    _Base = BaseModel
except ImportError:
    _HAS_PYDANTIC = False
    _Base = object  # falls back to plain dataclass


def _make_base():
    """Return BaseModel if pydantic available, else object."""
    return _Base


# ── Helpers ───────────────────────────────────────────────────────────────

def _clean(d: dict) -> dict:
    """Recursively remove None values for cleaner JSON output."""
    return {k: (_clean(v) if isinstance(v, dict) else v)
            for k, v in d.items() if v is not None}


# ══════════════════════════════════════════════════════════════════════════
# ANALYSIS SCHEMAS
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class AnalyseRequest:
    """
    POST /api/analyse — submit a log file for analysis.

    log_path:     Absolute path on the server to the log file.
    case_id:      Optional existing case DB to append to.
    min_severity: Filter threshold [INFO|LOW|MEDIUM|HIGH|CRITICAL].
    category:     Optional single-category filter.
    rules_dir:    Optional path to custom rules directory.
    analyst:      Analyst name for case attribution.
    run_chains:   Whether to run multi-stage attack chain detection.
    """
    log_path:     str            = ""
    log_paths:    list[str]      = field(default_factory=list)
    case_id:      Optional[str]  = None
    min_severity: str            = "LOW"
    category:     Optional[str]  = None
    rules_dir:    Optional[str]  = None
    analyst:      str            = "analyst"
    run_chains:   bool           = True
    profile:      str            = "balanced"
    batch_size:   int            = 5000
    no_enrich:    bool           = False
    defer_graph:  bool           = False
    max_line_bytes: Optional[int] = None

    def to_dict(self) -> dict:
        return _clean(asdict(self))

    @classmethod
    def from_dict(cls, d: dict) -> "AnalyseRequest":
        return cls(**{k: v for k, v in d.items()
                      if k in cls.__dataclass_fields__})

    def validate(self) -> list[str]:
        """Return list of validation errors (empty = valid)."""
        errors = []
        paths = self.log_paths or ([self.log_path] if self.log_path else [])
        if not paths:
            errors.append("log_path or log_paths is required")
        valid_sevs = {"INFO","LOW","MEDIUM","HIGH","CRITICAL"}
        if self.min_severity.upper() not in valid_sevs:
            errors.append(f"min_severity must be one of {valid_sevs}")
        if self.profile not in {"fast", "balanced", "deep"}:
            errors.append("profile must be one of fast, balanced, deep")
        if int(self.batch_size or 0) < 1:
            errors.append("batch_size must be >= 1")
        return errors


@dataclass
class SessionSummary:
    """Compact summary of one analysis session."""
    session_id:     str
    source_file:    str
    created_at:     str
    total_findings: int
    critical:       int
    high:           int
    max_risk_score: float
    avg_risk_score: float
    top_source_ips: list[str]  = field(default_factory=list)
    top_hostnames:  list[str]  = field(default_factory=list)
    attack_chains:  int        = 0
    sha256:         str        = ""

    def to_dict(self) -> dict:
        return _clean(asdict(self))

    @classmethod
    def from_db(cls, session: dict, summary: dict) -> "SessionSummary":
        """Build from a CaseDB session row + get_findings_summary() dict."""
        by_sev = summary.get("by_severity", {})
        return cls(
            session_id     = session.get("session_id", ""),
            source_file    = session.get("source_file", ""),
            created_at     = session.get("created_at", ""),
            total_findings = summary.get("total", 0),
            critical       = by_sev.get("CRITICAL", 0),
            high           = by_sev.get("HIGH", 0),
            max_risk_score = summary.get("max_risk_score", 0.0),
            avg_risk_score = summary.get("avg_risk_score", 0.0),
            top_source_ips = summary.get("top_source_ips", []),
            top_hostnames  = summary.get("top_hostnames", []),
            sha256         = session.get("sha256", ""),
        )


@dataclass
class AnalyseResponse:
    """Response from POST /api/analyse."""
    success:     bool
    session_id:  str             = ""
    session_ids: list[str]       = field(default_factory=list)
    case_path:   str             = ""
    summary:     Optional[SessionSummary] = None
    summaries:   list[SessionSummary] = field(default_factory=list)
    error:       Optional[str]   = None
    duration_ms: int             = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        if self.summary:
            d["summary"] = self.summary.to_dict()
        if self.summaries:
            d["summaries"] = [item.to_dict() for item in self.summaries]
        return _clean(d)


# ══════════════════════════════════════════════════════════════════════════
# FINDING SCHEMAS
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class MitreTagSchema:
    """MITRE ATT&CK technique tag."""
    tactic_id:      str
    tactic_name:    str
    technique_id:   str
    technique_name: str
    full_id:        str
    sub_technique:  Optional[str] = None

    def to_dict(self) -> dict:
        return _clean(asdict(self))

    @classmethod
    def from_finding_tag(cls, tag) -> "MitreTagSchema":
        return cls(
            tactic_id      = tag.tactic_id,
            tactic_name    = tag.tactic_name,
            technique_id   = tag.technique_id,
            technique_name = tag.technique_name,
            full_id        = tag.full_id,
            sub_technique  = tag.sub_technique,
        )


@dataclass
class FindingSchema:
    """
    Full Finding representation for API responses.
    Maps directly from Finding.to_dict() with camelCase aliases
    for frontend compatibility.
    """
    rule_id:         str
    rule_name:       str
    description:     str
    severity:        str
    confidence:      float
    risk_score:      float
    category:        str
    finding_id:      Optional[str]        = None
    triage_state:    str                  = "new"
    source_ip:       Optional[str]        = None
    dest_ip:         Optional[str]        = None
    hostname:        Optional[str]        = None
    username:        Optional[str]        = None
    process_name:    Optional[str]        = None
    event_id:        Optional[str]        = None
    timestamp:       Optional[str]        = None
    trigger_line:    Optional[str]        = None
    trigger_lineno:  Optional[int]        = None
    supporting_lines: list[str]           = field(default_factory=list)
    mitre_tags:      list[MitreTagSchema] = field(default_factory=list)
    technique_ids:   list[str]            = field(default_factory=list)
    tactic_names:    list[str]            = field(default_factory=list)
    indicators:      dict                 = field(default_factory=dict)
    source_file:     Optional[str]        = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["mitre_tags"] = [t.to_dict() for t in self.mitre_tags]
        return _clean(d)

    @classmethod
    def from_finding(cls, f) -> "FindingSchema":
        """Build from a Finding object."""
        return cls(
            rule_id         = f.rule_id,
            rule_name       = f.rule_name,
            description     = f.description or "",
            severity        = f.severity.value,
            confidence      = round(f.confidence, 4),
            risk_score      = f.risk_score,
            category        = f.category,
            finding_id      = getattr(f, "_db_id", None),
            triage_state    = getattr(f, "_triage_state", "new"),
            source_ip       = f.source_ip,
            dest_ip         = f.dest_ip,
            hostname        = f.hostname,
            username        = f.username,
            process_name    = f.process_name,
            event_id        = f.event_id,
            timestamp       = f.timestamp.isoformat() if f.timestamp else None,
            trigger_line    = f.trigger_line,
            trigger_lineno  = f.trigger_lineno,
            supporting_lines= f.supporting_lines,
            mitre_tags      = [MitreTagSchema.from_finding_tag(t)
                               for t in f.mitre_tags],
            technique_ids   = f.technique_ids,
            tactic_names    = f.tactic_names,
            indicators      = f.indicators,
            source_file     = f.source_file,
        )


@dataclass
class FindingListResponse:
    """Response from GET /api/findings."""
    findings:    list[FindingSchema]
    total:       int
    page:        int           = 1
    page_size:   int           = 50
    has_more:    bool          = False
    session_id:  Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "findings":   [f.to_dict() for f in self.findings],
            "total":      self.total,
            "page":       self.page,
            "page_size":  self.page_size,
            "has_more":   self.has_more,
            "session_id": self.session_id,
        }


# ══════════════════════════════════════════════════════════════════════════
# IOC SCHEMAS
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class IOCSchema:
    """Single IOC for API responses."""
    ioc_type:    str
    value:       str
    confidence:  float
    source_rule: str
    source_ip:   str            = ""
    timestamp:   str            = ""
    tags:        list[str]      = field(default_factory=list)

    def to_dict(self) -> dict:
        return _clean(asdict(self))

    @classmethod
    def from_ioc(cls, ioc) -> "IOCSchema":
        return cls(
            ioc_type    = ioc.ioc_type,
            value       = ioc.value,
            confidence  = round(ioc.confidence, 4),
            source_rule = ioc.source_rule,
            source_ip   = ioc.source_ip or "",
            timestamp   = ioc.timestamp or "",
            tags        = ioc.tags,
        )


@dataclass
class IOCListResponse:
    """Response from GET /api/iocs."""
    iocs:        list[IOCSchema]
    total:       int
    by_type:     dict[str, int] = field(default_factory=dict)
    session_id:  Optional[str]  = None

    def to_dict(self) -> dict:
        return {
            "iocs":       [i.to_dict() for i in self.iocs],
            "total":      self.total,
            "by_type":    self.by_type,
            "session_id": self.session_id,
        }


# ══════════════════════════════════════════════════════════════════════════
# REPORT SCHEMAS
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class ReportRequest:
    """POST /api/report — generate a report for a session."""
    session_id:     Optional[str] = None
    format:         str           = "json"   # json|text|markdown|pdf
    case_ref:       str           = "IR-UNKNOWN"
    analyst:        str           = "analyst"
    org:            str           = "NexLog"
    classification: str           = "TLP:AMBER"
    include_iocs:   bool          = True

    def to_dict(self) -> dict:
        return _clean(asdict(self))

    @classmethod
    def from_dict(cls, d: dict) -> "ReportRequest":
        return cls(**{k: v for k, v in d.items()
                      if k in cls.__dataclass_fields__})

    def validate(self) -> list[str]:
        errors = []
        valid_fmts = {"json","text","markdown","pdf"}
        if self.format not in valid_fmts:
            errors.append(f"format must be one of {valid_fmts}")
        return errors


@dataclass
class ReportResponse:
    """Response from POST /api/report."""
    success:      bool
    format:       str            = ""
    content:      Optional[str]  = None   # text/markdown/json as string
    file_path:    Optional[str]  = None   # PDF path for download
    sha256:       Optional[str]  = None   # report artifact checksum
    size_bytes:   int            = 0
    error:        Optional[str]  = None

    def to_dict(self) -> dict:
        return _clean(asdict(self))


# ══════════════════════════════════════════════════════════════════════════
# SYSTEM SCHEMAS
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class HealthResponse:
    """GET /api/health — liveness + readiness check."""
    status:         str              # "ok" | "degraded" | "error"
    version:        str   = "1.0.0"
    rules_loaded:   int   = 0
    db_connected:   bool  = False
    uptime_seconds: int   = 0
    checks:         dict  = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class StatsResponse:
    """GET /api/stats — global detection statistics."""
    total_sessions:   int
    total_findings:   int
    total_iocs:       int
    rules_loaded:     int
    categories:       list[str]       = field(default_factory=list)
    top_rules:        list[dict]      = field(default_factory=list)
    severity_summary: dict[str, int]  = field(default_factory=dict)
    last_analysis:    Optional[str]   = None

    def to_dict(self) -> dict:
        return _clean(asdict(self))


@dataclass
class NoteRequest:
    """POST /api/notes — add an analyst note."""
    note:       str
    session_id: Optional[str] = None
    analyst:    str           = "analyst"

    def validate(self) -> list[str]:
        return [] if self.note.strip() else ["note cannot be empty"]


@dataclass
class ErrorResponse:
    """Standard error envelope for all 4xx/5xx responses."""
    error:   str
    detail:  Optional[str] = None
    code:    int           = 400

    def to_dict(self) -> dict:
        return _clean(asdict(self))


# ── Schema registry for OpenAPI doc generation ───────────────────────────
ALL_SCHEMAS = [
    AnalyseRequest, AnalyseResponse, SessionSummary,
    FindingSchema, FindingListResponse, MitreTagSchema,
    IOCSchema, IOCListResponse,
    ReportRequest, ReportResponse,
    HealthResponse, StatsResponse,
    NoteRequest, ErrorResponse,
]
