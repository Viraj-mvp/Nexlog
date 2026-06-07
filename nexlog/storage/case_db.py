"""
storage/case_db.py â€” NexLog Layer 3
SQLite-backed case database. Persists findings, evidence files,
analyst notes, attack chains, and session metadata.

Fixes vs draft version:
  - Self-locating sys.path (same walk-up logic as test_layer2.py)
  - verify_evidence: fixed broken 'from core.reader' import
  - save_findings: hostname/process_name/event_id explicitly indexed
    (they exist in payload_json already, now also in hot columns)
  - get_findings: filters by hostname added
  - get_findings_summary: also returns top attacker IPs and hostnames

Design:
  - Single SQLite file per case (.facase extension)
  - All Finding fields in JSON blob (payload_json) â€” no schema migration
    needed when Finding grows new fields
  - Indexed hot columns for fast filtered queries without JSON parsing
  - Chain-of-custody table: SHA-256 anchors every ingested file
  - Notes are append-only â€” forensic integrity
"""

import json
import os
import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# â”€â”€ Self-locating path resolution â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
sys.path.insert(0, os.path.join(_ROOT, 'detection'))
sys.path.insert(0, os.path.join(_ROOT, 'core'))

from finding import Finding   # noqa: E402

# â”€â”€ Schema â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_SCHEMA_VERSION = 6   # bumped: enterprise workflow tables

_DDL = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS case_meta (
    key     TEXT PRIMARY KEY,
    value   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id    TEXT PRIMARY KEY,
    created_at    TEXT NOT NULL,
    source_file   TEXT,
    sha256        TEXT,
    file_size     INTEGER,
    rules_loaded  INTEGER DEFAULT 0,
    entries_parsed INTEGER DEFAULT 0,
    notes         TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS findings (
    id            TEXT PRIMARY KEY,
    session_id    TEXT NOT NULL REFERENCES sessions(session_id),
    rule_id       TEXT NOT NULL,
    rule_name     TEXT NOT NULL,
    severity      TEXT NOT NULL,
    confidence    REAL NOT NULL,
    risk_score    REAL NOT NULL,
    category      TEXT NOT NULL,
    source_ip     TEXT,
    hostname      TEXT,
    username      TEXT,
    process_name  TEXT,
    event_id      TEXT,
    timestamp     TEXT,
    mitre_ids     TEXT,
    trigger_line  TEXT,
    payload_json  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_severity   ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_category   ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_source_ip  ON findings(source_ip);
CREATE INDEX IF NOT EXISTS idx_findings_hostname   ON findings(hostname);
CREATE INDEX IF NOT EXISTS idx_findings_rule_id    ON findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_findings_session    ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_risk       ON findings(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_findings_session_ts ON findings(session_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_findings_session_sev ON findings(session_id, severity);
CREATE INDEX IF NOT EXISTS idx_findings_session_risk ON findings(session_id, risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_findings_session_source ON findings(session_id, source_ip);
CREATE INDEX IF NOT EXISTS idx_findings_session_rule ON findings(session_id, rule_id);
CREATE INDEX IF NOT EXISTS idx_findings_session_category ON findings(session_id, category);

CREATE TABLE IF NOT EXISTS evidence (
    id             TEXT PRIMARY KEY,
    session_id     TEXT NOT NULL REFERENCES sessions(session_id),
    file_path      TEXT NOT NULL,
    sha256         TEXT NOT NULL,
    file_size      INTEGER NOT NULL,
    ingested_at    TEXT NOT NULL,
    format         TEXT,
    lines_parsed   INTEGER DEFAULT 0,
    findings_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS notes (
    id         TEXT PRIMARY KEY,
    session_id TEXT REFERENCES sessions(session_id),
    created_at TEXT NOT NULL,
    analyst    TEXT DEFAULT 'analyst',
    note       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS case_journal (
    id            TEXT PRIMARY KEY,
    session_id    TEXT REFERENCES sessions(session_id) ON DELETE CASCADE,
    created_at    TEXT NOT NULL,
    analyst       TEXT DEFAULT 'analyst',
    title         TEXT DEFAULT '',
    body          TEXT NOT NULL,
    tags_json     TEXT NOT NULL DEFAULT '[]',
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS saved_views (
    id            TEXT PRIMARY KEY,
    session_id    TEXT REFERENCES sessions(session_id) ON DELETE CASCADE,
    created_at    TEXT NOT NULL,
    analyst       TEXT DEFAULT 'analyst',
    name          TEXT NOT NULL,
    view_type     TEXT NOT NULL,
    filters_json  TEXT NOT NULL DEFAULT '{}',
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS timeline_bookmarks (
    id            TEXT PRIMARY KEY,
    session_id    TEXT REFERENCES sessions(session_id) ON DELETE CASCADE,
    finding_id    TEXT REFERENCES findings(id) ON DELETE SET NULL,
    created_at    TEXT NOT NULL,
    analyst       TEXT DEFAULT 'analyst',
    label         TEXT NOT NULL,
    timestamp     TEXT,
    note          TEXT DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS attachment_metadata (
    id            TEXT PRIMARY KEY,
    session_id    TEXT REFERENCES sessions(session_id) ON DELETE CASCADE,
    created_at    TEXT NOT NULL,
    analyst       TEXT DEFAULT 'analyst',
    original_name TEXT NOT NULL,
    stored_path   TEXT NOT NULL,
    sha256        TEXT NOT NULL,
    size_bytes    INTEGER DEFAULT 0,
    media_type    TEXT DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS entity_risk_snapshots (
    id            TEXT PRIMARY KEY,
    session_id    TEXT REFERENCES sessions(session_id) ON DELETE CASCADE,
    created_at    TEXT NOT NULL,
    entity_kind   TEXT NOT NULL,
    entity_value  TEXT NOT NULL,
    risk_score    REAL NOT NULL,
    risk_band     TEXT NOT NULL,
    payload_json  TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_journal_session ON case_journal(session_id);
CREATE INDEX IF NOT EXISTS idx_saved_views_session ON saved_views(session_id);
CREATE INDEX IF NOT EXISTS idx_bookmarks_session ON timeline_bookmarks(session_id);
CREATE INDEX IF NOT EXISTS idx_attachments_session ON attachment_metadata(session_id);
CREATE INDEX IF NOT EXISTS idx_entity_risk_session ON entity_risk_snapshots(session_id);

CREATE TABLE IF NOT EXISTS attack_chains (
    id            TEXT PRIMARY KEY,
    session_id    TEXT NOT NULL REFERENCES sessions(session_id),
    chain_name    TEXT NOT NULL,
    source_ip     TEXT,
    categories    TEXT,
    finding_count INTEGER,
    max_risk      REAL,
    detected_at   TEXT NOT NULL,
    payload_json  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS analyst_actions (
    id            TEXT PRIMARY KEY,
    finding_id    TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    session_id    TEXT REFERENCES sessions(session_id) ON DELETE CASCADE,
    created_at    TEXT NOT NULL,
    analyst       TEXT NOT NULL DEFAULT 'analyst',
    action        TEXT NOT NULL,
    note          TEXT DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_actions_finding ON analyst_actions(finding_id);
CREATE INDEX IF NOT EXISTS idx_actions_session ON analyst_actions(session_id);
CREATE INDEX IF NOT EXISTS idx_actions_action  ON analyst_actions(action);
CREATE INDEX IF NOT EXISTS idx_actions_created ON analyst_actions(created_at);

CREATE TABLE IF NOT EXISTS analysis_jobs (
    job_id          TEXT PRIMARY KEY,
    session_id      TEXT,
    source_file     TEXT,
    status          TEXT NOT NULL,
    profile         TEXT DEFAULT 'balanced',
    phase           TEXT DEFAULT '',
    lines_parsed    INTEGER DEFAULT 0,
    line_number     INTEGER DEFAULT 1,
    findings_saved  INTEGER DEFAULT 0,
    byte_offset     INTEGER DEFAULT 0,
    source_size     INTEGER DEFAULT 0,
    source_mtime    REAL DEFAULT 0,
    source_fingerprint TEXT DEFAULT '',
    eta_seconds     REAL DEFAULT 0,
    error           TEXT DEFAULT '',
    created_at      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    metadata_json   TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_jobs_status ON analysis_jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_session ON analysis_jobs(session_id);
"""

_VALID_ANALYST_ACTIONS = {
    "new",
    "triaged",
    "escalated",
    "contained",
    "false_positive",
    "assigned",
    "note",
}


class CaseDB:
    """
    SQLite case database. One instance per analysis session.
    Context manager supported: with CaseDB("case.facase") as db: ...
    """

    def __init__(self, path: str | Path):
        self.path  = Path(path)
        self._conn: Optional[sqlite3.Connection] = None
        self.in_memory = str(path) == ":memory:"

    # â”€â”€ Lifecycle â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def open(self) -> "CaseDB":
        if str(self.path) != ":memory:" and self.path.parent != Path(""):
            self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            if str(self.path) == ":memory:":
                self._conn = sqlite3.connect(":memory:")
            else:
                uri = f"file:{self.path.resolve().as_posix()}?nolock=1"
                self._conn = sqlite3.connect(uri, uri=True)
            self._conn.row_factory = sqlite3.Row
            try:
                self._conn.executescript(
                    _DDL.replace("PRAGMA journal_mode = WAL;", "PRAGMA journal_mode = OFF;")
                )
            except sqlite3.OperationalError:
                # Some Windows/sandboxed folders reject WAL sidecar files.
                # Retry the same on-disk DB with DELETE journaling before
                # falling back to in-memory storage.
                self._conn.close()
                try:
                    if self.path.exists() and self.path.stat().st_size == 0:
                        self.path.unlink()
                except OSError:
                    pass
                uri = f"file:{self.path.resolve().as_posix()}?nolock=1"
                self._conn = sqlite3.connect(uri, uri=True)
                self._conn.row_factory = sqlite3.Row
                self._conn.executescript(
                    _DDL.replace("PRAGMA journal_mode = WAL;", "PRAGMA journal_mode = OFF;")
                )
        except sqlite3.OperationalError as exc:
            if str(self.path) == ":memory:":
                raise
            self.in_memory = True
            self._conn = sqlite3.connect(":memory:")
            self._conn.row_factory = sqlite3.Row
            self._conn.executescript(_DDL)
            self._conn.execute(
                "INSERT OR REPLACE INTO case_meta(key,value) VALUES(?,?)",
                ("storage_warning", f"file-backed database unavailable: {exc}"),
            )
        self._conn.commit()
        self._migrate_analysis_jobs()
        self._exec("INSERT OR REPLACE INTO case_meta(key,value) VALUES(?,?)",
                   ("schema_version", str(_SCHEMA_VERSION)))
        self._exec("INSERT OR IGNORE INTO case_meta(key,value) VALUES(?,?)",
                   ("created_at", _utcnow()))
        self._conn.commit()
        return self

    def _migrate_analysis_jobs(self) -> None:
        """Add job columns when opening older case databases."""
        for column, ddl in {
            "line_number": "ALTER TABLE analysis_jobs ADD COLUMN line_number INTEGER DEFAULT 1",
            "source_size": "ALTER TABLE analysis_jobs ADD COLUMN source_size INTEGER DEFAULT 0",
            "source_mtime": "ALTER TABLE analysis_jobs ADD COLUMN source_mtime REAL DEFAULT 0",
            "source_fingerprint": "ALTER TABLE analysis_jobs ADD COLUMN source_fingerprint TEXT DEFAULT ''",
        }.items():
            try:
                cols = [row["name"] for row in self._conn.execute("PRAGMA table_info(analysis_jobs)").fetchall()]
                if column not in cols:
                    self._conn.execute(ddl)
            except sqlite3.OperationalError:
                pass
        self._conn.commit()

    def close(self) -> None:
        if self._conn:
            conn = self._conn
            self._conn = None
            try:
                conn.commit()
            finally:
                conn.close()

    def __enter__(self) -> "CaseDB":
        return self.open()

    def __exit__(self, *_) -> None:
        self.close()

    # â”€â”€ Sessions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def create_session(
        self,
        source_file:    str = "",
        sha256:         str = "",
        file_size:      int = 0,
        rules_loaded:   int = 0,
        entries_parsed: int = 0,
        notes:          str = "",
    ) -> str:
        """Create a new analysis session. Returns session_id."""
        sid = str(uuid.uuid4())
        self._exec(
            """INSERT INTO sessions
               (session_id, created_at, source_file, sha256, file_size,
                rules_loaded, entries_parsed, notes)
               VALUES (?,?,?,?,?,?,?,?)""",
            (sid, _utcnow(), source_file, sha256, file_size,
             rules_loaded, entries_parsed, notes)
        )
        self._conn.commit()
        return sid

    def get_session(self, session_id: str) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT * FROM sessions WHERE session_id=?", (session_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_sessions(self) -> list[dict]:
        return [dict(r) for r in self._conn.execute(
            "SELECT * FROM sessions ORDER BY created_at DESC"
        ).fetchall()]

    def update_session(self, session_id: str, **kwargs) -> None:
        """Update scalar fields on a session row."""
        allowed = {"source_file", "sha256", "file_size",
                   "rules_loaded", "entries_parsed", "notes"}
        updates = {k: v for k, v in kwargs.items() if k in allowed}
        if not updates:
            return
        cols = ", ".join(f"{k}=?" for k in updates)
        self._exec(f"UPDATE sessions SET {cols} WHERE session_id=?",
                   (*updates.values(), session_id))
        self._conn.commit()

    # â”€â”€ Findings â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def save_findings(self, findings: list[Finding], session_id: str) -> int:
        """
        Persist Finding objects to SQLite.
        All fields from the updated Finding (hostname, process_name,
        event_id, supporting_lines, risk_score, tactic_names) are stored
        inside payload_json via to_dict(). Hot columns are indexed separately
        for fast queries without JSON parsing.
        """
        rows = []
        for f in findings:
            d = f.to_dict()          # includes all Layer 2 v2 fields
            fid = str(uuid.uuid4())
            setattr(f, "_db_id", fid)
            rows.append((
                fid,
                session_id,
                f.rule_id,
                f.rule_name,
                f.severity.value,
                round(f.confidence, 4),
                f.risk_score,        # property from updated finding.py
                f.category,
                f.source_ip,
                f.hostname,          # new field
                f.username,
                f.process_name,      # new field
                f.event_id,          # new field
                d.get("timestamp"),
                json.dumps(d.get("mitre_ids", [])),
                (f.trigger_line or "")[:2000],
                json.dumps(d),       # full blob including supporting_lines,
                                     # tactic_names, mitre_tags as dicts
            ))

        self._conn.executemany(
            """INSERT INTO findings
               (id, session_id, rule_id, rule_name, severity, confidence,
                risk_score, category, source_ip, hostname, username,
                process_name, event_id, timestamp, mitre_ids,
                trigger_line, payload_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            rows
        )
        self._conn.commit()
        return len(rows)

    def update_finding_payload(self, finding: Finding) -> bool:
        """Update a stored finding after async enrichment."""
        fid = getattr(finding, "_db_id", "")
        if not fid:
            return False
        d = finding.to_dict()
        cur = self._exec(
            """UPDATE findings
               SET confidence=?, risk_score=?, payload_json=?
               WHERE id=?""",
            (
                round(finding.confidence, 4),
                finding.risk_score,
                json.dumps(d),
                fid,
            ),
        )
        self._conn.commit()
        return cur.rowcount > 0

    def save_findings_batch(self, findings: list[Finding], session_id: str) -> int:
        """Persist one bounded batch of findings."""
        return self.save_findings(findings, session_id)

    def get_findings(
        self,
        session_id:     Optional[str] = None,
        min_severity:   Optional[str] = None,
        category:       Optional[str] = None,
        source_ip:      Optional[str] = None,
        hostname:       Optional[str] = None,
        rule_id:        Optional[str] = None,
        min_risk_score: float         = 0.0,
        limit:          int           = 1000,
        offset:         int           = 0,
    ) -> list[Finding]:
        """
        Query and reconstruct Finding objects.
        Filtering on min_severity is done after JSON deserialisation
        (uses Finding.severity.score()) so severity ordering is correct.
        All other filters use indexed columns.
        """
        _SEV = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

        where, params = [], []
        if session_id:
            where.append("session_id=?"); params.append(session_id)
        if category:
            where.append("category=?");   params.append(category)
        if source_ip:
            where.append("source_ip=?");  params.append(source_ip)
        if hostname:
            where.append("hostname=?");   params.append(hostname)
        if rule_id:
            where.append("rule_id=?");    params.append(rule_id)
        if min_risk_score > 0.0:
            where.append("risk_score>=?"); params.append(min_risk_score)

        sql = "SELECT id, payload_json FROM findings"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY risk_score DESC LIMIT ? OFFSET ?"
        params.extend([max(0, int(limit)), max(0, int(offset))])

        findings = []
        for row in self._conn.execute(sql, tuple(params)).fetchall():
            f = Finding.from_dict(json.loads(row["payload_json"]))
            setattr(f, "_db_id", row["id"])
            if min_severity:
                if f.severity.score() < _SEV.get(min_severity.upper(), 0):
                    continue
            findings.append(f)
        return findings

    def get_finding_row(self, finding_id: str) -> Optional[dict]:
        """Return the stored row for a finding, including payload JSON."""
        row = self._conn.execute(
            "SELECT * FROM findings WHERE id=?", (finding_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_findings_summary(self, session_id: Optional[str] = None) -> dict:
        """
        Aggregate stats using indexed columns â€” no JSON parsing.
        Returns severity breakdown, category breakdown, top attacker IPs,
        top hostnames, and max/avg risk scores.
        """
        w = "WHERE session_id=?" if session_id else ""
        p = (session_id,) if session_id else ()

        def _rows(sql): return self._conn.execute(sql, p).fetchall()

        by_sev = {r["severity"]: r["c"] for r in _rows(
            f"SELECT severity, COUNT(*) as c FROM findings {w} GROUP BY severity")}
        by_cat = {r["category"]: r["c"] for r in _rows(
            f"SELECT category, COUNT(*) as c FROM findings {w} "
            f"GROUP BY category ORDER BY c DESC")}
        w2 = (w + " AND " if w else "WHERE ")
        top_ips = [r["source_ip"] for r in _rows(
            f"SELECT source_ip, COUNT(*) as c FROM findings {w2}"
            f"source_ip IS NOT NULL GROUP BY source_ip "
            f"ORDER BY c DESC LIMIT 10") if r["source_ip"]]
        top_hosts = [r["hostname"] for r in _rows(
            f"SELECT hostname, COUNT(*) as c FROM findings {w2}"
            f"hostname IS NOT NULL GROUP BY hostname "
            f"ORDER BY c DESC LIMIT 10") if r["hostname"]]
        risk_row = self._conn.execute(
            f"SELECT COUNT(*) as c, MAX(risk_score) as mx, "
            f"AVG(risk_score) as av FROM findings {w}", p
        ).fetchone()

        return {
            "total":          risk_row["c"],
            "by_severity":    by_sev,
            "by_category":    by_cat,
            "top_source_ips": top_ips,
            "top_hostnames":  top_hosts,
            "max_risk_score": round(risk_row["mx"] or 0.0, 2),
            "avg_risk_score": round(risk_row["av"] or 0.0, 2),
        }

    # â”€â”€ Evidence / Chain of Custody â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def record_evidence(
        self,
        file_path:      str,
        sha256:         str,
        file_size:      int,
        session_id:     str = "",
        log_format:     str = "",
        lines_parsed:   int = 0,
        findings_count: int = 0,
    ) -> str:
        """
        Record an ingested evidence file for chain-of-custody.
        SHA-256 anchors the exact byte sequence â€” re-hashing later
        detects any modification.
        """
        eid = str(uuid.uuid4())
        self._exec(
            """INSERT INTO evidence
               (id, session_id, file_path, sha256, file_size,
                ingested_at, format, lines_parsed, findings_count)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (eid, session_id, str(file_path), sha256, file_size,
             _utcnow(), log_format, lines_parsed, findings_count)
        )
        self._conn.commit()
        return eid

    def update_evidence_stats(
        self,
        evidence_id: str,
        *,
        sha256: Optional[str] = None,
        lines_parsed: Optional[int] = None,
        findings_count: Optional[int] = None,
        log_format: Optional[str] = None,
    ) -> None:
        """Update evidence metadata after a streaming analysis completes."""
        updates = {}
        if sha256 is not None:
            updates["sha256"] = sha256
        if lines_parsed is not None:
            updates["lines_parsed"] = int(lines_parsed)
        if findings_count is not None:
            updates["findings_count"] = int(findings_count)
        if log_format is not None:
            updates["format"] = log_format
        if not updates:
            return
        cols = ", ".join(f"{key}=?" for key in updates)
        self._exec(f"UPDATE evidence SET {cols} WHERE id=?", (*updates.values(), evidence_id))
        self._conn.commit()

    def get_evidence(self, session_id: Optional[str] = None) -> list[dict]:
        w = "WHERE session_id=?" if session_id else ""
        p = (session_id,) if session_id else ()
        return [dict(r) for r in self._conn.execute(
            f"SELECT * FROM evidence {w} ORDER BY ingested_at DESC", p
        ).fetchall()]

    def verify_evidence(self, evidence_id: str) -> dict:
        """
        Re-hash the evidence file and compare with the stored SHA-256.
        Fixed: no longer uses broken 'from core.reader' import path.
        """
        import hashlib

        row = self._conn.execute(
            "SELECT * FROM evidence WHERE id=?", (evidence_id,)
        ).fetchone()
        checked_at = _utcnow()
        if not row:
            return {
                "verified": False,
                "status": "not_found",
                "checked_at": checked_at,
                "error": "evidence_id not found",
            }

        stored = row["sha256"]
        path   = row["file_path"]
        if not os.path.exists(path):
            return {
                "verified": False,
                "status": "missing",
                "checked_at": checked_at,
                "stored_hash": stored,
                "current_hash": "",
                "file_path": path,
                "error": f"file not found: {path}",
            }

        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        current = h.hexdigest()

        return {
            "verified":     current == stored,
            "status":       "verified" if current == stored else "changed",
            "checked_at":   checked_at,
            "stored_hash":  stored,
            "current_hash": current,
            "file_path":    path,
        }

    def verify_case_integrity(self, session_id: Optional[str] = None) -> dict:
        """
        Verify case integrity across the database and evidence records.
        This is intentionally read-only except for a SQLite checkpoint so the
        case-file hash reflects committed data when using WAL mode.
        """
        evidence = self.get_evidence(session_id=session_id)
        verifications = [self.verify_evidence(ev["id"]) for ev in evidence]
        status_counts = {
            "verified": sum(1 for v in verifications if v.get("status") == "verified"),
            "changed":  sum(1 for v in verifications if v.get("status") == "changed"),
            "missing":  sum(1 for v in verifications if v.get("status") == "missing"),
            "errors":   sum(1 for v in verifications
                            if v.get("status") in {"not_found"} or v.get("error")),
        }

        if status_counts["changed"] or status_counts["missing"]:
            status = "compromised"
        elif status_counts["errors"]:
            status = "warning"
        elif evidence:
            status = "trusted"
        else:
            status = "no_evidence"

        where = "WHERE session_id=?" if session_id else ""
        params = (session_id,) if session_id else ()
        finding_count = self._conn.execute(
            f"SELECT COUNT(*) AS n FROM findings {where}", params
        ).fetchone()["n"]
        session_count = (
            1 if session_id and self.get_session(session_id)
            else self._conn.execute("SELECT COUNT(*) AS n FROM sessions").fetchone()["n"]
        )
        action_count = self._conn.execute(
            f"SELECT COUNT(*) AS n FROM analyst_actions {where}", params
        ).fetchone()["n"]

        case_hash = ""
        if not self.in_memory and str(self.path) != ":memory:" and self.path.exists():
            try:
                self._conn.execute("PRAGMA wal_checkpoint(FULL)")
                self._conn.commit()
                case_hash = _sha256_file(self.path)
            except Exception:
                case_hash = ""

        return {
            "status": status,
            "session_id": session_id or "all",
            "checked_at": _utcnow(),
            "case_path": str(self.path),
            "case_sha256": case_hash,
            "session_count": session_count,
            "finding_count": finding_count,
            "evidence_count": len(evidence),
            "analyst_action_count": action_count,
            "verified_evidence": status_counts["verified"],
            "changed_evidence": status_counts["changed"],
            "missing_evidence": status_counts["missing"],
            "error_count": status_counts["errors"],
            "evidence_verifications": verifications,
        }

    # â”€â”€ Analyst Notes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def add_note(
        self,
        note:       str,
        session_id: str = "",
        analyst:    str = "analyst",
    ) -> str:
        """Append an analyst note. Immutable once written."""
        nid = str(uuid.uuid4())
        self._exec(
            "INSERT INTO notes(id,session_id,created_at,analyst,note) "
            "VALUES(?,?,?,?,?)",
            (nid, session_id, _utcnow(), analyst, note)
        )
        self._conn.commit()
        return nid

    def get_notes(self, session_id: Optional[str] = None) -> list[dict]:
        w = "WHERE session_id=?" if session_id else ""
        p = (session_id,) if session_id else ()
        return [dict(r) for r in self._conn.execute(
            f"SELECT * FROM notes {w} ORDER BY created_at ASC", p
        ).fetchall()]

    def add_journal_entry(
        self,
        body: str,
        *,
        title: str = "",
        session_id: str = "",
        analyst: str = "analyst",
        tags: Optional[list[str]] = None,
        metadata: Optional[dict] = None,
    ) -> str:
        """Add a durable case journal entry."""
        jid = str(uuid.uuid4())
        self._exec(
            """INSERT INTO case_journal
               (id, session_id, created_at, analyst, title, body,
                tags_json, metadata_json)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                jid, session_id or None, _utcnow(), analyst or "analyst",
                title or "", body,
                json.dumps(tags or []),
                json.dumps(metadata or {}, default=str),
            ),
        )
        self._conn.commit()
        return jid

    def get_journal(self, session_id: Optional[str] = None) -> list[dict]:
        """Return case journal entries newest first."""
        w = "WHERE session_id=?" if session_id else ""
        p = (session_id,) if session_id else ()
        rows = self._conn.execute(
            f"SELECT * FROM case_journal {w} ORDER BY created_at DESC", p
        ).fetchall()
        out = []
        for row in rows:
            d = dict(row)
            d["tags"] = _json_loads(d.pop("tags_json"), [])
            d["metadata"] = _json_loads(d.pop("metadata_json"), {})
            out.append(d)
        return out

    def save_view(
        self,
        name: str,
        view_type: str,
        filters: dict,
        *,
        session_id: str = "",
        analyst: str = "analyst",
        metadata: Optional[dict] = None,
    ) -> str:
        """Persist a saved investigation view/filter."""
        vid = str(uuid.uuid4())
        self._exec(
            """INSERT INTO saved_views
               (id, session_id, created_at, analyst, name, view_type,
                filters_json, metadata_json)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                vid, session_id or None, _utcnow(), analyst or "analyst",
                name, view_type,
                json.dumps(filters or {}, default=str),
                json.dumps(metadata or {}, default=str),
            ),
        )
        self._conn.commit()
        return vid

    def get_saved_views(self, session_id: Optional[str] = None) -> list[dict]:
        w = "WHERE session_id=?" if session_id else ""
        p = (session_id,) if session_id else ()
        rows = self._conn.execute(
            f"SELECT * FROM saved_views {w} ORDER BY created_at DESC", p
        ).fetchall()
        out = []
        for row in rows:
            d = dict(row)
            d["filters"] = _json_loads(d.pop("filters_json"), {})
            d["metadata"] = _json_loads(d.pop("metadata_json"), {})
            out.append(d)
        return out

    def add_timeline_bookmark(
        self,
        label: str,
        *,
        session_id: str = "",
        finding_id: str = "",
        timestamp: str = "",
        analyst: str = "analyst",
        note: str = "",
        metadata: Optional[dict] = None,
    ) -> str:
        """Bookmark an event/finding for timeline investigation."""
        bid = str(uuid.uuid4())
        self._exec(
            """INSERT INTO timeline_bookmarks
               (id, session_id, finding_id, created_at, analyst, label,
                timestamp, note, metadata_json)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                bid, session_id or None, finding_id or None, _utcnow(),
                analyst or "analyst", label, timestamp or None, note or "",
                json.dumps(metadata or {}, default=str),
            ),
        )
        self._conn.commit()
        return bid

    def get_timeline_bookmarks(self, session_id: Optional[str] = None) -> list[dict]:
        w = "WHERE session_id=?" if session_id else ""
        p = (session_id,) if session_id else ()
        rows = self._conn.execute(
            f"SELECT * FROM timeline_bookmarks {w} ORDER BY created_at DESC", p
        ).fetchall()
        out = []
        for row in rows:
            d = dict(row)
            d["metadata"] = _json_loads(d.pop("metadata_json"), {})
            out.append(d)
        return out

    # SOC analyst actions are append-only. Current finding state is derived
    # from the newest state-bearing action instead of mutating the finding row.

    def add_analyst_action(
        self,
        finding_id: str,
        action: str,
        analyst: str = "analyst",
        note: str = "",
        metadata: Optional[dict] = None,
    ) -> str:
        """Append a SOC triage action for a finding and return action id."""
        action = (action or "").strip().lower()
        if action not in _VALID_ANALYST_ACTIONS:
            raise ValueError(
                "action must be one of: " + ", ".join(sorted(_VALID_ANALYST_ACTIONS))
            )
        row = self._conn.execute(
            "SELECT id, session_id FROM findings WHERE id=?", (finding_id,)
        ).fetchone()
        if not row:
            raise KeyError(f"finding_id not found: {finding_id}")

        aid = str(uuid.uuid4())
        self._exec(
            """INSERT INTO analyst_actions
               (id, finding_id, session_id, created_at, analyst, action,
                note, metadata_json)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                aid,
                finding_id,
                row["session_id"],
                _utcnow(),
                analyst or "analyst",
                action,
                note or "",
                json.dumps(metadata or {}, default=str),
            ),
        )
        self._conn.commit()
        return aid

    def get_analyst_actions(
        self,
        finding_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> list[dict]:
        """Return analyst actions in append-only chronological order."""
        where, params = [], []
        if finding_id:
            where.append("finding_id=?"); params.append(finding_id)
        if session_id:
            where.append("session_id=?"); params.append(session_id)
        clause = "WHERE " + " AND ".join(where) if where else ""
        rows = self._conn.execute(
            f"SELECT * FROM analyst_actions {clause} ORDER BY created_at ASC",
            tuple(params),
        ).fetchall()
        actions = []
        for row in rows:
            d = dict(row)
            try:
                d["metadata"] = json.loads(d.pop("metadata_json") or "{}")
            except Exception:
                d["metadata"] = {}
            actions.append(d)
        return actions

    def get_finding_state(self, finding_id: str) -> str:
        """Return the current derived SOC state for a finding."""
        rows = self.get_analyst_actions(finding_id=finding_id)
        for action in reversed(rows):
            if action["action"] in {
                "new", "triaged", "escalated", "contained", "false_positive"
            }:
                return action["action"]
        return "new"

    # â”€â”€ Attack Chains â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def save_attack_chains(self, chains: list[dict], session_id: str) -> int:
        rows = []
        for c in chains:
            rows.append((
                str(uuid.uuid4()), session_id,
                c.get("chain_name", ""),
                c.get("source_ip"),
                json.dumps(c.get("categories", [])),
                c.get("finding_count", 0),
                c.get("max_risk_score", 0.0),
                _utcnow(),
                json.dumps(c),
            ))
        self._conn.executemany(
            """INSERT INTO attack_chains
               (id, session_id, chain_name, source_ip, categories,
                finding_count, max_risk, detected_at, payload_json)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            rows
        )
        self._conn.commit()
        return len(rows)

    def get_attack_chains(self, session_id: Optional[str] = None) -> list[dict]:
        w = "WHERE session_id=?" if session_id else ""
        p = (session_id,) if session_id else ()
        return [json.loads(r["payload_json"]) for r in self._conn.execute(
            f"SELECT payload_json FROM attack_chains {w} ORDER BY max_risk DESC", p
        ).fetchall()]

    # â”€â”€ Case metadata â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def set_meta(self, key: str, value: str) -> None:
        self._exec("INSERT OR REPLACE INTO case_meta(key,value) VALUES(?,?)",
                   (key, value))
        self._conn.commit()

    def get_meta(self, key: str) -> Optional[str]:
        row = self._conn.execute(
            "SELECT value FROM case_meta WHERE key=?", (key,)
        ).fetchone()
        return row["value"] if row else None

    def get_all_meta(self) -> dict:
        return {r["key"]: r["value"] for r in self._conn.execute(
            "SELECT key,value FROM case_meta"
        ).fetchall()}

    # â”€â”€ Search â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def search_findings(
        self,
        query:      str,
        session_id: Optional[str] = None,
        limit:      int           = 200,
    ) -> list["Finding"]:
        """
        Full-text search across trigger_line, rule_name, and rule_id.
        Uses LIKE on the hot trigger_line column and the payload_json blob.
        Both indexed columns (rule_id, severity) and text search are
        combined so the query planner can use an index for the session
        filter while SQLite scans only that session's rows for the LIKE.

        Args:
            query:      Search string â€” matched case-insensitively as
                        a substring (%query%).
            session_id: Restrict to one session (recommended for speed).
            limit:      Maximum rows to return.

        Returns:
            list[Finding] â€” same type as get_findings().
        """
        import json as _json
        pat = f"%{query}%"
        where_parts = ["(LOWER(trigger_line) LIKE LOWER(?) "
                       "OR LOWER(rule_name) LIKE LOWER(?) "
                       "OR LOWER(rule_id)    LIKE LOWER(?))"]
        params: list = [pat, pat, pat]
        if session_id:
            where_parts.insert(0, "session_id = ?")
            params.insert(0, session_id)

        sql = (
            "SELECT payload_json FROM findings "
            f"WHERE {' AND '.join(where_parts)} "
            f"ORDER BY risk_score DESC LIMIT ?"
        )
        params.append(limit)
        rows = self._conn.execute(sql, params).fetchall()
        findings = []
        for row in rows:
            try:
                findings.append(Finding.from_dict(_json.loads(row["payload_json"])))
            except Exception:
                pass
        return findings

    # â”€â”€ Timeline â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def get_timeline(
        self,
        session_id:   Optional[str] = None,
        min_severity: Optional[str] = None,
        start:        Optional[str] = None,
        end:          Optional[str] = None,
        limit:        int           = 500,
        offset:       int           = 0,
    ) -> list[dict]:
        """
        Return a timestamp-sorted event list suitable for timeline rendering.
        Each entry is a compact dict (not a full Finding) to keep serialisation
        lightweight for the web UI.

        Args:
            session_id:   Optional session filter.
            min_severity: Minimum severity threshold (same ordering as Severity enum).
            start:        ISO-8601 start timestamp (inclusive).
            end:          ISO-8601 end timestamp (inclusive).
            limit:        Maximum rows (default 500).

        Returns:
            list[dict] â€” keys: rule_id, rule_name, severity, risk_score,
                         source_ip, hostname, category, timestamp, mitre_ids.
                         Sorted by timestamp ASC, nulls last.
        """
        _SEV_ORDER = ("INFO","LOW","MEDIUM","HIGH","CRITICAL")
        where  = ["timestamp IS NOT NULL"]
        params: list = []

        if session_id:
            where.append("session_id = ?"); params.append(session_id)
        if min_severity and min_severity.upper() in _SEV_ORDER:
            idx = _SEV_ORDER.index(min_severity.upper())
            sevs = _SEV_ORDER[idx:]
            placeholders = ",".join("?" * len(sevs))
            where.append(f"severity IN ({placeholders})")
            params.extend(sevs)
        if start:
            where.append("timestamp >= ?"); params.append(start)
        if end:
            where.append("timestamp <= ?"); params.append(end)

        sql = (
            "SELECT rule_id, rule_name, severity, risk_score, "
            "       source_ip, hostname, category, timestamp, mitre_ids "
            "FROM findings "
            f"WHERE {' AND '.join(where)} "
            "ORDER BY timestamp ASC NULLS LAST "
            "LIMIT ? OFFSET ?"
        )
        params.append(limit)
        params.append(max(0, int(offset)))
        rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def upsert_analysis_job(
        self,
        job_id: str,
        *,
        session_id: str = "",
        source_file: str = "",
        status: str = "running",
        profile: str = "balanced",
        phase: str = "",
        lines_parsed: int = 0,
        line_number: int = 1,
        findings_saved: int = 0,
        byte_offset: int = 0,
        source_size: int = 0,
        source_mtime: float = 0.0,
        source_fingerprint: str = "",
        eta_seconds: float = 0.0,
        error: str = "",
        metadata: Optional[dict] = None,
    ) -> None:
        """Persist resumable/progressive analysis job state."""
        now = _utcnow()
        metadata_json = json.dumps(metadata or {}, default=str)
        self._exec(
            """INSERT INTO analysis_jobs
               (job_id, session_id, source_file, status, profile, phase,
                lines_parsed, line_number, findings_saved, byte_offset,
                source_size, source_mtime, source_fingerprint, eta_seconds,
                error, created_at, updated_at, metadata_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(job_id) DO UPDATE SET
                 session_id=excluded.session_id,
                 source_file=excluded.source_file,
                 status=excluded.status,
                 profile=excluded.profile,
                 phase=excluded.phase,
                 lines_parsed=excluded.lines_parsed,
                 line_number=excluded.line_number,
                 findings_saved=excluded.findings_saved,
                 byte_offset=excluded.byte_offset,
                 source_size=excluded.source_size,
                 source_mtime=excluded.source_mtime,
                 source_fingerprint=excluded.source_fingerprint,
                 eta_seconds=excluded.eta_seconds,
                 error=excluded.error,
                 updated_at=excluded.updated_at,
                 metadata_json=excluded.metadata_json""",
            (
                job_id, session_id, source_file, status, profile, phase,
                int(lines_parsed), int(line_number), int(findings_saved),
                int(byte_offset), int(source_size), float(source_mtime),
                source_fingerprint or "", float(eta_seconds), error or "",
                now, now, metadata_json,
            ),
        )
        self._conn.commit()

    def get_analysis_job(self, job_id: str) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT * FROM analysis_jobs WHERE job_id=?", (job_id,)
        ).fetchone()
        if not row:
            return None
        data = dict(row)
        try:
            data["metadata"] = json.loads(data.pop("metadata_json") or "{}")
        except Exception:
            data["metadata"] = {}
        return data

    # â”€â”€ Session management â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def delete_session(self, session_id: str) -> dict:
        """
        Delete a session and all its associated data:
          findings, evidence, notes, attack_chains.

        Evidence files on disk are NOT deleted â€” only the DB records.
        Returns a dict with counts of deleted rows per table.
        """
        deleted = {}
        action_cols = {
            row["name"] for row in self._conn.execute("PRAGMA table_info(analyst_actions)").fetchall()
        }
        if "session_id" in action_cols:
            cur = self._conn.execute(
                "DELETE FROM analyst_actions WHERE finding_id IN "
                "(SELECT id FROM findings WHERE session_id=?) OR session_id=?",
                (session_id, session_id),
            )
        else:
            cur = self._conn.execute(
                "DELETE FROM analyst_actions WHERE finding_id IN "
                "(SELECT id FROM findings WHERE session_id=?)",
                (session_id,),
            )
        deleted["analyst_actions"] = cur.rowcount
        for table in ("attack_chains", "notes", "evidence", "findings", "analysis_jobs"):
            cur = self._conn.execute(
                f"DELETE FROM {table} WHERE session_id=?", (session_id,))
            deleted[table] = cur.rowcount
        cur = self._conn.execute(
            "DELETE FROM sessions WHERE session_id=?", (session_id,))
        deleted["sessions"] = cur.rowcount
        self._conn.commit()
        return deleted

    # â”€â”€ Finding tags â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def tag_finding(
        self,
        finding_id: str,
        tags:       list[str],
        analyst:    str = "analyst",
    ) -> bool:
        """
        Attach analyst-supplied tags to a finding.
        Tags are stored as a note with a special prefix:
          _finding_tags:<finding_id>:<tag1>,<tag2>,...
        The session_id is set to empty string (no FK violation).

        Returns True if the finding exists and tags were saved.
        """
        row = self._conn.execute(
            "SELECT id FROM findings WHERE id=?", (finding_id,)
        ).fetchone()
        if not row:
            return False
        tag_note = f"_finding_tags:{finding_id}:" + ",".join(tags)
        nid = str(uuid.uuid4())
        self._exec(
            "INSERT INTO notes(id,session_id,created_at,analyst,note) "
            "VALUES(?,NULL,?,?,?)",
            (nid, _utcnow(), analyst, tag_note)
        )
        self._conn.commit()
        return True

    def get_finding_tags(self, finding_id: str) -> list[str]:
        """
        Retrieve analyst-supplied tags for a finding.
        Returns a deduplicated list of tag strings.
        """
        prefix = f"_finding_tags:{finding_id}:"
        rows = self._conn.execute(
            "SELECT note FROM notes WHERE note LIKE ?",
            (prefix + "%",)
        ).fetchall()
        tags: list[str] = []
        for row in rows:
            raw = row["note"][len(prefix):]
            tags.extend(t.strip() for t in raw.split(",") if t.strip())
        return list(dict.fromkeys(tags))  # deduplicate, preserve order

    # â”€â”€ Aggregate statistics â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def get_stats(
        self,
        session_id: Optional[str] = None,
        date_from:  Optional[str] = None,
        date_to:    Optional[str] = None,
    ) -> dict:
        """
        DB-wide (or session-scoped) aggregate statistics.
        All aggregations use indexed columns â€” no JSON parsing required.

        Returns:
            {
              total_findings:   int,
              total_sessions:   int,
              total_evidence:   int,
              by_severity:      {SEV: count},
              by_category:      {cat: count},
              top_source_ips:   [(ip, count), ...] top 10,
              top_hostnames:    [(host, count), ...] top 10,
              top_rules:        [(rule_id, count), ...] top 10,
              max_risk_score:   float,
              avg_risk_score:   float,
              date_range:       {min: str, max: str},
              attack_chains:    int,
            }
        """
        where_f: list[str] = []
        params_f: list     = []
        if session_id:
            where_f.append("session_id = ?"); params_f.append(session_id)
        if date_from:
            where_f.append("timestamp >= ?"); params_f.append(date_from)
        if date_to:
            where_f.append("timestamp <= ?"); params_f.append(date_to)
        where_clause = f"WHERE {' AND '.join(where_f)}" if where_f else ""

        def _agg(sql: str, params=None) -> list:
            return self._conn.execute(sql, params or params_f).fetchall()

        total = _agg(f"SELECT COUNT(*) AS n FROM findings {where_clause}")[0]["n"]
        by_sev = {r["severity"]: r["n"] for r in _agg(
            f"SELECT severity, COUNT(*) AS n FROM findings {where_clause} "
            "GROUP BY severity", params_f)}
        by_cat = {r["category"]: r["n"] for r in _agg(
            f"SELECT category, COUNT(*) AS n FROM findings {where_clause} "
            "GROUP BY category ORDER BY n DESC", params_f)}
        top_ips = [(r["source_ip"], r["n"]) for r in _agg(
            f"SELECT source_ip, COUNT(*) AS n FROM findings "
            f"{'WHERE ' + ' AND '.join(where_f + ['source_ip IS NOT NULL']) if where_f else 'WHERE source_ip IS NOT NULL'} "
            "GROUP BY source_ip ORDER BY n DESC LIMIT 10",
            params_f) if r["source_ip"]]
        top_hosts = [(r["hostname"], r["n"]) for r in _agg(
            f"SELECT hostname, COUNT(*) AS n FROM findings "
            f"{'WHERE ' + ' AND '.join(where_f + ['hostname IS NOT NULL']) if where_f else 'WHERE hostname IS NOT NULL'} "
            "GROUP BY hostname ORDER BY n DESC LIMIT 10",
            params_f) if r["hostname"]]
        top_rules = [(r["rule_id"], r["n"]) for r in _agg(
            f"SELECT rule_id, COUNT(*) AS n FROM findings {where_clause} "
            "GROUP BY rule_id ORDER BY n DESC LIMIT 10", params_f)]
        risk_row = _agg(
            f"SELECT MAX(risk_score) AS mx, AVG(risk_score) AS av, "
            f"       MIN(timestamp) AS mn, MAX(timestamp) AS mx_ts "
            f"FROM findings {where_clause}", params_f)[0]
        sess_count = self._conn.execute("SELECT COUNT(*) AS n FROM sessions").fetchone()["n"]
        ev_count   = self._conn.execute("SELECT COUNT(*) AS n FROM evidence").fetchone()["n"]
        chain_where = "WHERE session_id = ?" if session_id else ""
        chain_params = (session_id,) if session_id else ()
        chain_count = self._conn.execute(
            f"SELECT COUNT(*) AS n FROM attack_chains {chain_where}", chain_params
        ).fetchone()["n"]

        return {
            "total_findings":  total,
            "total_sessions":  sess_count,
            "total_evidence":  ev_count,
            "by_severity":     by_sev,
            "by_category":     by_cat,
            "top_source_ips":  top_ips,
            "top_hostnames":   top_hosts,
            "top_rules":       top_rules,
            "max_risk_score":  float(risk_row["mx"] or 0.0),
            "avg_risk_score":  float(risk_row["av"] or 0.0),
            "date_range":      {"min": risk_row["mn"] or "", "max": risk_row["mx_ts"] or ""},
            "attack_chains":   chain_count,
        }

    # â”€â”€ Case export / import â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def export_case(
        self,
        output_path: "str | Path",
        include_evidence_files: bool = False,
    ) -> "Path":
        """
        Export the case as a self-contained ZIP archive.

        Archive structure:
            case.facase           â€” copy of the SQLite database
            manifest.json         â€” metadata: sessions, counts, sha256 of DB
            evidence/             â€” original log files (if include_evidence_files=True)

        The archive is suitable for:
          - transferring cases between analysts
          - long-term archival
          - courtroom submission (pair with chain_of_custody.EvidenceLedger)

        Args:
            output_path:            Path to write the .zip archive.
            include_evidence_files: If True, copies original log files into
                                    the archive (increases size significantly).

        Returns:
            Path to the written ZIP file.
        """
        import json as _json
        import zipfile
        from pathlib import Path as _Path

        output_path = _Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Ensure all writes are flushed before copying
        self._conn.execute("PRAGMA wal_checkpoint(FULL)")
        self._conn.commit()

        db_sha256 = ""
        try:
            sys.path.insert(0, os.path.join(_ROOT, "storage"))
            from chain_of_custody import hash_file as _hash_file
            db_sha256 = _hash_file(self.path)
        except Exception:
            pass

        sessions  = self.list_sessions()
        stats     = self.get_stats()
        manifest  = {
            "nexlog_version": "1.0.0",
            "exported_at":  _utcnow(),
            "case_file":    str(self.path),
            "db_sha256":    db_sha256,
            "sessions":     len(sessions),
            "total_findings": stats["total_findings"],
            "total_evidence": stats["total_evidence"],
            "session_ids":  [s["session_id"] for s in sessions],
        }

        with zipfile.ZipFile(output_path, "w",
                             compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(self.path, "case.facase")
            zf.writestr("manifest.json",
                        _json.dumps(manifest, indent=2, default=str))

            if include_evidence_files:
                evidence_records = self.get_evidence()
                for ev in evidence_records:
                    fp = _Path(ev["file_path"])
                    if fp.exists():
                        zf.write(fp, f"evidence/{fp.name}")

        return output_path

    @classmethod
    def import_case(
        cls,
        archive_path: "str | Path",
        output_db:    "str | Path",
        overwrite:    bool = False,
    ) -> "tuple[CaseDB, dict]":
        """
        Restore a case database from a ZIP export.

        Args:
            archive_path: Path to the .zip file from export_case().
            output_db:    Where to write the restored .facase file.
            overwrite:    If False, raises FileExistsError if output_db exists.

        Returns:
            (CaseDB, manifest_dict) â€” open CaseDB ready for use
            and the manifest from the archive.
        """
        import json as _json
        import zipfile
        from pathlib import Path as _Path

        archive_path = _Path(archive_path)
        output_db    = _Path(output_db)

        if output_db.exists() and not overwrite:
            raise FileExistsError(
                f"{output_db} already exists. Pass overwrite=True to replace it.")

        with zipfile.ZipFile(archive_path, "r") as zf:
            names = zf.namelist()
            if "case.facase" not in names:
                raise ValueError(
                    "Archive does not contain case.facase â€” not a valid NexLog export")

            manifest = {}
            if "manifest.json" in names:
                manifest = _json.loads(zf.read("manifest.json").decode("utf-8"))

            output_db.parent.mkdir(parents=True, exist_ok=True)
            with zf.open("case.facase") as src, open(output_db, "wb") as dst:
                import shutil as _shutil
                _shutil.copyfileobj(src, dst)

        db = cls(output_db).open()
        return db, manifest

    # â”€â”€ Internal â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _exec(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        return self._conn.execute(sql, params)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_loads(raw: str, default):
    try:
        return json.loads(raw or "")
    except Exception:
        return default


def _sha256_file(path: str | Path) -> str:
    h = __import__("hashlib").sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
