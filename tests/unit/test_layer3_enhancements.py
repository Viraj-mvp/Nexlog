"""
tests/unit/test_layer3_enhancements.py â€” NexLog Layer 3 Enhancements
Tests for every method added in this session:

CaseDB (8 methods):
  search_findings  â€” full-text substring search across trigger_line/rule_name/rule_id
  get_timeline     â€” timestamp-sorted event list, min_severity + date range filters
  get_stats        â€” DB-wide aggregated statistics using indexed columns only
  tag_finding      â€” attach analyst tags to a finding (stored as note, FK-safe)
  get_finding_tags â€” retrieve analyst tags for a finding
  delete_session   â€” cascade delete session + all associated data
  export_case      â€” ZIP archive of case.facase + manifest.json
  import_case      â€” restore a case database from a ZIP export

IOC / IOCExtractor (6 methods):
  IOC.from_dict           â€” deserialise from to_dict() output
  IOC.to_stix_indicator   â€” single STIX 2.1 indicator object per IOC
  IOCExtractor.filter     â€” multi-criteria filter (type, confidence, rule, tag, private)
  IOCExtractor.deduplicateâ€” public dedup by (type, value.lower()), highest confidence wins
  IOCExtractor.merge      â€” merge N IOC lists with deduplication
  IOCExtractor.enrich     â€” inline GeoIP/AbuseIPDB tag enrichment (graceful degradation)

EvidenceLedger (2 methods):
  merge   â€” merge another ledger, skip SHA-256 duplicates, reject HMAC-tampered sources
  summary â€” compact integrity + metadata summary

Run: python test_layer3_enhancements.py  (from any directory)
"""

import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

# â”€â”€ Self-locating path â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
for _p in ['core', 'detection', 'storage', 'intelligence']:
    sys.path.insert(0, os.path.join(_ROOT, _p))

from finding import Finding, Severity, MitreTag
from case_db import CaseDB
from chain_of_custody import EvidenceLedger
from ioc_extractor import IOC, IOCExtractor

# â”€â”€ Test helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_passed = _failed = 0

def check(name: str, cond: bool, detail: str = "") -> None:
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  PASS  {name}")
    else:
        _failed += 1
        print(f"  FAIL  {name}" + (f"  [{detail}]" if detail else ""))

_TS = datetime(2026, 1, 4, 10, 0, 0, tzinfo=timezone.utc)
_TS2 = datetime(2026, 1, 4, 11, 0, 0, tzinfo=timezone.utc)
_TS3 = datetime(2026, 1, 4, 12, 0, 0, tzinfo=timezone.utc)

def _make_findings() -> list[Finding]:
    return [
        Finding("WEB-001", "SQL Injection", "SQLi in login endpoint",
                Severity.HIGH, 0.90, "web_attack",
                mitre_tags=[MitreTag("TA0001","Initial Access","T1190","Exploit",".001")],
                source_ip="203.0.113.5", hostname="web01",
                timestamp=_TS,
                trigger_line="GET /login?q=admin'+OR+1=1-- HTTP/1.1 200",
                supporting_lines=["http://evil.com/shell.php"]),

        Finding("AUTH-001", "SSH Brute Force", "5+ failed SSH attempts",
                Severity.CRITICAL, 0.95, "auth",
                mitre_tags=[MitreTag("TA0006","Credential Access","T1110","Brute Force",".001")],
                source_ip="185.220.100.5", hostname="bastion01",
                timestamp=_TS2,
                trigger_line="Failed password for root from 185.220.100.5 port 42222"),

        Finding("RECON-001", "Port Scan", "Nmap scan detected",
                Severity.MEDIUM, 0.80, "recon",
                mitre_tags=[MitreTag("TA0043","Reconnaissance","T1595","Active Scanning",None)],
                source_ip="9.9.9.9", hostname="web01",
                timestamp=_TS3,
                trigger_line="Nmap scan report for 10.0.0.0/24"),
    ]


def _populated_db(db_path: str) -> str:
    """Create a CaseDB with one session + findings. Returns session_id."""
    findings = _make_findings()
    with CaseDB(db_path) as db:
        sid = db.create_session(
            source_file="access.log", sha256="a"*64,
            file_size=204800, rules_loaded=162, entries_parsed=1500,
        )
        db.save_findings(findings, sid)
        db.record_evidence("access.log","a"*64,204800,sid,"apache",1500,3)
        db.add_note("Suspicious lateral movement detected", sid, "Jane Smith")
        db.save_attack_chains([{
            "chain_name":     "Full Compromise",
            "source_ip":      "203.0.113.5",
            "categories":     ["recon","web_attack"],
            "finding_count":  2,
            "max_risk_score": 8.5,
            "confidence_boost": 0.15,
        }], sid)
    return sid


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 1. CaseDB.search_findings
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_search_findings():
    print("\nâ”€â”€ 1. CaseDB.search_findings â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f:
        db_path = f.name
    sid = _populated_db(db_path)
    try:
        with CaseDB(db_path) as db:
            # Exact substring in trigger_line
            r = db.search_findings("admin'+OR+1=1")
            check("finds SQLi by trigger_line",   len(r) == 1)
            check("correct rule_id returned",      r[0].rule_id == "WEB-001")

            # Case-insensitive (LOWER on both sides)
            r2 = db.search_findings("NMAP")
            check("case-insensitive search",       len(r2) == 1)
            check("NMAP â†’ RECON-001",              r2[0].rule_id == "RECON-001")

            # Match in rule_name
            r3 = db.search_findings("Brute Force")
            check("matches rule_name",             len(r3) == 1)
            check("Brute Force â†’ AUTH-001",        r3[0].rule_id == "AUTH-001")

            # Match in rule_id
            r4 = db.search_findings("WEB-", session_id=sid)
            check("matches rule_id prefix",        len(r4) == 1)

            # Session-scoped
            r5 = db.search_findings("failed password", session_id=sid)
            check("session_id filter works",       len(r5) == 1)

            # No match
            r6 = db.search_findings("XXXXXXX_NO_MATCH")
            check("no-match returns empty list",   len(r6) == 0)

            # Limit respected
            r7 = db.search_findings("", limit=2)
            check("limit parameter respected",     len(r7) <= 2)

    finally:
        os.unlink(db_path)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 2. CaseDB.get_timeline
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_get_timeline():
    print("\nâ”€â”€ 2. CaseDB.get_timeline â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f:
        db_path = f.name
    sid = _populated_db(db_path)
    try:
        with CaseDB(db_path) as db:
            tl = db.get_timeline(session_id=sid)
            check("returns 3 events",             len(tl) == 3)
            check("all have timestamp",            all("timestamp" in e for e in tl))
            check("all have rule_id",              all("rule_id" in e for e in tl))
            check("all have severity",             all("severity" in e for e in tl))
            check("all have risk_score",           all("risk_score" in e for e in tl))
            check("all have hostname",             all("hostname" in e for e in tl))
            check("all have category",             all("category" in e for e in tl))
            # Sorted ascending by timestamp
            ts_vals = [e["timestamp"] for e in tl]
            check("sorted by timestamp ASC",       ts_vals == sorted(ts_vals))

            # min_severity filter
            tl_hi = db.get_timeline(session_id=sid, min_severity="HIGH")
            check("min_severity HIGH â†’ 2 events", len(tl_hi) == 2)
            check("all HIGH or CRITICAL",
                  all(e["severity"] in ("HIGH","CRITICAL") for e in tl_hi))

            tl_crit = db.get_timeline(session_id=sid, min_severity="CRITICAL")
            check("min_severity CRITICAL â†’ 1",    len(tl_crit) == 1)

            # Limit
            tl_lim = db.get_timeline(session_id=sid, limit=2)
            check("limit=2 respected",            len(tl_lim) <= 2)

            # Date range
            start = _TS.isoformat()
            end   = _TS2.isoformat()
            tl_range = db.get_timeline(session_id=sid, start=start, end=end)
            check("date range: 2 events",         len(tl_range) == 2)

    finally:
        os.unlink(db_path)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 3. CaseDB.get_stats
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_get_stats():
    print("\nâ”€â”€ 3. CaseDB.get_stats â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f:
        db_path = f.name
    sid = _populated_db(db_path)
    try:
        with CaseDB(db_path) as db:
            # Session-scoped
            s = db.get_stats(session_id=sid)
            check("total_findings = 3",           s["total_findings"] == 3)
            check("total_sessions >= 1",           s["total_sessions"] >= 1)
            check("total_evidence >= 1",           s["total_evidence"] >= 1)
            check("max_risk_score > 0",            s["max_risk_score"] > 0)
            check("avg_risk_score > 0",            s["avg_risk_score"] > 0)
            check("by_severity has HIGH",          "HIGH" in s["by_severity"])
            check("by_severity has CRITICAL",      "CRITICAL" in s["by_severity"])
            check("by_severity counts sum to 3",
                  sum(s["by_severity"].values()) == 3)
            check("by_category has web_attack",    "web_attack" in s["by_category"])
            check("top_source_ips is list",        isinstance(s["top_source_ips"], list))
            check("top_hostnames is list",         isinstance(s["top_hostnames"], list))
            check("top_rules is list",             isinstance(s["top_rules"], list))
            check("date_range has min/max",
                  "min" in s["date_range"] and "max" in s["date_range"])
            check("attack_chains = 1",             s["attack_chains"] == 1)

            # IPs and hosts in top lists
            top_ips   = [ip for ip, _ in s["top_source_ips"]]
            top_hosts = [h for h, _ in s["top_hostnames"]]
            check("203.0.113.5 in top IPs",        "203.0.113.5" in top_ips)
            check("web01 in top hostnames",         "web01" in top_hosts)

            # Global (no session filter)
            g = db.get_stats()
            check("global total_findings = 3",     g["total_findings"] == 3)

    finally:
        os.unlink(db_path)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 4. CaseDB.tag_finding + get_finding_tags
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_tag_finding():
    print("\nâ”€â”€ 4. CaseDB.tag_finding / get_finding_tags â”€")
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f:
        db_path = f.name
    _populated_db(db_path)
    try:
        with CaseDB(db_path) as db:
            # Get a real finding ID
            findings = db.get_findings(limit=1)
            fid = db._conn.execute(
                "SELECT id FROM findings LIMIT 1").fetchone()["id"]

            # Tag it
            ok = db.tag_finding(fid, ["confirmed","escalate","critical_path"], "Jane")
            check("tag_finding returns True",       ok is True)

            tags = db.get_finding_tags(fid)
            check("confirmed in tags",              "confirmed" in tags)
            check("escalate in tags",               "escalate" in tags)
            check("critical_path in tags",          "critical_path" in tags)
            check("no duplicate tags",              len(tags) == len(set(tags)))

            # Add more tags â€” should merge
            db.tag_finding(fid, ["false_positive","confirmed"], "Bob")
            tags2 = db.get_finding_tags(fid)
            check("false_positive added",           "false_positive" in tags2)
            check("confirmed still present",        "confirmed" in tags2)
            check("deduplication works",
                  tags2.count("confirmed") == 1)

            # Non-existent finding
            ok2 = db.tag_finding("nonexistent-id-xyz", ["tag"])
            check("non-existent ID returns False",  ok2 is False)

            # Empty tags for untagged finding
            fid2_row = db._conn.execute(
                "SELECT id FROM findings ORDER BY rowid DESC LIMIT 1"
            ).fetchone()
            if fid2_row and fid2_row["id"] != fid:
                empty_tags = db.get_finding_tags(fid2_row["id"])
                check("untagged finding returns []", empty_tags == [])

    finally:
        os.unlink(db_path)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 5. CaseDB.delete_session
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_delete_session():
    print("\nâ”€â”€ 5. CaseDB.delete_session â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f:
        db_path = f.name
    sid = _populated_db(db_path)
    try:
        with CaseDB(db_path) as db:
            # Create a second session to delete
            sid2 = db.create_session(source_file="second.log")
            db.save_findings(_make_findings()[:2], sid2)
            db.add_note("Note for session 2", sid2, "Bob")
            db.save_attack_chains([{
                "chain_name": "Test Chain", "source_ip": "1.2.3.4",
                "categories": ["recon"], "finding_count": 1,
                "max_risk_score": 5.0, "confidence_boost": 0.1,
            }], sid2)

            # Verify it exists
            check("session 2 exists before delete",
                  db.get_session(sid2) is not None)
            check("session 2 has findings",
                  len(db.get_findings(session_id=sid2)) == 2)

            # Delete it
            deleted = db.delete_session(sid2)
            check("sessions deleted = 1",         deleted["sessions"] == 1)
            check("findings deleted = 2",          deleted["findings"] == 2)
            check("notes deleted >= 1",            deleted["notes"] >= 1)
            check("chains deleted = 1",            deleted["attack_chains"] == 1)

            # Verify gone
            check("session gone",                  db.get_session(sid2) is None)
            check("findings gone",
                  len(db.get_findings(session_id=sid2)) == 0)

            # Original session unaffected
            check("session 1 still exists",
                  db.get_session(sid) is not None)
            check("session 1 findings intact",
                  len(db.get_findings(session_id=sid)) == 3)

    finally:
        os.unlink(db_path)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 6. CaseDB.export_case + import_case
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_export_import_case():
    print("\nâ”€â”€ 6. CaseDB.export_case / import_case â”€â”€â”€â”€â”€â”€")
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f:
        db_path = f.name
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
        zip_path = f.name
    with tempfile.TemporaryDirectory() as tmpdir:
        restored_path = os.path.join(tmpdir, "restored.facase")
    restored_path2 = os.path.join(tempfile.mkdtemp(), "restored.facase")

    sid = _populated_db(db_path)
    try:
        with CaseDB(db_path) as db:
            exported = db.export_case(zip_path)
            check("export returns Path",           isinstance(exported, Path))
            check("ZIP file exists",               Path(zip_path).exists())
            zip_size = Path(zip_path).stat().st_size
            check("ZIP file non-empty",            zip_size > 1000,
                  f"size={zip_size}")

        # Verify ZIP structure
        import zipfile
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
            check("ZIP contains case.facase",      "case.facase" in names)
            check("ZIP contains manifest.json",    "manifest.json" in names)
            manifest = json.loads(zf.read("manifest.json"))
            check("manifest has sessions",         manifest.get("sessions", 0) >= 1)
            check("manifest has total_findings",   "total_findings" in manifest)
            check("manifest has db_sha256",        "db_sha256" in manifest)
            check("manifest has exported_at",      "exported_at" in manifest)

        # import_case
        restored_db, manifest2 = CaseDB.import_case(zip_path, restored_path2)
        check("import returns CaseDB",             isinstance(restored_db, CaseDB))
        check("manifest returned",                 isinstance(manifest2, dict))
        check("manifest sessions match",           manifest2.get("sessions", 0) >= 1)
        check("restored sessions non-empty",       len(restored_db.list_sessions()) >= 1)
        check("restored findings non-empty",       len(restored_db.get_findings()) >= 1)
        check("restored findings count",
              len(restored_db.get_findings()) == 3)
        restored_db.close()

        # overwrite=False raises FileExistsError
        try:
            CaseDB.import_case(zip_path, restored_path2, overwrite=False)
            check("overwrite=False raises",        False, "no exception raised")
        except FileExistsError:
            check("overwrite=False raises FileExistsError", True)

        # overwrite=True works
        rdb2, _ = CaseDB.import_case(zip_path, restored_path2, overwrite=True)
        check("overwrite=True succeeds",           len(rdb2.list_sessions()) >= 1)
        rdb2.close()

    finally:
        for p in [db_path, zip_path, restored_path2]:
            try: os.unlink(p)
            except: pass


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 7. IOC.from_dict
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_ioc_from_dict():
    print("\nâ”€â”€ 7. IOC.from_dict â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    ioc = IOC("ipv4", "203.0.113.5", 0.87, "WEB-001", "203.0.113.5",
               "2026-01-04T10:00:00Z", ["web_attack","T1190.001"])
    d   = ioc.to_dict()
    restored = IOC.from_dict(d)

    check("ioc_type round-trip",    restored.ioc_type    == ioc.ioc_type)
    check("value round-trip",       restored.value       == ioc.value)
    check("confidence round-trip",  restored.confidence  == ioc.confidence)
    check("source_rule round-trip", restored.source_rule == ioc.source_rule)
    check("source_ip round-trip",   restored.source_ip   == ioc.source_ip)
    check("timestamp round-trip",   restored.timestamp   == ioc.timestamp)
    check("tags round-trip",        restored.tags        == ioc.tags)

    # from_dict also handles 'ioc_type' key (not 'type')
    d2 = {"ioc_type":"domain","value":"evil.com","confidence":0.75,"tags":[]}
    i2 = IOC.from_dict(d2)
    check("handles ioc_type key",   i2.ioc_type == "domain")
    check("handles missing fields", i2.source_rule == "")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 8. IOC.to_stix_indicator
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_ioc_to_stix_indicator():
    print("\nâ”€â”€ 8. IOC.to_stix_indicator â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    _PATTERNS = {
        "ipv4":        "ipv4-addr:value",
        "domain":      "domain-name:value",
        "url":         "url:value",
        "hash_md5":    "file:hashes.MD5",
        "hash_sha1":   "file:hashes.'SHA-1'",
        "hash_sha256": "file:hashes.'SHA-256'",
        "file_path":   "file:name",
        "email":       "email-addr:value",
        "hostname":    "domain-name:value",
        "process":     "process:name",
        "user_agent":  "http-request-ext",
    }
    for ioc_type, pattern_fragment in _PATTERNS.items():
        ioc = IOC(ioc_type, "test_value", 0.85, "TEST-001")
        obj = ioc.to_stix_indicator()
        check(f"{ioc_type}: returns dict",        isinstance(obj, dict))
        check(f"{ioc_type}: type=indicator",      obj["type"] == "indicator")
        check(f"{ioc_type}: spec_version=2.1",    obj["spec_version"] == "2.1")
        check(f"{ioc_type}: id format",           obj["id"].startswith("indicator--"))
        check(f"{ioc_type}: pattern contains fragment",
              pattern_fragment in obj["pattern"])
        check(f"{ioc_type}: pattern_type=stix",   obj["pattern_type"] == "stix")
        check(f"{ioc_type}: confidence 0-100",    0 <= obj["confidence"] <= 100)
        check(f"{ioc_type}: indicator_types list",
              isinstance(obj["indicator_types"], list))

    # Optional fields
    ioc2 = IOC("ipv4", "1.2.3.4", 0.90, "R1")
    obj2 = ioc2.to_stix_indicator(
        created_by_ref="identity--abc123",
        tlp_id="marking--def456"
    )
    check("created_by_ref set",     obj2.get("created_by_ref") == "identity--abc123")
    check("object_marking_refs set",
          "marking--def456" in obj2.get("object_marking_refs", []))

    # Single-quote escaping in pattern
    ioc3 = IOC("domain", "evil's.com", 0.80, "R2")
    obj3 = ioc3.to_stix_indicator()
    check("single quotes escaped",  "\\'" in obj3["pattern"])

    # None for unknown type
    ioc4 = IOC("unknown_type", "val", 0.80, "R3")
    check("unknown type returns None", ioc4.to_stix_indicator() is None)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 9. IOCExtractor.filter
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_ioc_filter():
    print("\nâ”€â”€ 9. IOCExtractor.filter â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    iocs = [
        IOC("ipv4",   "1.2.3.4",     0.90, "WEB-001", "", "", ["web","T1190"]),
        IOC("ipv4",   "10.0.0.5",    0.85, "WEB-001", "", "", ["internal"]),  # private
        IOC("domain", "evil.com",    0.75, "WEB-001", "", "", ["domain"]),
        IOC("ipv4",   "5.5.5.5",     0.60, "AUTH-001","", "", ["auth"]),
        IOC("url",    "http://x.com",0.95, "WEB-001", "", "", ["url","T1071"]),
        IOC("domain", "good.com",    0.50, "AUTH-001","", "", ["auth"]),
    ]

    # Type filter
    r = IOCExtractor.filter(iocs, ioc_types=["ipv4"])
    check("type=ipv4: 3 results",        len(r) == 3)
    check("all ipv4",                    all(i.ioc_type == "ipv4" for i in r))

    r2 = IOCExtractor.filter(iocs, ioc_types=["domain","url"])
    check("type=[domain,url]: 3",        len(r2) == 3)

    # Confidence filter
    r3 = IOCExtractor.filter(iocs, min_confidence=0.90)
    check("confidence>=0.90: 2",         len(r3) == 2)
    check("all >= 0.90",                 all(i.confidence >= 0.90 for i in r3))

    # Source rule filter (substring)
    r4 = IOCExtractor.filter(iocs, source_rule="WEB")
    check("source_rule='WEB': 4",        len(r4) == 4)

    r5 = IOCExtractor.filter(iocs, source_rule="AUTH-001")
    check("source_rule='AUTH-001': 2",   len(r5) == 2)

    # Tag filter (substring)
    r6 = IOCExtractor.filter(iocs, has_tag="T1190")
    check("has_tag='T1190': 1",          len(r6) == 1)

    r7 = IOCExtractor.filter(iocs, has_tag="auth")
    check("has_tag='auth': 2",           len(r7) == 2)

    # Exclude private IPs
    r8 = IOCExtractor.filter(iocs, ioc_types=["ipv4"],
                             exclude_private_ips=True)
    check("exclude_private: 2 public",   len(r8) == 2)
    check("10.0.0.5 excluded",
          all(i.value != "10.0.0.5" for i in r8))

    # Combined filters
    r9 = IOCExtractor.filter(iocs, ioc_types=["ipv4"],
                             min_confidence=0.85,
                             exclude_private_ips=True)
    check("combined: 1 result",          len(r9) == 1)
    check("combined: 1.2.3.4",           r9[0].value == "1.2.3.4")

    # Empty source list
    r10 = IOCExtractor.filter([], ioc_types=["ipv4"])
    check("empty source â†’ []",           len(r10) == 0)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 10. IOCExtractor.deduplicate
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_ioc_deduplicate():
    print("\nâ”€â”€ 10. IOCExtractor.deduplicate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")

    # No duplicates â€” same list returned
    iocs = [
        IOC("ipv4",   "1.1.1.1", 0.90, "R1", "", "", ["t1"]),
        IOC("domain", "evil.com",0.80, "R2", "", "", ["t2"]),
    ]
    deduped = IOCExtractor.deduplicate(iocs)
    check("no dupes: same count",        len(deduped) == 2)

    # Exact duplicates â€” highest confidence kept
    a = IOC("ipv4", "2.2.2.2", 0.70, "RULE-A", "", "", ["tag-a"])
    b = IOC("ipv4", "2.2.2.2", 0.95, "RULE-B", "", "", ["tag-b"])
    c = IOC("ipv4", "2.2.2.2", 0.60, "RULE-C", "", "", ["tag-c"])
    merged = IOCExtractor.deduplicate([a, b, c])
    check("3 dupes â†’ 1",                 len(merged) == 1)
    check("highest confidence (0.95)",   merged[0].confidence == 0.95)
    check("tags from all merged",
          all(t in merged[0].tags for t in ["tag-a","tag-b","tag-c"]))

    # Value comparison is case-insensitive
    d1 = IOC("domain", "Evil.COM", 0.80, "R1", "", "", ["low"])
    d2 = IOC("domain", "evil.com", 0.90, "R2", "", "", ["high"])
    merged2 = IOCExtractor.deduplicate([d1, d2])
    check("case-insensitive dedup",      len(merged2) == 1)
    check("value preserved from winner", merged2[0].confidence == 0.90)

    # Different types not merged
    ip = IOC("ipv4",   "1.2.3.4", 0.90, "R1")
    hn = IOC("hostname","1.2.3.4",0.80, "R2")
    mixed = IOCExtractor.deduplicate([ip, hn])
    check("different types not merged",  len(mixed) == 2)

    # Insertion order preserved (first-seen wins for ordering)
    ordered = [
        IOC("ipv4","3.3.3.3",0.70,"R1"),
        IOC("ipv4","1.1.1.1",0.80,"R2"),
        IOC("ipv4","2.2.2.2",0.90,"R3"),
    ]
    result = IOCExtractor.deduplicate(ordered)
    check("insertion order preserved",
          [i.value for i in result] == ["3.3.3.3","1.1.1.1","2.2.2.2"])


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 11. IOCExtractor.merge
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_ioc_merge():
    print("\nâ”€â”€ 11. IOCExtractor.merge â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")

    s1 = [
        IOC("ipv4",   "1.1.1.1", 0.90, "R1", "", "", ["sess1"]),
        IOC("domain", "evil.com",0.80, "R1", "", "", ["sess1"]),
    ]
    s2 = [
        IOC("ipv4",   "2.2.2.2", 0.85, "R2", "", "", ["sess2"]),
        IOC("ipv4",   "1.1.1.1", 0.70, "R3", "", "", ["sess2"]),  # overlap
        IOC("url",    "http://x",0.75, "R2", "", "", ["sess2"]),
    ]
    s3 = [
        IOC("ipv4",   "3.3.3.3", 0.60, "R4", "", "", ["sess3"]),
    ]

    combined = IOCExtractor.merge(s1, s2, s3)
    check("unique count = 5",            len(combined) == 5)

    # 1.1.1.1 overlap: higher confidence kept, tags merged
    ip1 = next(i for i in combined if i.value == "1.1.1.1")
    check("1.1.1.1 confidence = 0.90",   ip1.confidence == 0.90)
    check("1.1.1.1 tags merged",
          "sess1" in ip1.tags and "sess2" in ip1.tags)

    # All values present
    vals = {i.value for i in combined}
    check("1.1.1.1 present",             "1.1.1.1" in vals)
    check("2.2.2.2 present",             "2.2.2.2" in vals)
    check("evil.com present",            "evil.com" in vals)
    check("http://x present",            "http://x" in vals)
    check("3.3.3.3 present",             "3.3.3.3" in vals)

    # Single list merge = deduplicate
    single = IOCExtractor.merge(s1)
    check("single list = dedup(s1)",     len(single) == len(s1))

    # Empty lists handled
    empty = IOCExtractor.merge([], [])
    check("merge of empties â†’ []",       len(empty) == 0)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 12. IOCExtractor.enrich
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_ioc_enrich():
    print("\nâ”€â”€ 12. IOCExtractor.enrich â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    ext = IOCExtractor()

    # Private IPs: not enriched (no external call made)
    priv = [IOC("ipv4","10.0.0.1",0.90,"R1"),
            IOC("ipv4","192.168.1.1",0.85,"R2")]
    result = ext.enrich(priv, geoip=True, abuseipdb=False)
    check("returns same list",           result is priv)
    check("private IPs tags unchanged",
          all(i.tags == [] for i in result))

    # Public IP: GeoIP enrichment â€” graceful if unavailable
    pub = [IOC("ipv4","8.8.8.8",0.90,"R1")]
    result2 = ext.enrich(pub, geoip=True, abuseipdb=False)
    check("public IP returns same list", result2 is pub)
    # Tags may or may not be added depending on GeoIP availability
    check("no exception raised",         True)

    # Non-IP IOCs: not enriched
    others = [IOC("domain","evil.com",0.90,"R1"),
              IOC("url","http://x.com",0.80,"R2")]
    result3 = ext.enrich(others, geoip=True, abuseipdb=True)
    check("non-IP IOCs not enriched",    all(i.tags == [] for i in result3))

    # AbuseIPDB without key: graceful degradation
    pub2 = [IOC("ipv4","8.8.8.8",0.90,"R1")]
    result4 = ext.enrich(pub2, geoip=False, abuseipdb=True, abuseipdb_key="")
    check("no key: no exception",        True)
    check("returns list",                isinstance(result4, list))


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 13. EvidenceLedger.merge
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_evidence_ledger_merge():
    print("\nâ”€â”€ 13. EvidenceLedger.merge â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    KEY = "test-hmac-key-nexlog"
    p1 = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False).name
    p2 = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False).name
    p3 = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False).name

    try:
        L1 = EvidenceLedger(p1, KEY)
        L2 = EvidenceLedger(p2, KEY)
        L3 = EvidenceLedger(p3, KEY)

        L1.add("/log/access.log",sha256="a"*64,file_size=10240,analyst="Jane",session_id="s1")
        L1.add("/log/auth.log",  sha256="b"*64,file_size=2048, analyst="Jane",session_id="s1")
        L2.add("/log/nginx.log", sha256="c"*64,file_size=5000, analyst="Bob", session_id="s2")
        L2.add("/log/access.log",sha256="a"*64,file_size=10240,analyst="Bob", session_id="s2")

        # Merge L2 into L1 â€” only nginx.log is new (access.log is SHA-256 duplicate)
        added = L1.merge(L2, analyst="Jane")
        check("1 new entry added",               added == 1)
        check("total = 3 entries",               len(L1.list_entries()) == 3)

        # HMAC still valid after merge
        v = L1.verify_all()
        check("HMAC-tampered = 0",               len(v["tampered"]) == 0)

        # Merge with empty ledger â†’ 0 added
        L_empty = EvidenceLedger(
            tempfile.NamedTemporaryFile(suffix=".jsonl",delete=False).name, KEY)
        added2 = L1.merge(L_empty)
        check("merge empty: 0 added",            added2 == 0)
        check("total still 3",                   len(L1.list_entries()) == 3)

        # Create tampered ledger
        L3.add("/log/evil.log",sha256="d"*64,file_size=100,analyst="Eve")
        lines = open(p3).read().strip().splitlines()
        entries = [json.loads(l) for l in lines]
        for e in entries:
            if "entry_hmac" in e:
                e["entry_hmac"] = "tampered_value_xyz"
        open(p3, "w").write("\n".join(json.dumps(e) for e in entries) + "\n")

        L3t = EvidenceLedger(p3, KEY)
        try:
            L1.merge(L3t)
            check("tampered raises ValueError",   False, "no exception raised")
        except ValueError as e:
            check("tampered raises ValueError",   True)
            check("error message mentions tampered", "tampered" in str(e).lower() or "HMAC" in str(e))

    finally:
        for p in [p1, p2, p3]:
            try: os.unlink(p)
            except: pass


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 14. EvidenceLedger.summary
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_evidence_ledger_summary():
    print("\nâ”€â”€ 14. EvidenceLedger.summary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    KEY = "test-key-summary"
    p = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False).name
    try:
        L = EvidenceLedger(p, KEY)

        # Empty ledger
        s0 = L.summary()
        check("empty: total=0",             s0["total"] == 0)
        check("empty: analysts=[]",         s0["analysts"] == [])
        check("empty: total_bytes=0",       s0["total_bytes"] == 0)

        # Add entries
        L.add("/log/access.log",sha256="a"*64,file_size=10240,analyst="Jane",session_id="s1")
        L.add("/log/auth.log",  sha256="b"*64,file_size=2048, analyst="Jane",session_id="s1")
        L.add("/log/nginx.log", sha256="c"*64,file_size=5000, analyst="Bob", session_id="s2")

        s = L.summary()
        check("total = 3",                  s["total"] == 3)
        check("tampered = 0",               s["tampered"] == 0)
        check("total_bytes = 17288",        s["total_bytes"] == 17288)
        check("Jane in analysts",           "Jane" in s["analysts"])
        check("Bob in analysts",            "Bob" in s["analysts"])
        check("s1 in sessions",             "s1" in s["sessions"])
        check("s2 in sessions",             "s2" in s["sessions"])
        check("oldest is string",           isinstance(s["oldest"], str))
        check("newest is string",           isinstance(s["newest"], str))
        check("oldest <= newest",           s["oldest"] <= s["newest"])
        check("hmac_ok key present",        "hmac_ok" in s)
        check("missing key present",        "missing" in s)

    finally:
        os.unlink(p)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Main
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
if __name__ == "__main__":
    print("=" * 62)
    print("  NexLog Layer 3 Enhancements â€” Test Suite")
    print("=" * 62)

    test_search_findings()
    test_get_timeline()
    test_get_stats()
    test_tag_finding()
    test_delete_session()
    test_export_import_case()
    test_ioc_from_dict()
    test_ioc_to_stix_indicator()
    test_ioc_filter()
    test_ioc_deduplicate()
    test_ioc_merge()
    test_ioc_enrich()
    test_evidence_ledger_merge()
    test_evidence_ledger_summary()

    print(f"\n{'=' * 62}")
    print(f"  Results:  {_passed} passed Â· {_failed} failed")
    print(f"{'=' * 62}")
    if _failed:
        raise SystemExit(1)
