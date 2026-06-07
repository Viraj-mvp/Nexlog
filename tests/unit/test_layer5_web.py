"""
tests/unit/test_layer5_web.py â€” NexLog Layer 5 (Web)
Test suite for interface/web/:
  - schemas.py  â€” all 14 dataclass schemas (validate, to_dict, from_dict)
  - api.py      â€” _AppState, _Handler routing, all 14 endpoints (stdlib mode)

Tests run without FastAPI or a real HTTP server â€” all routing is tested
by calling _Handler._route() directly, which is the same code path used
by both the stdlib server and (through create_app) the FastAPI layer.

Run: python test_layer5_web.py  (from any directory)
"""

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
for _p in ['core', 'detection', 'storage', 'intelligence', 'output',
           'utils', 'interface/web']:
    sys.path.insert(0, os.path.join(_ROOT, _p))
sys.path.insert(0, _ROOT)

from finding import Finding, Severity, MitreTag
from case_db import CaseDB
from schemas import (
    AnalyseRequest, SessionSummary,
    FindingSchema, IOCSchema, ReportRequest, HealthResponse, StatsResponse,
    NoteRequest, ErrorResponse, ALL_SCHEMAS,
)
from api import _AppState, _Handler

# â”€â”€ Test helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_passed = _failed = 0

def check(name: str, cond: bool, detail: str = "") -> None:
    global _passed, _failed
    if cond:
        _passed += 1; print(f"  PASS  {name}")
    else:
        _failed += 1; print(f"  FAIL  {name}" + (f"  [{detail}]" if detail else ""))

_TS = datetime(2026, 1, 4, 10, 0, 0, tzinfo=timezone.utc)

def _f(rule_id="WEB-001", cat="web_attack",
       sev=Severity.HIGH, conf=0.90) -> Finding:
    return Finding(
        rule_id=rule_id, rule_name=f"Rule {rule_id}", description="test",
        severity=sev, confidence=conf, category=cat,
        mitre_tags=[MitreTag("TA0001","Initial Access","T1190","Exploit",".001")],
        source_ip="203.0.113.5", hostname="web01", process_name="nginx",
        event_id="4688", timestamp=_TS,
        trigger_line=f"GET /?rule={rule_id}",
        supporting_lines=["line1"],
    )

def _make_db_with_data(db_path: str, log_path: str = "test.log") -> str:
    """Create a CaseDB with one session + findings. Returns session_id."""
    with CaseDB(db_path) as db:
        sid = db.create_session(
            source_file=log_path, sha256="a"*64,
            file_size=4096, rules_loaded=162, entries_parsed=200,
        )
        db.save_findings([
            _f("WEB-001","web_attack", Severity.HIGH,     0.90),
            _f("AUTH-001","auth",      Severity.CRITICAL,  0.95),
            _f("DISC-008","discovery", Severity.CRITICAL,  0.96),
        ], sid)
        db.record_evidence(log_path,"a"*64,4096,sid,"apache",200,3)
        db.save_attack_chains([{
            "chain_name":"Full Web Compromise","source_ip":"203.0.113.5",
            "categories":["web_attack","persistence"],"finding_count":2,
            "max_risk_score":8.5,"confidence_boost":0.15,
        }], sid)
        db.add_note("Analyst note from test", sid, "test_analyst")
    return sid


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 1. Schemas â€” AnalyseRequest
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_analyse_request():
    print("\nâ”€â”€ 1. AnalyseRequest schema â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    req = AnalyseRequest(log_path="/var/log/nginx/access.log",
                         analyst="Jane", min_severity="HIGH")
    check("defaults set",           req.run_chains is True)
    check("analyst stored",         req.analyst == "Jane")
    check("min_severity stored",    req.min_severity == "HIGH")
    check("validate passes",        req.validate() == [])

    req_bad = AnalyseRequest(log_path="", min_severity="INVALID")
    errs = req_bad.validate()
    check("empty log_path flagged", any("log_path" in e for e in errs))
    check("bad severity flagged",   any("severity" in e.lower() for e in errs))
    check("two errors returned",    len(errs) == 2)

    d = req.to_dict()
    check("to_dict has log_path",   d["log_path"] == "/var/log/nginx/access.log")
    check("to_dict no None values", None not in d.values())

    req2 = AnalyseRequest.from_dict({"log_path":"/tmp/a.log","analyst":"Bob"})
    check("from_dict works",        req2.analyst == "Bob")
    check("from_dict defaults",     req2.run_chains is True)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 2. Schemas â€” SessionSummary
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_session_summary():
    print("\nâ”€â”€ 2. SessionSummary schema â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    sess = {"session_id":"s1","source_file":"access.log",
            "created_at":"2026-01-04T10:00:00","sha256":"a"*64}
    summ = {"total":5,"by_severity":{"CRITICAL":1,"HIGH":2,"MEDIUM":2},
            "max_risk_score":8.5,"avg_risk_score":5.2,
            "top_source_ips":["1.2.3.4","5.5.5.5"],
            "top_hostnames":["web01","db01"]}
    ss = SessionSummary.from_db(sess, summ)
    d  = ss.to_dict()
    check("total_findings",         d["total_findings"] == 5)
    check("critical count",         d["critical"] == 1)
    check("high count",             d["high"] == 2)
    check("max_risk_score",         d["max_risk_score"] == 8.5)
    check("top_source_ips",         "1.2.3.4" in d["top_source_ips"])
    check("top_hostnames",          "web01" in d["top_hostnames"])
    check("sha256 stored",          len(d["sha256"]) == 64)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 3. Schemas â€” FindingSchema
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_finding_schema():
    print("\nâ”€â”€ 3. FindingSchema schema â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    f  = _f()
    fs = FindingSchema.from_finding(f)
    d  = fs.to_dict()

    check("rule_id",               d["rule_id"] == "WEB-001")
    check("severity",              d["severity"] == "HIGH")
    check("confidence rounded",    isinstance(d["confidence"], float))
    check("risk_score present",    d["risk_score"] > 0)
    check("hostname",              d["hostname"] == "web01")
    check("process_name",          d["process_name"] == "nginx")
    check("event_id",              d["event_id"] == "4688")
    check("timestamp ISO string",  isinstance(d["timestamp"], str))
    check("mitre_tags list",       isinstance(d["mitre_tags"], list))
    check("mitre_tags non-empty",  len(d["mitre_tags"]) == 1)
    check("technique_ids",         "T1190.001" in d["technique_ids"])
    check("tactic_names",          "Initial Access" in d["tactic_names"])
    check("supporting_lines",      isinstance(d["supporting_lines"], list))
    check("triage_state default",  d["triage_state"] == "new")

    # MitreTagSchema
    tag_d = d["mitre_tags"][0]
    check("tag tactic_id",         tag_d["tactic_id"] == "TA0001")
    check("tag technique_id",      tag_d["technique_id"] == "T1190")
    check("tag full_id",           tag_d["full_id"] == "T1190.001")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 4. Schemas â€” IOCSchema
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_ioc_schema():
    print("\nâ”€â”€ 4. IOCSchema schema â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    sys.path.insert(0, os.path.join(_ROOT, 'intelligence'))
    from ioc_extractor import IOC
    ioc = IOC("ipv4","203.0.113.5",0.87,"WEB-001","203.0.113.5",
               "2026-01-04T10:00:00Z",["web_attack","T1190.001"])
    s  = IOCSchema.from_ioc(ioc)
    d  = s.to_dict()
    check("ioc_type",               d["ioc_type"] == "ipv4")
    check("value",                  d["value"] == "203.0.113.5")
    check("confidence",             d["confidence"] == 0.87)
    check("source_rule",            d["source_rule"] == "WEB-001")
    check("tags present",           "web_attack" in d["tags"])


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 5. Schemas â€” ReportRequest
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_report_request():
    print("\nâ”€â”€ 5. ReportRequest schema â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    rr = ReportRequest(format="pdf", case_ref="IR-2026", analyst="Jane")
    check("validate passes",        rr.validate() == [])
    check("format stored",          rr.format == "pdf")

    for fmt in ["json","text","markdown","pdf"]:
        check(f"valid format {fmt}", ReportRequest(format=fmt).validate() == [])

    bad = ReportRequest(format="html")
    check("bad format flagged",     len(bad.validate()) == 1)

    rr2 = ReportRequest.from_dict({"format":"json","analyst":"Bob"})
    check("from_dict works",        rr2.analyst == "Bob")
    check("from_dict format",       rr2.format == "json")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 6. Schemas â€” HealthResponse + StatsResponse + ErrorResponse
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_system_schemas():
    print("\nâ”€â”€ 6. System schemas â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    hr = HealthResponse(status="ok", rules_loaded=162, db_connected=True)
    d  = hr.to_dict()
    check("HealthResponse status",  d["status"] == "ok")
    check("HealthResponse rules",   d["rules_loaded"] == 162)
    check("HealthResponse db",      d["db_connected"] is True)

    hr_deg = HealthResponse(status="degraded", rules_loaded=0)
    check("degraded status",        hr_deg.to_dict()["status"] == "degraded")

    sr = StatsResponse(total_sessions=3, total_findings=42,
                       total_iocs=7, rules_loaded=162)
    sd = sr.to_dict()
    check("StatsResponse sessions", sd["total_sessions"] == 3)
    check("StatsResponse findings", sd["total_findings"] == 42)

    err = ErrorResponse(error="Not found", detail="Session missing", code=404)
    ed  = err.to_dict()
    check("ErrorResponse error",    ed["error"] == "Not found")
    check("ErrorResponse code",     ed["code"] == 404)
    check("ErrorResponse detail",   ed["detail"] == "Session missing")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 7. Schemas â€” NoteRequest
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_note_request():
    print("\nâ”€â”€ 7. NoteRequest schema â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    nr = NoteRequest(note="Attacker confirmed botnet", analyst="Jane")
    check("validate passes",        nr.validate() == [])
    check("note stored",            nr.note == "Attacker confirmed botnet")

    bad = NoteRequest(note="   ")   # whitespace only
    check("empty note flagged",     len(bad.validate()) == 1)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 8. Schemas â€” ALL_SCHEMAS registry
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_schemas_registry():
    print("\nâ”€â”€ 8. ALL_SCHEMAS registry â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    check("registry non-empty",     len(ALL_SCHEMAS) >= 10)
    names = {s.__name__ for s in ALL_SCHEMAS}
    for cls_name in ["AnalyseRequest","FindingSchema","IOCSchema",
                     "ReportRequest","HealthResponse","ErrorResponse"]:
        check(f"{cls_name} in registry", cls_name in names)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 9. _AppState â€” initialises with rule engine
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_appstate_init():
    print("\nâ”€â”€ 9. _AppState initialisation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f:
        db_path = f.name
    try:
        state = _AppState(case_db_path=db_path)
        check("rules loaded",      state._rules_loaded > 0,
              f"got {state._rules_loaded}")
        check("rules_loaded > 100",state._rules_loaded >= 100)
        h = state.health()
        check("health returns obj",isinstance(h, HealthResponse))
        check("health status ok",  h.status == "ok")
        check("health rules match",h.rules_loaded == state._rules_loaded)
    finally:
        os.unlink(db_path)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 10. _Handler â€” GET /api/health
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_handler_health():
    print("\nâ”€â”€ 10. GET /api/health â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f:
        db_path = f.name
    try:
        state   = _AppState(case_db_path=db_path)
        handler = _Handler(state)
        code, resp = handler._route("GET", "/api/health", {}, {})
        check("status 200",         code == 200)
        check("status key present", "status" in resp)
        check("rules_loaded present","rules_loaded" in resp)
        check("uptime_seconds",     resp.get("uptime_seconds", -1) >= 0)
    finally:
        os.unlink(db_path)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 11. _Handler â€” GET /api/stats
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_handler_stats():
    print("\nâ”€â”€ 11. GET /api/stats â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f:
        db_path = f.name
    try:
        _make_db_with_data(db_path)
        state   = _AppState(case_db_path=db_path)
        handler = _Handler(state)
        code, resp = handler._route("GET", "/api/stats", {}, {})
        check("status 200",            code == 200)
        check("total_findings >= 3",   resp.get("total_findings", 0) >= 3)
        check("total_sessions >= 1",   resp.get("total_sessions", 0) >= 1)
        check("rules_loaded",          resp.get("rules_loaded", 0) > 0)
    finally:
        os.unlink(db_path)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 12. _Handler â€” POST /api/analyse
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_handler_analyse():
    print("\nâ”€â”€ 12. POST /api/analyse â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log",
                                     delete=False, encoding="utf-8") as f:
        f.write('203.0.113.5 - - [04/Jan/2026:10:00:00 +0000] '
                '"GET /login?q=admin HTTP/1.1" 200 512 "-" "sqlmap/1.7"\n')
        log_path = f.name
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f:
        db_path = f.name
    try:
        state   = _AppState(case_db_path=db_path)
        handler = _Handler(state)

        # Valid request
        code, resp = handler._route(
            "POST", "/api/analyse", {},
            {"log_path": log_path, "analyst": "test", "min_severity": "LOW"})
        check("analyse 200",           code == 200, f"got {code}: {resp}")
        check("success=True",          resp.get("success") is True)
        check("session_id present",    bool(resp.get("session_id", "")))
        check("summary present",       "summary" in resp)
        check("total_findings >= 1",   resp.get("summary",{})
              .get("total_findings",0) >= 1)
        check("duration_ms > 0",       resp.get("duration_ms", 0) > 0)

        # Missing file
        code2, resp2 = handler._route(
            "POST", "/api/analyse", {},
            {"log_path": "/nonexistent/file.log"})
        check("missing file â†’ 400",   code2 == 400)
        check("error message",         bool(resp2.get("error", "")))

        # Invalid request body (empty log_path)
        code3, resp3 = handler._route(
            "POST", "/api/analyse", {},
            {"log_path": "", "min_severity": "INVALID"})
        check("invalid req â†’ 400",     code3 == 400)
    finally:
        os.unlink(log_path)
        os.unlink(db_path)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 13. _Handler â€” GET /api/sessions
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_handler_sessions():
    print("\nâ”€â”€ 13. GET /api/sessions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f:
        db_path = f.name
    try:
        sid = _make_db_with_data(db_path)
        state   = _AppState(case_db_path=db_path)
        handler = _Handler(state)

        code, resp = handler._route("GET", "/api/sessions", {}, {})
        check("200",                   code == 200)
        check("sessions key present",  "sessions" in resp)
        check("one session",           len(resp["sessions"]) == 1)
        s = resp["sessions"][0]
        check("session has total_findings",  "total_findings" in s)
        check("session has session_id",      "session_id" in s)
    finally:
        os.unlink(db_path)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 14. _Handler â€” GET /api/findings
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_handler_findings():
    print("\nâ”€â”€ 14. GET /api/findings â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f:
        db_path = f.name
    try:
        sid = _make_db_with_data(db_path)
        state   = _AppState(case_db_path=db_path)
        handler = _Handler(state)

        # All findings
        code, resp = handler._route(
            "GET", "/api/findings",
            {"session_id": [sid]}, {})
        check("200",                   code == 200)
        check("findings key",          "findings" in resp)
        check("total >= 3",            resp.get("total", 0) >= 3)
        check("finding_id exposed",    bool(resp["findings"][0].get("finding_id")))
        check("triage_state exposed",  resp["findings"][0].get("triage_state") == "new")

        # Category filter
        code2, resp2 = handler._route(
            "GET", "/api/findings",
            {"session_id":[sid], "category":["auth"]}, {})
        check("auth filter works",     code2 == 200)
        check("auth category only",
              all(f["category"] == "auth"
                  for f in resp2.get("findings",[])))

        # Risk filter
        code3, resp3 = handler._route(
            "GET", "/api/findings",
            {"session_id":[sid], "min_risk":["9.0"]}, {})
        check("high risk filter",      code3 == 200)
    finally:
        os.unlink(db_path)


def test_handler_integrity_and_actions():
    print("\n-- Case integrity and finding actions --")
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f:
        db_path = f.name
    try:
        sid = _make_db_with_data(db_path)
        state   = _AppState(case_db_path=db_path)
        handler = _Handler(state)

        code, resp = handler._route(
            "GET", "/api/case/integrity", {"session_id":[sid]}, {})
        check("integrity 200",          code == 200)
        check("integrity status",       "status" in resp)
        check("integrity evidence list", "evidence_verifications" in resp)

        with CaseDB(db_path) as db:
            fid = getattr(db.get_findings(session_id=sid)[0], "_db_id")
            eid = db.get_evidence(session_id=sid)[0]["id"]

        code2, resp2 = handler._route(
            "POST", "/api/evidence/verify", {}, {"evidence_id": eid})
        check("evidence verify 200",    code2 == 200)
        check("evidence status present", "status" in resp2)

        code3, resp3 = handler._route(
            "POST", f"/api/findings/{fid}/action", {},
            {"action":"triaged", "analyst":"Jane", "note":"reviewed"})
        check("action post 200",        code3 == 200)
        check("action id returned",     bool(resp3.get("action_id")))
        check("state triaged",          resp3.get("current_state") == "triaged")

        code4, resp4 = handler._route(
            "GET", f"/api/findings/{fid}/actions", {}, {})
        check("actions get 200",        code4 == 200)
        check("actions include one",    len(resp4.get("actions", [])) == 1)

        code5, _ = handler._route(
            "POST", "/api/findings/missing/action", {},
            {"action":"triaged"})
        check("missing finding 404",    code5 == 404)
    finally:
        os.unlink(db_path)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 15. _Handler â€” GET /api/iocs
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_handler_iocs():
    print("\nâ”€â”€ 15. GET /api/iocs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f:
        db_path = f.name
    try:
        sid = _make_db_with_data(db_path)
        state   = _AppState(case_db_path=db_path)
        handler = _Handler(state)

        code, resp = handler._route(
            "GET", "/api/iocs", {"session_id":[sid]}, {})
        check("200",                   code == 200)
        check("iocs key",              "iocs" in resp)
        check("total key",             "total" in resp)
        check("iocs is list",          isinstance(resp["iocs"], list))
    finally:
        os.unlink(db_path)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 16. _Handler â€” POST /api/report (all formats)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_handler_report():
    print("\nâ”€â”€ 16. POST /api/report â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f:
        db_path = f.name
    try:
        sid = _make_db_with_data(db_path)
        state   = _AppState(case_db_path=db_path)
        handler = _Handler(state)

        for fmt in ["json","text","markdown"]:
            code, resp = handler._route(
                "POST", "/api/report", {},
                {"session_id": sid, "format": fmt})
            check(f"report {fmt} 200",    code == 200, f"got {code}")
            check(f"report {fmt} success",resp.get("success") is True)
            check(f"report {fmt} content",bool(resp.get("content","")))
            check(f"report {fmt} size",   resp.get("size_bytes",0) > 0)
            check(f"report {fmt} sha",    len(resp.get("sha256","")) == 64)

        # Bad format
        code_bad, resp_bad = handler._route(
            "POST", "/api/report", {}, {"format":"html"})
        check("bad format â†’ 400",      code_bad == 400)
    finally:
        os.unlink(db_path)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 17. _Handler â€” POST /api/notes + GET /api/notes
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_handler_notes():
    print("\nâ”€â”€ 17. Notes endpoints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f:
        db_path = f.name
    try:
        sid = _make_db_with_data(db_path)
        state   = _AppState(case_db_path=db_path)
        handler = _Handler(state)

        code, resp = handler._route(
            "POST", "/api/notes", {},
            {"note": "Attacker confirmed botnet",
             "session_id": sid, "analyst": "Jane"})
        check("POST notes 200",        code == 200)
        check("note_id returned",      bool(resp.get("note_id","")))
        check("success flag",          resp.get("success") is True)

        code2, resp2 = handler._route(
            "GET", "/api/notes", {"session_id":[sid]}, {})
        check("GET notes 200",         code2 == 200)
        check("notes list present",    "notes" in resp2)
        check("at least 2 notes",      len(resp2["notes"]) >= 2)
        check("analyst stored",
              any(n.get("analyst","") == "Jane"
                  for n in resp2["notes"]))

        # Empty note â†’ 400
        code3, _ = handler._route(
            "POST", "/api/notes", {},
            {"note": "   ", "session_id": sid})
        check("empty note â†’ 400",      code3 == 400)
    finally:
        os.unlink(db_path)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 18. _Handler â€” GET /api/chains
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_handler_chains():
    print("\nâ”€â”€ 18. GET /api/chains â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f:
        db_path = f.name
    try:
        sid = _make_db_with_data(db_path)
        state   = _AppState(case_db_path=db_path)
        handler = _Handler(state)
        code, resp = handler._route(
            "GET", "/api/chains", {"session_id":[sid]}, {})
        check("200",                   code == 200)
        check("chains key",            "chains" in resp)
        check("one chain",             len(resp["chains"]) == 1)
        c = resp["chains"][0]
        check("chain_name present",    "chain_name" in c)
        check("max_risk_score",        "max_risk_score" in c)
    finally:
        os.unlink(db_path)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 19. _Handler â€” POST /api/export/stix
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_handler_stix_export():
    print("\nâ”€â”€ 19. POST /api/export/stix â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f:
        db_path = f.name
    try:
        sid = _make_db_with_data(db_path)
        state   = _AppState(case_db_path=db_path)
        handler = _Handler(state)
        code, resp = handler._route(
            "POST", "/api/export/stix", {},
            {"session_id": sid, "case_ref":"IR-TEST","analyst":"Jane"})
        check("200",                   code == 200)
        check("bundle key",            "bundle" in resp)
        check("summary key",           "summary" in resp)
        b = resp["bundle"]
        check("bundle type",           b["type"] == "bundle")
        check("bundle objects",        len(b["objects"]) > 3)
        s = resp["summary"]
        check("summary indicators",    "indicators" in s)
        check("summary relationships", "relationships" in s)
    finally:
        os.unlink(db_path)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 20. _Handler â€” 404 on unknown routes
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_handler_404():
    print("\nâ”€â”€ 20. 404 on unknown routes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f:
        db_path = f.name
    try:
        state   = _AppState(case_db_path=db_path)
        handler = _Handler(state)
        for path in ["/", "/api/", "/api/unknown",
                     "/api/findings/export", "/favicon.ico"]:
            code, resp = handler._route("GET", path, {}, {})
            check(f"404 on {path}",    code == 404, f"got {code}")
    finally:
        os.unlink(db_path)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 21. AI endpoint routing (/api/ai/*)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_handler_ai_endpoints():
    print("\nâ”€â”€ 21. AI endpoint routing (/api/ai/*) â”€â”€â”€â”€â”€â”€")
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f:
        db_path = f.name
    try:
        state   = _AppState(case_db_path=db_path)
        handler = _Handler(state)

        # GET /api/ai/status â€” must return 200 even without AI deps
        code, resp = handler._route("GET", "/api/ai/status", {}, {})
        check("GET /api/ai/status returns 200",  code == 200)
        check("status has n_indexed",             "n_indexed" in resp)
        check("status has llm_provider",          "llm_provider" in resp)

        # POST /api/ai/index â€” no findings yet -> standardized 409 envelope
        code, resp = handler._route("POST", "/api/ai/index",
                                    {}, {"session_id": None})
        check("POST /api/ai/index returns 409",   code == 409)
        check("index error envelope",             isinstance(resp.get("error"), dict))
        check("index error code",                 resp.get("error", {}).get("code") == "index_empty")

        # POST /api/ai/query â€” missing question -> standardized 400 envelope
        code, resp = handler._route("POST", "/api/ai/query",
                                    {}, {"question": ""})
        check("empty question â†’ 400",            code == 400)
        check("missing-question envelope",        resp.get("error", {}).get("code") == "missing_question")

        # POST /api/ai/query â€” valid question (no findings indexed) -> 409 envelope
        code, resp = handler._route("POST", "/api/ai/query",
                                    {}, {"question": "What happened?"})
        check("query with no index â†’ 409",       code == 409)
        check("no-index envelope",                resp.get("error", {}).get("code") == "index_empty")

        # GET /api/ai/history â€” empty
        code, resp = handler._route("GET", "/api/ai/history", {}, {})
        check("GET /api/ai/history â†’ 200",        code == 200)
        check("history has turns key",            "turns" in resp)
        check("turns is list",                    isinstance(resp["turns"], list))

        # POST /api/ai/clear_history
        code, resp = handler._route("POST", "/api/ai/clear_history", {}, {})
        check("POST /api/ai/clear_history â†’ 200", code == 200)
        check("cleared=True",                     resp.get("cleared") is True)

        # POST /api/ai/query with full findings indexed
        _populate_db_for_ai(db_path, state, handler)
        code2, resp2 = handler._route("POST", "/api/ai/query",
                                      {}, {"question": "What IPs are attacking?"})
        check("query after index â†’ 200",          code2 == 200)
        check("answer text non-empty",            len(resp2.get("text","")) > 5)
        check("sources is list",                  isinstance(resp2.get("sources",[]), list))
        check("has llm_tier",                     "llm_tier" in resp2)
        check("has llm_provider",                 "llm_provider" in resp2)
        check("has retrieval_ms",                 "retrieval_ms" in resp2)

        # Conversation history accumulates
        code3, resp3 = handler._route("GET", "/api/ai/history", {}, {})
        check("history grows after query",
              len(resp3.get("turns", [])) >= 1)

        # POST /api/ai/reset
        code4, resp4 = handler._route("POST", "/api/ai/reset", {}, {})
        check("POST /api/ai/reset â†’ 200",         code4 == 200)

    finally:
        os.unlink(db_path)


def test_handler_v1_parity_and_auth_status():
    print("\nâ”€â”€ 22. v1 parity + auth status â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f:
        db_path = f.name
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as logf:
        logf.write('203.0.113.5 - - [04/Jan/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 42 "-" "curl/8.0"\n')
        log_path = logf.name
    try:
        sid = _make_db_with_data(db_path)
        state = _AppState(case_db_path=db_path)
        handler = _Handler(state)

        code, resp = handler._route("GET", "/api/auth/status", {}, {})
        check("GET /api/auth/status â†’ 200",      code == 200)
        check("auth_enabled key present",         "auth_enabled" in resp)
        check("key_required key present",         "key_required" in resp)

        code, resp = handler._route("GET", "/api/v1/snapshot", {"session_id": [sid]}, {})
        check("GET /api/v1/snapshot â†’ 200",      code == 200)
        check("snapshot has dashboard",           "dashboard" in resp)

        code, resp = handler._route("GET", "/api/v1/attack-story", {"session_id": [sid]}, {})
        check("GET /api/v1/attack-story â†’ 200",  code == 200)
        check("attack-story has story",           "story" in resp)

        code, resp = handler._route(
            "POST", "/api/export/iocs", {}, {"session_id": sid}
        )
        check("POST /api/export/iocs â†’ 200",     code == 200)
        check("ioc export has summary",           "summary" in resp)
        check("ioc export has csv",               "csv" in resp)

        code, resp = handler._route(
            "POST", "/api/v1/jobs", {}, {"log_path": log_path, "min_severity": "LOW"}
        )
        check("POST /api/v1/jobs â†’ 200",         code == 200)
        check("v1 job has id",                    bool(resp.get("job_id", "")))
        if resp.get("job_id"):
            code2, resp2 = handler._route("GET", f"/api/v1/jobs/{resp['job_id']}", {}, {})
            check("GET /api/v1/jobs/{id} â†’ 200", code2 == 200)
            check("v1 job status present",        bool(resp2.get("status", "")))
    finally:
        os.unlink(log_path)
        os.unlink(db_path)


def test_sync_analyse_releases_case_handle():
    print("\n── 23. sync analyse releases .facase handle ─────────")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as logf:
        logf.write('203.0.113.5 - - [04/Jan/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 42 "-" "curl/8.0"\n')
        log_path = logf.name
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as dbf:
        case_path = dbf.name
    try:
        state = _AppState(case_db_path=case_path)
        req = AnalyseRequest.from_dict({
            "log_path": log_path,
            "min_severity": "LOW",
            "analyst": "test",
            "run_chains": True,
        })
        result = state.analyse(req, async_postprocess=False)
        check("sync analyse succeeds",            result.success is True, str(result.error))
        state.close()
        try:
            os.unlink(case_path)
            released = True
        except PermissionError:
            released = False
        check("case handle released for unlink", released)
    finally:
        if os.path.exists(log_path):
            os.unlink(log_path)
        if os.path.exists(case_path):
            try:
                os.unlink(case_path)
            except PermissionError:
                pass


def _populate_db_for_ai(db_path, state, handler):
    """Helper â€” analyse a tiny log so findings exist for AI to index."""
    import tempfile as _tmp
    with _tmp.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as lf:
        lf.write(
            '203.0.113.5 - - [04/Jan/2026:10:00:00 +0000] '
            '"GET /login?q=admin%27+OR+1=1-- HTTP/1.1" 200 512 "-" "sqlmap/1.7"\n'
            '185.220.100.5 - - [04/Jan/2026:10:00:01 +0000] '
            '"GET / HTTP/1.1" 200 100 "-" "nmap/7.94"\n'
        )
        log_path = lf.name
    try:
        handler._route("POST", "/api/analyse", {},
                       {"log_path": log_path, "analyst": "test",
                        "min_severity": "LOW"})
        # Also index into AI engine
        handler._route("POST", "/api/ai/index", {}, {"session_id": None})
    finally:
        import os as _os
        _os.unlink(log_path)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 23. interface/web package imports
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_web_package_imports():
    print("\nâ”€â”€ 23. interface/web package imports â”€â”€â”€â”€â”€â”€â”€â”€")
    sys.path.insert(0, _ROOT)
    import interface.web as web_pkg
    for name in ["AnalyseRequest","FindingSchema","IOCSchema",
                 "ReportRequest","HealthResponse","ErrorResponse"]:
        check(f"{name} importable",    hasattr(web_pkg, name))


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# main
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
if __name__ == "__main__":
    print("=" * 60)
    print("  NexLog Layer 5 (Web) â€” Test Suite")
    print("=" * 60)

    test_analyse_request()
    test_session_summary()
    test_finding_schema()
    test_ioc_schema()
    test_report_request()
    test_system_schemas()
    test_note_request()
    test_schemas_registry()
    test_appstate_init()
    test_handler_health()
    test_handler_stats()
    test_handler_analyse()
    test_handler_sessions()
    test_handler_findings()
    test_handler_integrity_and_actions()
    test_handler_iocs()
    test_handler_report()
    test_handler_notes()
    test_handler_chains()
    test_handler_stix_export()
    test_handler_404()
    test_handler_ai_endpoints()
    test_handler_v1_parity_and_auth_status()
    test_web_package_imports()

    print(f"\n{'=' * 60}")
    print(f"  Results:  {_passed} passed Â· {_failed} failed")
    print(f"{'=' * 60}")
    if _failed:
        raise SystemExit(1)
