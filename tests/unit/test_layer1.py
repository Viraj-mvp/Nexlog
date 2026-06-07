"""
test_layer1.py â€” NexLog Layer 1
Self-contained tests. No external files needed â€” sample logs are inline.

Run with:  python test_layer1.py
All tests print PASS / FAIL with the field that failed.
"""

import json
import tempfile
import os
import sys
from datetime import timezone

# â”€â”€ Self-locating path â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
sys.path.insert(0, os.path.join(_ROOT, 'core'))
sys.path.insert(0, os.path.join(_ROOT, 'detection'))

from models import LogFormat, LogEntry
from detector import detect_format
from parsers import (
    ApacheCombinedParser, SyslogParser,
    JsonParser, CloudTrailParser,
)
from engine import Engine


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Sample log data â€” one real example per format
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

APACHE_LINE = (
    '192.168.1.11 - admin [04/Jan/2026:10:01:00 +0000] '
    '"POST /login.php?user=admin\'+OR+1=1-- HTTP/1.1" '
    '200 512 "http://target.com" "sqlmap/1.7.8"'
)

SYSLOG_FAIL = (
    "Jan  4 10:01:32 webserver sshd[2841]: "
    "Failed password for root from 192.168.1.11 port 54321 ssh2"
)

SYSLOG_ACCEPT = (
    "Jan  4 10:01:35 webserver sshd[2841]: "
    "Accepted password for root from 192.168.1.11 port 54324 ssh2"
)

JSON_LINE = json.dumps({
    "timestamp": "2026-01-04T10:03:00Z",
    "ip": "192.168.1.12",
    "method": "GET",
    "uri": "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "status": 200,
    "user_agent": "Mozilla/5.0",
})

CLOUDTRAIL_RECORD = json.dumps({
    "eventTime": "2026-01-04T10:04:00Z",
    "eventName": "GetSecretValue",
    "eventSource": "secretsmanager.amazonaws.com",
    "sourceIPAddress": "185.220.101.45",
    "userAgent": "python-boto3/1.26.0",
    "userIdentity": {"type": "IAMUser", "userName": "dev-bot"},
    "requestParameters": {"secretId": "prod/db/master-password"},
    "errorCode": "AccessDenied",
    "errorMessage": "User is not authorized",
})


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Test helpers
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

_passed = 0
_failed = 0

def check(test_name: str, condition: bool, detail: str = "") -> None:
    global _passed, _failed
    if condition:
        _passed += 1
        print(f"  PASS  {test_name}")
    else:
        _failed += 1
        print(f"  FAIL  {test_name}" + (f"  [{detail}]" if detail else ""))


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Tests
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def test_apache_parser():
    print("\nâ”€â”€ Apache Combined Parser â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    p = ApacheCombinedParser()
    e = p.parse_line(APACHE_LINE, 1, "test.log")

    check("source_ip extracted",       e.source_ip == "192.168.1.11")
    check("username extracted",        e.username  == "admin")
    check("http_method extracted",     e.http_method == "POST")
    check("http_status extracted",     e.http_status == 200)
    check("user_agent extracted",      e.http_user_agent == "sqlmap/1.7.8")
    check("timestamp parsed",          e.timestamp is not None)
    check("timestamp is UTC",          e.timestamp.tzinfo == timezone.utc)
    check("uri URL-decoded",
          e.http_uri_decoded is not None and "OR 1=1" in e.http_uri_decoded,
          f"got: {e.http_uri_decoded}")
    check("raw_line preserved",        e.raw_line == APACHE_LINE)
    check("log_format set",            e.log_format == LogFormat.APACHE_COMBINED)


def test_syslog_parser():
    print("\nâ”€â”€ Syslog / Auth.log Parser â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    p = SyslogParser()

    fail_e = p.parse_line(SYSLOG_FAIL, 1, "auth.log")
    check("fail: source_ip",      fail_e.source_ip   == "192.168.1.11")
    check("fail: username",       fail_e.username    == "root")
    check("fail: auth_result",    fail_e.auth_result == "failure")
    check("fail: source_port",    fail_e.source_port == 54321)
    check("fail: severity",       fail_e.severity    == "WARNING")
    check("fail: timestamp set",  fail_e.timestamp is not None)
    check("fail: process_name",   fail_e.process_name == "sshd")

    acc_e = p.parse_line(SYSLOG_ACCEPT, 2, "auth.log")
    check("accept: auth_result",  acc_e.auth_result == "success")
    check("accept: severity",     acc_e.severity    == "INFO")


def test_json_parser():
    print("\nâ”€â”€ JSON Generic Parser â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    p = JsonParser()
    e = p.parse_line(JSON_LINE, 1, "app.json")

    check("source_ip",         e.source_ip   == "192.168.1.12")
    check("http_method",       e.http_method == "GET")
    check("http_status",       e.http_status == 200)
    check("timestamp parsed",  e.timestamp is not None)
    check("XSS decoded in uri",
          e.http_uri_decoded is not None and "<script>" in e.http_uri_decoded,
          f"got: {e.http_uri_decoded}")
    check("raw_line preserved", e.raw_line == JSON_LINE)


def test_cloudtrail_parser():
    print("\nâ”€â”€ CloudTrail Parser â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    p = CloudTrailParser()
    e = p.parse_line(CLOUDTRAIL_RECORD, 1, "cloudtrail.json")

    check("source_ip",       e.source_ip   == "185.220.101.45")
    check("username",        e.username    == "dev-bot")
    check("event_name",      e.http_method == "GetSecretValue")
    check("auth_result",     e.auth_result == "failure")
    check("severity",        e.severity    == "WARNING")
    check("error_code",      e.extra.get("errorCode") == "AccessDenied")
    check("timestamp UTC",   e.timestamp is not None and
                             e.timestamp.tzinfo == timezone.utc)


def test_format_detector():
    print("\nâ”€â”€ Format Detector â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")

    # Write temp files and detect them
    cases = [
        ("apache.log",   APACHE_LINE,      LogFormat.APACHE_COMBINED),
        ("auth.log",     SYSLOG_FAIL,      LogFormat.SYSLOG),
        ("events.jsonl", JSON_LINE,         LogFormat.JSON_GENERIC),
    ]

    for filename, content, expected_fmt in cases:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=filename, delete=False, encoding="utf-8"
        ) as f:
            f.write(content + "\n" * 5)  # write a few lines
            tmp_path = f.name
        try:
            detected = detect_format(tmp_path)
            check(
                f"detect {filename}",
                detected == expected_fmt,
                f"expected {expected_fmt.value}, got {detected.value}"
            )
        finally:
            os.unlink(tmp_path)


def test_engine_end_to_end():
    print("\nâ”€â”€ Engine end-to-end â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")

    # Write a fake Apache log with 3 lines
    lines = [
        '1.1.1.1 - - [04/Jan/2026:09:00:00 +0000] "GET / HTTP/1.1" 200 1024 "-" "curl/7.0"',
        APACHE_LINE,   # SQLi attempt
        '10.0.0.5 - - [04/Jan/2026:10:02:00 +0000] "POST /upload.php HTTP/1.1" 200 2048 "-" "python-requests/2.28"',
    ]

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".log", delete=False, encoding="utf-8"
    ) as f:
        f.write("\n".join(lines) + "\n")
        tmp_path = f.name

    try:
        eng    = Engine()
        entries = list(eng.parse(tmp_path))

        check("yields 3 entries",         len(entries) == 3,
              f"got {len(entries)}")
        check("all are LogEntry",          all(isinstance(e, LogEntry) for e in entries))
        check("sha256 in file_meta",       "sha256" in eng.file_meta)
        check("sha256 is 64 hex chars",    len(eng.file_meta["sha256"]) == 64)
        check("stats total_lines == 3",    eng.stats.total_lines == 3,
              f"got {eng.stats.total_lines}")
        check("stats unique_ips == 3",     len(eng.stats.unique_ips) == 3,
              f"got {eng.stats.unique_ips}")
        check("first entry ip",            entries[0].source_ip == "1.1.1.1")
        check("second entry SQLi decoded",
              entries[1].http_uri_decoded is not None and
              "OR 1=1" in entries[1].http_uri_decoded)
        check("third entry ip",            entries[2].source_ip == "10.0.0.5")

        summary = eng.stats.summary()
        check("summary has time_span",     summary["time_span"] is not None)
        check("summary parsed_ok == 3",    summary["parsed_ok"] == 3)

    finally:
        os.unlink(tmp_path)


def test_to_dict_serialisable():
    print("\nâ”€â”€ LogEntry.to_dict() serialisation â”€â”€â”€â”€â”€â”€â”€")
    p = ApacheCombinedParser()
    e = p.parse_line(APACHE_LINE, 1, "test.log")
    d = e.to_dict()

    check("to_dict returns dict",         isinstance(d, dict))
    check("timestamp is string",          isinstance(d["timestamp"], str))
    check("log_format is string",         isinstance(d["log_format"], str))
    # Ensure it's JSON-serialisable (no datetime objects left)
    try:
        json.dumps(d)
        check("JSON serialisable",        True)
    except TypeError as ex:
        check("JSON serialisable",        False, str(ex))


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# Run all tests
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

if __name__ == "__main__":
    print("=" * 52)
    print("  NexLog Layer 1 â€” Test Suite")
    print("=" * 52)

    test_apache_parser()
    test_syslog_parser()
    test_json_parser()
    test_cloudtrail_parser()
    test_format_detector()
    test_engine_end_to_end()
    test_to_dict_serialisable()

    print(f"\n{'=' * 52}")
    print(f"  Results:  {_passed} passed Â· {_failed} failed")
    print(f"{'=' * 52}")

    if _failed > 0:
        raise SystemExit(1)
