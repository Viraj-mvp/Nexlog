#!/usr/bin/env python3
"""Phase 0 audit script - map all rules, parsers, and sample logs."""
import yaml
import pathlib
import re
import sys

def audit_rules():
    rules_dir = pathlib.Path('nexlog/detection/rules')
    total_rules = 0
    categories = {}
    mitre_tactics = {}
    no_mitre = []
    severity_counts = {}
    rule_ids = []
    issues = []
    file_rule_counts = {}

    KNOWN_FIELDS = {
        'timestamp','source_ip','dest_ip','source_port','dest_port',
        'protocol','hostname','username','process','pid','action',
        'status_code','method','url','user_agent','bytes_sent','bytes_recv',
        'event_id','event_type','severity','message','raw','format','extra',
        'process_name','command_line','http_uri','http_uri_decoded',
        'http_method','http_status','http_user_agent','http_referrer',
        'dns_query','dns_type','dns_answer','file_path','file_hash_md5',
        'file_hash_sha256','auth_result','cloud_provider','cloud_service',
        'cloud_resource','tls_server_name','tls_ja3','rule_name','direction',
        'http_bytes','match_field',
    }

    for f in sorted(rules_dir.rglob('*.yaml')):
        file_count = 0
        try:
            content = f.read_text(encoding='utf-8')
            doc = yaml.safe_load(content)
            if not isinstance(doc, dict):
                issues.append(f'NOT_DICT {f.name}: top-level is {type(doc).__name__}')
                continue
            rules_list = doc.get('rules', [])
            if not rules_list:
                issues.append(f'NO_RULES {f.name}: no rules key or empty')
                continue
            for rule in rules_list:
                if not isinstance(rule, dict):
                    continue
                total_rules += 1
                file_count += 1
                rid = rule.get('id', 'NO_ID')
                rule_ids.append(rid)
                cat = rule.get('category', 'MISSING')
                categories[cat] = categories.get(cat, 0) + 1
                sev = rule.get('severity', 'MISSING')
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
                mitre = rule.get('mitre', None)
                if mitre and isinstance(mitre, list) and len(mitre) > 0:
                    for m in mitre:
                        tactic = m.get('tactic_name', 'MISSING')
                        mitre_tactics[tactic] = mitre_tactics.get(tactic, 0) + 1
                        tech = m.get('technique_id', '')
                        if tech and not re.match(r'T\d{4}', tech):
                            issues.append(f'BAD_TECHNIQUE {f.name}: {rid} technique={tech}')
                else:
                    no_mitre.append(rid)
                # Validate regex pattern
                rtype = rule.get('type', '')
                if rtype == 'regex':
                    pattern = rule.get('pattern', '')
                    if pattern:
                        # Clean YAML multiline
                        pattern = pattern.strip()
                        try:
                            re.compile(pattern)
                        except re.error as e:
                            issues.append(f'INVALID_REGEX {f.name}: {rid} {e}')
                    field = rule.get('match_field', '')
                    if field and field not in KNOWN_FIELDS and not field.startswith('extra.'):
                        issues.append(f'UNKNOWN_FIELD {f.name}: {rid} field={field}')
                for req in ['id','name','description','category','severity']:
                    if req not in rule:
                        issues.append(f'MISSING_FIELD {f.name}: {rid} missing={req}')
        except Exception as e:
            issues.append(f'ERROR {f}: {e}')
        file_rule_counts[f.name] = file_count

    print(f'Total rules: {total_rules}')
    print(f'Rule files: {len(list(rules_dir.rglob("*.yaml")))}')
    print()
    print('=== Rules per file ===')
    for fname, cnt in sorted(file_rule_counts.items()):
        print(f'  {fname:40s} {cnt:3d} rules')
    print()
    print('=== Categories ===')
    for k, v in sorted(categories.items(), key=lambda x: -x[1]):
        print(f'  {k:30s} {v:3d}')
    print()
    print('=== MITRE Tactics ===')
    for k, v in sorted(mitre_tactics.items(), key=lambda x: -x[1]):
        print(f'  {k:40s} {v:3d}')
    print()
    print('=== Severity ===')
    for k, v in sorted(severity_counts.items(), key=lambda x: -x[1]):
        print(f'  {k:15s} {v:3d}')
    print()
    print(f'Rules without MITRE: {len(no_mitre)}')
    for nid in no_mitre[:30]:
        print(f'  {nid}')
    print()
    print(f'Issues found: {len(issues)}')
    for i in issues:
        print(f'  {i}')

def audit_parsers():
    print('\n' + '='*70)
    print('PARSER REGISTRY')
    print('='*70)
    sys.path.insert(0, 'nexlog/core')
    from models import LogFormat
    formats = [f for f in LogFormat if f not in (LogFormat.UNKNOWN,)]
    print(f'LogFormat enum members (excl UNKNOWN): {len(formats)}')

def audit_samples():
    print('\n' + '='*70)
    print('SAMPLE LOG FILES')
    print('='*70)
    log_dir = pathlib.Path('examples/logs')
    for f in sorted(log_dir.iterdir()):
        size = f.stat().st_size
        lines = 0
        try:
            with open(f, 'r', errors='replace') as fh:
                first = fh.readline().rstrip()[:100]
                lines = sum(1 for _ in fh) + 1
        except:
            first = '<binary>'
        print(f'  {f.name:30s} {size:>10,} bytes  {lines:>6,} lines')

if __name__ == '__main__':
    audit_rules()
    audit_parsers()
    audit_samples()
