#!/usr/bin/env python3
import ast
import yaml
import pathlib
import sys
import re

def parse_parsers_file():
    parsers_path = pathlib.Path('nexlog/core/parsers.py')
    if not parsers_path.exists():
        print("Error: parsers.py not found.")
        return {}

    tree = ast.parse(parsers_path.read_text(encoding='utf-8-sig'))
    parsers = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            # Check if it inherits from BaseParser or another Parser
            base_names = [b.id for b in node.bases if isinstance(b, ast.Name)]
            if 'BaseParser' in base_names or any('Parser' in bn for bn in base_names):
                parser_name = node.name
                assigned_fields = set()
                log_format = None
                
                # Check for log_format assignment or fields set in parse_line
                for body_node in node.body:
                    if isinstance(body_node, ast.Assign):
                        for target in body_node.targets:
                            if isinstance(target, ast.Name) and target.id == 'log_format':
                                if isinstance(body_node.value, ast.Attribute) and isinstance(body_node.value.value, ast.Name):
                                    log_format = body_node.value.attr
                    
                    elif isinstance(body_node, ast.FunctionDef) and body_node.name == 'parse_line':
                        # Find all attribute assignments on the LogEntry variable (usually 'e')
                        for sub_node in ast.walk(body_node):
                            if isinstance(sub_node, ast.Assign):
                                for target in sub_node.targets:
                                    if isinstance(target, ast.Attribute):
                                        if isinstance(target.value, ast.Name) and target.value.id == 'e':
                                            assigned_fields.add(target.attr)
                
                parsers[parser_name] = {
                    'log_format': log_format,
                    'fields': assigned_fields
                }
    return parsers

def parse_rules():
    rules_dir = pathlib.Path('nexlog/detection/rules')
    if not rules_dir.exists():
        print("Error: rules directory not found.")
        return []

    rules = []
    for f in rules_dir.glob('*.yaml'):
        try:
            doc = yaml.safe_load(f.read_text(encoding='utf-8'))
            if not doc or 'rules' not in doc:
                continue
            for r in doc['rules']:
                rule_id = r.get('id')
                # Extract fields referenced by this rule
                referenced_fields = set()
                if 'match_field' in r:
                    referenced_fields.add(r['match_field'])
                if 'group_by' in r:
                    referenced_fields.add(r['group_by'])
                if 'filter' in r and isinstance(r['filter'], dict):
                    for k in r['filter'].keys():
                        # Some filters end in _in or _contains (e.g. http_status_in, process_name_contains)
                        # We strip suffix to match LogEntry attribute
                        field = k
                        for suffix in ['_in', '_contains']:
                            if field.endswith(suffix):
                                field = field[:-len(suffix)]
                        referenced_fields.add(field)
                if 'steps' in r and isinstance(r['steps'], list):
                    for step in r['steps']:
                        if 'match_field' in step:
                            referenced_fields.add(step['match_field'])
                        if 'match_field2' in step:
                            referenced_fields.add(step['match_field2'])
                if 'sub_rules' in r and isinstance(r['sub_rules'], list):
                    # For composite rules, recursively collect
                    pass # We will collect from actual leaf rules
                
                rules.append({
                    'id': rule_id,
                    'file': f.name,
                    'referenced_fields': referenced_fields,
                    'category': r.get('category')
                })
        except Exception as e:
            print(f"Error parsing rule file {f.name}: {e}")
    return rules

def main():
    parsers = parse_parsers_file()
    rules = parse_rules()

    print(f"Parsed {len(parsers)} parsers and {len(rules)} rules.")
    
    # Check 1: All fields referenced by rules
    all_referenced_fields = set()
    for r in rules:
        all_referenced_fields.update(r['referenced_fields'])
    
    # Check 2: All fields produced by parsers
    all_produced_fields = set()
    for p_name, p_data in parsers.items():
        all_produced_fields.update(p_data['fields'])
        
    print("\n--- Fields Referenced by Rules but Never Explicitly Set by Any Parser Class ---")
    # Note: Some default fields in LogEntry might be set in BaseParser._minimal, let's verify
    # BaseParser._minimal sets: raw_line, line_number, source_file, log_format
    core_fields = {'raw_line', 'line_number', 'source_file', 'log_format'}
    missing_fields = all_referenced_fields - all_produced_fields - core_fields
    # Remove extra. prefix fields as they can be anything
    missing_fields = {f for f in missing_fields if not f.startswith('extra.')}
    for f in sorted(missing_fields):
        print(f"  {f}")
        
    print("\n--- Parsers and Their Produced Fields ---")
    for p_name in sorted(parsers.keys()):
        p_data = parsers[p_name]
        print(f"  {p_name} ({p_data['log_format']}): {sorted(list(p_data['fields']))}")

if __name__ == '__main__':
    main()
