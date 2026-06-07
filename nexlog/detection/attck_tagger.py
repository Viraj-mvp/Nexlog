"""
detection/attck_tagger.py â€” NexLog Layer 2
Converts raw MITRE dicts from YAML rules into MitreTag objects.
Also applies confidence boosters based on contextual signals.

Confidence boosting rules (additive, capped at 1.0):
  +0.10  known attack tool in user-agent (sqlmap, nikto, etc.)
  +0.08  source IP is external (not RFC1918 private)
  +0.08  HTTP status 200 on an attack attempt (it worked)
  +0.05  auth_result == "failure" on auth rules
  +0.05  multiple MITRE tactics present (multi-stage attack)
  -0.15  source IP is internal (could be scanner, misconfiguration)
  -0.10  single indicator only (less evidence)
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'core'))

import re
from models import LogEntry
from finding import MitreTag

# â”€â”€ Known attack tool UA fingerprints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_ATTACK_TOOLS = re.compile(
    r'(?i)(sqlmap|nikto|nessus|openvas|masscan|nmap|nuclei|'
    r'dirbuster|gobuster|feroxbuster|hydra|medusa|burpsuite|'
    r'metasploit|zgrab)',
    re.IGNORECASE,
)

# â”€â”€ Private/RFC1918 IP ranges â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_PRIVATE_IP = re.compile(
    r'^(10\.\d+\.\d+\.\d+|'
    r'172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|'
    r'192\.168\.\d+\.\d+|'
    r'127\.\d+\.\d+\.\d+)$'
)


def build_mitre_tags(mitre_list: list[dict]) -> list[MitreTag]:
    """
    Convert a list of YAML mitre dicts into MitreTag objects.
    Called once per rule when the rule engine loads YAML.
    """
    tags = []
    for m in mitre_list:
        tags.append(MitreTag(
            tactic_id      = m.get("tactic_id", ""),
            tactic_name    = m.get("tactic_name", ""),
            technique_id   = m.get("technique_id", ""),
            technique_name = m.get("technique_name", ""),
            sub_technique  = m.get("sub_technique"),
        ))
    return tags


def adjust_confidence(
    base_confidence: float,
    entry: LogEntry,
    mitre_tags: list[MitreTag],
    matched_context: dict,
) -> float:
    """
    Adjust the base confidence score from the YAML rule using
    contextual signals from the triggering LogEntry.

    Returns a float clamped to [0.0, 1.0].
    """
    delta = 0.0

    # â”€â”€ Positive signals â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    # Known attack tool in user-agent â†’ high confidence it's real
    ua = entry.http_user_agent or ""
    if _ATTACK_TOOLS.search(ua):
        delta += 0.10

    # External source IP â†’ real attacker, not internal scan
    ip = entry.source_ip or ""
    if ip and not _PRIVATE_IP.match(ip):
        delta += 0.08

    # HTTP 200 on attack = the attack worked (server responded normally)
    if entry.http_status == 200 and entry.http_method in ("POST", "GET"):
        delta += 0.08

    # Auth failure on auth-category rules
    if entry.auth_result == "failure":
        delta += 0.05

    # Multiple distinct tactics = multi-stage, higher confidence
    tactic_ids = {t.tactic_id for t in mitre_tags}
    if len(tactic_ids) > 1:
        delta += 0.05

    # â”€â”€ Negative signals â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    # Internal source IP = might be scanner, pentest, or misconfiguration
    if ip and _PRIVATE_IP.match(ip):
        delta -= 0.15

    # Threshold rules with very few events = borderline, lower confidence
    event_count = matched_context.get("event_count", 0)
    if event_count and event_count < 3:
        delta -= 0.10

    return max(0.0, min(1.0, base_confidence + delta))


def get_tactic_coverage(findings: list) -> dict[str, int]:
    """
    Summarise which ATT&CK tactics are covered across all findings.
    Used by the dashboard kill-chain view.

    Returns: {"TA0001": 3, "TA0006": 5, ...}
    """
    coverage: dict[str, int] = {}
    for finding in findings:
        for tag in finding.mitre_tags:
            coverage[tag.tactic_id] = coverage.get(tag.tactic_id, 0) + 1
    return coverage


def compute_risk_score(finding, asset_value: float = 1.0) -> float:
    """
    Composite risk score: severity_weight Ã— confidence Ã— asset_value
    Clamped to [0.0, 10.0]. CRITICAL=10, HIGH=7, MEDIUM=4, LOW=2, INFO=1.
    asset_value: 1.0=standard, 2.0=DC/prod DB, 3.0=crown jewel
    """
    weights = {"CRITICAL":10.0,"HIGH":7.0,"MEDIUM":4.0,"LOW":2.0,"INFO":1.0}
    w = weights.get(finding.severity.value, 4.0)
    return round(min(w * finding.confidence * asset_value, 10.0), 2)


def detect_attack_chain(findings: list) -> list[dict]:
    """
    Cross-rule correlation. Detects multi-stage attack sequences
    from the same source IP across different rule categories.
    This is what enterprise SIEMs do â€” NexLog now does it too.
    """
    from collections import defaultdict
    by_ip: dict = defaultdict(list)
    for f in findings:
        if f.source_ip:
            by_ip[f.source_ip].append(f)

    CHAINS = [
        {"name":"Full Web Compromise",            "steps":["recon","web_attack","persistence"],                       "boost":0.15},
        {"name":"Network Intrusion Chain",        "steps":["recon","auth","lateral_movement"],                        "boost":0.15},
        {"name":"Credential to Implant to Exfil", "steps":["auth","malware","exfiltration"],                          "boost":0.20},
        {"name":"Webshell to Lateral Pivot",      "steps":["web_attack","persistence","lateral_movement"],             "boost":0.18},
        {"name":"AI-Era Attack Chain",            "steps":["ai_attack","exfiltration"],                                 "boost":0.20},
        {"name":"Full Compromise to Ransomware",  "steps":["auth","privilege_escalation","impact"],                   "boost":0.25},
        {"name":"Supply Chain to Persistence",    "steps":["supply_chain","persistence"],                               "boost":0.18},
        {"name":"Discovery to Exfiltration",      "steps":["discovery","exfiltration"],                                 "boost":0.15},
        {"name":"Living Off The Land Escalation", "steps":["lolbin","privilege_escalation","lateral_movement"],        "boost":0.20},
        {"name":"Insider Data Theft",             "steps":["insider_threat","exfiltration"],                            "boost":0.18},
        {"name":"Red Team Full Chain",            "steps":["recon","web_attack","privilege_escalation","exfiltration"],"boost":0.25},
    ]

    chains_found = []
    for ip, ip_findings in by_ip.items():
        cats = {f.category for f in ip_findings}
        for chain in CHAINS:
            if set(chain["steps"]).issubset(cats):
                matched = [f for f in ip_findings if f.category in chain["steps"]]
                chains_found.append({
                    "chain_name":     chain["name"],
                    "source_ip":      ip,
                    "categories":     sorted(cats & set(chain["steps"])),
                    "finding_count":  len(matched),
                    "max_risk_score": max((compute_risk_score(f) for f in matched), default=0.0),
                    "confidence_boost": chain["boost"],
                })
    return chains_found
