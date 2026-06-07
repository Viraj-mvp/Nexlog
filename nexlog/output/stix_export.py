"""
output/stix_export.py â€” NexLog Layer 4
Full STIX 2.1 bundle builder. Stdlib only â€” no stix2 package required.

Goes significantly beyond the basic indicator-only bundle in ioc_extractor.py.
Produces a complete STIX graph:

  Objects produced
  â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  identity          â€” the tool creating this bundle (NexLog)
  threat-actor      â€” inferred attacker identity per source IP group
  attack-pattern    â€” one per unique MITRE ATT&CK technique seen in findings
  indicator         â€” one per IOC (with STIX pattern + valid_from)
  malware           â€” for findings in the malware/lolbin categories
  course-of-action  â€” one per hardening recommendation category
  observed-data     â€” groups findings from the same source IP + timeframe

  Relationships produced (SRO â€” STIX Relationship Objects)
  â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  threat-actor  â†’ uses             â†’ attack-pattern
  indicator     â†’ indicates        â†’ threat-actor
  indicator     â†’ indicates        â†’ malware     (for malware findings)
  attack-patternâ†’ mitigated-by     â†’ course-of-action
  observed-data â†’ related-to       â†’ indicator

  Spec compliance
  â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  STIX 2.1 (spec_version: "2.1")
  All timestamps: YYYY-MM-DDTHH:MM:SSZ (Zulu, no microseconds)
  All IDs: <type>--<uuid4>
  confidence: int 0â€“100

Usage:
    from output.stix_export import STIXExport
    from intelligence.ioc_extractor import IOCExtractor

    extractor = IOCExtractor()
    iocs      = extractor.extract(findings)

    bundle = STIXExport(
        findings   = findings,
        iocs       = iocs,
        case_ref   = "IR-2026-001",
        analyst    = "Jane Smith",
        org        = "ACME Corp SOC",
    )

    # Write to file
    bundle.write("case_stix.json")

    # Or get the string
    json_str = bundle.to_json()

    # Summary of what was produced
    print(bundle.summary())
"""

import json
import os
import sys
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

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
sys.path.insert(0, os.path.join(_ROOT, 'detection'))
sys.path.insert(0, os.path.join(_ROOT, 'output'))

from finding import Finding, Severity  # type: ignore

# â”€â”€ STIX pattern map for each IOC type â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_IOC_PATTERN: dict[str, str] = {
    "ipv4":        "[ipv4-addr:value = '{v}']",
    "domain":      "[domain-name:value = '{v}']",
    "url":         "[url:value = '{v}']",
    "hash_md5":    "[file:hashes.MD5 = '{v}']",
    "hash_sha1":   "[file:hashes.'SHA-1' = '{v}']",
    "hash_sha256": "[file:hashes.'SHA-256' = '{v}']",
    "file_path":   "[file:name = '{v}']",
    "email":       "[email-addr:value = '{v}']",
    "hostname":    "[domain-name:value = '{v}']",
    "process":     "[process:name = '{v}']",
    "user_agent":  (
        "[network-traffic:extensions.'http-request-ext'"
        ".request_header.'User-Agent' = '{v}']"
    ),
}

# â”€â”€ MITRE ATT&CK technique â†’ STIX attack-pattern name (abbreviated) â”€â”€â”€â”€â”€â”€
_MITRE_NAMES: dict[str, str] = {
    "T1190": "Exploit Public-Facing Application",
    "T1059": "Command and Scripting Interpreter",
    "T1110": "Brute Force",
    "T1078": "Valid Accounts",
    "T1021": "Remote Services",
    "T1003": "OS Credential Dumping",
    "T1046": "Network Service Scanning",
    "T1082": "System Information Discovery",
    "T1486": "Data Encrypted for Impact",
    "T1055": "Process Injection",
    "T1547": "Boot or Logon Autostart Execution",
    "T1053": "Scheduled Task/Job",
    "T1505": "Server Software Component",
    "T1071": "Application Layer Protocol",
    "T1041": "Exfiltration Over C2 Channel",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1105": "Ingress Tool Transfer",
    "T1566": "Phishing",
    "T1133": "External Remote Services",
    "T1068": "Exploitation for Privilege Escalation",
    "T1134": "Access Token Manipulation",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1070": "Indicator Removal",
    "T1027": "Obfuscated Files or Information",
    "T1218": "System Binary Proxy Execution",
    "T1562": "Impair Defenses",
    "T1557": "Adversary-in-the-Middle",
    "T1558": "Steal or Forge Kerberos Tickets",
    "T1552": "Unsecured Credentials",
    "T1195": "Supply Chain Compromise",
    "T1609": "Container Administration Command",
    "T1611": "Escape to Host",
    "T1528": "Steal Application Access Token",
    "T1583": "Acquire Infrastructure",
    "T1595": "Active Scanning",
    "T1596": "Search Open Technical Databases",
    "T1590": "Gather Victim Network Information",
}

# â”€â”€ Malware-category findings â†’ STIX malware object â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_MALWARE_CATEGORIES = {
    "malware", "lolbin", "impact",
}

# â”€â”€ Hardening â†’ STIX course-of-action â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_COA_DESCRIPTIONS: dict[str, str] = {
    "web_attack":          "Deploy WAF with OWASP CRS; enforce parameterised queries; add CSP headers.",
    "auth":                "Enforce MFA on all accounts; lock after 5 failures; disable root SSH.",
    "malware":             "Isolate host immediately; deploy AppLocker/WDAC; enable PowerShell logging.",
    "persistence":         "Audit cron/tasks; restrict upload execution; deploy Sysmon.",
    "lateral_movement":    "Segment network; enforce AES Kerberos; enable Credential Guard.",
    "privilege_escalation":"Audit sudo rules; patch kernel CVEs; enable UAC max level.",
    "exfiltration":        "Deploy DLP; block paste sites; enforce egress filtering.",
    "recon":               "Rate-limit responses; deploy honeypot paths; hide server versions.",
    "discovery":           "Restrict enum commands; enable PS Script Block Logging; patch Log4j.",
    "impact":              "Offline backups; disable VSS deletion by non-admin; deploy EDR.",
    "supply_chain":        "Pin package versions; enforce secret scanning in CI/CD.",
    "cloud_attack":        "Enforce IMDSv2; enable GuardDuty/CloudTrail; least-privilege IAM.",
    "ai_attack":           "Treat LLM input as untrusted; store API keys in vault; rate-limit endpoints.",
    "lolbin":              "Block certutil/mshta/regsvr32 in AppLocker; alert on LOLBin chains.",
    "api_attack":          "Rate-limit API; disable GraphQL introspection; validate JSON schema.",
    "network_attack":      "Enable DAI; disable SMBv1; enforce DNSSEC; block Tor exit ranges.",
    "insider_threat":      "Least privilege; audit mass downloads; block personal cloud uploads.",
    "bot_activity":        "Deploy CAPTCHA; rate-limit login; block headless browser UAs at WAF.",
    "defense_evasion":     "Alert on EventLog stop; monitor AMSI bypass patterns; FIM on system paths.",
}


def _stix_id(obj_type: str) -> str:
    """Generate a valid STIX 2.1 ID: <type>--<uuid4>."""
    return f"{obj_type}--{uuid.uuid4()}"


def _ts(dt: Optional[datetime] = None) -> str:
    """Return a STIX-compliant timestamp string (Zulu, no microseconds)."""
    if dt is None:
        dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _escape(v: str) -> str:
    """Escape single quotes in a STIX pattern value."""
    return v.replace("'", "\\'")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# STIX EXPORT
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class STIXExport:
    """
    Full STIX 2.1 bundle from NexLog findings and IOCs.

    Builds a complete threat intelligence graph, not just a flat IOC list.
    All objects reference each other via relationship objects (SROs).

    Args:
        findings:   list[Finding] â€” from Layer 2 detection engine
        iocs:       list[IOC]     â€” from IOCExtractor.extract()
        case_ref:   Case reference string (e.g. "IR-2026-001")
        analyst:    Analyst name for created_by attribution
        org:        Organisation name
        tlp_level:  TLP marking ("white"|"green"|"amber"|"red")
    """

    def __init__(
        self,
        findings:  Optional[list[Any]] = None,
        iocs:      Optional[list[Any]] = None,
        case_ref:  str           = "IR-UNKNOWN",
        analyst:   str           = "analyst",
        org:       str           = "NexLog",
        tlp_level: str           = "amber",
    ):
        self._findings  = findings or []
        self._iocs      = iocs     or []
        self._case_ref  = case_ref
        self._analyst   = analyst
        self._org       = org
        self._tlp_level = tlp_level.lower()
        self._now       = _ts()

        # Object registries â€” built progressively
        self._objects:  list[dict] = []
        self._rels:     list[dict] = []

        # ID maps for cross-referencing
        self._identity_id:   str            = ""
        self._ta_ids:        dict[str, str] = {}   # source_ip â†’ threat-actor id
        self._ap_ids:        dict[str, str] = {}   # technique_id â†’ attack-pattern id
        self._ind_ids:       dict[tuple[str, str], str] = {}   # ioc (type,value) â†’ indicator id
        self._malware_ids:   dict[str, str] = {}   # rule_id â†’ malware id
        self._coa_ids:       dict[str, str] = {}   # category â†’ coa id
        self._obs_ids:       dict[str, str] = {}   # source_ip â†’ observed-data id
        self._tlp_marking:   dict[str, Any] = {}

        # TLP marking definition
        self._tlp_id = self._make_tlp_marking()

    # â”€â”€ Build â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def build(self) -> dict:
        """
        Construct the full STIX bundle dict.
        Call this once; subsequent calls rebuild from scratch.
        """
        self._objects = []
        self._rels    = []

        # 1. Identity â€” the creating tool
        self._identity_id = _stix_id("identity")
        self._add({
            "type":           "identity",
            "spec_version":   "2.1",
            "id":             self._identity_id,
            "created":        self._now,
            "modified":       self._now,
            "name":           "NexLog v2",
            "identity_class": "system",
            "description":    f"Case: {self._case_ref} | Analyst: {self._analyst} | Org: {self._org}",
            "object_marking_refs": [self._tlp_id],
        })

        # 2. Attack-patterns (MITRE TTPs from findings)
        self._build_attack_patterns()

        # 3. Threat actors (per unique source IP cluster)
        self._build_threat_actors()

        # 4. Malware objects (malware/lolbin/impact category findings)
        self._build_malware()

        # 5. Course-of-action (hardening recs per observed category)
        self._build_coa()

        # 6. Indicators (one per IOC)
        self._build_indicators()

        # 7. Observed-data (groups findings by source IP)
        self._build_observed_data()

        # 8. Relationships
        self._build_relationships()

        # Assemble bundle
        all_objects = [self._tlp_marking] + self._objects + self._rels
        bundle = {
            "type":         "bundle",
            "id":           _stix_id("bundle"),
            "spec_version": "2.1",
            "objects":      all_objects,
        }
        return bundle

    # â”€â”€ STIX object builders â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _make_tlp_marking(self) -> str:
        """Create a TLP marking-definition object. Returns its ID."""
        _tlp_colours = {
            "white": ("TLP:WHITE", "Unrestricted sharing"),
            "green": ("TLP:GREEN", "Community sharing only"),
            "amber": ("TLP:AMBER", "Organisation and named partners only"),
            "red":   ("TLP:RED",   "Named recipients only"),
        }
        label, desc = _tlp_colours.get(self._tlp_level,
                                        _tlp_colours["amber"])
        tlp_id = _stix_id("marking-definition")
        self._tlp_marking = {
            "type":            "marking-definition",
            "spec_version":    "2.1",
            "id":              tlp_id,
            "created":         self._now,
            "definition_type": "statement",
            "definition":      {"statement": f"{label} â€” {desc}"},
        }
        return tlp_id

    def _build_attack_patterns(self) -> None:
        """Create one attack-pattern per unique MITRE technique in findings."""
        seen: dict[str, str] = {}   # technique_id â†’ ap_id
        for f in self._findings:
            for tag in f.mitre_tags:
                tid = tag.technique_id
                if tid in seen:
                    self._ap_ids[tid] = seen[tid]
                    continue
                ap_id = _stix_id("attack-pattern")
                name  = _MITRE_NAMES.get(tid, tag.technique_name or tid)
                self._add({
                    "type":          "attack-pattern",
                    "spec_version":  "2.1",
                    "id":            ap_id,
                    "created":       self._now,
                    "modified":      self._now,
                    "created_by_ref": self._identity_id,
                    "name":          name,
                    "description":   (
                        f"MITRE ATT&CK {tag.full_id} â€” {tag.tactic_name}. "
                        f"Observed in case {self._case_ref}."
                    ),
                    "external_references": [{
                        "source_name": "mitre-attack",
                        "url":         f"https://attack.mitre.org/techniques/{tid.replace('.','/')}/",
                        "external_id": tag.full_id,
                    }],
                    "kill_chain_phases": [{
                        "kill_chain_name": "mitre-attack",
                        "phase_name":      tag.tactic_name.lower().replace(" ", "-"),
                    }],
                    "object_marking_refs": [self._tlp_id],
                })
                seen[tid]            = ap_id
                self._ap_ids[tid]    = ap_id

    def _build_threat_actors(self) -> None:
        """
        Create one threat-actor per unique source IP that has HIGH+
        findings. Groups findings by source IP to build a per-actor profile.
        """
        ip_findings: dict[str, list[Finding]] = defaultdict(list)
        for f in self._findings:
            if f.source_ip and f.severity >= Severity.HIGH:
                ip_findings[f.source_ip].append(f)

        for ip, flist in ip_findings.items():
            ta_id      = _stix_id("threat-actor")
            categories: list[str] = sorted({f.category for f in flist})
            techniques: list[str] = sorted({t.full_id for f in flist for t in f.mitre_tags})
            max_sev    = max(flist, key=lambda f: f.severity.score()).severity.value
            risk_score = max(f.risk_score for f in flist)

            self._add({
                "type":           "threat-actor",
                "spec_version":   "2.1",
                "id":             ta_id,
                "created":        self._now,
                "modified":       self._now,
                "created_by_ref": self._identity_id,
                "name":           f"Threat Actor â€” {ip}",
                "description":    (
                    f"Source IP {ip} observed in case {self._case_ref}. "
                    f"Max severity: {max_sev}. Risk score: {risk_score:.1f}/10. "
                    f"Attack categories: {', '.join(categories)}."
                ),
                "threat_actor_types": ["unknown"],
                "sophistication":     "intermediate" if risk_score >= 7 else "minimal",
                "resource_level":     "individual",
                "aliases":            [ip],
                "goals":              categories[:5],
                "labels":             techniques[:8],
                "confidence":         int(
                    sum(f.confidence for f in flist) / len(flist) * 100
                ),
                "object_marking_refs": [self._tlp_id],
            })
            self._ta_ids[ip] = ta_id

    def _build_malware(self) -> None:
        """
        Create malware STIX objects for findings in malware/lolbin/impact
        categories. One object per unique rule_id.
        """
        seen: set[str] = set()
        for f in self._findings:
            if f.category not in _MALWARE_CATEGORIES:
                continue
            if f.rule_id in seen:
                continue
            seen.add(f.rule_id)

            mal_id = _stix_id("malware")
            self._add({
                "type":             "malware",
                "spec_version":     "2.1",
                "id":               mal_id,
                "created":          self._now,
                "modified":         self._now,
                "created_by_ref":   self._identity_id,
                "name":             f.rule_name,
                "description":      f.description[:300],
                "malware_types":    [
                    "ransomware"    if f.rule_id.startswith("IMP") else
                    "rootkit"       if "lsass" in (f.trigger_line or "").lower() else
                    "backdoor"      if f.category == "persistence" else
                    "tool"          if f.category == "lolbin" else
                    "unknown"
                ],
                "is_family":        False,
                "labels":           [f.rule_id, f.category],
                "confidence":       int(f.confidence * 100),
                "object_marking_refs": [self._tlp_id],
            })
            self._malware_ids[f.rule_id] = mal_id

    def _build_coa(self) -> None:
        """
        Create course-of-action objects for every attack category observed.
        """
        observed_cats = {f.category for f in self._findings}
        for cat in sorted(observed_cats):
            desc = _COA_DESCRIPTIONS.get(cat, f"Apply hardening controls for {cat}.")
            coa_id = _stix_id("course-of-action")
            self._add({
                "type":           "course-of-action",
                "spec_version":   "2.1",
                "id":             coa_id,
                "created":        self._now,
                "modified":       self._now,
                "created_by_ref": self._identity_id,
                "name":           f"Mitigate â€” {cat.replace('_',' ').title()}",
                "description":    desc,
                "labels":         [cat],
                "object_marking_refs": [self._tlp_id],
            })
            self._coa_ids[cat] = coa_id

    def _build_indicators(self) -> None:
        """
        Create one STIX indicator per IOC with a properly-formed STIX pattern.
        Skips IOC types not in the pattern map (graceful degradation).
        """
        for ioc in self._iocs:
            pattern_tmpl = _IOC_PATTERN.get(ioc.ioc_type)
            if not pattern_tmpl:
                continue
            try:
                pattern = pattern_tmpl.format(v=_escape(ioc.value))
            except Exception:
                continue

            ind_id = _stix_id("indicator")
            ts     = ioc.timestamp or self._now

            # valid_from must be a STIX timestamp string
            try:
                # Parse ISO â†’ reformat to Zulu
                from datetime import datetime
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                valid_from = _ts(dt)
            except Exception:
                valid_from = self._now

            self._add({
                "type":             "indicator",
                "spec_version":     "2.1",
                "id":               ind_id,
                "created":          self._now,
                "modified":         self._now,
                "created_by_ref":   self._identity_id,
                "name":             f"{ioc.ioc_type}: {ioc.value[:80]}",
                "description":      (
                    f"IOC extracted from case {self._case_ref}. "
                    f"Source rule: {ioc.source_rule}. "
                    f"Confidence: {ioc.confidence:.0%}."
                ),
                "indicator_types":  self._indicator_types(ioc),
                "pattern":          pattern,
                "pattern_type":     "stix",
                "valid_from":       valid_from,
                "confidence":       int(ioc.confidence * 100),
                "labels":           ioc.tags[:10],
                "object_marking_refs": [self._tlp_id],
            })
            self._ind_ids[(ioc.ioc_type, ioc.value.lower())] = ind_id

    def _build_observed_data(self) -> None:
        """
        Create observed-data objects grouping findings by source IP.
        Represents the raw observation of the attack traffic.
        """
        ip_findings: dict[str, list[Finding]] = defaultdict(list)
        for f in self._findings:
            key = f.source_ip or f.hostname or "unknown"
            ip_findings[key].append(f)

        for key, flist in ip_findings.items():
            # Find time range
            ts_list = [f.timestamp for f in flist if f.timestamp]
            first   = min(ts_list) if ts_list else None
            last    = max(ts_list) if ts_list else None

            sorted_rules: list[str] = sorted({f.rule_id for f in flist})
            rules_top10 = sorted_rules[:10]
            obs_id = _stix_id("observed-data")
            self._add({
                "type":           "observed-data",
                "spec_version":   "2.1",
                "id":             obs_id,
                "created":        self._now,
                "modified":       self._now,
                "created_by_ref": self._identity_id,
                "first_observed": _ts(first) if first else self._now,
                "last_observed":  _ts(last)  if last  else self._now,
                "number_observed": len(flist),
                "description":    (
                    f"Source: {key}. "
                    f"Findings: {len(flist)}. "
                    f"Severities: {', '.join(sorted({f.severity.value for f in flist}))}. "
                    f"Rules: {', '.join(rules_top10)}."
                ),
                "object_marking_refs": [self._tlp_id],
            })
            self._obs_ids[key] = obs_id

    def _build_relationships(self) -> None:
        """
        Build the SRO (relationship) graph connecting all objects.

        Relationships:
          threat-actor   â†’ uses         â†’ attack-pattern  (per technique used)
          indicator      â†’ indicates    â†’ threat-actor    (IP indicators)
          indicator      â†’ indicates    â†’ malware         (malware-related IOCs)
          attack-pattern â†’ mitigated-by â†’ course-of-action
          observed-data  â†’ related-to   â†’ indicator       (links observations to IOCs)
        """
        # 1. threat-actor â†’ uses â†’ attack-pattern
        ip_techniques: dict[str, set[str]] = defaultdict(set)
        for f in self._findings:
            ip = f.source_ip
            if ip not in self._ta_ids:
                continue
            for tag in f.mitre_tags:
                if tag.technique_id in self._ap_ids:
                    ip_techniques[ip].add(tag.technique_id)

        for ip, techniques in ip_techniques.items():
            ta_id = self._ta_ids[ip]
            for tid in techniques:
                self._add_rel(ta_id, "uses", self._ap_ids[tid],
                              f"Threat actor {ip} used technique {tid}")

        # 2. indicator â†’ indicates â†’ threat-actor  (for ipv4 IOCs)
        for ioc in self._iocs:
            if ioc.ioc_type != "ipv4":
                continue
            ind_id = self._ind_ids.get(("ipv4", ioc.value.lower()))
            ta_id  = self._ta_ids.get(ioc.value)
            if ind_id and ta_id:
                self._add_rel(ind_id, "indicates", ta_id,
                              f"Indicator {ioc.value} associated with threat actor")

        # 3. indicator â†’ indicates â†’ malware
        rule_ioc_map: dict[str, list] = defaultdict(list)
        for ioc in self._iocs:
            rule_ioc_map[ioc.source_rule].append(ioc)

        for rule_id, mal_id in self._malware_ids.items():
            for ioc in rule_ioc_map.get(rule_id, []):
                ind_id = self._ind_ids.get((ioc.ioc_type, ioc.value.lower()))
                if ind_id:
                    self._add_rel(ind_id, "indicates", mal_id,
                                  f"Indicator extracted from malware detection {rule_id}")

        # 4. attack-pattern â†’ mitigated-by â†’ course-of-action
        ap_cats: dict[str, set[str]] = defaultdict(set)
        for f in self._findings:
            for tag in f.mitre_tags:
                if tag.technique_id in self._ap_ids:
                    ap_cats[tag.technique_id].add(f.category)

        for tid, cats in ap_cats.items():
            ap_id = self._ap_ids[tid]
            for cat in cats:
                if cat in self._coa_ids:
                    self._add_rel(ap_id, "mitigated-by", self._coa_ids[cat],
                                  f"Technique {tid} mitigated by controls for {cat}")

        # 5. observed-data â†’ related-to â†’ indicator
        ip_ioc_map: dict[str, list] = defaultdict(list)
        for ioc in self._iocs:
            if ioc.source_ip:
                ip_ioc_map[ioc.source_ip].append(ioc)

        for key, obs_id in self._obs_ids.items():
            ioc_sublist: list[Any] = ip_ioc_map.get(key, [])
            for ioc in ioc_sublist[:5]:   # cap at 5 per observed-data
                ind_id = self._ind_ids.get((ioc.ioc_type, ioc.value.lower()))
                if ind_id:
                    self._add_rel(obs_id, "related-to", ind_id,
                                  "Observed data contains this indicator")

    # â”€â”€ Helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _add(self, obj: dict) -> None:
        self._objects.append(obj)

    def _add_rel(
        self,
        src_id:   str,
        rel_type: str,
        tgt_id:   str,
        desc:     str = "",
    ) -> None:
        self._rels.append({
            "type":                 "relationship",
            "spec_version":         "2.1",
            "id":                   _stix_id("relationship"),
            "created":              self._now,
            "modified":             self._now,
            "created_by_ref":       self._identity_id,
            "relationship_type":    rel_type,
            "source_ref":           src_id,
            "target_ref":           tgt_id,
            "description":          desc,
            "object_marking_refs":  [self._tlp_id],
        })

    @staticmethod
    def _indicator_types(ioc) -> list[str]:
        """Map IOC type to STIX indicator_types vocabulary."""
        _MAP = {
            "ipv4":        ["malicious-activity"],
            "domain":      ["malicious-activity", "compromised"],
            "url":         ["malicious-activity"],
            "hash_md5":    ["malicious-activity"],
            "hash_sha1":   ["malicious-activity"],
            "hash_sha256": ["malicious-activity"],
            "file_path":   ["malicious-activity"],
            "email":       ["attribution"],
            "hostname":    ["compromised"],
            "process":     ["malicious-activity"],
            "user_agent":  ["malicious-activity", "attribution"],
        }
        return _MAP.get(ioc.ioc_type, ["unknown"])

    # â”€â”€ Output â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def to_json(self, indent: int = 2) -> str:
        """Build and serialise the STIX bundle to a JSON string."""
        return json.dumps(self.build(), indent=indent, ensure_ascii=False)

    def write(self, path: str | Path, indent: int = 2) -> Path:
        """Write the STIX bundle to a file. Returns the resolved path."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json(indent), encoding="utf-8")
        return path

    def summary(self) -> dict:
        """
        Return a count summary of what was produced.
        Call after build() or to_json().
        """
        type_counts: dict[str, int] = defaultdict(int)
        for obj in self._objects + self._rels:
            type_counts[obj["type"]] += 1
        return {
            "bundle_objects":   len(self._objects) + len(self._rels) + 1,
            "attack_patterns":  len(self._ap_ids),
            "threat_actors":    len(self._ta_ids),
            "indicators":       len(self._ind_ids),
            "malware":          len(self._malware_ids),
            "course_of_action": len(self._coa_ids),
            "observed_data":    len(self._obs_ids),
            "relationships":    len(self._rels),
            "by_type":          dict(type_counts),
        }
