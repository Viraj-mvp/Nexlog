"""
output/report_builder.py â€” NexLog Layer 3
Generates incident reports from a CaseDB session.

Fixes vs draft version:
  - Timeline now includes hostname and process_name (new Layer 2 fields)
  - Executive summary includes max_risk_score and avg_risk_score
  - Affected hosts section (uses hostname from updated findings)
  - _HARDENING covers all 19 attack categories from the rule library:
    added lolbin, api_attack, network_attack, insider_threat,
    bot_activity, defense_evasion (were missing before)
  - Self-locating sys.path
  - to_markdown: hostname column added to timeline table

Outputs:
  - JSON  â€” full machine-readable report
  - Text  â€” stakeholder-readable plain text
  - Markdown â€” GitHub Issues / Confluence / docs
"""

import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

# â”€â”€ Self-locating path â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
# detection already on path via pathconfig
# storage already on path via pathconfig


# â”€â”€ Hardening recommendations â€” all 19 categories â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_HARDENING: dict[str, list[str]] = {
    "web_attack": [
        "Deploy a WAF with OWASP Core Rule Set (CRS) in blocking mode.",
        "Use parameterised queries / prepared statements to prevent SQLi.",
        "Enforce Content-Security-Policy and X-Content-Type-Options headers.",
        "Disable directory listing; restrict script execution in upload paths.",
        "Validate and encode all user-supplied input server-side.",
    ],
    "auth": [
        "Lock accounts after 5 failed attempts within 10 minutes.",
        "Enforce MFA on all privileged and externally-accessible accounts.",
        "Disable root SSH login (PermitRootLogin no in sshd_config).",
        "Rotate SSH host keys; audit all authorised_keys files.",
        "Deploy adaptive rate-limiting (Fail2Ban or equivalent).",
    ],
    "malware": [
        "Isolate affected hosts immediately and take forensic memory images.",
        "Deploy application whitelisting (AppLocker / WDAC).",
        "Enable PowerShell Script Block Logging and AMSI.",
        "Block known C2 IPs/domains at the perimeter firewall.",
        "Audit scheduled tasks, startup keys, and installed services.",
    ],
    "persistence": [
        "Audit all cron jobs, scheduled tasks, and startup scripts daily.",
        "Monitor EventID 4698 (task created) and 7045 (service installed).",
        "Restrict web-accessible upload directories from script execution.",
        "Deploy Sysmon with SwiftOnSecurity config to capture EIDs 19/20/21.",
    ],
    "lateral_movement": [
        "Segment the network â€” isolate production, corporate, and DMZ.",
        "Disable NTLM where possible; enforce AES-only Kerberos.",
        "Enable Credential Guard on all Windows 10/11 endpoints.",
        "Restrict RDP, WinRM, and SMB between workstations via GPO firewall.",
        "Alert on EventID 4624 LogonType 3 + NTLM from workstation sources.",
    ],
    "privilege_escalation": [
        "Audit sudo rules and group membership quarterly.",
        "Keep kernel and OS patches current â€” most exploits target known CVEs.",
        "Enable UAC at maximum level on all Windows workstations.",
        "Remove SUID bits from non-essential Linux binaries (GTFOBins list).",
        "Monitor EventID 4672 (special privileges assigned to new logon).",
    ],
    "exfiltration": [
        "Deploy DLP controls on email gateways and web proxies.",
        "Block outbound access to paste sites and personal cloud storage.",
        "Alert on large outbound HTTP POST requests (>5 MB).",
        "Enforce egress filtering â€” deny-all outbound except required protocols.",
    ],
    "recon": [
        "Rate-limit HTTP responses to 10 req/s per IP to slow scanners.",
        "Return generic 404 pages â€” avoid leaking framework/server version.",
        "Block known scanner IP ranges (Shodan, Censys, ZoomEye) at perimeter.",
        "Deploy honeypot paths (e.g. /admin, /backup) to detect enumeration.",
    ],
    "discovery": [
        "Restrict access to enumeration commands via AppLocker/sudo policy.",
        "Enable PowerShell Script Block Logging (EventID 4104).",
        "Patch all Java applications to Log4j 2.17.1+ (Log4Shell mitigation).",
        "Monitor for bursts of whoami/systeminfo/net user in process logs.",
    ],
    "impact": [
        "Maintain offline, air-gapped backups tested for restoration monthly.",
        "Disable VSS deletion by non-admin processes via GPO.",
        "Deploy EDR with ransomware behavioural detection enabled.",
        "Alert on vssadmin delete / bcdedit / wmic shadowcopy delete commands.",
    ],
    "supply_chain": [
        "Pin all package versions; use a private registry mirror.",
        "Run Trivy or Snyk dependency scanning in CI/CD on every push.",
        "Enforce GitLeaks / TruffleHog secret scanning as a pre-commit hook.",
        "Audit GitHub Actions YAML for expression injection (${{ }}) patterns.",
    ],
    "cloud_attack": [
        "Enforce IMDSv2 on all EC2 instances â€” disable IMDSv1 at org level.",
        "Enable AWS GuardDuty, CloudTrail, and Security Hub in all regions.",
        "Apply least-privilege IAM; rotate all access keys every 90 days.",
        "Block pod egress to 169.254.169.254 via Kubernetes NetworkPolicy.",
    ],
    "ai_attack": [
        "Treat all LLM-ingested data as untrusted; apply semantic filtering.",
        "Store AI API keys in a secrets manager â€” never in code or logs.",
        "Rate-limit LLM API endpoints; monitor for systematic extraction.",
        "Scope MCP tool permissions to minimum required; audit tool call logs.",
    ],
    "lolbin": [
        "Deploy AppLocker or WDAC to block certutil, mshta, regsvr32 misuse.",
        "Alert on Sysmon EID 1 for certutil/mshta/regsvr32 with network args.",
        "Enable WDAC intelligent script enforcement for PowerShell.",
        "Monitor for LOLBin parent-child process chains (e.g. Word â†’ cmd.exe).",
    ],
    "api_attack": [
        "Enforce rate limiting and authentication on all API endpoints.",
        "Disable GraphQL introspection in production environments.",
        "Validate all JSON input against strict schema â€” reject extra fields.",
        "Implement RBAC/ABAC at the object level to prevent BOLA/IDOR.",
        "Return 404 instead of 403 for unauthorised object access.",
    ],
    "network_attack": [
        "Enable Dynamic ARP Inspection (DAI) on all managed switches.",
        "Disable SMBv1 via GPO â€” block port 445 at perimeter and between VLANs.",
        "Enforce DNSSEC; monitor for short-TTL DNS responses (<10 s).",
        "Block Tor exit node IP ranges at perimeter firewall.",
        "Deploy IDS/IPS (Suricata) with ET Pro rules for protocol anomalies.",
    ],
    "insider_threat": [
        "Enforce least privilege â€” review access rights quarterly.",
        "Enable file access auditing on sensitive shares (EventID 4663).",
        "Monitor for mass download events: >30 files in 10 minutes per user.",
        "Block uploads to personal cloud storage from corporate network.",
        "Conduct offboarding reviews â€” revoke access within 24h of departure.",
    ],
    "bot_activity": [
        "Implement CAPTCHA on login and registration forms.",
        "Enforce rate limiting: max 10 auth attempts per IP per minute.",
        "Block headless browser UA strings (HeadlessChrome, PhantomJS) at WAF.",
        "Use device fingerprinting to detect automation tools.",
        "Deploy a bot management solution (Cloudflare Bot Management, etc.).",
    ],
    "defense_evasion": [
        "Deploy Sysmon with EID 8 (CreateRemoteThread) alerting enabled.",
        "Enable AMSI and ETW telemetry; alert on AMSI bypass patterns.",
        "Monitor for EventLog service stop (EventID 7036) and clear (1102).",
        "Alert on double URL encoding (%25xx) in web requests at WAF.",
        "Enforce file integrity monitoring on critical system paths.",
    ],
}


class ReportBuilder:
    """
    Generates incident reports from a CaseDB session.
    Uses all fields from the updated Layer 2 Finding (hostname,
    process_name, event_id, risk_score, tactic_names).
    """

    def __init__(self, db, session_id: Optional[str] = None):
        self._db         = db
        self._session_id = session_id
        self._generated  = datetime.now(timezone.utc).isoformat()

        self._findings = db.get_findings(session_id=session_id, limit=5000)
        self._evidence = db.get_evidence(session_id=session_id)
        self._notes    = db.get_notes(session_id=session_id)
        self._chains   = db.get_attack_chains(session_id=session_id)
        self._session  = db.get_session(session_id) if session_id else {}
        self._summary  = db.get_findings_summary(session_id=session_id)
        self._integrity = db.verify_case_integrity(session_id=session_id)
        self._actions   = db.get_analyst_actions(session_id=session_id)
        for f in self._findings:
            fid = getattr(f, "_db_id", None)
            if fid:
                setattr(f, "_triage_state", db.get_finding_state(fid))

    # â”€â”€ Data assembly â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _build_report_data(self) -> dict:
        findings = self._findings
        s        = self._summary

        sev_counts: dict[str, int] = defaultdict(int)
        for f in findings:
            sev_counts[f.severity.value] += 1

        cat_counts: dict[str, int] = defaultdict(int)
        for f in findings:
            cat_counts[f.category] += 1

        # Unique attacker IPs (from indexed summary â€” faster)
        attacker_ips = s.get("top_source_ips", [])

        # Affected hosts (new â€” uses hostname field from Layer 2)
        affected_hosts = s.get("top_hostnames", [])

        mitre_ids = sorted({
            tid for f in findings for tid in f.technique_ids
        })

        timeline = sorted(
            [f for f in findings if f.timestamp],
            key=lambda f: f.timestamp
        )

        top_findings = sorted(findings, key=lambda f: f.risk_score, reverse=True)[:5]
        top_finding_dicts = []
        finding_provenance = []
        for f in top_findings:
            fid = getattr(f, "_db_id", None)
            state = getattr(f, "_triage_state", "new")
            fd = f.to_dict()
            fd["finding_id"] = fid
            fd["triage_state"] = state
            fd["provenance"] = {
                "finding_id": fid,
                "source_file": f.source_file,
                "trigger_lineno": f.trigger_lineno,
                "trigger_line": f.trigger_line,
                "supporting_line_count": len(f.supporting_lines or []),
                "confidence": f.confidence,
            }
            top_finding_dicts.append(fd)
            finding_provenance.append({
                "finding_id": fid,
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "confidence": f.confidence,
                "risk_score": f.risk_score,
                "triage_state": state,
                "source_file": f.source_file,
                "trigger_lineno": f.trigger_lineno,
                "trigger_line": f.trigger_line,
                "supporting_line_count": len(f.supporting_lines or []),
            })
        all_finding_dicts = []
        for f in findings:
            fd = f.to_dict()
            fd["finding_id"] = getattr(f, "_db_id", None)
            fd["triage_state"] = getattr(f, "_triage_state", "new")
            all_finding_dicts.append(fd)
        integrity_summary = {
            k: v for k, v in self._integrity.items()
            if k != "evidence_verifications"
        }

        hardening = {
            cat: _HARDENING[cat]
            for cat in cat_counts
            if cat in _HARDENING
        }

        return {
            "report_meta": {
                "generated_at": self._generated,
                "tool":         "NexLog v2",
                "session_id":   self._session_id or "all",
                "source_file":  (self._session.get("source_file", "unknown")
                                 if self._session else "multiple"),
                "sha256":       (self._session.get("sha256", "")
                                 if self._session else ""),
            },
            "executive_summary": {
                "total_findings":         len(findings),
                "critical_count":         sev_counts.get("CRITICAL", 0),
                "high_count":             sev_counts.get("HIGH", 0),
                "severity_breakdown":     dict(sev_counts),
                "attacker_ips":           attacker_ips,
                "affected_hosts":         affected_hosts,    # new
                "attack_categories":      list(cat_counts.keys()),
                "mitre_techniques":       mitre_ids,
                "attack_chains_detected": len(self._chains),
                "max_risk_score":         s.get("max_risk_score", 0.0),  # new
                "avg_risk_score":         s.get("avg_risk_score", 0.0),  # new
            },
            "timeline": [
                {
                    "timestamp":    f.timestamp.isoformat(),
                    "rule_id":      f.rule_id,
                    "rule_name":    f.rule_name,
                    "severity":     f.severity.value,
                    "risk_score":   f.risk_score,        # new
                    "source_ip":    f.source_ip,
                    "hostname":     f.hostname,          # new
                    "process_name": f.process_name,      # new
                    "category":     f.category,
                    "summary":      f.trigger_line[:200],
                }
                for f in timeline
            ],
            "attack_chains":               self._chains,
            "top_findings":                top_finding_dicts,
            "all_findings":                all_finding_dicts,
            "hardening_recommendations":   hardening,
            "chain_of_custody":            self._evidence,
            "integrity_summary":           integrity_summary,
            "evidence_verifications":      self._integrity.get("evidence_verifications", []),
            "analyst_action_trail":        self._actions,
            "finding_provenance":          finding_provenance,
            "analyst_notes":               self._notes,
        }

    # â”€â”€ Output formats â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self._build_report_data(), indent=indent, default=str)

    def to_text(self) -> str:
        d    = self._build_report_data()
        es   = d["executive_summary"]
        meta = d["report_meta"]

        lines = [
            "=" * 68,
            "  NEXLOG INCIDENT REPORT",
            f"  Generated : {meta['generated_at']}",
            f"  Source    : {meta['source_file']}",
            f"  SHA-256   : {meta['sha256'] or 'n/a'}",
            "=" * 68, "",
            "EXECUTIVE SUMMARY", "-" * 40,
            f"  Total findings   : {es['total_findings']}",
            f"  Critical         : {es['critical_count']}",
            f"  High             : {es['high_count']}",
            f"  Max risk score   : {es['max_risk_score']}",
            f"  Avg risk score   : {es['avg_risk_score']}",
            f"  Attacker IPs     : {', '.join(es['attacker_ips']) or 'none'}",
            f"  Affected hosts   : {', '.join(es['affected_hosts']) or 'none'}",
            f"  Attack categories: {', '.join(es['attack_categories']) or 'none'}",
            f"  MITRE techniques : {', '.join(es['mitre_techniques']) or 'none'}",
            f"  Attack chains    : {es['attack_chains_detected']}",
            "",
        ]

        if self._chains:
            lines += ["ATTACK CHAINS DETECTED", "-" * 40]
            for c in self._chains:
                lines.append(
                    f"  [{c['chain_name']}]  IP: {c.get('source_ip','?')}"
                    f"  risk={c.get('max_risk_score',0):.1f}  "
                    f"steps={'â†’'.join(c.get('categories',[]))}"
                )
            lines.append("")

        lines += ["TIMELINE (top 20 by time)", "-" * 40]
        for e in d["timeline"][:20]:
            host_str = f" host={e['hostname']}" if e.get('hostname') else ""
            proc_str = f" proc={e['process_name']}" if e.get('process_name') else ""
            lines.append(
                f"  {e['timestamp'][:19]}  [{e['severity']:<8}] risk={e['risk_score']:<4}"
                f"  {e['rule_name']:<32}  src={e.get('source_ip','?')}"
                f"{host_str}{proc_str}"
            )
        if len(d["timeline"]) > 20:
            lines.append(f"  â€¦ and {len(d['timeline'])-20} more events")
        lines.append("")

        lines += ["HARDENING RECOMMENDATIONS", "-" * 40]
        for cat, recs in d["hardening_recommendations"].items():
            lines.append(f"\n  [{cat.upper()}]")
            for rec in recs:
                lines.append(f"    â€¢ {rec}")
        lines.append("")

        integ = d["integrity_summary"]
        lines += ["EVIDENCE INTEGRITY", "-" * 40]
        lines += [
            f"  Status          : {integ.get('status', 'unknown')}",
            f"  Verified at     : {integ.get('checked_at', 'n/a')}",
            f"  Case DB SHA-256 : {integ.get('case_sha256') or 'n/a'}",
            f"  Evidence files  : {integ.get('verified_evidence', 0)} verified, "
            f"{integ.get('changed_evidence', 0)} changed, "
            f"{integ.get('missing_evidence', 0)} missing",
            f"  Findings        : {integ.get('finding_count', 0)}",
            f"  Analyst actions : {integ.get('analyst_action_count', 0)}",
        ]
        for ev in d["evidence_verifications"]:
            lines.append(
                f"  - {os.path.basename(ev.get('file_path', '?'))}: "
                f"{ev.get('status', 'unknown')}"
            )
        lines.append("")

        lines += ["CHAIN OF CUSTODY", "-" * 40]
        for ev in d["chain_of_custody"]:
            lines += [
                f"  {ev.get('file_path','?')}",
                f"    SHA-256  : {ev.get('sha256','?')}",
                f"    Ingested : {ev.get('ingested_at','?')}",
                f"    Lines    : {ev.get('lines_parsed',0)}  "
                f"Findings: {ev.get('findings_count',0)}",
            ]
        if not d["chain_of_custody"]:
            lines.append("  (no evidence files recorded)")
        lines.append("")

        if d["analyst_notes"]:
            lines += ["ANALYST NOTES", "-" * 40]
            for n in d["analyst_notes"]:
                lines.append(
                    f"  [{n.get('created_at','?')[:19]}] "
                    f"{n.get('analyst','analyst')}: {n.get('note','')}"
                )
            lines.append("")

        if d["analyst_action_trail"]:
            lines += ["ANALYST ACTION TRAIL", "-" * 40]
            for a in d["analyst_action_trail"]:
                lines.append(
                    f"  [{a.get('created_at','?')[:19]}] "
                    f"{a.get('analyst','analyst')} -> {a.get('action','?')} "
                    f"finding={a.get('finding_id','?')} {a.get('note','')}"
                )
            lines.append("")

        lines.append("=" * 68)
        return "\n".join(lines)

    def to_markdown(self) -> str:
        d    = self._build_report_data()
        es   = d["executive_summary"]
        meta = d["report_meta"]

        badges = {
            "CRITICAL": "ðŸ”´", "HIGH": "ðŸŸ ",
            "MEDIUM":   "ðŸŸ¡", "LOW":  "ðŸ”µ", "INFO": "âšª",
        }

        md = [
            "# NexLog Incident Report",
            "",
            f"> **Generated:** {meta['generated_at']}  ",
            f"> **Source:** `{meta['source_file']}`  ",
            f"> **SHA-256:** `{meta['sha256'] or 'n/a'}`",
            "",
            "## Executive Summary",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Total findings | **{es['total_findings']}** |",
            f"| Critical | ðŸ”´ {es['critical_count']} |",
            f"| High | ðŸŸ  {es['high_count']} |",
            f"| Max risk score | `{es['max_risk_score']}` |",
            f"| Avg risk score | `{es['avg_risk_score']}` |",
            f"| Attacker IPs | `{', '.join(es['attacker_ips']) or 'none'}` |",
            f"| Affected hosts | `{', '.join(es['affected_hosts']) or 'none'}` |",
            f"| Attack chains | {es['attack_chains_detected']} |",
            "",
        ]

        if self._chains:
            md += ["## Attack Chains", ""]
            for c in self._chains:
                md.append(
                    f"- **{c['chain_name']}** â€” `{c.get('source_ip','?')}` "
                    f"risk `{c.get('max_risk_score',0):.1f}` "
                    f"â†’ `{'â†’'.join(c.get('categories',[]))}`"
                )
            md.append("")

        md += [
            "## Timeline",
            "",
            "| Time | Sev | Risk | Rule | Source IP | Host |",
            "|------|-----|------|------|-----------|------|",
        ]
        for e in d["timeline"][:30]:
            b = badges.get(e["severity"], "âšª")
            md.append(
                f"| {e['timestamp'][:19]} | {b} {e['severity']} "
                f"| {e['risk_score']} "
                f"| {e['rule_name']} "
                f"| `{e.get('source_ip') or '?'}` "
                f"| `{e.get('hostname') or '-'}` |"
            )
        if len(d["timeline"]) > 30:
            md.append(f"\n_â€¦ and {len(d['timeline'])-30} more events_")
        md.append("")

        md += ["## MITRE ATT&CK Techniques", ""]
        md.append(
            ", ".join(f"`{t}`" for t in es["mitre_techniques"])
            or "_None detected_"
        )
        md.append("")

        md += ["## Hardening Recommendations", ""]
        for cat, recs in d["hardening_recommendations"].items():
            md.append(f"### {cat.replace('_', ' ').title()}")
            for rec in recs:
                md.append(f"- {rec}")
            md.append("")

        integ = d["integrity_summary"]
        md += ["## Evidence Integrity", ""]
        md += ["| Check | Value |", "|-------|-------|"]
        md.append(f"| Status | `{integ.get('status', 'unknown')}` |")
        md.append(f"| Verified at | `{integ.get('checked_at', 'n/a')}` |")
        md.append(f"| Case DB SHA-256 | `{integ.get('case_sha256') or 'n/a'}` |")
        md.append(f"| Evidence verified | `{integ.get('verified_evidence', 0)}` |")
        md.append(f"| Evidence changed | `{integ.get('changed_evidence', 0)}` |")
        md.append(f"| Evidence missing | `{integ.get('missing_evidence', 0)}` |")
        md.append(f"| Analyst actions | `{integ.get('analyst_action_count', 0)}` |")
        md.append("")
        if d["evidence_verifications"]:
            md += ["| Evidence | Status | Current SHA-256 |",
                   "|----------|--------|----------------|"]
            for ev in d["evidence_verifications"]:
                cur = ev.get("current_hash") or ev.get("stored_hash") or ""
                md.append(
                    f"| `{os.path.basename(ev.get('file_path','?'))}` "
                    f"| `{ev.get('status', 'unknown')}` "
                    f"| `{cur[:16] if cur else 'n/a'}` |"
                )
            md.append("")

        md += ["## Chain of Custody", ""]
        if d["chain_of_custody"]:
            md += ["| File | SHA-256 | Ingested | Lines | Findings |",
                   "|------|---------|----------|-------|----------|"]
            for ev in d["chain_of_custody"]:
                sha = ev.get("sha256", "?")
                md.append(
                    f"| `{ev.get('file_path','?')}` "
                    f"| `{sha[:16]}â€¦` "
                    f"| {ev.get('ingested_at','?')[:19]} "
                    f"| {ev.get('lines_parsed',0)} "
                    f"| {ev.get('findings_count',0)} |"
                )
        else:
            md.append("_No evidence files recorded_")
        md.append("")

        if d["analyst_notes"]:
            md += ["## Analyst Notes", ""]
            for n in d["analyst_notes"]:
                md.append(
                    f"- **[{n.get('created_at','?')[:19]}]** "
                    f"_{n.get('analyst','analyst')}_: {n.get('note','')}"
                )
            md.append("")

        if d["analyst_action_trail"]:
            md += ["## Analyst Action Trail", ""]
            for a in d["analyst_action_trail"]:
                md.append(
                    f"- **[{a.get('created_at','?')[:19]}]** "
                    f"_{a.get('analyst','analyst')}_ "
                    f"`{a.get('action','?')}` on `{a.get('finding_id','?')}`"
                    f" - {a.get('note','')}"
                )
            md.append("")

        return "\n".join(md)
