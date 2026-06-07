"""
detection/playbook_engine.py â€” NexLog v2  Analyst Playbook Engine
=======================================================================
Step-by-step incident response playbooks triggered automatically by
finding category. Each playbook is a structured checklist the analyst
follows during an active investigation.

Playbooks cover all 19 detection categories from the rule library.
Each step has: action, tool, expected_result, and MITRE technique context.

Usage:
    from detection.playbook_engine import PlaybookEngine

    engine = PlaybookEngine()
    playbook = engine.get_playbook("auth_attack")
    for step in playbook["steps"]:
        print(f"[{step['phase']}] {step['action']}")
        print(f"  Tool: {step['tool']}")
        print(f"  Expected: {step['expected']}")

    # Auto-select the right playbook from a finding
    pb = engine.playbook_for_finding(finding)
"""

import os
import sys

_root = os.path.dirname(os.path.abspath(__file__))
for _ in range(8):
    if os.path.isfile(os.path.join(_root, "pathconfig.py")):
        break
    _root = os.path.dirname(_root)
if _root not in sys.path:
    sys.path.insert(0, _root)
from pathconfig import ROOT, add_root
add_root()


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# PLAYBOOK LIBRARY
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

_PLAYBOOKS: dict = {

    "auth_attack": {
        "title":       "Brute Force / Credential Attack IR Playbook",
        "description": "Response to authentication attacks, credential stuffing, or brute force.",
        "severity":    "HIGH",
        "mitre":       ["T1110", "T1078"],
        "steps": [
            {"phase": "Contain",  "action": "Block the attacking IP at the perimeter firewall immediately.",
             "tool": "iptables / pfSense / WAF", "expected": "IP blocked, attack traffic drops to zero."},
            {"phase": "Contain",  "action": "Lock the targeted account(s) if real credentials were used.",
             "tool": "Active Directory / IAM console", "expected": "Account locked, all sessions terminated."},
            {"phase": "Identify", "action": "Pull all Event ID 4625 (failed logon) records for the last 24h.",
             "tool": "Event Viewer / Splunk: index=wineventlog EventCode=4625",
             "expected": "Full list of targeted accounts and source IPs."},
            {"phase": "Identify", "action": "Check if any 4624 (successful logon) follows the brute force.",
             "tool": "Event ID 4624 correlation",
             "expected": "Determines if breach was successful."},
            {"phase": "Identify", "action": "Extract all IPs from the attack. Check against CTI (VT, OTX, AbuseIPDB).",
             "tool": "NexLog CTI Enricher / AbuseIPDB API",
             "expected": "Identify botnet infrastructure or nation-state IPs."},
            {"phase": "Eradicate", "action": "Force password reset on all potentially compromised accounts.",
             "tool": "AD: Set-ADAccountPassword -Reset", "expected": "All sessions invalidated."},
            {"phase": "Eradicate", "action": "Review and revoke any API keys or tokens issued to compromised accounts.",
             "tool": "IAM / OAuth console", "expected": "No active sessions from attacker."},
            {"phase": "Recover",  "action": "Enable MFA on all targeted accounts before re-enabling.",
             "tool": "Entra ID / Okta MFA", "expected": "MFA enforced on all reactivated accounts."},
            {"phase": "Recover",  "action": "Implement account lockout policy: 5 failures â†’ 15 min lockout.",
             "tool": "GPO: Account Lockout Policy", "expected": "Policy active on all domain controllers."},
            {"phase": "Lessons",  "action": "Document IOCs: attacking IPs, targeted accounts, timeframe.",
             "tool": "NexLog STIX export / TheHive case",
             "expected": "IOC report shared with threat intel team."},
        ],
    },

    "web_attack": {
        "title":       "Web Application Attack IR Playbook",
        "description": "Response to SQLi, XSS, LFI, RFI, SSRF, or other web attacks.",
        "severity":    "HIGH",
        "mitre":       ["T1190", "T1059.007", "T1071.001"],
        "steps": [
            {"phase": "Contain",  "action": "Enable WAF blocking mode if currently in detection-only.",
             "tool": "ModSecurity / Cloudflare / AWS WAF",
             "expected": "Malicious requests returning 403."},
            {"phase": "Contain",  "action": "Block attacking IP range at CDN / edge.",
             "tool": "Cloudflare / Akamai / nginx geo-block",
             "expected": "Traffic from attacker ASN drops."},
            {"phase": "Identify", "action": "Extract the malicious payload from the trigger line.",
             "tool": "NexLog: copy trigger_line â†’ decode URL-encoding",
             "expected": "Plain-text payload reveals injection type."},
            {"phase": "Identify", "action": "Determine if the injection was successful (HTTP 200 vs 500).",
             "tool": "Access log correlation",
             "expected": "If 200: assume data exposure. If 500: likely blocked."},
            {"phase": "Identify", "action": "Check database query logs for anomalous queries matching the injection.",
             "tool": "MySQL general_log / PostgreSQL pg_stat_activity",
             "expected": "Confirm data accessed or exfiltrated."},
            {"phase": "Eradicate", "action": "Patch the vulnerable endpoint â€” parameterise all queries.",
             "tool": "Code review + SAST (Bandit / Semgrep)",
             "expected": "No injectable parameters in codebase."},
            {"phase": "Eradicate", "action": "Review and rotate any credentials stored in the database.",
             "tool": "Password manager + DB credential rotation",
             "expected": "All credentials changed, old ones revoked."},
            {"phase": "Recover",  "action": "Run DAST scan against the fixed endpoint before re-deployment.",
             "tool": "OWASP ZAP / Burp Suite Scanner",
             "expected": "Zero critical/high findings on target endpoint."},
            {"phase": "Lessons",  "action": "Export all attacker IPs and payloads as STIX bundle.",
             "tool": "NexLog STIX export",
             "expected": "IOCs distributed to all ingestion points."},
        ],
    },

    "privilege_escalation": {
        "title":       "Privilege Escalation IR Playbook",
        "description": "Response to detected privilege escalation attempts.",
        "severity":    "CRITICAL",
        "mitre":       ["T1068", "T1055", "T1134"],
        "steps": [
            {"phase": "Contain",  "action": "Immediately isolate the affected host from the network.",
             "tool": "EDR: isolate host / firewall rule", "expected": "Host can only reach SOC jump box."},
            {"phase": "Contain",  "action": "Kill the escalated process and revoke the elevated token.",
             "tool": "Task Manager / kill PID / net user /del",
             "expected": "Attacker no longer has elevated access."},
            {"phase": "Identify", "action": "Collect memory dump of the affected system.",
             "tool": "WinPmem / avml (Linux) / NexLog memory parser",
             "expected": "Memory image for offline analysis."},
            {"phase": "Identify", "action": "Check Event ID 4672 (special privileges assigned) for the timeline.",
             "tool": "Event log / Splunk: EventCode=4672",
             "expected": "Full escalation timeline and method."},
            {"phase": "Identify", "action": "Identify the escalation vector: SUID, token impersonation, kernel exploit?",
             "tool": "LinPEAS / WinPEAS (offline review of output)",
             "expected": "Specific CVE or misconfiguration identified."},
            {"phase": "Eradicate", "action": "Patch the kernel/driver CVE or fix the misconfiguration used.",
             "tool": "WSUS / apt upgrade / remove SUID bit",
             "expected": "Escalation path closed. Verified with re-test."},
            {"phase": "Eradicate", "action": "Audit all accounts that gained elevated privileges in the past 30 days.",
             "tool": "Event ID 4728/4732 (group membership changes)",
             "expected": "All unexpected escalations identified and reverted."},
            {"phase": "Recover",  "action": "Reimage the affected host or restore from last clean snapshot.",
             "tool": "Hyper-V / VMware snapshot / WDS",
             "expected": "Clean host re-joined to domain."},
            {"phase": "Lessons",  "action": "Update CIS Benchmark compliance to prevent recurrence.",
             "tool": "CIS-CAT / OpenSCAP",
             "expected": "Benchmark score improved, failing controls remediated."},
        ],
    },

    "lateral_movement": {
        "title":       "Lateral Movement IR Playbook",
        "description": "Response to detected attacker movement between systems.",
        "severity":    "CRITICAL",
        "mitre":       ["T1021", "T1550", "T1076"],
        "steps": [
            {"phase": "Contain",  "action": "Block SMB (445), RDP (3389), WinRM (5985) between all non-admin hosts.",
             "tool": "Windows Firewall GPO / ACL", "expected": "Lateral traffic blocked between workstations."},
            {"phase": "Contain",  "action": "Invalidate all Kerberos tickets on affected domain controllers.",
             "tool": "nltest /sc_reset or krbtgt password reset (twice)",
             "expected": "All existing tickets invalidated â€” attacker loses persistent access."},
            {"phase": "Identify", "action": "Map the full movement chain using NexLog attack graph.",
             "tool": "NexLog: Attack Graph View",
             "expected": "Visual map of all lateral movement hops."},
            {"phase": "Identify", "action": "Run BloodHound against current AD state to find attack paths.",
             "tool": "BloodHound / SharpHound",
             "expected": "All remaining exploitable paths to Domain Admin identified."},
            {"phase": "Identify", "action": "Check for scheduled tasks, services, or registry persistence on ALL hopped hosts.",
             "tool": "Autoruns / Event ID 4698 / registry query",
             "expected": "All persistence mechanisms identified."},
            {"phase": "Eradicate", "action": "Remove all persistence on every hopped host simultaneously.",
             "tool": "PowerShell / Autoruns / manual removal",
             "expected": "No persistence remains. Verify with Autoruns scan."},
            {"phase": "Eradicate", "action": "Rotate credentials for all accounts used in the movement chain.",
             "tool": "AD bulk password reset",
             "expected": "All compromised credentials invalidated."},
            {"phase": "Recover",  "action": "Re-enable host comms in phases â€” monitor for re-infection.",
             "tool": "Firewall rule rollback + EDR monitoring",
             "expected": "No re-infection detected after 48h."},
            {"phase": "Lessons",  "action": "Implement network segmentation to prevent future lateral movement.",
             "tool": "VLAN segmentation / microsegmentation (Illumio/NSX)",
             "expected": "Workstations cannot communicate peer-to-peer."},
        ],
    },

    "persistence": {
        "title":       "Persistence Mechanism IR Playbook",
        "description": "Response to detected attacker persistence mechanisms.",
        "severity":    "HIGH",
        "mitre":       ["T1547", "T1053", "T1543"],
        "steps": [
            {"phase": "Identify", "action": "Run Autoruns on affected host â€” export to CSV for evidence.",
             "tool": "Sysinternals Autoruns64.exe /a /c",
             "expected": "Full list of autostart locations. Highlight unsigned entries."},
            {"phase": "Identify", "action": "Query all scheduled tasks: schtasks /query /fo CSV /v",
             "tool": "schtasks / Event ID 4698",
             "expected": "Identify any attacker-created tasks."},
            {"phase": "Identify", "action": "Check registry run keys: HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
             "tool": "reg query / Autoruns",
             "expected": "All run key entries reviewed and unexpected ones flagged."},
            {"phase": "Contain",  "action": "Disable the persistence mechanism WITHOUT deleting (preserve evidence).",
             "tool": "schtasks /disable / reg disable",
             "expected": "Persistence inactive but intact for forensic imaging."},
            {"phase": "Identify", "action": "Hash the persisted binary. Check VirusTotal.",
             "tool": "CertUtil -hashfile / NexLog CTI Enricher",
             "expected": "Malware family and C2 infrastructure identified."},
            {"phase": "Eradicate", "action": "Remove all persistence mechanisms after forensic imaging.",
             "tool": "schtasks /delete / reg delete / sc delete",
             "expected": "All persistence removed. Autoruns confirms clean state."},
            {"phase": "Recover",  "action": "Verify with EDR that no new persistence is created post-cleanup.",
             "tool": "CrowdStrike / Defender ATP process monitor",
             "expected": "No new autostart entries in 24h post-remediation."},
        ],
    },

    "exfiltration": {
        "title":       "Data Exfiltration IR Playbook",
        "description": "Response to detected data exfiltration or staging.",
        "severity":    "CRITICAL",
        "mitre":       ["T1041", "T1048", "T1567"],
        "steps": [
            {"phase": "Contain",  "action": "Block the destination IP/domain at the firewall IMMEDIATELY.",
             "tool": "pfSense / iptables / Palo Alto",
             "expected": "All traffic to exfil destination drops."},
            {"phase": "Identify", "action": "Quantify the exfiltration: bytes sent, duration, destination.",
             "tool": "NetFlow / Zeek conn.log / PCAP analysis",
             "expected": "Exact data volume and timeframe documented."},
            {"phase": "Identify", "action": "Identify what data was accessed before exfiltration.",
             "tool": "File access audit logs / DLP event logs",
             "expected": "Data classification of exfiltrated content."},
            {"phase": "Identify", "action": "Check for DNS tunneling: high-volume DNS queries to unusual domains.",
             "tool": "Zeek dns.log / Wireshark / NexLog IOC extractor",
             "expected": "DNS tunnel traffic identified or ruled out."},
            {"phase": "Eradicate", "action": "Remove all data staging directories and archives.",
             "tool": "Manual removal + EDR file quarantine",
             "expected": "No compressed archives remain on compromised hosts."},
            {"phase": "Recover",  "action": "Notify legal / DPO â€” assess regulatory notification obligation (GDPR 72h).",
             "tool": "Legal team / DPO",
             "expected": "Notification decision made within 24h of discovery."},
            {"phase": "Lessons",  "action": "Deploy DLP on all email and cloud storage gateways.",
             "tool": "Microsoft Purview / Symantec DLP",
             "expected": "DLP policy active. Test with synthetic sensitive data."},
        ],
    },

    "malware": {
        "title":       "Malware Detection IR Playbook",
        "description": "Response to malware detection on a host.",
        "severity":    "HIGH",
        "mitre":       ["T1204", "T1059", "T1055"],
        "steps": [
            {"phase": "Contain",  "action": "Isolate the infected host from the network immediately.",
             "tool": "EDR quarantine / VLAN change / firewall ACL",
             "expected": "Host isolated. No C2 traffic possible."},
            {"phase": "Identify", "action": "Collect memory dump for malware analysis.",
             "tool": "WinPmem (Windows) / AVML (Linux)",
             "expected": "Memory image acquired and SHA256 hashed for chain of custody."},
            {"phase": "Identify", "action": "Hash the malware binary and check VT / MalwareBazaar.",
             "tool": "NexLog CTI Enricher",
             "expected": "Malware family, C2 IPs, and dropper identified."},
            {"phase": "Identify", "action": "Check for lateral movement from the infected host (last 48h).",
             "tool": "NexLog Attack Graph / Zeek conn.log",
             "expected": "Blast radius quantified."},
            {"phase": "Eradicate", "action": "Quarantine the malware binary with EDR.",
             "tool": "CrowdStrike / Defender ATP quarantine",
             "expected": "Binary quarantined. Cannot execute."},
            {"phase": "Eradicate", "action": "Remove all malware persistence and clean registry/scheduled tasks.",
             "tool": "Autoruns / manual cleanup",
             "expected": "Host clean per Autoruns scan."},
            {"phase": "Recover",  "action": "Reimage the host â€” never trust a cleaned malware host for production.",
             "tool": "WDS / Intune Autopilot / OS reimaging",
             "expected": "Fresh OS. Re-joined to domain. EDR re-deployed."},
            {"phase": "Lessons",  "action": "Write a YARA rule from the malware binary and deploy to all endpoints.",
             "tool": "NexLog YARA Studio â†’ export to CrowdStrike / Defender",
             "expected": "YARA rule active on all endpoints. Blocked in 24h."},
        ],
    },

    "default": {
        "title":       "Generic Incident Response Playbook",
        "description": "General-purpose IR checklist for unclassified incidents.",
        "severity":    "MEDIUM",
        "mitre":       [],
        "steps": [
            {"phase": "Identify", "action": "Triage the finding â€” confirm true positive vs false positive.",
             "tool": "NexLog AI Query: 'Is this finding credible?'",
             "expected": "Confirmed true positive or false positive determination."},
            {"phase": "Identify", "action": "Determine scope: how many hosts/users are affected?",
             "tool": "NexLog Findings View â€” filter by category",
             "expected": "List of all affected entities."},
            {"phase": "Contain",  "action": "Apply the minimum necessary containment to stop active threat.",
             "tool": "Firewall / EDR / account lock",
             "expected": "Threat contained without unnecessary service disruption."},
            {"phase": "Eradicate", "action": "Remove the threat and its persistence mechanisms.",
             "tool": "EDR / manual cleanup",
             "expected": "No remaining threat artifacts."},
            {"phase": "Recover",  "action": "Restore affected services and monitor for recurrence.",
             "tool": "Service restore + EDR monitoring",
             "expected": "Services restored. No recurrence in 72h."},
            {"phase": "Lessons",  "action": "Document the incident â€” timeline, IOCs, remediation steps.",
             "tool": "NexLog AI Report / TheHive case",
             "expected": "Incident report filed. IOCs shared with threat intel team."},
        ],
    },
}

# Category aliases
_ALIASES = {
    "api_security":           "web_attack",
    "bot_activity":           "web_attack",
    "recon":                  "default",
    "discovery":              "default",
    "defense_evasion":        "persistence",
    "impact":                 "malware",
    "insider_threat":         "auth_attack",
    "cloud_container_attack": "default",
    "supply_chain":           "malware",
    "living_off_land":        "privilege_escalation",
    "network_protocol":       "lateral_movement",
}


class PlaybookEngine:
    """Retrieve and manage IR playbooks for NexLog findings."""

    def get_playbook(self, category: str) -> dict:
        """
        Get the IR playbook for a detection category.
        Falls back to 'default' if no specific playbook exists.
        """
        cat = category.lower().replace(" ", "_").replace("-", "_")
        cat = _ALIASES.get(cat, cat)
        return _PLAYBOOKS.get(cat, _PLAYBOOKS["default"]).copy()

    def playbook_for_finding(self, finding) -> dict:
        """Auto-select the right playbook from a finding object or dict."""
        if isinstance(finding, dict):
            cat = finding.get("category", "default")
        else:
            cat = str(getattr(finding, "category", "default"))
        return self.get_playbook(cat)

    def all_categories(self) -> list[str]:
        """List all categories that have specific playbooks."""
        return [k for k in _PLAYBOOKS if k != "default"]

    def phase_steps(self, category: str, phase: str) -> list[dict]:
        """Get only steps for a specific IR phase (Contain/Identify/Eradicate/Recover/Lessons)."""
        pb = self.get_playbook(category)
        return [s for s in pb.get("steps", [])
                if s.get("phase", "").lower() == phase.lower()]
