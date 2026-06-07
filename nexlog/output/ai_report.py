"""
output/ai_report.py â€” NexLog v2  AI Narrative Incident Report
====================================================================
Generates a full natural-language incident report from findings using
the LLM client. Produces both markdown and PDF outputs.

No competitor produces a prose narrative IR report â€” this is the
single biggest differentiator for enterprise demo / portfolio value.

Sections produced:
  1. Executive Summary   â€” non-technical, CISO-ready
  2. Timeline            â€” chronological reconstruction of the attack
  3. TTP Analysis        â€” MITRE ATT&CK mapping with analyst commentary
  4. IOC Inventory       â€” deduplicated IPs, domains, hashes
  5. Affected Scope      â€” hosts, usernames, processes touched
  6. Risk Assessment     â€” risk scores, severity distribution
  7. Recommendations     â€” prioritised hardening steps

Usage:
    from output.ai_report import AIReportBuilder
    from storage.case_db import CaseDB
    from ai.llm_client import LLMClient

    with CaseDB("case.facase") as db:
        builder = AIReportBuilder(db=db, llm=LLMClient())
        md = builder.build_markdown(session_id="sess-001")
        builder.save_pdf(md, "report.pdf")
"""

import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Optional

_root = os.path.dirname(os.path.abspath(__file__))
for _ in range(8):
    if os.path.isfile(os.path.join(_root, "pathconfig.py")):
        break
    _root = os.path.dirname(_root)
if _root not in sys.path:
    sys.path.insert(0, _root)
from pathconfig import ROOT, add_root
add_root()
_ROOT = ROOT


# â”€â”€ Hardening map (category â†’ steps) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_HARDENING = {
    "web_attack":       ["Deploy WAF with OWASP CRS in blocking mode.",
                         "Enforce parameterised queries to prevent SQLi.",
                         "Implement Content-Security-Policy headers."],
    "auth_attack":      ["Enforce MFA on all privileged accounts.",
                         "Implement account lockout after 5 failed attempts.",
                         "Audit and rotate all service account credentials."],
    "privilege_escalation": ["Apply principle of least privilege across all accounts.",
                             "Audit SUID/SGID binaries monthly.",
                             "Monitor for token impersonation events (Event ID 4624 Type 3)."],
    "lateral_movement": ["Segment the network â€” restrict lateral SMB/RDP/WMI.",
                         "Enforce SMB signing on all Windows hosts.",
                         "Deploy CrowdStrike or Defender ATP for process chain visibility."],
    "persistence":      ["Audit scheduled tasks, registry run keys, and startup scripts.",
                         "Enable and monitor Event ID 4698 (new scheduled task).",
                         "Deploy application whitelisting (AppLocker/WDAC)."],
    "exfiltration":     ["Implement DLP on email and cloud storage gateways.",
                         "Block DNS-over-HTTPS at the perimeter.",
                         "Monitor for abnormal outbound data volumes (NetFlow baselining)."],
    "malware":          ["Block macro execution in Office documents (GPO).",
                         "Enforce email attachment sandboxing.",
                         "Maintain up-to-date YARA signatures on all endpoints."],
    "recon":            ["Limit publicly exposed service banners.",
                         "Rate-limit unauthenticated enumeration attempts.",
                         "Deploy honeypots to detect internal reconnaissance."],
    "default":          ["Review and apply all outstanding OS and application patches.",
                         "Conduct a privileged access audit.",
                         "Enable comprehensive audit logging (Windows + Linux)."],
}


def _safe_str(val) -> str:
    return str(val) if val is not None else ""


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# CONTEXT BUILDER  (raw findings â†’ LLM-ready text blocks)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def _build_context(findings: list, max_chars: int = 8000) -> str:
    """
    Converts finding objects/dicts into a compact text block for the LLM.
    Prioritises CRITICAL/HIGH findings and caps length to fit token limits.
    """
    lines = []
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_f = sorted(
        findings,
        key=lambda f: (
            sev_rank.get(_safe_str(getattr(f, "severity", {}) if hasattr(f, "severity")
                         else f.get("severity", "INFO") if isinstance(f, dict) else "INFO")
                         if not isinstance(
                             getattr(f, "severity", None), str)
                         else getattr(f, "severity", "INFO"), 5),
        )
    )
    for f in sorted_f:
        if isinstance(f, dict):
            sev   = f.get("severity", "")
            rid   = f.get("rule_id", "")
            rname = f.get("rule_name", "")
            ip    = f.get("source_ip", "")
            host  = f.get("hostname", "")
            risk  = f.get("risk_score", 0)
            trig  = f.get("trigger_line", "")[:200]
            mitre = ", ".join(t.get("full_id", "") for t in f.get("mitre_tags", []))
            ts    = f.get("timestamp", "")
        else:
            sev   = getattr(getattr(f, "severity", None), "value",
                            str(getattr(f, "severity", "")))
            rid   = getattr(f, "rule_id", "")
            rname = getattr(f, "rule_name", "")
            ip    = getattr(f, "source_ip", "") or ""
            host  = getattr(f, "hostname", "") or ""
            risk  = getattr(f, "risk_score", 0)
            trig  = (getattr(f, "trigger_line", "") or "")[:200]
            mitre = ", ".join(getattr(t, "full_id", "")
                              for t in getattr(f, "mitre_tags", []))
            ts    = getattr(f, "timestamp", "")

        line = (f"[{sev}] Rule {rid} ({rname}) | IP:{ip} | Host:{host} | "
                f"Risk:{risk:.1f} | MITRE:{mitre} | TS:{ts} | Trigger:{trig}")
        lines.append(line)

    text = "\n".join(lines)
    return text[:max_chars]


def _extract_stats(findings: list) -> dict:
    """Pull aggregate stats without the LLM."""
    sev_counts: Counter = Counter()
    ips: set  = set()
    hosts: set = set()
    users: set = set()
    tactics: Counter = Counter()
    risk_scores: list = []
    categories: Counter = Counter()

    for f in findings:
        if isinstance(f, dict):
            sev   = f.get("severity", "INFO")
            ip    = f.get("source_ip")
            host  = f.get("hostname")
            user  = f.get("username")
            risk  = f.get("risk_score", 0)
            cat   = f.get("category", "")
            tags  = f.get("mitre_tags", [])
        else:
            sev   = getattr(getattr(f, "severity", None), "value",
                            str(getattr(f, "severity", "INFO")))
            ip    = getattr(f, "source_ip", None)
            host  = getattr(f, "hostname", None)
            user  = getattr(f, "username", None)
            risk  = getattr(f, "risk_score", 0)
            cat   = getattr(f, "category", "")
            tags  = getattr(f, "mitre_tags", [])

        sev_counts[sev] += 1
        if ip:   ips.add(ip)
        if host: hosts.add(host)
        if user: users.add(user)
        if risk: risk_scores.append(float(risk))
        if cat:  categories[cat] += 1
        for t in tags:
            tname = t.get("tactic_name") if isinstance(t, dict) else getattr(t, "tactic_name", "")
            if tname:
                tactics[tname] += 1

    return {
        "total":        sum(sev_counts.values()),
        "sev_counts":   dict(sev_counts),
        "source_ips":   sorted(ips)[:20],
        "hosts":        sorted(hosts)[:20],
        "users":        sorted(users)[:20],
        "tactics":      dict(tactics.most_common(10)),
        "categories":   dict(categories.most_common(10)),
        "max_risk":     max(risk_scores, default=0.0),
        "avg_risk":     sum(risk_scores) / len(risk_scores) if risk_scores else 0.0,
    }


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# REPORT BUILDER
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class AIReportBuilder:
    """
    Builds a full AI-generated IR report from case findings.

    Args:
        db:          Open CaseDB instance.
        llm:         LLMClient instance (any tier).
        analyst:     Analyst name for report header.
    """

    def __init__(self, db, llm=None, analyst: str = "NexLog Analyst"):
        self._db      = db
        self._analyst = analyst

        # Lazy-import LLM to avoid hard dependency
        if llm is None:
            try:
                from ai.llm_client import LLMClient
                self._llm = LLMClient()
            except Exception:
                self._llm = None
        else:
            self._llm = llm

    def _llm_generate(self, query: str, context: str) -> str:
        """Generate with LLM or return template fallback."""
        if self._llm is None:
            return f"[LLM unavailable â€” install Ollama or set GROQ_API_KEY] Context had {len(context)} chars."
        try:
            return self._llm.generate(query, context, max_tokens=600)
        except Exception as e:
            return f"[LLM error: {e}]"

    def build_markdown(
        self,
        session_id: Optional[str] = None,
        findings: Optional[list] = None,
    ) -> str:
        """
        Generate the full markdown report.

        Args:
            session_id: Load findings from this session in the DB.
            findings:   Pass findings directly (overrides session_id).

        Returns:
            Full markdown string.
        """
        if findings is None:
            findings = self._db.get_findings(
                session_id=session_id, limit=2000)

        if not findings:
            return "# NexLog Incident Report\n\n_No findings to report._\n"

        stats   = _extract_stats(findings)
        context = _build_context(findings)
        now     = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        # â”€â”€ Header â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        lines = [
            "# NexLog AI Incident Report",
            "",
            f"**Generated:** {now}  ",
            f"**Analyst:** {self._analyst}  ",
            f"**Total Findings:** {stats['total']}  ",
            f"**Max Risk Score:** {stats['max_risk']:.1f}/10  ",
            f"**Avg Risk Score:** {stats['avg_risk']:.1f}/10  ",
            "",
            "---",
            "",
        ]

        # â”€â”€ Section 1: Executive Summary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        exec_query = (
            "Write a 3-paragraph executive summary of this security incident for a CISO. "
            "Be direct. State what happened, how severe it is, and what immediate action is needed. "
            "Do not use jargon. Use plain business language."
        )
        exec_text = self._llm_generate(exec_query, context)
        lines += ["## 1. Executive Summary", "", exec_text, "", "---", ""]

        # â”€â”€ Section 2: Severity Distribution â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        lines += ["## 2. Finding Severity Distribution", ""]
        sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        sev_icons = {"CRITICAL": "ðŸ”´", "HIGH": "ðŸŸ ", "MEDIUM": "ðŸŸ¡",
                     "LOW": "ðŸŸ¢", "INFO": "ðŸ”µ"}
        for sev in sev_order:
            cnt = stats["sev_counts"].get(sev, 0)
            if cnt:
                bar = "â–ˆ" * min(cnt, 40)
                lines.append(f"| {sev_icons.get(sev,'')} **{sev}** | {bar} | {cnt} |")

        lines += ["", "---", ""]

        # â”€â”€ Section 3: Attack Timeline â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        timeline_query = (
            "Reconstruct the attacker's timeline chronologically. "
            "Use numbered steps. Start with initial access, through persistence, "
            "lateral movement, and any exfiltration. Cite specific rule IDs and timestamps."
        )
        timeline_text = self._llm_generate(timeline_query, context)
        lines += ["## 3. Attack Timeline Reconstruction", "", timeline_text, "", "---", ""]

        # â”€â”€ Section 4: MITRE ATT&CK Coverage â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        lines += ["## 4. MITRE ATT&CK Tactic Coverage", ""]
        if stats["tactics"]:
            lines.append("| Tactic | Findings |")
            lines.append("|--------|----------|")
            for tactic, cnt in sorted(stats["tactics"].items(),
                                      key=lambda x: -x[1]):
                lines.append(f"| {tactic} | {cnt} |")
        lines += [""]

        ttp_query = (
            "For each observed MITRE ATT&CK technique in the findings, "
            "briefly explain what the attacker was doing and why it is dangerous. "
            "Format as: Technique ID â€” what it means â€” why it matters."
        )
        ttp_text = self._llm_generate(ttp_query, context)
        lines += [ttp_text, "", "---", ""]

        # â”€â”€ Section 5: Affected Scope â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        lines += ["## 5. Affected Scope", ""]
        if stats["source_ips"]:
            lines.append(f"**Attacker Source IPs:** {', '.join(stats['source_ips'][:10])}")
        if stats["hosts"]:
            lines.append(f"**Affected Hosts:** {', '.join(stats['hosts'][:10])}")
        if stats["users"]:
            lines.append(f"**Affected Accounts:** {', '.join(stats['users'][:10])}")
        lines += ["", "---", ""]

        # â”€â”€ Section 6: Risk Assessment â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        risk_query = (
            "Provide a 2-paragraph risk assessment. "
            "State the overall risk level (Critical/High/Medium/Low), "
            "what business impact is likely if this is a real breach, "
            "and what is the estimated attacker dwell time based on the evidence."
        )
        risk_text = self._llm_generate(risk_query, context)
        lines += ["## 6. Risk Assessment", "", risk_text, "", "---", ""]

        # â”€â”€ Section 7: Recommendations â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        # Build hardening list from detected categories
        recs: list[str] = []
        for cat in stats["categories"]:
            recs.extend(_HARDENING.get(cat, []))
        if not recs:
            recs = _HARDENING["default"]
        recs = list(dict.fromkeys(recs))[:12]  # dedupe, cap at 12

        rec_query = (
            "Based on the findings, provide 5 specific, actionable remediation steps "
            "ordered by priority. Be concrete â€” name the specific tool, command, or "
            "policy that the team should implement. Tie each step to a specific finding."
        )
        rec_text = self._llm_generate(rec_query, context)
        lines += ["## 7. Recommendations", "", rec_text, ""]
        lines.append("### Hardening checklist")
        for i, rec in enumerate(recs, 1):
            lines.append(f"- [ ] {rec}")
        lines += ["", "---", ""]

        # â”€â”€ Footer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        lines += [
            "_Report generated by NexLog v2 AI Report Engine._",
            f"_LLM tier: {getattr(self._llm, 'tier_name', 'template-synthesis')}_",
        ]

        return "\n".join(lines)

    def save_markdown(self, path: str,
                      session_id: Optional[str] = None,
                      findings: Optional[list] = None) -> str:
        """Build and save markdown report. Returns path."""
        md = self.build_markdown(session_id=session_id, findings=findings)
        with open(path, "w", encoding="utf-8") as f:
            f.write(md)
        return path

    def save_pdf(self, md_text: str, path: str) -> str:
        """
        Render markdown to PDF using ReportLab.
        Falls back to saving as .txt if ReportLab is unavailable.
        """
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.lib import colors
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, HRFlowable, Table, TableStyle
            )

            doc   = SimpleDocTemplate(path, pagesize=A4,
                                      leftMargin=2*cm, rightMargin=2*cm,
                                      topMargin=2*cm, bottomMargin=2*cm)
            styles = getSampleStyleSheet()

            # Deep Space theme colors
            BG     = colors.HexColor("#080C14")
            CYAN   = colors.HexColor("#00C8FF")
            AMBER  = colors.HexColor("#FFB700")
            RED    = colors.HexColor("#FF3B5C")
            TEXT   = colors.HexColor("#C8DFF0")
            DIM    = colors.HexColor("#5A8FA8")

            title_style = ParagraphStyle("title", parent=styles["Title"],
                                         textColor=CYAN, fontSize=18, spaceAfter=12)
            h1_style    = ParagraphStyle("h1", parent=styles["Heading1"],
                                         textColor=CYAN, fontSize=14, spaceAfter=8)
            h2_style    = ParagraphStyle("h2", parent=styles["Heading2"],
                                         textColor=AMBER, fontSize=12, spaceAfter=6)
            body_style  = ParagraphStyle("body", parent=styles["Normal"],
                                         textColor=TEXT, fontSize=9,
                                         leading=14, spaceAfter=6)
            dim_style   = ParagraphStyle("dim", parent=styles["Normal"],
                                         textColor=DIM, fontSize=8)

            story = []
            for line in md_text.split("\n"):
                stripped = line.strip()
                if not stripped:
                    story.append(Spacer(1, 6))
                elif stripped.startswith("# "):
                    story.append(Paragraph(stripped[2:], title_style))
                elif stripped.startswith("## "):
                    story.append(Paragraph(stripped[3:], h1_style))
                elif stripped.startswith("### "):
                    story.append(Paragraph(stripped[4:], h2_style))
                elif stripped == "---":
                    story.append(HRFlowable(width="100%", color=DIM, thickness=0.5))
                    story.append(Spacer(1, 6))
                elif stripped.startswith("- [ ]"):
                    story.append(Paragraph("â˜ " + stripped[5:], body_style))
                elif stripped.startswith("- "):
                    story.append(Paragraph("â€¢ " + stripped[2:], body_style))
                elif stripped.startswith("**") or stripped.startswith("_"):
                    # Bold/italic metadata lines
                    clean = stripped.replace("**", "").replace("_", "")
                    story.append(Paragraph(clean, dim_style))
                elif stripped.startswith("|"):
                    # Table row â€” collect into paragraph for now
                    story.append(Paragraph(stripped.replace("|", "  "), body_style))
                else:
                    story.append(Paragraph(stripped, body_style))

            doc.build(story)

        except ImportError:
            # Fallback: save as text file
            txt_path = path.replace(".pdf", ".txt")
            with open(txt_path, "w", encoding="utf-8") as f:
                f.write(md_text)
            return txt_path

        return path
