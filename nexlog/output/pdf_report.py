"""
output/pdf_report.py â€” NexLog Layer 4
Professional forensic incident report as a PDF document.

Design philosophy:
  - Court-admissible quality: case metadata on every page, chain-of-custody
    hash, page numbers, generation timestamp in footer
  - Colour-coded severity: CRITICAL red, HIGH amber, MEDIUM yellow, LOW cyan
  - Structured sections: Cover â†’ Exec Summary â†’ Attack Chains â†’ Timeline
    â†’ Finding Detail â†’ IOC Table â†’ Hardening â†’ Chain of Custody â†’ Appendix
  - MITRE ATT&CK heatmap bar chart â€” shows tactic coverage visually
  - Risk score bar per finding â€” CVSS-style 0â€“10 visual indicator
  - Requires: reportlab >= 3.6  (pip install reportlab)

Usage:
    from output.pdf_report import PDFReport
    from storage.case_db import CaseDB

    with CaseDB("case.facase") as db:
        pdf = PDFReport(db, session_id="session-001")
        pdf.build("report_2026_01.pdf")

    # Or with IOCs and enrichment data:
    pdf = PDFReport(db, iocs=ioc_list, analyst="Jane Smith", case_ref="IR-2026-001")
    pdf.build("report.pdf")
"""

import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

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
sys.path.insert(0, os.path.join(_ROOT, 'storage'))
sys.path.insert(0, os.path.join(_ROOT, 'intelligence'))

from finding import Finding

# â”€â”€ ReportLab imports â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.platypus import (
    HRFlowable, KeepTogether, PageBreak,
    Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Circle

# â”€â”€ Colour palette â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_C = {
    "bg_dark":    colors.HexColor("#0D1117"),
    "bg_card":    colors.HexColor("#161B22"),
    "accent":     colors.HexColor("#58A6FF"),
    "critical":   colors.HexColor("#DA3633"),
    "high":       colors.HexColor("#E3B341"),
    "medium":     colors.HexColor("#388BFD"),
    "low":        colors.HexColor("#3DC9B0"),
    "info":       colors.HexColor("#8B949E"),
    "text_main":  colors.HexColor("#E6EDF3"),
    "text_sub":   colors.HexColor("#8B949E"),
    "border":     colors.HexColor("#30363D"),
    "grid_line":  colors.HexColor("#1C2128"),
    "white":      colors.white,
    "black":      colors.black,
    "header_bg":  colors.HexColor("#1C2128"),
    "row_alt":    colors.HexColor("#1C2128"),
}

_SEV_COLOUR = {
    "CRITICAL": _C["critical"],
    "HIGH":     _C["high"],
    "MEDIUM":   _C["medium"],
    "LOW":      _C["low"],
    "INFO":     _C["info"],
}

_PAGE_W, _PAGE_H = A4
_MARGIN = 1.8 * cm


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# PROCEDURAL GRAPHICS ENGINE
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

import random as _random

def _apply_graph_backdrop(d: Drawing, width: float, height: float) -> None:
    """
    Applies a procedural cyber-grid background strictly within the drawing
    bounding box â€” no bleed into surrounding page content.
    Grid lines + randomised glow particles drawn with primitives only.
    """
    d.add(Rect(0, 0, width, height,
               fillColor=_C["bg_card"], strokeColor=_C["grid_line"],
               strokeWidth=1))
    step = 30
    for x in range(0, int(width), step):
        d.add(Line(x, 0, x, height,
                   strokeColor=_C["grid_line"], strokeWidth=0.4))
    for y in range(0, int(height), step):
        d.add(Line(0, y, width, y,
                   strokeColor=_C["grid_line"], strokeWidth=0.4))
    # Bounded glow particles â€” seeded so output is deterministic
    rng = _random.Random(42)
    for _ in range(12):
        px = rng.randint(4, int(width)  - 4)
        py = rng.randint(4, int(height) - 4)
        r  = rng.uniform(0.5, 1.4)
        d.add(Circle(px, py, r * 3,
                     fillColor=_C["accent"], strokeColor=None,
                     fillOpacity=0.12))
        d.add(Circle(px, py, r,
                     fillColor=_C["accent"], strokeColor=None,
                     fillOpacity=0.70))


def _attack_chain_node_graph(chain: dict,
                              width: float = 460,
                              height: float = 90) -> Drawing:
    """
    Node-edge diagram for one attack chain.
    Each category in the chain is a glowing node connected by directed edges.
    Falls back gracefully when there are no categories.
    """
    d    = Drawing(width, height)
    _apply_graph_backdrop(d, width, height)
    cats = chain.get("categories", [])

    if not cats:
        d.add(String(width / 2, height / 2, "No chain data",
                     textAnchor="middle", fillColor=_C["text_sub"],
                     fontSize=8))
        return d

    step  = width / (len(cats) + 1)
    cy    = height / 2 + 5
    nodes = [(round((i + 1) * step), cy) for i in range(len(cats))]

    # Edges
    for i in range(len(nodes) - 1):
        x1, y1 = nodes[i]
        x2, y2 = nodes[i + 1]
        d.add(Line(x1, y1, x2, y2,
                   strokeColor=_C["accent"], strokeWidth=1.5,
                   strokeOpacity=0.5))

    # Nodes
    for i, (x, y) in enumerate(nodes):
        d.add(Circle(x, y, 14,
                     fillColor=_C["critical"], strokeColor=None,
                     fillOpacity=0.18))
        d.add(Circle(x, y, 6,
                     fillColor=_C["critical"], strokeColor=None))
        label = cats[i].replace("_", " ").title()
        d.add(String(x, y - 24, label,
                     textAnchor="middle", fontSize=7.5,
                     fillColor=_C["text_main"]))
    return d


def _topology_graph(findings: list,
                    width: float = 460,
                    height: float = 200) -> Drawing:
    """
    Network attack topology using networkx spring layout.
    Requires: pip install networkx   (graceful fallback if absent)

    Edges = source_ip â†’ hostname pairs from findings.
    Capped at 40 findings to prevent DoS via massive graphs.
    """
    d = Drawing(width, height)
    _apply_graph_backdrop(d, width, height)

    try:
        import networkx as nx
    except ImportError:
        d.add(String(width / 2, height / 2,
                     "pip install networkx  to enable topology graph",
                     textAnchor="middle", fillColor=_C["text_sub"],
                     fontSize=8))
        return d

    G = nx.Graph()
    for f in findings[:40]:
        src  = getattr(f, "source_ip", None)
        host = getattr(f, "hostname",  None)
        if src and host:
            G.add_edge(src, host)

    if G.number_of_nodes() == 0:
        d.add(String(width / 2, height / 2,
                     "No source_ip â†” hostname edges in findings",
                     textAnchor="middle", fillColor=_C["text_sub"],
                     fontSize=8))
        return d

    pos = nx.spring_layout(G, seed=42)

    # Edges
    for u, v in G.edges():
        x1, y1 = pos[u]
        x2, y2 = pos[v]
        px1 = (x1 + 1) * width  / 2
        py1 = (y1 + 1) * height / 2
        px2 = (x2 + 1) * width  / 2
        py2 = (y2 + 1) * height / 2
        d.add(Line(px1, py1, px2, py2,
                   strokeColor=_C["border"], strokeWidth=0.8))

    # Nodes
    for node, (x, y) in pos.items():
        px = (x + 1) * width  / 2
        py = (y + 1) * height / 2
        d.add(Circle(px, py, 12,
                     fillColor=_C["high"], fillOpacity=0.15,
                     strokeColor=None))
        d.add(Circle(px, py, 4,
                     fillColor=_C["high"], strokeColor=None))
        d.add(String(px, py + 8, str(node)[:16],
                     textAnchor="middle", fontSize=6,
                     fillColor=_C["text_main"]))
    return d


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# STYLE SHEET
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def _make_styles() -> dict:
    base = getSampleStyleSheet()
    s = {}

    def ps(name, **kw) -> ParagraphStyle:
        parent = kw.pop("parent", "Normal")
        style  = ParagraphStyle(name, parent=base[parent], **kw)
        return style

    s["cover_title"] = ps("CoverTitle",
        fontSize=28, textColor=_C["text_main"], fontName="Helvetica-Bold",
        leading=34, spaceAfter=8)
    s["cover_sub"] = ps("CoverSub",
        fontSize=13, textColor=_C["accent"], fontName="Helvetica",
        leading=18, spaceAfter=4)
    s["cover_meta"] = ps("CoverMeta",
        fontSize=10, textColor=_C["text_sub"], fontName="Helvetica",
        leading=15, spaceAfter=3)
    s["section"] = ps("Section",
        fontSize=16, textColor=_C["accent"], fontName="Helvetica-Bold",
        leading=22, spaceBefore=14, spaceAfter=8)
    s["subsection"] = ps("SubSection",
        fontSize=12, textColor=_C["text_main"], fontName="Helvetica-Bold",
        leading=16, spaceBefore=8, spaceAfter=4)
    s["body"] = ps("Body",
        fontSize=9, textColor=_C["text_main"], fontName="Helvetica",
        leading=14, spaceAfter=4)
    s["body_sub"] = ps("BodySub",
        fontSize=8, textColor=_C["text_sub"], fontName="Helvetica",
        leading=12, spaceAfter=3)
    s["code"] = ps("Code",
        fontSize=7.5, textColor=_C["low"], fontName="Courier",
        leading=11, spaceAfter=2, backColor=_C["bg_card"],
        leftIndent=6, rightIndent=6)
    s["table_head"] = ps("TableHead",
        fontSize=8, textColor=_C["white"], fontName="Helvetica-Bold",
        leading=11, alignment=TA_LEFT)
    s["table_cell"] = ps("TableCell",
        fontSize=8, textColor=_C["text_main"], fontName="Helvetica",
        leading=11, alignment=TA_LEFT)
    s["table_cell_code"] = ps("TableCellCode",
        fontSize=7, textColor=_C["low"], fontName="Courier",
        leading=10, alignment=TA_LEFT)
    s["severity_label"] = ps("SevLabel",
        fontSize=8, textColor=_C["white"], fontName="Helvetica-Bold",
        leading=11, alignment=TA_CENTER)
    s["toc_entry"] = ps("TocEntry",
        fontSize=9, textColor=_C["accent"], fontName="Helvetica",
        leading=14, leftIndent=10)
    s["footer"] = ps("Footer",
        fontSize=7, textColor=_C["text_sub"], fontName="Helvetica",
        leading=10, alignment=TA_CENTER)
    return s


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TABLE STYLE HELPERS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def _base_table_style(header_rows: int = 1) -> list:
    return [
        ("BACKGROUND",  (0, 0),          (-1, header_rows - 1), _C["header_bg"]),
        ("TEXTCOLOR",   (0, 0),          (-1, header_rows - 1), _C["white"]),
        ("FONTNAME",    (0, 0),          (-1, header_rows - 1), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0),          (-1, -1),              8),
        ("ROWBACKGROUNDS", (0, header_rows), (-1, -1),
             [_C["bg_dark"], _C["row_alt"]]),
        ("TEXTCOLOR",   (0, header_rows),  (-1, -1),            _C["text_main"]),
        ("GRID",        (0, 0),          (-1, -1),              0.3, _C["border"]),
        ("TOPPADDING",  (0, 0),          (-1, -1),              4),
        ("BOTTOMPADDING",(0, 0),         (-1, -1),              4),
        ("LEFTPADDING", (0, 0),          (-1, -1),              6),
        ("RIGHTPADDING",(0, 0),          (-1, -1),              6),
        ("VALIGN",      (0, 0),          (-1, -1),              "MIDDLE"),
    ]


def _severity_chip(sev: str, styles: dict) -> Paragraph:
    """Coloured severity badge paragraph."""
    col = _SEV_COLOUR.get(sev, _C["info"])
    style = ParagraphStyle(
        f"chip_{sev}", parent=styles["severity_label"],
        backColor=col, borderPadding=2,
    )
    return Paragraph(sev, style)


def _risk_bar(score: float, width: float = 60, height: float = 8) -> Drawing:
    """Horizontal risk score bar 0â€“10, colour-coded."""
    d = Drawing(width, height)
    # Background track
    d.add(Rect(0, 0, width, height, fillColor=_C["border"], strokeColor=None))
    # Fill
    fill_w = max(1, (score / 10.0) * width)
    if score >= 8.5:
        col = _C["critical"]
    elif score >= 6.0:
        col = _C["high"]
    elif score >= 3.5:
        col = _C["medium"]
    else:
        col = _C["low"]
    d.add(Rect(0, 0, fill_w, height, fillColor=col, strokeColor=None))
    d.add(String(width / 2, 1, f"{score:.1f}",
                 fontSize=6, fillColor=_C["white"],
                 textAnchor="middle", fontName="Helvetica-Bold"))
    return d


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# MITRE TACTIC BAR CHART
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def _mitre_chart(findings: list[Finding], width: float = 400, height: float = 120) -> Drawing:
    """
    Horizontal bar chart of finding counts by MITRE tactic.
    Uses reportlab VerticalBarChart with transposed layout via custom drawing.
    """
    # Tally tactics
    tactic_counts: dict[str, int] = defaultdict(int)
    tactic_names: dict[str, str]  = {}
    for f in findings:
        for tag in f.mitre_tags:
            tactic_counts[tag.tactic_id] += 1
            tactic_names[tag.tactic_id]   = tag.tactic_name[:18]

    if not tactic_counts:
        d = Drawing(width, height)
        d.add(String(width / 2, height / 2, "No MITRE data",
                     fontSize=9, fillColor=_C["text_sub"],
                     textAnchor="middle"))
        return d

    sorted_items = sorted(tactic_counts.items(), key=lambda x: -x[1])[:12]
    labels  = [tactic_names.get(k, k) for k, _ in sorted_items]
    values  = [v for _, v in sorted_items]
    n       = len(values)

    d = Drawing(width, height)

    bar_h    = min(12, (height - 20) / max(n, 1))
    gap      = 3
    label_w  = 120
    bar_area = width - label_w - 10
    max_val  = max(values) if values else 1

    for i, (label, val) in enumerate(zip(labels, values)):
        y   = height - 15 - i * (bar_h + gap)
        bw  = (val / max_val) * bar_area

        # Colour by tactic group
        if "TA004" in sorted_items[i][0]:
            col = _C["critical"]
        elif "TA000" in sorted_items[i][0]:
            col = _C["high"]
        elif "TA001" in sorted_items[i][0]:
            col = _C["medium"]
        else:
            col = _C["accent"]

        # Bar background
        d.add(Rect(label_w, y, bar_area, bar_h,
                   fillColor=_C["border"], strokeColor=None))
        # Filled bar
        d.add(Rect(label_w, y, bw, bar_h,
                   fillColor=col, strokeColor=None))
        # Label
        d.add(String(label_w - 4, y + 2, label,
                     fontSize=6.5, fillColor=_C["text_main"],
                     textAnchor="end", fontName="Helvetica"))
        # Count
        d.add(String(label_w + bw + 3, y + 2, str(val),
                     fontSize=6, fillColor=_C["text_sub"],
                     textAnchor="start", fontName="Helvetica-Bold"))
    return d


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# PAGE TEMPLATE
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class _ForensicDocTemplate(SimpleDocTemplate):
    """
    Custom page template: dark header bar, page number + case ref footer,
    SHA-256 watermark on first page.
    """

    def __init__(self, path, case_ref: str, sha256: str, analyst: str, **kw):
        self.case_ref  = case_ref
        self.sha256    = sha256
        self.analyst   = analyst
        self._gen_ts   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        super().__init__(str(path), **kw)

    def handle_pageBegin(self):
        super().handle_pageBegin()
        c = self.canv
        w, h = A4

        # Isolate background fill so it never bleeds into platypus text colour
        c.saveState()
        c.setFillColor(_C["bg_dark"])
        c.rect(0, 0, w, h, fill=1, stroke=0)
        c.restoreState()

        # Top accent bar
        c.setFillColor(_C["accent"])
        c.rect(0, h - 6 * mm, w, 6 * mm, fill=1, stroke=0)

        # Header text on the bar
        c.setFillColor(_C["black"])
        c.setFont("Helvetica-Bold", 7)
        c.drawString(_MARGIN, h - 4 * mm, "NEXLOG v2")
        c.setFont("Helvetica", 7)
        c.drawRightString(w - _MARGIN, h - 4 * mm,
                          f"Case: {self.case_ref}  |  {self._gen_ts}")

        # Bottom footer bar
        c.setFillColor(_C["header_bg"])
        c.rect(0, 0, w, 10 * mm, fill=1, stroke=0)
        c.setFillColor(_C["text_sub"])
        c.setFont("Helvetica", 6.5)
        pg = self.page
        c.drawCentredString(w / 2, 3.5 * mm, f"Page {pg}  |  CONFIDENTIAL")
        c.setFont("Courier", 5.5)
        if self.sha256:
            c.drawString(_MARGIN, 1.5 * mm, f"SHA-256: {self.sha256}")
        c.setFont("Helvetica", 5.5)
        c.drawRightString(w - _MARGIN, 1.5 * mm, f"Analyst: {self.analyst}")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# PDF REPORT BUILDER
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class PDFReport:
    """
    NexLog PDF incident report generator.

    Sections (in order):
      1. Cover page          â€” case ref, logo, classification, SHA-256
      2. Table of contents   â€” section list with page anchors (future)
      3. Executive summary   â€” KPIs: total, critical, high, risk score, IPs, hosts
      4. Attack chains       â€” multi-stage sequences detected
      5. MITRE ATT&CK heatmap â€” tactic coverage bar chart
      6. Timeline            â€” chronological event table
      7. Finding detail      â€” per-finding cards with risk bar + evidence
      8. IOC table           â€” all extracted indicators
      9. Hardening recs      â€” per-category remediation table
     10. Chain of custody    â€” evidence file SHA-256 table
     11. Appendix            â€” rule summary, detection statistics

    Args:
        db:         Open CaseDB instance (or None if passing findings directly)
        session_id: Specific session to report on (None = all)
        findings:   Pre-loaded findings list (used if db is None)
        iocs:       IOC objects from IOCExtractor (optional)
        chains:     Attack chain dicts from detect_attack_chain (optional)
        evidence:   Evidence records from db.get_evidence() (optional)
        case_ref:   Case reference number (e.g. "IR-2026-001")
        analyst:    Analyst name for attribution
        org:        Organisation name for cover page
        classification: Document classification label (e.g. "TLP:RED")
    """

    def __init__(
        self,
        db=None,
        session_id:     Optional[str]   = None,
        findings:       list[Finding]   = None,
        iocs:           list            = None,
        chains:         list[dict]      = None,
        evidence:       list[dict]      = None,
        case_ref:       str             = "IR-UNKNOWN",
        analyst:        str             = "Analyst",
        org:            str             = "NexLog",
        classification: str             = "TLP:AMBER",
        ai_narrative:   Optional[str]   = None,
    ):
        self.case_ref       = case_ref
        self.analyst        = analyst
        self.org            = org
        self.classification = classification
        self.ai_narrative   = ai_narrative or ""
        self._styles        = _make_styles()
        self._gen_ts        = datetime.now(timezone.utc).isoformat()

        # Load data from CaseDB or use supplied lists
        if db is not None:
            self._findings = findings or db.get_findings(
                session_id=session_id, limit=2000)
            self._evidence = evidence or db.get_evidence(session_id=session_id)
            self._chains   = chains   or db.get_attack_chains(session_id=session_id)
            self._notes    = db.get_notes(session_id=session_id)
            self._summary  = db.get_findings_summary(session_id=session_id)
            self._integrity = db.verify_case_integrity(session_id=session_id)
            self._actions   = db.get_analyst_actions(session_id=session_id)
            for f in self._findings:
                fid = getattr(f, "_db_id", None)
                if fid:
                    setattr(f, "_triage_state", db.get_finding_state(fid))
            sess           = db.get_session(session_id) if session_id else {}
            self._sha256   = (sess or {}).get("sha256", "")
            self._src_file = (sess or {}).get("source_file", "unknown")
        else:
            self._findings = findings or []
            self._evidence = evidence or []
            self._chains   = chains   or []
            self._notes    = []
            self._actions   = []
            self._sha256   = ""
            self._src_file = "unknown"
            self._integrity = {
                "status": "not_verified",
                "checked_at": self._gen_ts,
                "case_sha256": "",
                "verified_evidence": 0,
                "changed_evidence": 0,
                "missing_evidence": 0,
                "analyst_action_count": 0,
                "evidence_verifications": [],
            }
            self._summary  = {
                "total": len(self._findings),
                "by_severity": Counter(f.severity.value for f in self._findings),
                "by_category": Counter(f.category for f in self._findings),
                "top_source_ips": [],
                "top_hostnames":  [],
                "max_risk_score": max((f.risk_score for f in self._findings), default=0),
                "avg_risk_score": (sum(f.risk_score for f in self._findings) /
                                   max(len(self._findings), 1)),
            }

        self._iocs     = iocs or []
        self._story: list = []

    # â”€â”€ Build â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def build(self, output_path: str | Path) -> Path:
        """
        Render the PDF and write it to output_path.
        Returns the resolved output path.
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        doc = _ForensicDocTemplate(
            output_path,
            case_ref   = self.case_ref,
            sha256     = self._sha256[:32] + "â€¦" if self._sha256 else "",
            analyst    = self.analyst,
            pagesize   = A4,
            topMargin  = 1.4 * cm,
            bottomMargin = 1.4 * cm,
            leftMargin  = _MARGIN,
            rightMargin = _MARGIN,
        )

        self._story = []
        self._add_cover()
        self._story.append(PageBreak())
        self._add_executive_summary()
        self._add_evidence_integrity()
        self._story.append(PageBreak())
        self._add_attack_chains()
        self._add_topology()
        self._add_mitre_chart()
        self._story.append(PageBreak())
        self._add_timeline()
        self._story.append(PageBreak())
        self._add_findings_detail()
        if self.ai_narrative:
            self._story.append(PageBreak())
            self._add_ai_narrative()
        if self._iocs:
            self._story.append(PageBreak())
            self._add_ioc_table()
        self._story.append(PageBreak())
        self._add_hardening()
        self._story.append(PageBreak())
        self._add_chain_of_custody()
        self._add_appendix()

        doc.build(self._story)
        return output_path

    def _add_ai_narrative(self):
        """Optional AI-generated explanation rendered inside the standard PDF format."""
        S = self._styles
        add = self._story.append
        add(Paragraph("7. AI Case Explanation", S["section"]))
        add(HRFlowable(width="100%", thickness=0.5, color=_C["border"]))
        add(Spacer(1, 4 * mm))
        add(Paragraph(
            "This section is generated from local case findings and should be reviewed by an analyst before external sharing.",
            S["body"],
        ))
        add(Spacer(1, 3 * mm))
        for raw in self.ai_narrative.splitlines():
            line = raw.strip()
            if not line:
                add(Spacer(1, 2 * mm))
                continue
            if line.startswith("#"):
                add(Paragraph(line.lstrip("# ").strip(), S["subsection"]))
            elif line.startswith(("-", "*")):
                add(Paragraph("• " + line.lstrip("-* ").strip(), S["body"]))
            else:
                add(Paragraph(line, S["body"]))

    # â”€â”€ Section: Cover â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _add_cover(self):
        S   = self._styles
        add = self._story.append

        add(Spacer(1, 2.5 * cm))

        # Classification banner
        cls_style = ParagraphStyle(
            "ClsStyle", parent=S["body"],
            backColor=_C["critical"] if "RED" in self.classification
            else _C["high"] if "AMBER" in self.classification else _C["medium"],
            textColor=_C["white"], fontSize=10, fontName="Helvetica-Bold",
            alignment=TA_CENTER, borderPadding=6,
        )
        add(Paragraph(f"âš  {self.classification} â€” RESTRICTED DISTRIBUTION", cls_style))
        add(Spacer(1, 1.2 * cm))

        # Title block
        add(HRFlowable(width="100%", thickness=2, color=_C["accent"]))
        add(Spacer(1, 6 * mm))
        add(Paragraph("INCIDENT INVESTIGATION REPORT", S["cover_title"]))
        add(Paragraph("NexLog v2 â€” Attacker-Aware Log Analysis Platform", S["cover_sub"]))
        add(Spacer(1, 6 * mm))
        add(HRFlowable(width="100%", thickness=1, color=_C["border"]))
        add(Spacer(1, 1.5 * cm))

        # Metadata table
        sev_counts = self._summary.get("by_severity", {})
        meta_data = [
            ["Case Reference",    self.case_ref],
            ["Analyst",           self.analyst],
            ["Organisation",      self.org],
            ["Source File",       Path(self._src_file).name],
            ["Total Findings",    str(self._summary.get("total", 0))],
            ["Critical / High",   f"{sev_counts.get('CRITICAL',0)} / {sev_counts.get('HIGH',0)}"],
            ["Max Risk Score",    f"{self._summary.get('max_risk_score',0):.1f} / 10.0"],
            ["Generated",         self._gen_ts[:19] + " UTC"],
            ["SHA-256 (evidence)", self._sha256[:48] + ("â€¦" if len(self._sha256) > 48 else "")
             if self._sha256 else "N/A"],
        ]
        t_style = [
            ("BACKGROUND",   (0, 0), (0, -1), _C["header_bg"]),
            ("TEXTCOLOR",    (0, 0), (0, -1), _C["accent"]),
            ("FONTNAME",     (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME",     (1, 0), (1, -1), "Helvetica"),
            ("FONTSIZE",     (0, 0), (-1, -1), 9),
            ("TEXTCOLOR",    (1, 0), (1, -1), _C["text_main"]),
            ("GRID",         (0, 0), (-1, -1), 0.3, _C["border"]),
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [_C["bg_dark"], _C["row_alt"]]),
            ("TOPPADDING",   (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
            ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ]
        meta_table = Table(
            [[Paragraph(k, S["body"]), Paragraph(v, S["body"])]
             for k, v in meta_data],
            colWidths=[5 * cm, 11 * cm],
        )
        meta_table.setStyle(TableStyle(t_style))
        add(meta_table)
        add(Spacer(1, 2 * cm))

        # Severity summary cards
        add(Paragraph("Severity Distribution", S["subsection"]))
        sev_order = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
        card_data  = [[]]
        for sev in sev_order:
            count = sev_counts.get(sev, 0)
            col   = _SEV_COLOUR.get(sev, _C["info"])
            style = ParagraphStyle(f"card_{sev}", parent=S["severity_label"],
                                   backColor=col, fontSize=10,
                                   borderPadding=6, leading=14)
            cell  = Table([
                [Paragraph(f"{count}", ParagraphStyle(f"n_{sev}", parent=S["cover_title"],
                    fontSize=22, textColor=_C["white"], fontName="Helvetica-Bold",
                    alignment=TA_CENTER))],
                [Paragraph(sev, style)],
            ], colWidths=[3.2 * cm])
            cell.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,-1), col),
                ("ALIGN", (0,0), (-1,-1), "CENTER"),
                ("TOPPADDING", (0,0), (-1,-1), 6),
                ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ]))
            card_data[0].append(cell)
        cards = Table(card_data, colWidths=[3.2 * cm] * 5,
                      hAlign="CENTER")
        cards.setStyle(TableStyle([
            ("ALIGN", (0,0), (-1,-1), "CENTER"),
            ("LEFTPADDING", (0,0), (-1,-1), 4),
            ("RIGHTPADDING", (0,0), (-1,-1), 4),
        ]))
        add(cards)

    # â”€â”€ Section: Executive Summary â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _add_executive_summary(self):
        S   = self._styles
        add = self._story.append
        s   = self._summary

        add(Paragraph("1. Executive Summary", S["section"]))
        add(HRFlowable(width="100%", thickness=0.5, color=_C["border"]))
        add(Spacer(1, 4 * mm))

        # KPI table
        top_ips   = ", ".join(s.get("top_source_ips", [])[:5]) or "None"
        top_hosts = ", ".join(s.get("top_hostnames",  [])[:5]) or "None"
        all_mitre = sorted({
            tid for f in self._findings for tid in f.technique_ids
        })
        kpi_rows = [
            ["Total Findings",       str(s.get("total", 0))],
            ["Critical",             str(s.get("by_severity",{}).get("CRITICAL",0))],
            ["High",                 str(s.get("by_severity",{}).get("HIGH",0))],
            ["Max Risk Score",       f"{s.get('max_risk_score',0):.1f} / 10.0"],
            ["Avg Risk Score",       f"{s.get('avg_risk_score',0):.1f}"],
            ["Attack Chains",        str(len(self._chains))],
            ["Top Attacker IPs",     top_ips[:80]],
            ["Affected Hosts",       top_hosts[:80]],
            ["MITRE Techniques",     ", ".join(all_mitre[:15])
                                     + ("â€¦" if len(all_mitre) > 15 else "")],
            ["Attack Categories",    ", ".join(sorted(s.get("by_category",{}).keys()))],
        ]
        kpi_table = Table(
            [[Paragraph(k, S["body"]), Paragraph(v, S["body"])]
             for k, v in kpi_rows],
            colWidths=[5 * cm, 11 * cm],
        )
        kpi_table.setStyle(TableStyle(_base_table_style()))
        add(kpi_table)
        add(Spacer(1, 6 * mm))

        # Category breakdown table
        by_cat = s.get("by_category", {})
        if by_cat:
            add(Paragraph("Findings by Attack Category", S["subsection"]))
            cat_rows = [["Category", "Findings", "% of Total"]]
            total    = max(s.get("total", 1), 1)
            for cat, cnt in sorted(by_cat.items(), key=lambda x: -x[1]):
                cat_rows.append([
                    Paragraph(cat.replace("_"," ").title(), S["table_cell"]),
                    Paragraph(str(cnt), S["table_cell"]),
                    Paragraph(f"{cnt/total*100:.1f}%", S["table_cell"]),
                ])
            cat_table = Table(cat_rows,
                              colWidths=[8 * cm, 3 * cm, 3 * cm])
            cat_table.setStyle(TableStyle(_base_table_style()))
            add(cat_table)

    # â”€â”€ Section: Attack Chains â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _add_evidence_integrity(self):
        S   = self._styles
        add = self._story.append
        integ = self._integrity

        add(Spacer(1, 6 * mm))
        add(Paragraph("Evidence Integrity", S["section"]))
        add(HRFlowable(width="100%", thickness=0.5, color=_C["border"]))
        add(Spacer(1, 4 * mm))

        rows = [
            ["Case Status", str(integ.get("status", "unknown")).upper()],
            ["Verified At", str(integ.get("checked_at", "n/a"))[:19]],
            ["Case DB SHA-256", (integ.get("case_sha256") or "n/a")[:32]],
            ["Evidence", (
                f"{integ.get('verified_evidence', 0)} verified / "
                f"{integ.get('changed_evidence', 0)} changed / "
                f"{integ.get('missing_evidence', 0)} missing"
            )],
            ["Analyst Actions", str(integ.get("analyst_action_count", 0))],
        ]
        t = Table(
            [[Paragraph(k, S["body"]), Paragraph(v, S["body"])]
             for k, v in rows],
            colWidths=[5 * cm, 11 * cm],
        )
        t.setStyle(TableStyle(_base_table_style()))
        add(t)
        add(Spacer(1, 4 * mm))

        verifications = integ.get("evidence_verifications", [])
        if verifications:
            ev_rows = [["Evidence", "Status", "Current SHA-256"]]
            for ev in verifications[:20]:
                current = ev.get("current_hash") or ev.get("stored_hash") or ""
                ev_rows.append([
                    Paragraph(Path(ev.get("file_path", "?")).name, S["table_cell"]),
                    Paragraph(str(ev.get("status", "unknown")).upper(), S["table_cell"]),
                    Paragraph(current[:24] if current else "N/A", S["table_cell_code"]),
                ])
            ev_table = Table(ev_rows, colWidths=[6*cm, 3*cm, 7*cm], repeatRows=1)
            ev_table.setStyle(TableStyle(_base_table_style()))
            add(ev_table)

        if self._actions:
            add(Spacer(1, 4 * mm))
            add(Paragraph("Analyst Action Trail", S["subsection"]))
            action_rows = [["Time", "Analyst", "Action", "Finding"]]
            for a in self._actions[:20]:
                action_rows.append([
                    Paragraph(str(a.get("created_at", "?"))[:19], S["table_cell_code"]),
                    Paragraph(str(a.get("analyst", "analyst")), S["table_cell"]),
                    Paragraph(str(a.get("action", "?")), S["table_cell"]),
                    Paragraph(str(a.get("finding_id", "?"))[:16], S["table_cell_code"]),
                ])
            action_table = Table(action_rows,
                                 colWidths=[4*cm, 3.2*cm, 3.2*cm, 5.6*cm],
                                 repeatRows=1)
            action_table.setStyle(TableStyle(_base_table_style()))
            add(action_table)

    def _add_attack_chains(self):
        S   = self._styles
        add = self._story.append

        add(Spacer(1, 6 * mm))
        add(Paragraph("2. Multi-Stage Attack Chains", S["section"]))
        add(HRFlowable(width="100%", thickness=0.5, color=_C["border"]))
        add(Spacer(1, 4 * mm))

        if not self._chains:
            add(Paragraph("No multi-stage attack chains were detected in this session.",
                           S["body_sub"]))
            return

        for c in self._chains:
            name     = c.get("chain_name", "Unknown Chain")
            src_ip   = c.get("source_ip", "?")
            risk     = c.get("max_risk_score", 0.0)
            cats     = c.get("categories", [])
            n_finds  = c.get("finding_count", 0)
            boost    = c.get("confidence_boost", 0.0)

            chain_style = ParagraphStyle(
                "chain_h", parent=S["subsection"],
                backColor=_C["bg_card"], borderPadding=5,
            )
            add(KeepTogether([
                Paragraph(f"â–¶  {name}", chain_style),
                Spacer(1, 2 * mm),
                # Node-graph diagram (new visual)
                _attack_chain_node_graph(c),
                Spacer(1, 2 * mm),
                Table([[
                    Paragraph(f"Source IP: {src_ip}", S["body"]),
                    Paragraph(f"Findings: {n_finds}", S["body"]),
                    Paragraph(f"Confidence boost: +{boost:.0%}", S["body"]),
                    _risk_bar(risk, width=80, height=10),
                ]], colWidths=[5*cm, 3*cm, 4*cm, 2.5*cm],
                    style=[("VALIGN",(0,0),(-1,-1),"MIDDLE"),
                           ("LEFTPADDING",(0,0),(-1,-1),4)]),
                Spacer(1, 4 * mm),
            ]))

    def _add_topology(self):
        """
        Network attack topology view using networkx spring layout.
        Shows source_ip â†’ hostname edges from all findings.
        Renders as a procedural graph â€” no external images required.
        Silently skipped if there are no IPâ†”hostname pairs.
        """
        S   = self._styles
        add = self._story.append

        # Only render if there are source_ip + hostname pairs
        pairs = [(f.source_ip, f.hostname)
                 for f in self._findings
                 if f.source_ip and f.hostname]
        if not pairs:
            return

        add(Spacer(1, 4 * mm))
        add(Paragraph("3. Network Attack Topology", S["section"]))
        add(HRFlowable(width="100%", thickness=0.5, color=_C["border"]))
        add(Spacer(1, 4 * mm))
        add(_topology_graph(self._findings, width=460, height=180))
        add(Spacer(1, 3 * mm))
        add(Paragraph(
            "Nodes represent attacker IPs and targeted hostnames. "
            "Edges indicate observed attack traffic between them. "
            "Requires: pip install networkx",
            S["body_sub"]))
        add(PageBreak())

    # â”€â”€ Section: MITRE Heatmap â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _add_mitre_chart(self):
        S   = self._styles
        add = self._story.append

        add(Paragraph("4. MITRE ATT&CK Tactic Coverage", S["section"]))
        add(HRFlowable(width="100%", thickness=0.5, color=_C["border"]))
        add(Spacer(1, 4 * mm))

        chart = _mitre_chart(self._findings, width=460, height=130)
        add(chart)
        add(Spacer(1, 3 * mm))
        add(Paragraph(
            "Bar chart shows finding counts grouped by MITRE ATT&CK tactic. "
            "Tactics with the highest bar represent the primary attack phases "
            "observed in this investigation.",
            S["body_sub"]))

    # â”€â”€ Section: Timeline â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _add_timeline(self):
        S   = self._styles
        add = self._story.append

        add(Paragraph("5. Event Timeline", S["section"]))
        add(HRFlowable(width="100%", thickness=0.5, color=_C["border"]))
        add(Spacer(1, 4 * mm))

        tl = sorted(
            [f for f in self._findings if f.timestamp],
            key=lambda f: f.timestamp
        )[:50]   # cap at 50 rows

        if not tl:
            add(Paragraph("No timestamped events to display.", S["body_sub"]))
            return

        rows = [["Timestamp", "Sev", "Rule", "Source IP", "Host", "Risk"]]
        for f in tl:
            rows.append([
                Paragraph(f.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                          S["table_cell_code"]),
                _severity_chip(f.severity.value, S),
                Paragraph(f"{f.rule_id}: {f.rule_name[:28]}", S["table_cell"]),
                Paragraph(f.source_ip or "â€”", S["table_cell_code"]),
                Paragraph(f.hostname   or "â€”", S["table_cell"]),
                _risk_bar(f.risk_score, width=40, height=7),
            ])

        tl_table = Table(
            rows,
            colWidths=[3.6*cm, 1.5*cm, 6.5*cm, 2.8*cm, 2.5*cm, 1.8*cm],
            repeatRows=1,
        )
        tl_table.setStyle(TableStyle(_base_table_style()))
        add(tl_table)
        if len(self._findings) > 50:
            add(Spacer(1, 3 * mm))
            add(Paragraph(
                f"Note: Timeline limited to first 50 of "
                f"{len(self._findings)} timestamped events. "
                "Full data available in the JSON report.",
                S["body_sub"]))

    # â”€â”€ Section: Finding Detail â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _add_findings_detail(self):
        S   = self._styles
        add = self._story.append

        add(Paragraph("6. Finding Detail", S["section"]))
        add(HRFlowable(width="100%", thickness=0.5, color=_C["border"]))
        add(Spacer(1, 4 * mm))

        # Show top 30 findings by risk score
        top = sorted(self._findings,
                     key=lambda f: f.risk_score, reverse=True)[:30]

        for i, f in enumerate(top, 1):
            sev_col = _SEV_COLOUR.get(f.severity.value, _C["info"])
            mitre   = ", ".join(f.technique_ids) or "â€”"
            tactics = ", ".join(f.tactic_names) or "â€”"

            header_style = ParagraphStyle(
                f"fh_{i}", parent=S["subsection"],
                backColor=sev_col, textColor=_C["white"],
                borderPadding=5, leading=14,
            )

            # Finding card
            info_rows = [
                ["Rule ID",      f.rule_id,         "Severity",    f.severity.value],
                ["Category",     f.category,        "Confidence",  f"{f.confidence:.0%}"],
                ["Source IP",    f.source_ip or "â€”","Hostname",    f.hostname or "â€”"],
                ["Username",     f.username  or "â€”","Process",     f.process_name or "â€”"],
                ["Event ID",     f.event_id  or "â€”","Timestamp",   f.timestamp.strftime("%Y-%m-%d %H:%M:%S") if f.timestamp else "â€”"],
                ["MITRE IDs",    mitre,             "Tactics",     tactics],
                ["Triage State", getattr(f, "_triage_state", "new"), "Finding ID", getattr(f, "_db_id", "n/a") or "n/a"],
                ["Source File",  f.source_file or "n/a", "Line", f.trigger_lineno or "n/a"],
            ]
            info_table = Table(
                [[Paragraph(k1, S["body"]), Paragraph(str(v1), S["body"]),
                  Paragraph(k2, S["body"]), Paragraph(str(v2), S["body"])]
                 for k1, v1, k2, v2 in info_rows],
                colWidths=[2.8*cm, 5.5*cm, 2.8*cm, 5.5*cm],
            )
            info_table.setStyle(TableStyle([
                ("BACKGROUND",  (0,0),(0,-1), _C["header_bg"]),
                ("BACKGROUND",  (2,0),(2,-1), _C["header_bg"]),
                ("TEXTCOLOR",   (0,0),(0,-1), _C["accent"]),
                ("TEXTCOLOR",   (2,0),(2,-1), _C["accent"]),
                ("FONTNAME",    (0,0),(0,-1), "Helvetica-Bold"),
                ("FONTNAME",    (2,0),(2,-1), "Helvetica-Bold"),
                ("FONTSIZE",    (0,0),(-1,-1), 8),
                ("ROWBACKGROUNDS",(1,0),(1,-1), [_C["bg_dark"], _C["row_alt"]]),
                ("ROWBACKGROUNDS",(3,0),(3,-1), [_C["bg_dark"], _C["row_alt"]]),
                ("TEXTCOLOR",   (1,0),(1,-1), _C["text_main"]),
                ("TEXTCOLOR",   (3,0),(3,-1), _C["text_main"]),
                ("GRID",        (0,0),(-1,-1), 0.3, _C["border"]),
                ("TOPPADDING",  (0,0),(-1,-1), 4),
                ("BOTTOMPADDING",(0,0),(-1,-1), 4),
                ("LEFTPADDING", (0,0),(-1,-1), 6),
            ]))

            # Evidence line
            trig = (f.trigger_line or "")[:200]
            desc = (f.description or "")[:300]

            add(KeepTogether([
                Paragraph(f"{i}. {f.rule_name}  [{f.rule_id}]", header_style),
                Spacer(1, 1 * mm),
                Table([[Paragraph("Risk Score", S["body"]),
                        _risk_bar(f.risk_score, width=200, height=10)]],
                      colWidths=[2.5*cm, 7.5*cm],
                      style=[("VALIGN",(0,0),(-1,-1),"MIDDLE")]),
                Spacer(1, 2 * mm),
                info_table,
                Spacer(1, 2 * mm),
                Paragraph(f"Description: {desc}", S["body"]),
                Paragraph("Trigger Line:", S["body"]),
                Paragraph(trig, S["code"]),
                Spacer(1, 4 * mm),
            ]))

        if len(self._findings) > 30:
            add(Paragraph(
                f"Note: Showing top 30 of {len(self._findings)} findings by risk score. "
                "Complete findings available in the JSON export.",
                S["body_sub"]))

    # â”€â”€ Section: IOC Table â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _add_ioc_table(self):
        S   = self._styles
        add = self._story.append

        add(Paragraph("7. Indicators of Compromise", S["section"]))
        add(HRFlowable(width="100%", thickness=0.5, color=_C["border"]))
        add(Spacer(1, 4 * mm))

        # Group by type
        by_type: dict[str, list] = defaultdict(list)
        for ioc in self._iocs:
            by_type[ioc.ioc_type].append(ioc)

        for ioc_type, ioc_list in sorted(by_type.items()):
            add(Paragraph(f"{ioc_type.replace('_',' ').upper()} ({len(ioc_list)})",
                          S["subsection"]))
            rows = [["Value", "Confidence", "Source Rule", "Tags"]]
            for ioc in sorted(ioc_list, key=lambda i: -i.confidence)[:25]:
                rows.append([
                    Paragraph(ioc.value[:60], S["table_cell_code"]),
                    Paragraph(f"{ioc.confidence:.0%}", S["table_cell"]),
                    Paragraph(ioc.source_rule, S["table_cell"]),
                    Paragraph(", ".join(ioc.tags[:4]), S["body_sub"]),
                ])
            t = Table(rows, colWidths=[7*cm, 2*cm, 3*cm, 4.6*cm],
                      repeatRows=1)
            t.setStyle(TableStyle(_base_table_style()))
            add(t)
            add(Spacer(1, 4 * mm))

    # â”€â”€ Section: Hardening â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _add_hardening(self):
        from report_builder import _HARDENING
        S   = self._styles
        add = self._story.append

        add(Paragraph("8. Hardening Recommendations", S["section"]))
        add(HRFlowable(width="100%", thickness=0.5, color=_C["border"]))
        add(Spacer(1, 4 * mm))

        observed = {f.category for f in self._findings}
        for cat in sorted(observed):
            recs = _HARDENING.get(cat, [])
            if not recs:
                continue
            add(Paragraph(cat.replace("_"," ").title(), S["subsection"]))
            rows = [[f"â€¢ {r}"] for r in recs]
            t = Table(
                [[Paragraph(r[0], S["body"])] for r in rows],
                colWidths=[16.6 * cm],
            )
            t.setStyle(TableStyle([
                ("ROWBACKGROUNDS", (0,0),(-1,-1),
                 [_C["bg_dark"], _C["row_alt"]]),
                ("TOPPADDING",    (0,0),(-1,-1), 4),
                ("BOTTOMPADDING", (0,0),(-1,-1), 4),
                ("LEFTPADDING",   (0,0),(-1,-1), 8),
                ("GRID",          (0,0),(-1,-1), 0.3, _C["border"]),
            ]))
            add(t)
            add(Spacer(1, 4 * mm))

    # â”€â”€ Section: Chain of Custody â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _add_chain_of_custody(self):
        S   = self._styles
        add = self._story.append

        add(Paragraph("9. Chain of Custody", S["section"]))
        add(HRFlowable(width="100%", thickness=0.5, color=_C["border"]))
        add(Spacer(1, 4 * mm))

        if not self._evidence:
            add(Paragraph("No evidence files recorded.", S["body_sub"]))
            return

        rows = [["File", "SHA-256", "Size", "Format", "Ingested At",
                 "Lines", "Findings"]]
        for ev in self._evidence:
            sha  = ev.get("sha256", "")
            rows.append([
                Paragraph(Path(ev.get("file_path","?")).name, S["table_cell"]),
                Paragraph(sha[:16]+"â€¦" if sha else "N/A", S["table_cell_code"]),
                Paragraph(f"{ev.get('file_size',0)//1024:,} KB", S["table_cell"]),
                Paragraph(ev.get("format","?"), S["table_cell"]),
                Paragraph(ev.get("ingested_at","?")[:19], S["table_cell_code"]),
                Paragraph(str(ev.get("lines_parsed",0)), S["table_cell"]),
                Paragraph(str(ev.get("findings_count",0)), S["table_cell"]),
            ])
        t = Table(rows,
                  colWidths=[4*cm,2.8*cm,1.8*cm,2.2*cm,3.5*cm,1.5*cm,1.8*cm],
                  repeatRows=1)
        t.setStyle(TableStyle(_base_table_style()))
        add(t)
        add(Spacer(1, 6 * mm))

        # Full hash block
        add(Paragraph("Full SHA-256 Hashes", S["subsection"]))
        for ev in self._evidence:
            sha = ev.get("sha256","N/A")
            add(Paragraph(
                f"{Path(ev.get('file_path','?')).name}: {sha}",
                S["code"]))

    # â”€â”€ Section: Appendix â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _add_appendix(self):
        S   = self._styles
        add = self._story.append

        add(PageBreak())
        add(Paragraph("Appendix â€” Detection Statistics", S["section"]))
        add(HRFlowable(width="100%", thickness=0.5, color=_C["border"]))
        add(Spacer(1, 4 * mm))

        # Rule firing frequency
        rule_counts = Counter(f.rule_id for f in self._findings)
        if rule_counts:
            add(Paragraph("Most Frequently Triggered Rules", S["subsection"]))
            rows = [["Rule ID", "Rule Name", "Firing Count", "Category"]]
            rule_map = {f.rule_id: (f.rule_name, f.category)
                        for f in self._findings}
            for rid, cnt in rule_counts.most_common(20):
                name, cat = rule_map.get(rid, ("?", "?"))
                rows.append([
                    Paragraph(rid, S["table_cell_code"]),
                    Paragraph(name[:40], S["table_cell"]),
                    Paragraph(str(cnt), S["table_cell"]),
                    Paragraph(cat, S["table_cell"]),
                ])
            t = Table(rows, colWidths=[2.5*cm,8*cm,2.5*cm,4*cm],
                      repeatRows=1)
            t.setStyle(TableStyle(_base_table_style()))
            add(t)

        add(Spacer(1, 6 * mm))
        add(Paragraph(
            f"Report generated by NexLog v2 on {self._gen_ts}. "
            "This document is intended for authorised personnel only. "
            "Unauthorised disclosure is prohibited.",
            S["body_sub"]))
