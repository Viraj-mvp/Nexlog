"""
interface/gui/findings_view.py â€” NexLog v2  [Deep Space Command Center]
==============================================================================
Findings detail view â€” Tab 3.

Exact Layout (proportional, fills all available space):
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  FINDINGS        [Searchâ€¦]  [JSON]  [STIX]           N FINDINGS         â”‚ â† top bar 40px
â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
â”‚                                              â”‚ â”Œâ”€â”€ FINDING DETAIL â”€â”€â”€â”€â”€â”â”‚
â”‚  Risk â”‚ Sev â”‚ Rule ID â”‚ Rule Name â”‚ IP â”‚ ... â”‚ â”‚ â•”â•â• rule â€” name       â”‚â”‚
â”‚  â–‘â–‘â–‘â–‘ â”‚CRIT â”‚ BF-001  â”‚ Brute...  â”‚...â”‚ ... â”‚ â”‚ â•‘   Severity: ...     â”‚â”‚
â”‚  â–‘â–‘â–‘  â”‚HIGH â”‚ LM-012  â”‚ ...       â”‚   â”‚ ... â”‚ â”‚ â•‘   Category: ...     â”‚â”‚
â”‚  â–‘â–‘   â”‚MED  â”‚ ...     â”‚ ...       â”‚   â”‚ ... â”‚ â”‚ â•šâ•â•                   â”‚â”‚
â”‚  (scrollable, risk-sorted, Rule Name stretches)â”‚ â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜â”‚
â”‚                                              â”‚ â”Œâ”€â”€ EXTRACTED IOCs â”€â”€â”€â”€â”€â”â”‚
â”‚                                              â”‚ â”‚  [IP_ADDRESS ]  1.2.. â”‚â”‚
â”‚                                              â”‚ â”‚  [DOMAIN     ]  evil. â”‚â”‚
â”‚                                              â”‚ â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

Proportions: table 58% | right panel 42%  (resizable splitter handle)
Right panel: FINDING DETAIL 65% | EXTRACTED IOCs 35%  (inner splitter)

Fixes v2.1:
  â€¢ _apply_search: added None guards on f.rule_id, f.rule_name, f.category,
    f.source_ip, f.hostname â€” any of these can be None from the DB, causing
    AttributeError on .lower() (crash on every keystroke in search box).
  â€¢ Removed duplicated "import sys as _pc_sys / walk up dirs" block â€”
    path setup is done once cleanly at module top.
  â€¢ _set_row: added None guard on f.severity before calling .value,
    with graceful fallback to "INFO".
"""

import os
import sys
from typing import Optional

# â”€â”€ Single clean path-walk block â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_here = os.path.dirname(os.path.abspath(__file__))
_root = _here
for _ in range(8):
    if os.path.isfile(os.path.join(_root, "pathconfig.py")):
        break
    _root = os.path.dirname(_root)
if _root not in sys.path:
    sys.path.insert(0, _root)

try:
    from pathconfig import ROOT, add_root
    add_root()
    _ROOT = ROOT
except ImportError:
    _ROOT = _root

for _pkg in ["core", "detection", "storage", "intelligence", "output"]:
    _p2 = os.path.join(_ROOT, _pkg)
    if _p2 not in sys.path:
        sys.path.insert(0, _p2)

try:
    from PySide6.QtCore import Qt, Signal, QRect, QSize
    from PySide6.QtGui import (
        QBrush, QColor, QFont, QPainter, QPen, QLinearGradient,
    )
    from PySide6.QtWidgets import (
        QFileDialog, QFrame, QHBoxLayout,
        QHeaderView, QLabel, QLineEdit, QPushButton,
        QSplitter, QTableWidget, QTableWidgetItem,
        QTextEdit, QVBoxLayout, QWidget,
    )
    _HAS_PYSIDE6 = True
except ImportError:
    _HAS_PYSIDE6 = False
if os.environ.get("NEXLOG_GUI_STUBS", "").strip().lower() in {"1", "true", "yes", "on"}:
    _HAS_PYSIDE6 = False

# â”€â”€ Theme â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
try:
    from interface.gui.theme import PALETTE as P, sev_fg, FONT_MONO_CSS, SEV_RANK
except ImportError:
    try:
        from theme import PALETTE as P, sev_fg, FONT_MONO_CSS, SEV_RANK
    except ImportError:
        P = {
            "bg_base":    "#080C14", "bg_surface": "#0D1420",
            "bg_raised":  "#111C2E", "bg_void":    "#04080F",
            "bg_hover":   "#162238", "bg_input":   "#0A1628",
            "border_dim": "#1A2A3F", "border_mid": "#1E3A5A",
            "cyan":       "#00C8FF", "cyan_dim":   "#007A9C",
            "green":      "#00FF9D", "amber":      "#FFB700",
            "critical":   "#FF3B5C", "critical_bg":"#1A0510",
            "high":       "#FF6B35", "high_bg":    "#1A0D06",
            "medium":     "#FFB700", "medium_bg":  "#1A1100",
            "low":        "#00FF9D", "low_bg":     "#001A12",
            "info":       "#4A8FA8", "info_bg":    "#080C14",
            "text_primary":   "#C8DFF0",
            "text_secondary": "#5A8FA8",
            "text_mono":      "#8ECFAA",
            "text_dim":       "#2A4A5E",
        }
        def sev_fg(s): return P.get(s.lower(), P["text_primary"])

_SEV_FG = {s: sev_fg(s) for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
_SEV_COLOURS = _SEV_FG
_COLS   = ["Risk", "Sev", "Rule ID", "Rule Name", "Source IP", "Host", "Category", "Conf"]
_MONO   = FONT_MONO_CSS  # from theme

# Safe string helper â€” always returns a str, never raises on None
def _s(val) -> str:
    return str(val) if val is not None else ""

# â”€â”€ Stylesheets â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

_TABLE_CSS = f"""
QTableWidget {{
    background-color: {P['bg_base']};
    color: {P['text_primary']};
    alternate-background-color: {P['bg_surface']};
    border: none;
    gridline-color: {P['border_dim']};
    font-family: {_MONO};
    font-size: 9px;
    outline: none;
}}
QHeaderView::section {{
    background-color: {P.get('bg_void', P['bg_base'])};
    color: {P['text_secondary']};
    border: none;
    border-right: 1px solid {P['border_dim']};
    border-bottom: 1px solid {P['border_mid']};
    padding: 5px 6px;
    font-family: {_MONO};
    font-size: 8px;
    letter-spacing: 1px;
}}
QTableWidget::item {{
    padding: 0 4px;
    border: none;
}}
QTableWidget::item:selected {{
    background-color: {P['bg_hover']};
    color: {P['cyan']};
}}
"""

_DETAIL_CSS = f"""
QTextEdit {{
    background-color: {P['bg_surface']};
    color: {P['text_mono']};
    border: none;
    font-family: {_MONO};
    font-size: 9px;
    line-height: 1.5;
    padding: 8px;
    selection-background-color: {P['bg_hover']};
    selection-color: {P['cyan']};
}}
"""

_BTN_CSS = f"""
QPushButton {{
    background-color: transparent;
    color: {P['text_secondary']};
    border: 1px solid {P['border_dim']};
    border-radius: 2px;
    padding: 3px 10px;
    font-family: {_MONO};
    font-size: 9px;
    letter-spacing: 1px;
    min-width: 56px;
}}
QPushButton:hover {{
    color: {P['cyan']};
    border-color: {P['cyan']};
    background-color: rgba(0,200,255,0.06);
}}
QPushButton:pressed {{
    background-color: rgba(0,200,255,0.12);
}}
"""

_SPLITTER_CSS = f"""
QSplitter::handle {{
    background-color: {P['border_dim']};
}}
QSplitter::handle:hover {{
    background-color: {P['cyan_dim']};
}}
"""


if _HAS_PYSIDE6:

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # RISK BAR CELL
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    class _RiskCell(QWidget):
        """Neon gradient risk bar, 64Ã—24 px, score label at 8px."""
        def __init__(self, score: float, parent=None):
            super().__init__(parent)
            self._score = min(max(float(score), 0.0), 10.0)
            self.setFixedSize(QSize(64, 24))

        def paintEvent(self, event) -> None:
            p  = QPainter(self)
            p.setRenderHint(QPainter.Antialiasing)
            cy = self.height() // 2
            th = 8
            ty = cy - th // 2
            tw = self.width() - 4

            p.setBrush(QBrush(QColor(P["bg_raised"])))
            p.setPen(Qt.NoPen)
            p.drawRoundedRect(QRect(2, ty, tw, th), 2, 2)

            bw = max(int(self._score / 10.0 * tw), 3)
            if self._score >= 8.5:   c0, c1 = P["critical"], "#FF8FAA"
            elif self._score >= 6.0: c0, c1 = P["high"],     "#FFB87A"
            elif self._score >= 3.5: c0, c1 = P["medium"],   "#FFE07A"
            else:                    c0, c1 = P["low"],       P["cyan"]

            grad = QLinearGradient(2, ty, 2 + bw, ty)
            grad.setColorAt(0.0, QColor(c0))
            grad.setColorAt(1.0, QColor(c1))
            p.setBrush(QBrush(grad))
            p.drawRoundedRect(QRect(2, ty, bw, th), 2, 2)

            f = QFont("JetBrains Mono", 7)
            f.setBold(True)
            p.setFont(f)
            p.setPen(QPen(QColor(P["bg_void"] if "bg_void" in P else P["bg_base"])))
            p.drawText(QRect(2, ty, tw, th), Qt.AlignCenter,
                       f"{self._score:.1f}")
            p.end()


    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # SECTION HEADER STRIP
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    def _section_header(title: str, parent: QWidget) -> QWidget:
        """Returns a 24px fixed-height title strip."""
        w = QWidget(parent)
        w.setFixedHeight(24)
        w.setStyleSheet(f"""
            background-color: {P.get('bg_void', P['bg_base'])};
            border-bottom: 1px solid {P['border_mid']};
        """)
        lay = QHBoxLayout(w)
        lay.setContentsMargins(10, 0, 10, 0)
        lbl = QLabel(title, w)
        lbl.setStyleSheet(f"""
            color: {P['text_secondary']};
            font-family: {_MONO};
            font-size: 8px;
            font-weight: bold;
            letter-spacing: 2px;
            background: transparent;
            border: none;
        """)
        lay.addWidget(lbl)
        lay.addStretch()
        return w


    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # FINDINGS VIEW
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    class FindingsView(QWidget):
        """
        Risk-sorted findings list with inline risk bars, detail terminal
        and IOC extraction panel â€” all in a fixed bento layout.
        """

        def __init__(self, case_db_path: str, parent=None):
            super().__init__(parent)
            self._case_db   = case_db_path
            self._findings: list = []
            self._selected  = None
            self._session_id = None
            self.setStyleSheet(f"background-color: {P['bg_base']};")
            self._build_ui()

        # â”€â”€ Build â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def _build_ui(self) -> None:
            root = QVBoxLayout(self)
            root.setContentsMargins(0, 0, 0, 0)
            root.setSpacing(0)

            root.addWidget(self._build_top_bar())

            sep = QFrame(self)
            sep.setFrameShape(QFrame.HLine)
            sep.setFixedHeight(1)
            sep.setStyleSheet(
                f"background-color: {P['border_mid']}; border: none;")
            root.addWidget(sep)

            h_split = QSplitter(Qt.Horizontal, self)
            h_split.setHandleWidth(2)
            h_split.setStyleSheet(_SPLITTER_CSS)
            h_split.addWidget(self._build_table_panel())
            h_split.addWidget(self._build_right_panel())
            h_split.setStretchFactor(0, 58)
            h_split.setStretchFactor(1, 42)
            h_split.setSizes([700, 500])

            root.addWidget(h_split)

        # â”€â”€ Top bar â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def _build_top_bar(self) -> QWidget:
            bar = QWidget(self)
            bar.setFixedHeight(40)
            bar.setStyleSheet(f"""
                background-color: {P.get('bg_void', P['bg_base'])};
                border-bottom: 1px solid {P['border_mid']};
            """)
            lay = QHBoxLayout(bar)
            lay.setContentsMargins(12, 0, 12, 0)
            lay.setSpacing(10)

            title = QLabel("FINDINGS", bar)
            title.setStyleSheet(f"""
                color: {P['cyan']};
                font-family: {_MONO};
                font-size: 11px;
                font-weight: bold;
                letter-spacing: 4px;
                background: transparent;
                border: none;
            """)
            lay.addWidget(title)

            lay.addStretch(1)

            self._search = QLineEdit(bar)
            self._search.setPlaceholderText("Search rule / IP / categoryâ€¦")
            self._search.setFixedWidth(210)
            self._search.setFixedHeight(26)
            self._search.setStyleSheet(f"""
                QLineEdit {{
                    background-color: {P.get('bg_input', P['bg_raised'])};
                    color: {P['text_primary']};
                    border: 1px solid {P['border_dim']};
                    border-radius: 2px;
                    padding: 3px 8px;
                    font-family: {_MONO};
                    font-size: 9px;
                }}
                QLineEdit:focus {{
                    border-color: {P['cyan']};
                    background-color: {P['bg_raised']};
                }}
            """)
            self._search.textChanged.connect(self._apply_search)
            lay.addWidget(self._search)

            for label, slot in [("[ PDF ]",  self._export_pdf),
                                 ("[ JSON ]", self._export_json),
                                 ("[ STIX ]", self._export_stix)]:
                btn = QPushButton(label, bar)
                btn.setFixedHeight(26)
                btn.setStyleSheet(_BTN_CSS)
                btn.clicked.connect(slot)
                lay.addWidget(btn)

            for label, action in [("[ TRIAGE ]", "triaged"),
                                  ("[ ESCALATE ]", "escalated"),
                                  ("[ FP ]", "false_positive")]:
                btn = QPushButton(label, bar)
                btn.setFixedHeight(26)
                btn.setStyleSheet(_BTN_CSS)
                btn.clicked.connect(lambda _=False, a=action: self._apply_action(a))
                lay.addWidget(btn)

            self._count_lbl = QLabel("0 FINDINGS", bar)
            self._count_lbl.setFixedWidth(100)
            self._count_lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self._count_lbl.setStyleSheet(f"""
                color: {P['text_dim']};
                font-family: {_MONO};
                font-size: 8px;
                letter-spacing: 1px;
                background: transparent;
                border: none;
            """)
            lay.addWidget(self._count_lbl)

            return bar

        # â”€â”€ Table panel â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def _build_table_panel(self) -> QWidget:
            container = QWidget(self)
            container.setStyleSheet(f"background-color: {P['bg_base']};")
            lay = QVBoxLayout(container)
            lay.setContentsMargins(0, 0, 0, 0)
            lay.setSpacing(0)

            self._table = QTableWidget(0, len(_COLS), container)
            self._table.setHorizontalHeaderLabels(_COLS)
            self._table.setAlternatingRowColors(True)
            self._table.setSelectionBehavior(
                QTableWidget.SelectionBehavior.SelectRows)
            self._table.setEditTriggers(
                QTableWidget.EditTrigger.NoEditTriggers)
            self._table.setSortingEnabled(True)
            self._table.verticalHeader().setVisible(False)
            self._table.setShowGrid(False)
            self._table.setFrameShape(QFrame.NoFrame)
            self._table.setStyleSheet(_TABLE_CSS)

            hdr = self._table.horizontalHeader()
            hdr.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
            hdr.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
            hdr.resizeSection(0, 70)
            hdr.resizeSection(1, 74)
            hdr.resizeSection(2, 88)
            hdr.resizeSection(4, 116)
            hdr.resizeSection(5, 90)
            hdr.resizeSection(6, 96)
            hdr.resizeSection(7, 46)

            self._table.itemSelectionChanged.connect(self._on_row_selected)
            lay.addWidget(self._table)
            return container

        # â”€â”€ Right panel â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def _build_right_panel(self) -> QWidget:
            container = QWidget(self)
            container.setStyleSheet(
                f"background-color: {P['bg_surface']};")
            lay = QVBoxLayout(container)
            lay.setContentsMargins(0, 0, 0, 0)
            lay.setSpacing(0)

            v_split = QSplitter(Qt.Vertical, container)
            v_split.setHandleWidth(2)
            v_split.setStyleSheet(_SPLITTER_CSS)

            # FINDING DETAIL
            dp = QWidget(v_split)
            dp.setStyleSheet(f"background-color: {P['bg_surface']};")
            dp_lay = QVBoxLayout(dp)
            dp_lay.setContentsMargins(0, 0, 0, 0)
            dp_lay.setSpacing(0)
            dp_lay.addWidget(_section_header("FINDING DETAIL", dp))
            self._detail = QTextEdit(dp)
            self._detail.setReadOnly(True)
            self._detail.setFrameShape(QFrame.NoFrame)
            self._detail.setStyleSheet(_DETAIL_CSS)
            self._detail.setPlaceholderText(
                "Select a finding from the table to view detailsâ€¦")
            dp_lay.addWidget(self._detail)
            v_split.addWidget(dp)

            # EXTRACTED IOCs
            ip = QWidget(v_split)
            ip.setStyleSheet(f"background-color: {P['bg_surface']};")
            ip_lay = QVBoxLayout(ip)
            ip_lay.setContentsMargins(0, 0, 0, 0)
            ip_lay.setSpacing(0)
            ip_lay.addWidget(_section_header("EXTRACTED IOCs", ip))
            self._ioc_view = QTextEdit(ip)
            self._ioc_view.setReadOnly(True)
            self._ioc_view.setFrameShape(QFrame.NoFrame)
            self._ioc_view.setStyleSheet(_DETAIL_CSS)
            self._ioc_view.setPlaceholderText(
                "IOCs will appear here when a finding is selectedâ€¦")
            ip_lay.addWidget(self._ioc_view)
            v_split.addWidget(ip)

            v_split.setStretchFactor(0, 65)
            v_split.setStretchFactor(1, 35)
            v_split.setSizes([400, 200])

            lay.addWidget(v_split)
            return container

        # â”€â”€ Data â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def load_session(self, session_id: Optional[str]) -> None:
            self._session_id = session_id
            try:
                from storage.case_db import CaseDB
                with CaseDB(self._case_db) as db:
                    self._findings = db.get_findings(
                        session_id=session_id, limit=5000)
                    for f in self._findings:
                        fid = getattr(f, "_db_id", None)
                        if fid:
                            setattr(f, "_triage_state", db.get_finding_state(fid))
            except Exception as e:
                print(f"[FindingsView] load_session: {e}",
                      file=sys.stderr)
                self._findings = []
            self._populate(self._findings)

        def _populate(self, findings: list) -> None:
            rows = sorted(findings, key=lambda f: f.risk_score, reverse=True)
            self._table.setSortingEnabled(False)
            self._table.setRowCount(0)
            for f in rows:
                r = self._table.rowCount()
                self._table.insertRow(r)
                self._set_row(r, f)
            self._table.setSortingEnabled(True)
            self._count_lbl.setText(f"{len(rows):,} FINDINGS")

        def _set_row(self, row: int, f) -> None:
            # FIX: guard severity â€” f.severity could be None or a raw string
            sev_raw = getattr(f, "severity", None)
            sev     = (sev_raw.value if hasattr(sev_raw, "value")
                       else str(sev_raw) if sev_raw else "INFO")
            sev_col = _SEV_FG.get(sev, P["text_secondary"])

            cells = [
                f"{f.risk_score:.1f}",
                sev,
                _s(getattr(f, "rule_id",      None)),
                _s(getattr(f, "rule_name",     None)),
                _s(getattr(f, "source_ip",     None)) or "â€”",
                _s(getattr(f, "hostname",      None)) or "â€”",
                _s(getattr(f, "category",      None)),
                f"{getattr(f, 'confidence', 0):.0%}",
            ]
            for col, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if col == 0:
                    item.setTextAlignment(Qt.AlignCenter)
                    item.setForeground(QBrush(QColor(sev_col)))
                elif col == 1:
                    item.setForeground(QBrush(QColor(sev_col)))
                    item.setFont(QFont("JetBrains Mono", 8,
                                       QFont.Weight.Bold))
                elif col == 7:
                    item.setTextAlignment(Qt.AlignCenter)
                    item.setForeground(QBrush(QColor(P["text_secondary"])))
                else:
                    item.setForeground(QBrush(QColor(P["text_primary"])))
                item.setData(Qt.UserRole, f)
                self._table.setItem(row, col, item)

            self._table.setCellWidget(row, 0, _RiskCell(f.risk_score))
            self._table.setRowHeight(row, 24)

        # â”€â”€ Filtering â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def _apply_search(self) -> None:
            q = self._search.text().strip().lower()
            if not q:
                self._populate(self._findings)
                return
            # FIX: every field access uses _s() to guard against None values.
            # Previously f.rule_id.lower() would raise AttributeError if
            # rule_id was None â€” crashing on every keystroke in the search box.
            self._populate([
                f for f in self._findings
                if (q in _s(getattr(f, "rule_id",   None)).lower()
                    or q in _s(getattr(f, "rule_name", None)).lower()
                    or q in _s(getattr(f, "source_ip", None)).lower()
                    or q in _s(getattr(f, "category",  None)).lower()
                    or q in _s(getattr(f, "hostname",  None)).lower())
            ])

        # â”€â”€ Selection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def _on_row_selected(self) -> None:
            items = self._table.selectedItems()
            if not items:
                return
            f = items[0].data(Qt.UserRole)
            if not f:
                return
            self._selected = f
            self._show_detail(f)
            self._show_iocs(f)

        def _show_detail(self, f) -> None:
            ts    = f.timestamp.isoformat() if getattr(f, "timestamp", None) else "N/A"
            state = getattr(f, "_triage_state", "new")
            fid   = getattr(f, "_db_id", "N/A") or "N/A"
            mitre = "\n".join(
                f"  {t.full_id}  {t.tactic_name} / {t.technique_name}"
                for t in getattr(f, "mitre_tags", [])
            ) or "  None"
            supp  = "\n".join(
                f"  {line}"
                for line in getattr(f, "supporting_lines", [])[:5]
            ) or "  None"
            sev_raw = getattr(f, "severity", None)
            sev_str = (sev_raw.value if hasattr(sev_raw, "value")
                       else str(sev_raw) if sev_raw else "N/A")
            self._detail.setPlainText(
                f"â•”â•â• {_s(getattr(f, 'rule_id', None))}  â”€  "
                f"{_s(getattr(f, 'rule_name', None))}\n"
                f"â•‘\n"
                f"â•‘   Severity:   {sev_str:<12}"
                f"  Confidence: {getattr(f, 'confidence', 0):.0%}"
                f"   Risk: {getattr(f, 'risk_score', 0):.2f}/10\n"
                f"â•‘   Category:   {_s(getattr(f, 'category',     None))}\n"
                f"â•‘   Source IP:  {_s(getattr(f, 'source_ip',    None)) or 'N/A'}\n"
                f"â•‘   Hostname:   {_s(getattr(f, 'hostname',     None)) or 'N/A'}\n"
                f"â•‘   Username:   {_s(getattr(f, 'username',     None)) or 'N/A'}\n"
                f"â•‘   Process:    {_s(getattr(f, 'process_name', None)) or 'N/A'}\n"
                f"â•‘   Event ID:   {_s(getattr(f, 'event_id',     None)) or 'N/A'}\n"
                f"â•‘   Timestamp:  {ts}\n"
                f"â•‘\n"
                f"â•‘   Description:\n"
                f"â•‘   {_s(getattr(f, 'description',  None)) or 'N/A'}\n"
                f"â•‘\n"
                f"â•‘   Trigger Line:\n"
                f"â•‘   {_s(getattr(f, 'trigger_line', None)) or 'N/A'}\n"
                f"â•‘\n"
                f"â•‘   MITRE ATT&CK:\n"
                f"{mitre}\n"
                f"â•‘\n"
                f"â•‘   Supporting Evidence:\n"
                f"{supp}\n"
                f"â•šâ•â•"
            )

        def _apply_action(self, action: str) -> None:
            if not self._selected:
                return
            fid = getattr(self._selected, "_db_id", None)
            if not fid:
                from PySide6.QtWidgets import QMessageBox
                QMessageBox.warning(self, "Disposition", "Selected finding has no database id.")
                return
            try:
                from storage.case_db import CaseDB
                with CaseDB(self._case_db) as db:
                    db.add_analyst_action(
                        finding_id=fid,
                        action=action,
                        analyst="gui",
                        note="Disposition set from Findings view.",
                    )
                    setattr(self._selected, "_triage_state", db.get_finding_state(fid))
                self.load_session(self._session_id)
                from PySide6.QtWidgets import QMessageBox
                QMessageBox.information(self, "Disposition", f"Finding marked {action}.")
            except Exception as e:
                from PySide6.QtWidgets import QMessageBox
                QMessageBox.critical(self, "Disposition Error", str(e))

        def _show_iocs(self, f) -> None:
            try:
                from ioc_extractor import IOCExtractor
                iocs = IOCExtractor(include_private_ips=True).extract([f])
                if not iocs:
                    self._ioc_view.setPlainText(
                        "  NO IOCs EXTRACTED FROM THIS FINDING")
                    return
                self._ioc_view.setPlainText("\n".join(
                    f"  [{ioc.ioc_type.upper():<12}]  "
                    f"{ioc.value:<55}  conf={ioc.confidence:.0%}"
                    for ioc in iocs
                ))
            except Exception as e:
                self._ioc_view.setPlainText(
                    f"  IOC EXTRACTION ERROR:\n  {e}")

        # â”€â”€ Exports â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def _export_json(self) -> None:
            from datetime import datetime
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_fn = f"forensic_findings_{ts}.json"

            # AUTOMATED: Save to workspace output/ directory
            from pathlib import Path
            out_dir = Path(_ROOT) / "output"
            out_dir.mkdir(parents=True, exist_ok=True)
            path = str(out_dir / default_fn)
            try:
                Path(path).write_text(
                    json.dumps([f.to_dict() for f in self._findings],
                               indent=2, default=str),
                    encoding="utf-8")
                from PySide6.QtWidgets import QMessageBox
                QMessageBox.information(
                    self, "Exported", f"Findings JSON saved to:\n{path}")
            except Exception as e:
                from PySide6.QtWidgets import QMessageBox
                QMessageBox.critical(self, "Export Error", str(e))

        def _export_stix(self) -> None:
            if not self._findings:
                return
            from datetime import datetime
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_fn = f"forensic_stix_{ts}.json"

            # AUTOMATED: Save to workspace output/ directory
            from pathlib import Path
            out_dir = Path(_ROOT) / "output"
            out_dir.mkdir(parents=True, exist_ok=True)
            path = str(out_dir / default_fn)
            try:
                from ioc_extractor import IOCExtractor
                from output.stix_export import STIXExport
                iocs = IOCExtractor().extract(self._findings)
                STIXExport(findings=self._findings, iocs=iocs).write(path)
                from PySide6.QtWidgets import QMessageBox
                QMessageBox.information(
                    self, "STIX Exported", f"STIX bundle saved to:\n{path}")
            except Exception as e:
                from PySide6.QtWidgets import QMessageBox
                QMessageBox.critical(self, "STIX Export Error", str(e))

        def _export_pdf(self) -> None:
            if not self._findings:
                return
            from datetime import datetime
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_fn = f"forensic_findings_{ts}.pdf"
            
            from PySide6.QtWidgets import QFileDialog, QMessageBox
            path, _ = QFileDialog.getSaveFileName(
                self, "Export PDF Report", default_fn, "PDF Files (*.pdf)")
            
            if not path:
                return
                
            try:
                from output.pdf_report import PDFReport
                from ioc_extractor import IOCExtractor
                iocs = IOCExtractor().extract(self._findings)
                # Find current session ID if possible
                main_win = self.window()
                sid = getattr(main_win, "_current_session_id", None)
                
                report = PDFReport(
                    findings=self._findings,
                    iocs=iocs,
                    session_id=sid,
                    case_ref="IR-FINDINGS-EXPORT"
                )
                report.build(path)
                QMessageBox.information(self, "Exported", f"PDF report saved to:\n{path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to generate PDF: {e}")


else:
    class FindingsView:
        def __init__(self, *a, **kw): pass
        def load_session(self, *a, **kw): pass
