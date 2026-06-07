"""
interface/gui/timeline_view.py â€” NexLog v2  [Deep Space Command Center]
==============================================================================
Chronological event timeline view â€” Tab 2.

Visual Design:
  â€¢ Table rows coloured with Deep Space neon severity palette
  â€¢ Monospace font throughout (JetBrains Mono)
  â€¢ Filter bar: terminal-styled inputs with neon focus border
  â€¢ Detail panel: CRT-green monospace terminal block on click
  â€¢ Export CSV: tactical button styling

Layout:
  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
  â”‚  TIMELINE FILTER: [SEV â–¼]  [IPâ€¦]  [RULEâ€¦]  [CLEAR] [CSV]  â”‚
  â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
  â”‚  TIMELINE TABLE (severity-coloured rows, sortable)         â”‚
  â”‚  Timestamp | Sev | Risk | Rule ID | Rule | IP | Host | Cat â”‚
  â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
  â”‚  FINDING DETAIL (monospace terminal block)                 â”‚
  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

Fixes v2.1:
  â€¢ _export_csv: QTableWidget.item(row, col) returns None if a cell widget
    (e.g. _RiskCell) is set instead of a QTableWidgetItem. Previously
    calling .text() on None crashed the export. Now uses safe helper that
    falls back to empty string.
  â€¢ Removed duplicated path-walk block â€” single clean setup at module top.
  â€¢ _set_row: added severity guard consistent with findings_view.py.
  â€¢ _apply_filter: added None guard on source_ip before .lower().
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

for _pkg in ["core", "detection", "storage"]:
    _p2 = os.path.join(_ROOT, _pkg)
    if _p2 not in sys.path:
        sys.path.insert(0, _p2)

try:
    from PySide6.QtCore import Qt, Signal, Slot
    from PySide6.QtGui import QColor, QBrush, QFont
    from PySide6.QtWidgets import (
        QComboBox, QFileDialog, QHBoxLayout, QHeaderView,
        QLabel, QLineEdit, QPushButton, QScrollArea,
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
    from interface.gui.theme import PALETTE as P, sev_fg, sev_bg, sev_order, FONT_MONO_CSS, SEV_RANK
except ImportError:
    try:
        from theme import PALETTE as P, sev_fg, sev_bg, sev_order, FONT_MONO_CSS, SEV_RANK
    except ImportError:
        P = {
            "bg_base": "#080C14", "bg_surface": "#0D1420",
            "bg_raised": "#111C2E", "bg_void": "#04080F",
            "bg_hover": "#162238", "bg_input": "#0A1628",
            "border_dim": "#1A2A3F", "border_mid": "#1E3A5A",
            "cyan": "#00C8FF", "cyan_dim": "#007A9C",
            "green": "#00FF9D", "amber": "#FFB700",
            "critical": "#FF3B5C", "critical_bg": "#1A0510",
            "high": "#FF6B35", "high_bg": "#1A0D06",
            "medium": "#FFB700", "medium_bg": "#1A1100",
            "low": "#00FF9D", "low_bg": "#001A12",
            "info": "#4A8FA8", "info_bg": "#080C14",
            "text_primary": "#C8DFF0", "text_secondary": "#5A8FA8",
            "text_mono": "#8ECFAA", "text_dim": "#2A4A5E",
        }
        def sev_fg(s): return P.get(s.lower(), P["text_primary"])
        def sev_bg(s): return P.get(s.lower() + "_bg", P["bg_base"])
        def sev_order(): return ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

_SEV_FG = {s: sev_fg(s) for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
_SEV_BG = {s: sev_bg(s) for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}
_SEV_COLOURS = _SEV_FG
_SEV_ORDER = sev_order()
_SEV_ORDER_FILTER = ["ALL"] + _SEV_ORDER
_COLS = ["Timestamp", "Severity", "Risk", "Rule ID", "Rule Name",
         "Source IP", "Host", "Category"]
_MONO = FONT_MONO_CSS  # from theme

# Safe string helper
def _s(val) -> str:
    return str(val) if val is not None else ""

_TABLE_CSS = f"""
    QTableWidget {{
        background-color: {P['bg_base']};
        color: {P['text_primary']};
        alternate-background-color: {P['bg_surface']};
        border: 1px solid {P['border_mid']};
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
    QTableWidget::item:selected {{
        background-color: {P['bg_hover']};
        color: {P['cyan']};
    }}
"""

_DETAIL_CSS = f"""
    QTextEdit {{
        background-color: {P['bg_surface']};
        color: {P['text_mono']};
        border: 1px solid {P['border_dim']};
        border-top: 1px solid {P['border_mid']};
        font-family: {_MONO};
        font-size: 9px;
        line-height: 1.4;
        selection-background-color: {P['bg_hover']};
        padding: 6px;
    }}
"""

_FILTER_INPUT_CSS = f"""
    QLineEdit {{
        background-color: {P.get('bg_input', P['bg_raised'])};
        color: {P['text_primary']};
        border: 1px solid {P['border_dim']};
        border-radius: 2px;
        padding: 4px 8px;
        font-family: {_MONO};
        font-size: 9px;
    }}
    QLineEdit:focus {{
        border-color: {P['cyan']};
    }}
"""

_COMBO_CSS = f"""
    QComboBox {{
        background-color: {P.get('bg_input', P['bg_raised'])};
        color: {P['text_primary']};
        border: 1px solid {P['border_dim']};
        border-radius: 2px;
        padding: 3px 8px;
        font-family: {_MONO};
        font-size: 9px;
    }}
    QComboBox:focus {{
        border-color: {P['cyan']};
    }}
    QComboBox::drop-down {{ border: none; width: 16px; }}
    QComboBox QAbstractItemView {{
        background-color: {P['bg_surface']};
        color: {P['text_primary']};
        selection-background-color: {P['bg_hover']};
        border: 1px solid {P['border_mid']};
        font-family: {_MONO};
        font-size: 9px;
    }}
"""

_BTN_CSS = f"""
    QPushButton {{
        background-color: transparent;
        color: {P['text_secondary']};
        border: 1px solid {P['border_dim']};
        border-radius: 2px;
        padding: 4px 10px;
        font-family: {_MONO};
        font-size: 9px;
        letter-spacing: 1px;
    }}
    QPushButton:hover {{
        color: {P['cyan']};
        border-color: {P['cyan']};
        background-color: rgba(0,200,255,0.05);
    }}
"""


if _HAS_PYSIDE6:

    class TimelineView(QWidget):
        """
        Deep Space chronological timeline of all findings for a session.
        Call load_session(session_id, case_db_path) to populate.
        """
        finding_selected = Signal(dict)

        def __init__(self, parent=None):
            super().__init__(parent)
            self._findings: list = []
            self._case_db:  str  = ""
            self.setStyleSheet(f"background-color: {P['bg_base']};")
            self._build_ui()

        def _build_ui(self) -> None:
            layout = QVBoxLayout(self)
            layout.setContentsMargins(10, 10, 10, 10)
            layout.setSpacing(6)

            # â”€â”€ Header â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            hdr = QHBoxLayout()
            title = QLabel("EVENT TIMELINE", self)
            title.setStyleSheet(f"""
                color: {P['cyan']};
                font-family: {_MONO};
                font-size: 11px;
                font-weight: bold;
                letter-spacing: 4px;
                background: transparent;
            """)
            hdr.addWidget(title)
            hdr.addStretch()
            self._count_label = QLabel("0 EVENTS", self)
            self._count_label.setStyleSheet(f"""
                color: {P['text_dim']};
                font-family: {_MONO};
                font-size: 8px;
                letter-spacing: 1px;
                background: transparent;
            """)
            hdr.addWidget(self._count_label)
            layout.addLayout(hdr)

            # â”€â”€ Filter bar â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            filter_bar = QHBoxLayout()
            filter_bar.setSpacing(6)

            sev_lbl = QLabel("SEV:", self)
            sev_lbl.setStyleSheet(f"""
                color: {P['text_secondary']};
                font-family: {_MONO};
                font-size: 8px;
                background: transparent;
            """)
            filter_bar.addWidget(sev_lbl)

            self._sev_combo = QComboBox(self)
            self._sev_combo.addItems(_SEV_ORDER_FILTER)
            self._sev_combo.setFixedWidth(110)
            self._sev_combo.setStyleSheet(_COMBO_CSS)
            self._sev_combo.currentTextChanged.connect(self._apply_filter)
            filter_bar.addWidget(self._sev_combo)

            self._ip_filter = QLineEdit(self)
            self._ip_filter.setPlaceholderText("Filter IPâ€¦")
            self._ip_filter.setFixedWidth(130)
            self._ip_filter.setStyleSheet(_FILTER_INPUT_CSS)
            self._ip_filter.textChanged.connect(self._apply_filter)
            filter_bar.addWidget(self._ip_filter)

            self._rule_filter = QLineEdit(self)
            self._rule_filter.setPlaceholderText("Filter Rule IDâ€¦")
            self._rule_filter.setFixedWidth(120)
            self._rule_filter.setStyleSheet(_FILTER_INPUT_CSS)
            self._rule_filter.textChanged.connect(self._apply_filter)
            filter_bar.addWidget(self._rule_filter)

            btn_clear = QPushButton("[ CLEAR ]", self)
            btn_clear.setFixedWidth(72)
            btn_clear.setStyleSheet(_BTN_CSS)
            btn_clear.clicked.connect(self._clear_filters)
            filter_bar.addWidget(btn_clear)

            btn_export = QPushButton("[ CSV ]", self)
            btn_export.setFixedWidth(64)
            btn_export.setStyleSheet(_BTN_CSS)
            btn_export.clicked.connect(self._export_csv)
            filter_bar.addWidget(btn_export)

            btn_pdf = QPushButton("[ PDF ]", self)
            btn_pdf.setFixedWidth(64)
            btn_pdf.setStyleSheet(_BTN_CSS)
            btn_pdf.clicked.connect(self._export_pdf)
            filter_bar.addWidget(btn_pdf)

            filter_bar.addStretch()
            layout.addLayout(filter_bar)

            # â”€â”€ Splitter: table + detail â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            splitter = QSplitter(Qt.Vertical)
            splitter.setHandleWidth(2)
            splitter.setStyleSheet(f"""
                QSplitter::handle {{
                    background-color: {P['border_dim']};
                }}
                QSplitter::handle:hover {{
                    background-color: {P['cyan_dim']};
                }}
            """)

            self._table = QTableWidget(0, len(_COLS), self)
            self._table.setHorizontalHeaderLabels(_COLS)
            self._table.setAlternatingRowColors(True)
            self._table.setSelectionBehavior(
                QTableWidget.SelectionBehavior.SelectRows)
            self._table.setEditTriggers(
                QTableWidget.EditTrigger.NoEditTriggers)
            self._table.setSortingEnabled(True)
            self._table.verticalHeader().setVisible(False)
            self._table.setShowGrid(False)
            self._table.setStyleSheet(_TABLE_CSS)

            hdr2 = self._table.horizontalHeader()
            hdr2.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
            hdr2.setStretchLastSection(True)
            hdr2.resizeSection(0, 148)
            hdr2.resizeSection(1, 78)
            hdr2.resizeSection(2, 46)
            hdr2.resizeSection(3, 82)
            hdr2.resizeSection(4, 180)
            hdr2.resizeSection(5, 120)
            hdr2.resizeSection(6, 100)
            self._table.itemSelectionChanged.connect(self._on_row_selected)
            splitter.addWidget(self._table)

            # Detail panel
            detail_widget = QWidget()
            detail_widget.setStyleSheet(
                f"background-color: {P['bg_surface']};")
            detail_layout = QVBoxLayout(detail_widget)
            detail_layout.setContentsMargins(0, 0, 0, 0)
            detail_layout.setSpacing(0)

            detail_header = QWidget()
            detail_header.setFixedHeight(24)
            detail_header.setStyleSheet(f"""
                background-color: {P.get('bg_void', P['bg_base'])};
                border-top: 1px solid {P['border_mid']};
                border-bottom: 1px solid {P['border_dim']};
            """)
            dh_layout = QHBoxLayout(detail_header)
            dh_layout.setContentsMargins(10, 0, 10, 0)
            detail_title = QLabel("FINDING DETAIL", detail_header)
            detail_title.setStyleSheet(f"""
                color: {P['text_secondary']};
                font-family: {_MONO};
                font-size: 8px;
                letter-spacing: 2px;
                background: transparent;
            """)
            dh_layout.addWidget(detail_title)
            detail_layout.addWidget(detail_header)

            self._detail = QTextEdit(detail_widget)
            self._detail.setReadOnly(True)
            self._detail.setStyleSheet(_DETAIL_CSS)
            detail_layout.addWidget(self._detail)

            splitter.addWidget(detail_widget)
            splitter.setSizes([460, 190])
            layout.addWidget(splitter)

        # â”€â”€ Load session â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def load_session(self, session_id: Optional[str],
                         case_db_path: str) -> None:
            self._case_db = case_db_path
            try:
                from storage.case_db import CaseDB
                with CaseDB(case_db_path) as db:
                    self._findings = db.get_findings(
                        session_id=session_id, limit=5000)
            except Exception:
                self._findings = []
            self._populate_table(self._findings)

        def _populate_table(self, findings: list) -> None:
            sorted_f = sorted(
                [f for f in findings if getattr(f, "timestamp", None)],
                key=lambda f: f.timestamp
            ) + [f for f in findings if not getattr(f, "timestamp", None)]

            self._table.setSortingEnabled(False)
            self._table.setRowCount(0)
            for f in sorted_f:
                row = self._table.rowCount()
                self._table.insertRow(row)
                self._set_row(row, f)
            self._table.setSortingEnabled(True)
            n = self._table.rowCount()
            self._count_label.setText(f"{n:,} EVENTS")

        def _set_row(self, row: int, f) -> None:
            # FIX: guard severity â€” consistent with findings_view.py
            sev_raw = getattr(f, "severity", None)
            sev     = (sev_raw.value if hasattr(sev_raw, "value")
                       else str(sev_raw) if sev_raw else "INFO")
            fg      = _SEV_FG.get(sev, P["text_primary"])
            bg      = _SEV_BG.get(sev, P["bg_base"])

            ts = getattr(f, "timestamp", None)
            cells = [
                ts.strftime("%Y-%m-%d  %H:%M:%S") if ts else "â€”",
                sev,
                f"{getattr(f, 'risk_score', 0):.1f}",
                _s(getattr(f, "rule_id",   None)),
                _s(getattr(f, "rule_name", None)),
                _s(getattr(f, "source_ip", None)) or "â€”",
                _s(getattr(f, "hostname",  None)) or "â€”",
                _s(getattr(f, "category",  None)),
            ]
            for col, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if col == 1:
                    item.setForeground(QBrush(QColor(fg)))
                    item.setFont(QFont("JetBrains Mono", 8,
                                       QFont.Weight.Bold))
                elif col == 2:
                    item.setForeground(QBrush(QColor(fg)))
                    item.setTextAlignment(Qt.AlignCenter)
                else:
                    item.setForeground(QBrush(QColor(P["text_primary"])))
                item.setBackground(QBrush(QColor(bg)))
                item.setData(Qt.UserRole, f)
                self._table.setItem(row, col, item)
            self._table.setRowHeight(row, 24)

        # â”€â”€ Filters â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def _apply_filter(self) -> None:
            sev_filter  = self._sev_combo.currentText()
            ip_filter   = self._ip_filter.text().strip().lower()
            rule_filter = self._rule_filter.text().strip().lower()

            filtered = []
            for f in self._findings:
                sev_raw = getattr(f, "severity", None)
                sev     = (sev_raw.value if hasattr(sev_raw, "value")
                           else str(sev_raw) if sev_raw else "INFO")
                if sev_filter != "ALL" and sev != sev_filter:
                    continue
                # FIX: guard source_ip â€” can be None
                if ip_filter and ip_filter not in _s(
                        getattr(f, "source_ip", None)).lower():
                    continue
                if rule_filter and rule_filter not in _s(
                        getattr(f, "rule_id", None)).lower():
                    continue
                filtered.append(f)
            self._populate_table(filtered)

        def _clear_filters(self) -> None:
            self._sev_combo.setCurrentIndex(0)
            self._ip_filter.clear()
            self._rule_filter.clear()
            self._populate_table(self._findings)

        # â”€â”€ Row selection â†’ terminal detail â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def _on_row_selected(self) -> None:
            rows = self._table.selectedItems()
            if not rows:
                return
            f = rows[0].data(Qt.UserRole)
            if not f:
                return
            ts    = f.timestamp.isoformat() if getattr(f, "timestamp", None) else "N/A"
            mitre = "\n".join(
                f"  {t.full_id}  {t.tactic_name} / {t.technique_name}"
                for t in getattr(f, "mitre_tags", [])
            ) or "  None"
            supporting = "\n".join(
                f"  {line}"
                for line in getattr(f, "supporting_lines", [])[:5]
            ) or "  None"

            sev_raw = getattr(f, "severity", None)
            sev_str = (sev_raw.value if hasattr(sev_raw, "value")
                       else str(sev_raw) if sev_raw else "N/A")
            detail = (
                f"â•”â•â• {_s(getattr(f, 'rule_id', None))}  â”€  "
                f"{_s(getattr(f, 'rule_name', None))}\n"
                f"â•‘   Severity:   {sev_str:<10}"
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
                f"â•‘   MITRE ATT&CK:\n{mitre}\n"
                f"â•‘\n"
                f"â•‘   Supporting Evidence:\n{supporting}\n"
                f"â•šâ•â•"
            )
            self._detail.setPlainText(detail)
            self.finding_selected.emit(f.to_dict() if hasattr(f, "to_dict") else {})

        # â”€â”€ Export â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def _export_csv(self) -> None:
            from datetime import datetime
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_fn = f"forensic_timeline_{ts}.csv"

            # AUTOMATED: Save to workspace output/ directory
            from pathlib import Path
            out_dir = Path(_ROOT) / "output"
            out_dir.mkdir(parents=True, exist_ok=True)
            path = str(out_dir / default_fn)
            import csv
            # FIX: QTableWidget.item(row, col) returns None when a cell widget
            # (e.g. a custom _RiskCell) is set instead of a QTableWidgetItem.
            # Calling .text() on None raises AttributeError and crashes the export.
            # Safe helper: returns empty string for None items.
            def _cell(r: int, c: int) -> str:
                item = self._table.item(r, c)
                return item.text() if item is not None else ""

            try:
                with open(path, "w", newline="", encoding="utf-8") as fh:
                    writer = csv.writer(fh)
                    writer.writerow(_COLS)
                    for row in range(self._table.rowCount()):
                        writer.writerow([_cell(row, col) for col in range(len(_COLS))])
                from PySide6.QtWidgets import QMessageBox
                QMessageBox.information(
                    self, "Exported", f"Timeline CSV saved to:\n{path}")
            except Exception as e:
                from PySide6.QtWidgets import QMessageBox
                QMessageBox.critical(self, "Export Error", str(e))

        def _export_pdf(self) -> None:
            if not self._findings:
                return
            from datetime import datetime
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_fn = f"forensic_timeline_{ts}.pdf"
            
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
                    case_ref="IR-TIMELINE-EXPORT"
                )
                report.build(path)
                QMessageBox.information(self, "Exported", f"PDF report saved to:\n{path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to generate PDF: {e}")


else:
    class TimelineView:
        def __init__(self, *a, **kw): pass
        def load_session(self, *a, **kw): pass
