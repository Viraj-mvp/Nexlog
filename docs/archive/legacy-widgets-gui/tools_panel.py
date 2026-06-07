"""
interface/gui/tools_panel.py â€” NexLog v2  Integrated Tools Panel
======================================================================
Single tab that hosts all Tier-1 tools:
  â€¢ AI Narrative IR Report generator
  â€¢ Sigma Rule bulk export
  â€¢ Canary Token manager  
  â€¢ YARA Studio (basic â€” write and test rules against findings)
  â€¢ UEBA anomaly report
  â€¢ CTI quick enrichment

All styled with the Deep Space / 2026 SecOps theme.
"""

import os
import sys
import threading

_root = os.path.dirname(os.path.abspath(__file__))
for _ in range(8):
    if os.path.isfile(os.path.join(_root, "pathconfig.py")):
        break
    _root = os.path.dirname(_root)
if _root not in sys.path:
    sys.path.insert(0, _root)
from pathconfig import ROOT, add_root
add_root()

try:
    from PySide6.QtCore import Qt, QThread, Signal, Slot
    from PySide6.QtGui import QFont
    from PySide6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel,
        QPushButton, QTabWidget, QTextEdit, QLineEdit,
        QComboBox, QSizePolicy, QFrame, QScrollArea,
        QTableWidget, QTableWidgetItem, QHeaderView,
        QGroupBox, QSplitter, QProgressBar,
    )
    _HAS_PYSIDE6 = True
except ImportError:
    _HAS_PYSIDE6 = False

try:
    from interface.gui.theme import PALETTE as P, FONT_MONO_CSS
except ImportError:
    try:
        from theme import PALETTE as P, FONT_MONO_CSS
    except ImportError:
        P = {
            "bg_base": "#080C14", "bg_surface": "#0D1420",
            "bg_raised": "#111C2E", "bg_void": "#04080F",
            "bg_input": "#0A1628", "border_dim": "#1A2A3F",
            "border_mid": "#1E3A5A", "cyan": "#00C8FF",
            "cyan_dim": "#007A9C", "green": "#00FF9D",
            "amber": "#FFB700", "critical": "#FF3B5C",
            "high": "#FF6B35", "text_primary": "#C8DFF0",
            "text_secondary": "#5A8FA8", "text_mono": "#8ECFAA",
            "text_dim": "#2A4A5E",
        }
        FONT_MONO_CSS = "'JetBrains Mono','Consolas',monospace"

_MONO = FONT_MONO_CSS


def _btn(label: str, accent: str = "cyan") -> "QPushButton":
    color = P.get(accent, P["cyan"])
    dim   = P.get(f"{accent}_dim", P["cyan_dim"])
    b = QPushButton(label)
    b.setStyleSheet(f"""
        QPushButton {{
            background: transparent; color: {color};
            border: 1px solid {dim}; border-radius: 2px;
            padding: 5px 14px; font-family: {_MONO};
            font-size: 9px; letter-spacing: 1px;
        }}
        QPushButton:hover {{
            background: rgba(0,200,255,0.08); border-color: {color};
        }}
        QPushButton:pressed {{ background: rgba(0,200,255,0.15); }}
        QPushButton:disabled {{ color: {P['text_dim']}; border-color: {P['border_dim']}; }}
    """)
    return b


def _section_label(text: str) -> "QLabel":
    lbl = QLabel(text)
    lbl.setStyleSheet(f"""
        color: {P['cyan']}; font-family: {_MONO};
        font-size: 9px; letter-spacing: 2px; font-weight: bold;
    """)
    return lbl


def _output_box() -> "QTextEdit":
    box = QTextEdit()
    box.setReadOnly(True)
    box.setStyleSheet(f"""
        QTextEdit {{
            background: {P['bg_surface']}; color: {P['text_mono']};
            border: 1px solid {P['border_dim']}; border-radius: 3px;
            font-family: {_MONO}; font-size: 9px; padding: 6px;
        }}
    """)
    return box


if _HAS_PYSIDE6:

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # AI REPORT SUB-PANEL
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    class _AIReportWorker(QThread):
        done  = Signal(str)
        error = Signal(str)

        def __init__(self, case_db_path: str, session_id: str):
            super().__init__()
            self._path = case_db_path
            self._sid  = session_id

        def run(self):
            try:
                from storage.case_db import CaseDB
                from output.ai_report import AIReportBuilder
                from ai.llm_client import LLMClient

                with CaseDB(self._path) as db:
                    llm     = LLMClient()
                    builder = AIReportBuilder(db=db, llm=llm)
                    md      = builder.build_markdown(session_id=self._sid or None)
                self.done.emit(md)
            except Exception as e:
                self.error.emit(str(e))


    class _AIReportPanel(QWidget):
        def __init__(self, parent=None):
            super().__init__(parent)
            self._case_db_path = ""
            self._session_id   = ""
            layout = QVBoxLayout(self)
            layout.setContentsMargins(8, 8, 8, 8)
            layout.setSpacing(8)

            layout.addWidget(_section_label("AI NARRATIVE INCIDENT REPORT"))
            desc = QLabel(
                "Generates a full prose IR report using the LLM â€” "
                "executive summary, attack timeline, MITRE analysis, and recommendations.")
            desc.setStyleSheet(f"color: {P['text_secondary']}; font-family: {_MONO}; font-size: 9px;")
            desc.setWordWrap(True)
            layout.addWidget(desc)

            row = QHBoxLayout()
            self._btn_gen = _btn("[ âš¡ GENERATE REPORT ]", "green")
            self._btn_gen.clicked.connect(self._generate)
            row.addWidget(self._btn_gen)
            self._btn_save = _btn("[ SAVE PDF ]")
            self._btn_save.clicked.connect(self._save_pdf)
            self._btn_save.setEnabled(False)
            row.addWidget(self._btn_save)
            self._btn_copy = _btn("[ COPY MD ]")
            self._btn_copy.clicked.connect(self._copy_md)
            self._btn_copy.setEnabled(False)
            row.addWidget(self._btn_copy)
            row.addStretch()
            layout.addLayout(row)

            self._progress = QProgressBar()
            self._progress.setRange(0, 0)
            self._progress.setVisible(False)
            self._progress.setStyleSheet(f"""
                QProgressBar {{
                    border: 1px solid {P['border_mid']}; border-radius: 2px;
                    background: {P['bg_raised']}; color: {P['cyan']}; height: 8px;
                }}
                QProgressBar::chunk {{ background: {P['cyan']}; }}
            """)
            layout.addWidget(self._progress)

            self._output = _output_box()
            self._output.setPlaceholderText("Report will appear hereâ€¦")
            layout.addWidget(self._output)
            self._worker = None
            self._last_md = ""

        def set_context(self, case_db_path: str, session_id: str):
            self._case_db_path = case_db_path
            self._session_id   = session_id

        def _generate(self):
            if not self._case_db_path:
                self._output.setText("Open a case database first (File â†’ Open Case).")
                return
            self._btn_gen.setEnabled(False)
            self._progress.setVisible(True)
            self._output.setText("Generating reportâ€¦ (LLM query in progress)")
            self._worker = _AIReportWorker(self._case_db_path, self._session_id)
            self._worker.done.connect(self._on_done)
            self._worker.error.connect(self._on_error)
            self._worker.start()

        @Slot(str)
        def _on_done(self, md: str):
            self._last_md = md
            self._output.setMarkdown(md)
            self._btn_gen.setEnabled(True)
            self._btn_save.setEnabled(True)
            self._btn_copy.setEnabled(True)
            self._progress.setVisible(False)

        @Slot(str)
        def _on_error(self, err: str):
            self._output.setText(f"Error: {err}")
            self._btn_gen.setEnabled(True)
            self._progress.setVisible(False)

        def _save_pdf(self):
            if not self._last_md:
                return
            from PySide6.QtWidgets import QFileDialog
            from datetime import datetime
            ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
            path, _ = QFileDialog.getSaveFileName(
                self, "Save PDF Report", f"ir_report_{ts}.pdf",
                "PDF Files (*.pdf)")
            if path:
                try:
                    from output.ai_report import AIReportBuilder
                    AIReportBuilder(db=None).save_pdf(self._last_md, path)
                    self._output.append(f"\nâœ“ Saved to {path}")
                except Exception as e:
                    self._output.append(f"\nâœ— Save error: {e}")

        def _copy_md(self):
            from PySide6.QtWidgets import QApplication
            QApplication.clipboard().setText(self._last_md)


    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # SIGMA EXPORT SUB-PANEL
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    class _SigmaPanel(QWidget):
        def __init__(self, parent=None):
            super().__init__(parent)
            self._findings = []
            layout = QVBoxLayout(self)
            layout.setContentsMargins(8, 8, 8, 8)
            layout.setSpacing(8)

            layout.addWidget(_section_label("SIGMA RULE EXPORTER"))
            desc = QLabel(
                "Convert all detected findings to Sigma YAML rules. "
                "Export to a directory or copy as a multi-document bundle.")
            desc.setStyleSheet(f"color: {P['text_secondary']}; font-family: {_MONO}; font-size: 9px;")
            desc.setWordWrap(True)
            layout.addWidget(desc)

            row = QHBoxLayout()
            btn_export = _btn("[ EXPORT ALL RULES ]", "amber")
            btn_export.clicked.connect(self._export_all)
            row.addWidget(btn_export)
            btn_copy   = _btn("[ COPY BUNDLE ]")
            btn_copy.clicked.connect(self._copy_bundle)
            row.addWidget(btn_copy)
            row.addStretch()
            layout.addLayout(row)

            self._output = _output_box()
            self._output.setPlaceholderText("Sigma YAML output will appear hereâ€¦")
            layout.addWidget(self._output)

        def set_findings(self, findings: list):
            self._findings = findings

        def _export_all(self):
            if not self._findings:
                self._output.setText("No findings loaded. Run analysis first.")
                return
            from PySide6.QtWidgets import QFileDialog
            directory = QFileDialog.getExistingDirectory(
                self, "Select output directory for Sigma rules")
            if not directory:
                return
            try:
                from detection.sigma_exporter import SigmaExporter
                exporter = SigmaExporter()
                paths    = exporter.export_bundle(self._findings, directory)
                self._output.setText(
                    f"âœ“ Exported {len(paths)} Sigma rules to:\n{directory}\n\n"
                    + "\n".join(os.path.basename(p) for p in paths[:30]))
            except Exception as e:
                self._output.setText(f"Error: {e}")

        def _copy_bundle(self):
            if not self._findings:
                return
            try:
                from detection.sigma_exporter import SigmaExporter
                bundle = SigmaExporter().export_single_bundle(self._findings)
                from PySide6.QtWidgets import QApplication
                QApplication.clipboard().setText(bundle)
                self._output.setText("âœ“ Sigma bundle copied to clipboard.\n\n" + bundle[:3000])
            except Exception as e:
                self._output.setText(f"Error: {e}")


    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # CANARY TOKEN SUB-PANEL
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    class _CanaryPanel(QWidget):
        def __init__(self, parent=None):
            super().__init__(parent)
            self._manager  = None
            self._listener = None
            layout = QVBoxLayout(self)
            layout.setContentsMargins(8, 8, 8, 8)
            layout.setSpacing(8)

            layout.addWidget(_section_label("CANARY TOKEN GENERATOR"))
            desc = QLabel(
                "Generate honeytokens. Plant them in documents, emails, or configs. "
                "Token hits appear automatically as CANARY findings in the case.")
            desc.setStyleSheet(f"color: {P['text_secondary']}; font-family: {_MONO}; font-size: 9px;")
            desc.setWordWrap(True)
            layout.addWidget(desc)

            # Token creation row
            create_row = QHBoxLayout()
            self._type_combo = QComboBox()
            self._type_combo.addItems(["URL Token", "AWS Key Token", "API Key Token", "DNS Token"])
            self._type_combo.setStyleSheet(f"""
                QComboBox {{
                    background: {P['bg_input']}; color: {P['text_primary']};
                    border: 1px solid {P['border_dim']}; border-radius: 2px;
                    padding: 4px 8px; font-family: {_MONO}; font-size: 9px;
                }}
                QComboBox:focus {{ border-color: {P['cyan']}; }}
            """)
            create_row.addWidget(self._type_combo)

            self._label_input = QLineEdit()
            self._label_input.setPlaceholderText("Token label (e.g. 'Finance Invoice Q4')")
            self._label_input.setStyleSheet(f"""
                QLineEdit {{
                    background: {P['bg_input']}; color: {P['text_primary']};
                    border: 1px solid {P['border_dim']}; border-radius: 2px;
                    padding: 4px 8px; font-family: {_MONO}; font-size: 9px;
                }}
                QLineEdit:focus {{ border-color: {P['cyan']}; }}
            """)
            create_row.addWidget(self._label_input)

            btn_create = _btn("[ CREATE TOKEN ]", "green")
            btn_create.clicked.connect(self._create_token)
            create_row.addWidget(btn_create)

            btn_start  = _btn("[ START LISTENER ]")
            btn_start.clicked.connect(self._start_listener)
            create_row.addWidget(btn_start)
            layout.addLayout(create_row)

            # Token table
            self._table = QTableWidget(0, 4)
            self._table.setHorizontalHeaderLabels(["Type", "Label", "Token / URL", "Hits"])
            self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
            self._table.setStyleSheet(f"""
                QTableWidget {{
                    background: {P['bg_base']}; color: {P['text_primary']};
                    border: 1px solid {P['border_dim']}; gridline-color: {P['border_dim']};
                    font-family: {_MONO}; font-size: 9px;
                }}
                QHeaderView::section {{
                    background: {P['bg_void']}; color: {P['text_secondary']};
                    border: none; padding: 4px; font-size: 8px; letter-spacing: 1px;
                }}
            """)
            self._table.setSelectionBehavior(QTableWidget.SelectRows)
            layout.addWidget(self._table)

            self._status = QLabel("Listener: not started")
            self._status.setStyleSheet(f"color: {P['text_dim']}; font-family: {_MONO}; font-size: 8px;")
            layout.addWidget(self._status)

        def set_db(self, db_path: str):
            try:
                from intelligence.canary import CanaryManager
                from storage.case_db import CaseDB
                with CaseDB(db_path) as db:
                    self._manager = CanaryManager(db=None)  # no live DB for thread safety
                self._refresh_table()
            except Exception:
                pass

        def _create_token(self):
            if self._manager is None:
                from intelligence.canary import CanaryManager
                self._manager = CanaryManager()

            label    = self._label_input.text().strip() or "Unlabelled token"
            tok_type = self._type_combo.currentText()
            try:
                if "URL" in tok_type:
                    token = self._manager.create_url_token(label)
                    value = token["token_url"]
                elif "AWS" in tok_type:
                    token = self._manager.create_aws_key_token(label)
                    value = token["access_key"]
                elif "API" in tok_type:
                    token = self._manager.create_api_key_token(label)
                    value = token["api_key"]
                else:
                    token = self._manager.create_dns_token(label)
                    value = token["hostname"]

                row = self._table.rowCount()
                self._table.insertRow(row)
                self._table.setItem(row, 0, QTableWidgetItem(tok_type))
                self._table.setItem(row, 1, QTableWidgetItem(label))
                self._table.setItem(row, 2, QTableWidgetItem(value))
                self._table.setItem(row, 3, QTableWidgetItem("0"))

                # Copy to clipboard
                from PySide6.QtWidgets import QApplication
                QApplication.clipboard().setText(value)
                self._status.setText(f"âœ“ Token created and copied: {value[:60]}")
                self._label_input.clear()
            except Exception as e:
                self._status.setText(f"Error: {e}")

        def _start_listener(self):
            if self._manager is None:
                from intelligence.canary import CanaryManager
                self._manager = CanaryManager()
            try:
                from intelligence.canary import run_listener
                self._listener = run_listener(self._manager)
                self._status.setText(
                    f"âœ“ Listener active at http://localhost:9999/ping/<token_id>")
                self._status.setStyleSheet(
                    f"color: {P['green']}; font-family: {_MONO}; font-size: 8px;")
            except Exception as e:
                self._status.setText(f"Error starting listener: {e}")

        def _refresh_table(self):
            if not self._manager:
                return
            tokens = self._manager.list_tokens()
            self._table.setRowCount(0)
            for t in tokens:
                row = self._table.rowCount()
                self._table.insertRow(row)
                self._table.setItem(row, 0, QTableWidgetItem(t.get("type", "")))
                self._table.setItem(row, 1, QTableWidgetItem(t.get("label", "")))
                val = (t.get("token_url") or t.get("access_key") or
                       t.get("api_key") or t.get("hostname") or "")
                self._table.setItem(row, 2, QTableWidgetItem(val))
                self._table.setItem(row, 3, QTableWidgetItem(str(t.get("hit_count", 0))))


    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # UEBA SUB-PANEL
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    class _UEBAPanel(QWidget):
        def __init__(self, parent=None):
            super().__init__(parent)
            self._findings = []
            layout = QVBoxLayout(self)
            layout.setContentsMargins(8, 8, 8, 8)
            layout.setSpacing(8)

            layout.addWidget(_section_label("BEHAVIORAL UEBA ANOMALY DETECTION"))
            desc = QLabel(
                "Z-score behavioral analysis. Scores each entity (IP/user/host) against "
                "their normal baseline. Score 0â€“10: â‰¥6 = anomalous, â‰¥8 = critical.")
            desc.setStyleSheet(f"color: {P['text_secondary']}; font-family: {_MONO}; font-size: 9px;")
            desc.setWordWrap(True)
            layout.addWidget(desc)

            row = QHBoxLayout()
            btn_score = _btn("[ RUN UEBA ANALYSIS ]", "amber")
            btn_score.clicked.connect(self._run_ueba)
            row.addWidget(btn_score)
            row.addStretch()
            layout.addLayout(row)

            self._table = QTableWidget(0, 4)
            self._table.setHorizontalHeaderLabels(["Entity", "Score", "Label", "Flags"])
            self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
            self._table.setStyleSheet(f"""
                QTableWidget {{
                    background: {P['bg_base']}; color: {P['text_primary']};
                    border: 1px solid {P['border_dim']}; gridline-color: {P['border_dim']};
                    font-family: {_MONO}; font-size: 9px;
                }}
                QHeaderView::section {{
                    background: {P['bg_void']}; color: {P['text_secondary']};
                    border: none; padding: 4px; font-size: 8px; letter-spacing: 1px;
                }}
            """)
            layout.addWidget(self._table)

        def set_findings(self, findings: list):
            self._findings = findings

        def _run_ueba(self):
            if not self._findings:
                return
            try:
                from detection.ueba import UEBAEngine
                engine    = UEBAEngine(threshold=4.0)
                results   = engine.score_findings(self._findings)
                self._table.setRowCount(0)
                for entity, score, detail in results:
                    if score < 1.0:
                        continue
                    row = self._table.rowCount()
                    self._table.insertRow(row)
                    self._table.setItem(row, 0, QTableWidgetItem(str(entity)))
                    score_item = QTableWidgetItem(f"{score:.1f}")
                    if score >= 8:
                        score_item.setForeground(QFont())
                        score_item.setData(Qt.ForegroundRole,
                                           __import__("PySide6.QtGui", fromlist=["QColor"]).QColor(P["critical"]))
                    elif score >= 6:
                        score_item.setData(Qt.ForegroundRole,
                                           __import__("PySide6.QtGui", fromlist=["QColor"]).QColor(P["amber"]))
                    self._table.setItem(row, 1, score_item)
                    self._table.setItem(row, 2, QTableWidgetItem(detail.get("label", "")))
                    self._table.setItem(row, 3, QTableWidgetItem(
                        "; ".join(detail.get("flags", []))[:100]))
            except Exception as e:
                pass


    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # MAIN TOOLS PANEL
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    class ToolsPanel(QWidget):
        """
        Master tools panel â€” tabbed container for all Tier-1 analysis tools.
        Add to MainWindow tabs as: self._tabs.addTab(tools, "ðŸ”§  TOOLS")
        """

        def __init__(self, case_db_path: str = "", parent=None):
            super().__init__(parent)
            self._case_db_path = case_db_path
            self._session_id   = ""
            self._findings:    list = []

            layout = QVBoxLayout(self)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(0)

            self._tabs = QTabWidget(self)
            self._tabs.setStyleSheet(f"""
                QTabWidget::pane {{
                    background: {P['bg_base']}; border: none;
                }}
                QTabBar::tab {{
                    background: {P['bg_void']}; color: {P['text_secondary']};
                    padding: 5px 12px; border: 1px solid {P['border_dim']};
                    border-bottom: none; margin-right: 2px;
                    font-family: {_MONO}; font-size: 8px; letter-spacing: 1px;
                }}
                QTabBar::tab:selected {{
                    background: {P['bg_base']}; color: {P['amber']};
                    border-color: {P['border_mid']}; border-bottom: 2px solid {P['amber']};
                }}
            """)
            layout.addWidget(self._tabs)

            self._ai_report = _AIReportPanel(self)
            self._sigma     = _SigmaPanel(self)
            self._canary    = _CanaryPanel(self)
            self._ueba      = _UEBAPanel(self)

            self._tabs.addTab(self._ai_report, "â—ˆ AI REPORT")
            self._tabs.addTab(self._sigma,     "Î£  SIGMA RULES")
            self._tabs.addTab(self._canary,    "ðŸ¯ CANARY TOKENS")
            self._tabs.addTab(self._ueba,      "ðŸ“Š UEBA / ANOMALY")

        def set_context(self, case_db_path: str, session_id: str,
                        findings: list = None) -> None:
            """Update all sub-panels with new session context."""
            self._case_db_path = case_db_path
            self._session_id   = session_id
            if findings is not None:
                self._findings = findings

            self._ai_report.set_context(case_db_path, session_id)
            self._sigma.set_findings(self._findings)
            self._ueba.set_findings(self._findings)
            if case_db_path:
                self._canary.set_db(case_db_path)

else:
    class ToolsPanel:
        def __init__(self, *a, **kw): pass
        def set_context(self, *a, **kw): pass
