"""
interface/gui/main_window.py â€” NexLog v2  [Deep Space Command Center]
============================================================================
PySide6 desktop application main window.

Visual Design: Bento Grid Command Center
  â€¢ Deep Space dark mode    â€” #080C14 base, layered surface hierarchy
  â€¢ Glassmorphism 2.0       â€” semi-transparent panel edges with neon glow
  â€¢ Neon accents            â€” Cyan #00C8FF / Green #00FF9D / Amber #FFB700
  â€¢ Terminal-integrated     â€” JetBrains Mono throughout all panels
  â€¢ Tactical motion         â€” animated progress bar, severity pulse on findings
  â€¢ Scanline texture        â€” QPainter overlay on main surface for CRT depth

Architecture:
  MainWindow
  â”œâ”€â”€ TopBar         â€” Logo + live status indicator + case label + clock
  â”œâ”€â”€ ToolBar        â€” Tactical action buttons with neon styling
  â”œâ”€â”€ StatusBar      â€” Animated progress + live finding counter + threat level
  â”œâ”€â”€ SidePanel      â€” Session history tree with severity-colour coding
  â””â”€â”€ CentralStack   â€” Tab widget (bento-style) hosting all views
      â”œâ”€â”€ DashboardView   (dashboard.py)
      â”œâ”€â”€ TimelineView    (timeline_view.py)
      â”œâ”€â”€ FindingsView    (findings_view.py)
      â””â”€â”€ AIPanel         (ai_panel.py)

Fixes v2.1:
  â€¢ _TopBar._tick: 'from datetime import datetime, timezone' was INSIDE the
    method body â€” called every 1 000 ms. Now imported once at module level.

  â€¢ _start_analysis: threat badge was NOT reset between analyses. Starting a
    new analysis left the badge showing the previous run's highest severity
    before any new finding arrives. Now resets to "--" at analysis start.

  â€¢ _AnalysisWorker.run: detect._rules_loaded and parse.stats.total_lines
    accessed via private attribute / raw attr chain without guard.
    Both now use getattr() with safe fallbacks.

  â€¢ Removed duplicated path-walk block â€” single clean setup at module top.

  â€¢ _on_finding_found: removed private _level access on _ThreatBadge â€”
    added public current_level() getter instead.
"""

import os
import sys
from pathlib import Path
from datetime import datetime, timezone   # FIX: imported at module level
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
    from PySide6.QtCore import (
        Qt, QThread, QTimer, Signal, Slot,
        QSize, QSettings, QPropertyAnimation,
        QEasingCurve, QPoint,
    )
    from PySide6.QtGui import (
        QAction, QColor, QFont, QIcon, QPalette,
        QKeySequence, QPainter, QPen, QBrush, QShortcut,
        QLinearGradient, QRadialGradient,
    )
    from PySide6.QtWidgets import (
        QApplication, QFileDialog, QHBoxLayout,
        QLabel, QMainWindow, QMenuBar, QMessageBox,
        QProgressBar, QPushButton, QSizePolicy,
        QSplitter, QStatusBar, QTabWidget, QToolBar,
        QTreeWidget, QTreeWidgetItem, QVBoxLayout,
        QWidget, QInputDialog, QLineEdit, QFrame,
        QDialog, QListWidget, QListWidgetItem, QButtonGroup,
    )
    _HAS_PYSIDE6 = True
except ImportError:
    _HAS_PYSIDE6 = False
if os.environ.get("NEXLOG_GUI_STUBS", "").strip().lower() in {"1", "true", "yes", "on"}:
    _HAS_PYSIDE6 = False

# â”€â”€ Theme â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
try:
    from interface.gui.theme import (
        PALETTE as P, STYLESHEET, sev_fg, FONT_MONO_CSS, SEV_RANK,
        card_style, caption_style, ghost_button_style, nav_button_style,
        primary_button_style, section_title_style,
    )
except ImportError:
    try:
        from theme import (
            PALETTE as P, STYLESHEET, sev_fg, FONT_MONO_CSS, SEV_RANK,
            card_style, caption_style, ghost_button_style, nav_button_style,
            primary_button_style, section_title_style,
        )
    except ImportError:
        P = {
            "bg_void": "#04080F", "bg_base": "#080C14",
            "bg_surface": "#0D1420", "bg_raised": "#111C2E",
            "bg_hover": "#162238", "border_dim": "#1A2A3F",
            "border_mid": "#1E3A5A", "border_glow": "#00C8FF",
            "cyan": "#00C8FF", "cyan_dim": "#007A9C",
            "green": "#00FF9D", "green_dim": "#009960",
            "amber": "#FFB700", "critical": "#FF3B5C",
            "high": "#FF6B35", "medium": "#FFB700", "low": "#00FF9D",
            "info": "#4A8FA8", "text_primary": "#C8DFF0",
            "text_secondary": "#5A8FA8", "text_dim": "#2A4A5E",
            "text_value": "#00E5FF",
        }
        STYLESHEET = ""
        def sev_fg(s): return P.get(s.lower(), P["text_primary"])
        def card_style(accent=""): return ""
        def caption_style(): return ""
        def ghost_button_style(accent=None): return ""
        def nav_button_style(): return ""
        def primary_button_style(): return ""
        def section_title_style(): return ""

_DARK_PALETTE = {
    "bg":       P.get("bg_base", "#080C14"),
    "surface":  P.get("bg_surface", "#0D1420"),
    "border":   P.get("border_mid", "#1E3A5A"),
    "accent":   P.get("cyan", "#00C8FF"),
    "critical": P.get("critical", "#FF3B5C"),
    "high":     P.get("high", "#FF6B35"),
    "medium":   P.get("medium", "#FFB700"),
    "low":      P.get("low", "#00FF9D"),
    "text":     P.get("text_primary", "#C8DFF0"),
    "subtext":  P.get("text_secondary", "#5A8FA8"),
}
_STYLESHEET = STYLESHEET

_MONO = FONT_MONO_CSS  # from theme
_GLASS_REFRESH_ENABLED = os.environ.get(
    "NEXLOG_ENABLE_GLASS", ""
).strip().lower() in {"1", "true", "yes", "on"}

# Severity rank helper (used in multiple places)
_SEV_RANK = SEV_RANK  # from theme


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# ANALYSIS WORKER THREAD
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

if _HAS_PYSIDE6:

    class _AnalysisWorker(QThread):
        """
        Runs the full Layer 1 â†’ Layer 2 â†’ Layer 3 pipeline in a background
        thread so the UI stays responsive during long analyses.
        """
        progress      = Signal(int, str)
        finding_found = Signal(dict)
        finished      = Signal(dict)
        error         = Signal(str)

        def __init__(
            self,
            log_path:     str = "",
            case_path:    str = "",
            min_severity: str = "LOW",
            category:     Optional[str] = None,
            analyst:      str = "analyst",
        ):
            super().__init__()
            self.log_path     = log_path
            self.case_path    = case_path
            self.min_severity = min_severity
            self.category     = category
            self.analyst      = analyst

        def run(self):
            try:
                sys.path.insert(0, _ROOT)
                from rule_engine import RuleEngine
                from storage.case_db import CaseDB
                from attck_tagger import detect_attack_chain

                rules_dir = Path(_ROOT) / "detection" / "rules"

                self.progress.emit(5, "Loading detection rulesâ€¦")
                detect = RuleEngine(str(rules_dir))

                self.progress.emit(15, f"Parsing {Path(self.log_path).name}â€¦")

                from engine import Engine
                parse    = Engine()
                findings = []
                line_count = 0

                for entry in parse.parse(Path(self.log_path)):
                    line_count += 1
                    if line_count % 5000 == 0:
                        self.progress.emit(
                            min(15 + int(line_count / 1000), 70),
                            f"Parsed {line_count:,} linesâ€¦"
                        )
                    for f in detect.evaluate(entry):
                        findings.append(f)
                        self.finding_found.emit({
                            "rule_id":    f.rule_id,
                            "severity":   getattr(
                                getattr(f, "severity", None), "value",
                                str(getattr(f, "severity", "INFO"))
                            ),
                            "source_ip":  getattr(f, "source_ip", None) or "?",
                            "risk_score": getattr(f, "risk_score", 0),
                            "category":   getattr(f, "category",  ""),
                        })

                self.progress.emit(75, "Deduplicating findingsâ€¦")
                findings = RuleEngine.deduplicate_findings(findings)

                self.progress.emit(80, "Enriching via AbuseIPDBâ€¦")
                try:
                    from intelligence.abuseipdb import AbuseIPDB
                    AbuseIPDB().enrich_findings(findings)
                except Exception as e:
                    import traceback as _tb
                    print(f"AbuseIPDB enrichment failed: {e}\n{_tb.format_exc()}")

                self.progress.emit(82, "Saving to case databaseâ€¦")
                with CaseDB(self.case_path) as db:
                    meta = getattr(parse, "file_meta", None) or {}
                    # FIX: access private-ish attributes via getattr with fallback
                    rules_loaded   = getattr(detect, "_rules_loaded", 0)
                    stats          = getattr(parse,  "stats",         None)
                    entries_parsed = getattr(stats,  "total_lines",   0)

                    sid = db.create_session(
                        source_file    = self.log_path,
                        sha256         = meta.get("sha256", ""),
                        file_size      = meta.get("size", 0),
                        rules_loaded   = rules_loaded,
                        entries_parsed = entries_parsed,
                    )
                    db.record_evidence(
                        self.log_path,
                        sha256         = meta.get("sha256", ""),
                        file_size      = meta.get("size", 0),
                        session_id     = sid,
                        lines_parsed   = entries_parsed,
                        findings_count = len(findings),
                    )
                    db.save_findings(findings, sid)

                    self.progress.emit(90, "Detecting attack chainsâ€¦")
                    chains = detect_attack_chain(findings)
                    if chains:
                        db.save_attack_chains(chains, sid)

                    summary = db.get_findings_summary(session_id=sid)

                self.progress.emit(100, f"Complete â€” {len(findings)} findings")
                self.finished.emit({
                    "session_id": sid,
                    "findings":   findings,
                    "chains":     chains,
                    "summary":    summary,
                    "stats":      stats.summary() if (stats and hasattr(stats, "summary")) else {},
                })

            except Exception as e:
                import traceback as _tb
                self.error.emit(f"{type(e).__name__}: {e}\n{_tb.format_exc()}")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TOP BAR â€” NexLog brand strip with live clock
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    class _TopBar(QWidget):
        """
        Slim top brand bar:
          [NEXLOG v2]  [â—LIVE]  Â·Â·stretchÂ·Â·  [case label]  [clock]
        """
        def __init__(self, parent=None):
            super().__init__(parent)
            self.setFixedHeight(32)
            self.setStyleSheet(f"""
                QWidget {{
                    background-color: {P.get('bg_void', P['bg_base'])};
                    border-bottom: 1px solid {P['border_mid']};
                }}
            """)
            layout = QHBoxLayout(self)
            layout.setContentsMargins(12, 0, 12, 0)
            layout.setSpacing(12)

            brand = QLabel("NEXLOG", self)
            brand.setStyleSheet(f"""
                color: {P['cyan']};
                font-family: {_MONO};
                font-size: 12px;
                font-weight: bold;
                letter-spacing: 4px;
                background: transparent;
            """)
            layout.addWidget(brand)

            ver = QLabel("v2", self)
            ver.setStyleSheet(f"""
                color: {P['text_secondary']};
                font-family: {_MONO};
                font-size: 9px;
                background: transparent;
                padding-top: 2px;
            """)
            layout.addWidget(ver)

            self._live_dot = QLabel("â— LIVE", self)
            self._live_dot.setStyleSheet(f"""
                color: {P['green']};
                font-family: {_MONO};
                font-size: 8px;
                letter-spacing: 2px;
                background: transparent;
            """)
            layout.addWidget(self._live_dot)

            layout.addStretch()

            self._case_lbl = QLabel("NO CASE LOADED", self)
            self._case_lbl.setStyleSheet(f"""
                color: {P['text_dim']};
                font-family: {_MONO};
                font-size: 8px;
                letter-spacing: 1px;
                background: transparent;
            """)
            layout.addWidget(self._case_lbl)

            sep = QLabel("|", self)
            sep.setStyleSheet(f"color: {P['border_mid']}; background: transparent;")
            layout.addWidget(sep)

            self._clock = QLabel("", self)
            self._clock.setStyleSheet(f"""
                color: {P['cyan_dim']};
                font-family: {_MONO};
                font-size: 9px;
                letter-spacing: 1px;
                background: transparent;
                min-width: 130px;
            """)
            layout.addWidget(self._clock)

            # FIX: QTimer fires every 1 000 ms. The original code imported
            # datetime inside _tick() â€” Python reimports on every tick.
            # datetime is now imported at module level (top of file).
            self._timer = QTimer(self)
            self._timer.timeout.connect(self._tick)
            self._timer.start(1000)
            self._tick()

            self._dot_state = True
            self._dot_timer = QTimer(self)
            self._dot_timer.timeout.connect(self._pulse_dot)
            self._dot_timer.start(1200)

        def set_case(self, name: str) -> None:
            self._case_lbl.setText(f"CASE: {name.upper()}")
            self._case_lbl.setStyleSheet(f"""
                color: {P['text_secondary']};
                font-family: {_MONO};
                font-size: 8px;
                letter-spacing: 1px;
                background: transparent;
            """)

        def _tick(self) -> None:
            # FIX: datetime imported at module level â€” no repeated import overhead
            now = datetime.now(timezone.utc)
            self._clock.setText(now.strftime("UTC %Y-%m-%d  %H:%M:%S"))

        def _pulse_dot(self) -> None:
            self._dot_state = not self._dot_state
            col = P["green"] if self._dot_state else P.get("green_dim", "#009960")
            self._live_dot.setStyleSheet(f"""
                color: {col};
                font-family: {_MONO};
                font-size: 8px;
                letter-spacing: 2px;
                background: transparent;
            """)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# SIDE PANEL â€” Session history tree
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    class _SidePanel(QWidget):
        """Left-side panel: session history tree with severity-colour coding."""
        session_selected = Signal(str)

        def __init__(self, parent=None):
            super().__init__(parent)
            self.setFixedWidth(210)
            self.setStyleSheet(f"""
                QWidget {{
                    background-color: {P['bg_surface']};
                    border-right: 1px solid {P['border_dim']};
                }}
            """)
            layout = QVBoxLayout(self)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.setSpacing(0)

            header = QWidget(self)
            header.setFixedHeight(32)
            header.setStyleSheet(f"""
                background-color: {P.get('bg_void', P['bg_base'])};
                border-bottom: 1px solid {P['border_mid']};
            """)
            h_layout = QHBoxLayout(header)
            h_layout.setContentsMargins(10, 0, 10, 0)

            title = QLabel("SESSIONS", header)
            title.setStyleSheet(f"""
                color: {P['text_secondary']};
                font-family: {_MONO};
                font-size: 8px;
                letter-spacing: 3px;
                background: transparent;
            """)
            h_layout.addWidget(title)
            layout.addWidget(header)

            self._tree = QTreeWidget(self)
            self._tree.setHeaderHidden(True)
            self._tree.setAlternatingRowColors(True)
            self._tree.setIndentation(12)
            self._tree.itemClicked.connect(self._on_item_clicked)
            layout.addWidget(self._tree)

        def add_session(self, session_id: str, label: str,
                        finding_count: int, severity: str) -> None:
            item = QTreeWidgetItem([f" {label}"])
            item.setData(0, Qt.UserRole, session_id)
            col = sev_fg(severity)
            item.setForeground(0, QColor(col))
            sub = QTreeWidgetItem([f"  {finding_count} findings"])
            sub.setForeground(0, QColor(P["text_dim"]))
            item.addChild(sub)
            self._tree.addTopLevelItem(item)
            self._tree.expandItem(item)

        def clear_sessions(self) -> None:
            self._tree.clear()

        def _on_item_clicked(self, item: QTreeWidgetItem, column: int) -> None:
            sid = item.data(0, Qt.UserRole)
            if sid:
                self.session_selected.emit(sid)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# THREAT LEVEL BADGE
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    class _ThreatBadge(QLabel):
        """Animated threat level label. Flashes when level is CRITICAL or HIGH."""

        def __init__(self, parent=None):
            super().__init__("â— THREAT: --", parent)
            self._level = ""
            self._col   = P["text_dim"]
            self._flash_state = True
            self._timer = QTimer(self)
            self._timer.timeout.connect(self._flash)
            self._set_style(P["text_dim"])

        def current_level(self) -> str:
            """Public accessor â€” avoids callers reading _level directly."""
            return self._level

        def reset(self) -> None:
            """Reset badge to idle state. Call at the start of each analysis."""
            self._timer.stop()
            self._level = ""
            self._col   = P["text_dim"]
            self.setText("â— THREAT: --")
            self._set_style(P["text_dim"])

        def set_level(self, severity: str) -> None:
            self._level = severity
            label_map = {
                "CRITICAL": "â— THREAT: CRITICAL",
                "HIGH":     "â— THREAT: HIGH",
                "MEDIUM":   "â— THREAT: MEDIUM",
                "LOW":      "â— THREAT: LOW",
                "INFO":     "â— THREAT: INFO",
            }
            self.setText(label_map.get(severity, "â— THREAT: --"))
            colours = {
                "CRITICAL": P["critical"],
                "HIGH":     P["high"],
                "MEDIUM":   P["medium"],
                "LOW":      P["low"],
                "INFO":     P["info"],
            }
            self._col = colours.get(severity, P["text_dim"])
            self._set_style(self._col)

            if severity in ("CRITICAL", "HIGH"):
                self._timer.start(600)
            else:
                self._timer.stop()
                self._set_style(self._col)

        def _flash(self) -> None:
            self._flash_state = not self._flash_state
            col = self._col if self._flash_state else P["text_dim"]
            self._set_style(col)

        def _set_style(self, colour: str) -> None:
            self.setStyleSheet(f"""
                color: {colour};
                font-family: {_MONO};
                font-size: 8px;
                letter-spacing: 1px;
                padding: 0 8px;
                background: transparent;
            """)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# MAIN WINDOW
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    class MainWindow(QMainWindow):
        """NexLog v2 main application window â€” Deep Space Command Center."""
        analysis_complete = Signal(dict)
        session_changed   = Signal(str)

        def __init__(self, case_db_path: str = "nexlog.facase"):
            self._qt_app = QApplication.instance()
            if self._qt_app is None:
                self._qt_app = QApplication(sys.argv[:1])
            super().__init__()
            self._case_db       = case_db_path
            self._worker:       Optional[_AnalysisWorker] = None
            self._settings      = QSettings("ForensicAmp", "v2")
            self._finding_count = 0
            self._min_severity  = "LOW"
            self._glass_refresh_enabled = _GLASS_REFRESH_ENABLED
            self._glass_refresh_timer = QTimer(self)
            self._glass_refresh_timer.setSingleShot(True)
            self._glass_refresh_timer.timeout.connect(self._refresh_all_glass)

            self._setup_window()
            self._setup_menu()
            self._setup_central()
            self._setup_toolbar()
            self._setup_cyber_shell()
            self._setup_statusbar()
            self._setup_shortcuts()
            self._load_sessions()
            self._schedule_glass_refresh(200)

        # â”€â”€ Window setup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def _setup_window(self) -> None:
            self.setWindowTitle("NexLog Legacy â€” Cyber OS Desktop")
            icon_path = Path(_ROOT) / "interface" / "gui" / "assets" / "nexlog-icon.png"
            if icon_path.exists():
                self.setWindowIcon(QIcon(str(icon_path)))
            self.setMinimumSize(QSize(1280, 780))
            geom = self._settings.value("geometry")
            if geom:
                self.restoreGeometry(geom)
            else:
                self.resize(1440, 900)
            self.setStyleSheet(STYLESHEET)
            self.setAutoFillBackground(True)
            pal = self.palette()
            pal.setColor(QPalette.Window, QColor(P["bg_base"]))
            self.setPalette(pal)

        # â”€â”€ Menu bar â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def _setup_menu(self) -> None:
            mb = self.menuBar()

            fm = mb.addMenu("FILE")
            a_open = QAction("Open Log Fileâ€¦", self)
            a_open.setShortcut(QKeySequence.Open)
            a_open.triggered.connect(self._open_log_file)
            fm.addAction(a_open)

            a_case = QAction("New Case Databaseâ€¦", self)
            a_case.triggered.connect(self._new_case)
            fm.addAction(a_case)

            a_open_case = QAction("Open Case Databaseâ€¦", self)
            a_open_case.triggered.connect(self._open_case)
            fm.addAction(a_open_case)

            fm.addSeparator()
            a_exit = QAction("Exit", self)
            a_exit.setShortcut(QKeySequence.Quit)
            a_exit.triggered.connect(self.close)
            fm.addAction(a_exit)

            am = mb.addMenu("ANALYSIS")
            a_analyse = QAction("Analyse Log Fileâ€¦", self)
            a_analyse.setShortcut("Ctrl+Return")
            a_analyse.triggered.connect(self._open_log_file)
            am.addAction(a_analyse)

            a_sev = QAction("Set Min Severityâ€¦", self)
            a_sev.triggered.connect(self._set_severity)
            am.addAction(a_sev)

            rm = mb.addMenu("REPORTS")
            a_ai_report = QAction("Generate AI Narrative Reportâ€¦", self)
            a_ai_report.triggered.connect(self._generate_ai_report)
            rm.addAction(a_ai_report)
            rm.addSeparator()
            for fmt, label in [("pdf","PDF Report"), ("markdown","Markdown"),
                                ("json","JSON"), ("text","Plain Text")]:
                a = QAction(label, self)
                a.triggered.connect(lambda checked, f=fmt: self._export_report(f))
                rm.addAction(a)
            rm.addSeparator()

            a_stix = QAction("Export STIX 2.1 Bundleâ€¦", self)
            a_stix.triggered.connect(self._export_stix)
            rm.addAction(a_stix)

            a_ioc = QAction("Export IOC CSVâ€¦", self)
            a_ioc.triggered.connect(lambda: self._export_iocs("csv"))
            rm.addAction(a_ioc)

            a_ioc_all = QAction("Export All IOC Formatsâ€¦", self)
            a_ioc_all.triggered.connect(lambda: self._export_iocs("all"))
            rm.addAction(a_ioc_all)

            # â”€â”€ Tools menu (new) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            tm = mb.addMenu("TOOLS")
            a_ai_report = QAction("Generate AI IR Reportâ€¦", self)
            a_ai_report.triggered.connect(self._run_ai_report)
            tm.addAction(a_ai_report)

            a_sigma = QAction("Export Sigma Rulesâ€¦", self)
            a_sigma.triggered.connect(self._export_sigma)
            tm.addAction(a_sigma)

            a_ueba = QAction("Run UEBA Analysisâ€¦", self)
            a_ueba.triggered.connect(self._run_ueba_quick)
            tm.addAction(a_ueba)

            a_canary = QAction("Open Canary Token Manager", self)
            a_canary.triggered.connect(self._open_canary_tab)
            tm.addAction(a_canary)

            a_graph = QAction("Show Attack Graph", self)
            a_graph.triggered.connect(self._show_attack_graph_tab)
            tm.addAction(a_graph)

            hm = mb.addMenu("HELP")
            a_about = QAction("About", self)
            a_about.triggered.connect(self._show_about)
            hm.addAction(a_about)

        # ——— Toolbar ———————————————————————————————————————————————————————————————

        def _setup_toolbar(self) -> None:
            tb = QToolBar("Main Toolbar", self)
            # Initialize main tabs with placeholder for AI panel (lazy-loaded)
            # # Tabs are initialized in _setup_central; no tab addition here.
            # Lazy-load AI panel placeholder
            # AI panel placeholder moved to central setup (handled in _setup_central)

            self._legacy_toolbar = tb
            tb.setMovable(False)
            tb.setIconSize(QSize(14, 14))
            tb.setStyleSheet(f"""
                QToolBar {{
                    background-color: {P.get('bg_void', P['bg_base'])};
                    border-bottom: 1px solid {P['border_mid']};
                    spacing: 4px;
                    padding: 4px 8px;
                }}
            """)
            self.addToolBar(tb)

            def _btn(label: str, tip: str = "") -> QPushButton:
                b = QPushButton(label)
                if tip:
                    b.setToolTip(tip)
                b.setStyleSheet(f"""
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
                        background-color: rgba(0,200,255,0.06);
                    }}
                    QPushButton:pressed {{
                        background-color: rgba(0,200,255,0.12);
                    }}
                """)
                return b

            btn_open = _btn("[ OPEN LOG ]", "Open a log file for analysis")
            btn_open.clicked.connect(self._open_log_file)
            tb.addWidget(btn_open)

            tb.addSeparator()

            btn_analyse = QPushButton("[ âš¡ ANALYSE ]")
            btn_analyse.setObjectName("btn_analyse")
            btn_analyse.clicked.connect(self._open_log_file)
            tb.addWidget(btn_analyse)

            tb.addSeparator()

            btn_pdf = _btn("[ PDF ]", "Export PDF report")
            btn_pdf.clicked.connect(lambda: self._export_report("pdf"))
            tb.addWidget(btn_pdf)

            btn_stix = _btn("[ STIX ]", "Export STIX 2.1 bundle")
            btn_stix.clicked.connect(self._export_stix)
            tb.addWidget(btn_stix)

            btn_sigma = _btn("[ SIGMA ]", "Export Sigma rules")
            btn_sigma.clicked.connect(self._export_sigma)
            tb.addWidget(btn_sigma)

            btn_ai_rpt = _btn("[ AI REPORT ]", "Generate AI narrative IR report")
            btn_ai_rpt.clicked.connect(self._generate_ai_report)
            tb.addWidget(btn_ai_rpt)

            spacer = QWidget()
            spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
            tb.addWidget(spacer)

            self._case_label_tb = QLabel("", self)
            self._case_label_tb.setStyleSheet(f"""
                color: {P['text_secondary']};
                font-family: {_MONO};
                font-size: 8px;
                letter-spacing: 1px;
                padding: 0 10px;
            """)
            tb.addWidget(self._case_label_tb)

        # â”€â”€ Central widget â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def _setup_central(self) -> None:
            outer = QWidget(self)
            outer.setStyleSheet(f"background-color: {P['bg_base']};")
            outer_layout = QVBoxLayout(outer)
            outer_layout.setContentsMargins(0, 0, 0, 0)
            outer_layout.setSpacing(0)

            self._top_bar = _TopBar(self)
            self._top_bar.set_case(Path(self._case_db).name)
            outer_layout.addWidget(self._top_bar)

            central = QWidget(self)
            central.setStyleSheet(f"background-color: {P['bg_base']};")
            h_layout = QHBoxLayout(central)
            h_layout.setContentsMargins(0, 0, 0, 0)
            h_layout.setSpacing(0)

            self._side = _SidePanel(self)
            self._side.session_selected.connect(self._on_session_selected)

            splitter = QSplitter(Qt.Horizontal)
            splitter.setHandleWidth(1)
            splitter.addWidget(self._side)

            self._tabs = QTabWidget(self)
            self._tabs.setTabPosition(QTabWidget.North)
            self._tabs.setDocumentMode(False)

            from interface.gui.dashboard     import DashboardView
            from interface.gui.timeline_view import TimelineView
            from interface.gui.findings_view import FindingsView

            self._dashboard = DashboardView(self._case_db, self)
            self._timeline  = TimelineView(self)
            self._findings  = FindingsView(self._case_db, self)
            self._current_session_id = None
            self._findings_data = []  # Full Finding objects for current session

            # Initialize main tabs; AI panel will be lazy-loaded
            self._tabs.addTab(self._dashboard, "▣  DASHBOARD")
            self._tabs.addTab(self._timeline,  "±  TIMELINE")
            self._tabs.addTab(self._findings,  "⚠  FINDINGS")
            # Lazy-load AI panel placeholder
            self._ai_panel = QWidget()
            self._ai_panel_loaded = False
            self._tabs.addTab(self._ai_panel, "◇  AI QUERY")

            # â”€â”€ New Feature Tabs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            try:
                from interface.gui.attack_graph_view import AttackGraphView
                self._attack_graph = AttackGraphView(self)
                self._tabs.addTab(self._attack_graph, "â¬¡  ATTACK GRAPH")
            except Exception:
                self._attack_graph = None

            try:
                from interface.gui.mitre_heatmap import MITREHeatmapPanel
                self._mitre_heatmap = MITREHeatmapPanel(self)
                self._tabs.addTab(self._mitre_heatmap, "âŠž  MITRE MAP")
            except Exception:
                self._mitre_heatmap = None

            try:
                from interface.gui.tools_panel import ToolsPanel
                self._tools_panel = ToolsPanel(
                    case_db_path=self._case_db, parent=self)
                self._tabs.addTab(self._tools_panel, "âš™  TOOLS")
            except Exception:
                self._tools_panel = None

            splitter.addWidget(self._tabs)
            splitter.setSizes([210, 1000])
            h_layout.addWidget(splitter)

            outer_layout.addWidget(central)
            self.setCentralWidget(outer)

        # â”€â”€ Status bar â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def _setup_cyber_shell(self) -> None:
            """Re-host the stable panels into the modern Cyber OS shell."""
            if getattr(self, "_legacy_toolbar", None):
                self._legacy_toolbar.setVisible(False)

            old_tabs = self._tabs
            old_side = self._side
            old_top_bar = self._top_bar
            old_tabs.setParent(None)
            old_side.setParent(None)
            old_top_bar.setParent(None)
            old_top_bar.setVisible(False)
            old_tabs.tabBar().hide()
            old_tabs.setDocumentMode(True)
            old_tabs.currentChanged.connect(self._on_workspace_changed)

            root = QWidget(self)
            root.setObjectName("CyberShellRoot")
            root.setStyleSheet(f"background-color: {P['bg_base']};")
            old_top_bar.setParent(root)
            root_layout = QHBoxLayout(root)
            root_layout.setContentsMargins(10, 10, 10, 10)
            root_layout.setSpacing(12)

            nav = QFrame(root)
            nav.setObjectName("CyberNavRail")
            nav.setFixedWidth(288)
            nav.setStyleSheet(f"""
                QFrame#CyberNavRail {{
                    background-color: {P['bg_void']};
                    border: 1px solid {P['border_dim']};
                    border-radius: 18px;
                }}
            """)
            nav_layout = QVBoxLayout(nav)
            nav_layout.setContentsMargins(16, 16, 16, 16)
            nav_layout.setSpacing(10)

            brand = QLabel("NEXLOG")
            brand.setStyleSheet(f"""
                color: {P['cyan']};
                background: transparent;
                border: none;
                font-family: {_MONO};
                font-size: 16px;
                font-weight: 800;
                letter-spacing: 2px;
            """)
            nav_layout.addWidget(brand)

            subtitle = QLabel("Cyber OS Desktop")
            subtitle.setStyleSheet(caption_style())
            nav_layout.addWidget(subtitle)

            self._nav_group = QButtonGroup(self)
            self._nav_group.setExclusive(True)
            self._nav_buttons = {}
            self._page_labels = []

            nav_specs = [
                ("DASHBOARD", "Command Center", "Summary, risk, and recent activity"),
                ("TIMELINE", "Incident Timeline", "Chronological event stream"),
                ("FINDINGS", "Findings", "Search, filter, and inspect detections"),
                ("AI QUERY", "AI Query", "Ask questions over the case"),
                ("ATTACK GRAPH", "Attack Graph", "Graph-first investigation map"),
                ("MITRE MAP", "MITRE Map", "ATT&CK heatmap"),
                ("TOOLS", "Tools", "Exports and advanced utilities"),
            ]
            for key, label, tip in nav_specs:
                if not self._tab_index_for(key, missing_ok=True) >= 0:
                    continue
                btn = QPushButton(label, nav)
                btn.setCheckable(True)
                btn.setToolTip(tip)
                btn.setStyleSheet(nav_button_style())
                btn.clicked.connect(lambda checked=False, k=key: self._switch_tab_matching(k))
                self._nav_group.addButton(btn)
                self._nav_buttons[key] = btn
                nav_layout.addWidget(btn)

            nav_layout.addSpacing(8)
            session_title = QLabel("Case Sessions")
            session_title.setStyleSheet(section_title_style())
            nav_layout.addWidget(session_title)
            nav_layout.addWidget(old_side, 1)
            root_layout.addWidget(nav)

            workspace = QWidget(root)
            workspace_layout = QVBoxLayout(workspace)
            workspace_layout.setContentsMargins(0, 0, 0, 0)
            workspace_layout.setSpacing(12)

            action_bar = QFrame(workspace)
            action_bar.setStyleSheet(card_style())
            action_layout = QHBoxLayout(action_bar)
            action_layout.setContentsMargins(18, 14, 18, 14)
            action_layout.setSpacing(10)

            title_col = QVBoxLayout()
            title_col.setContentsMargins(0, 0, 0, 0)
            title_col.setSpacing(2)
            self._workspace_title = QLabel("Command Center")
            self._workspace_title.setStyleSheet(section_title_style())
            self._workspace_subtitle = QLabel("Open a log file or select a case session to begin.")
            self._workspace_subtitle.setStyleSheet(caption_style())
            title_col.addWidget(self._workspace_title)
            title_col.addWidget(self._workspace_subtitle)
            action_layout.addLayout(title_col, 1)

            self._global_search = QLineEdit(workspace)
            self._global_search.setPlaceholderText("Search commands, views, exports...  Ctrl+K")
            self._global_search.setClearButtonEnabled(True)
            self._global_search.setFixedWidth(330)
            self._global_search.returnPressed.connect(self._open_command_palette)
            action_layout.addWidget(self._global_search)

            btn_open = QPushButton("Open Log")
            btn_open.setStyleSheet(primary_button_style())
            btn_open.clicked.connect(self._open_log_file)
            action_layout.addWidget(btn_open)

            btn_graph = QPushButton("Graph")
            btn_graph.setStyleSheet(ghost_button_style(P["cyan"]))
            btn_graph.clicked.connect(self._show_attack_graph_tab)
            action_layout.addWidget(btn_graph)

            self._case_label_tb = QLabel(f"CASE: {Path(self._case_db).name.upper()}", workspace)
            self._case_label_tb.setStyleSheet(caption_style())
            action_layout.addWidget(self._case_label_tb)

            workspace_layout.addWidget(action_bar)
            workspace_layout.addWidget(old_tabs, 1)
            root_layout.addWidget(workspace, 1)

            self.setCentralWidget(root)
            self._top_bar = old_top_bar
            self._sync_nav_to_page(old_tabs.currentIndex())

        def _ensure_ai_panel_loaded(self) -> None:
            if self._ai_panel_loaded:
                return

            try:
                idx = self._tab_index_for("AI QUERY", missing_ok=True)
                if idx >= 0:
                    from interface.gui.ai_panel import AIPanel
                    real_panel = AIPanel(case_db_path=self._case_db, parent=self)
                    
                    old_widget = self._ai_panel
                    
                    # Replace placeholder in tabs
                    self._tabs.removeTab(idx)
                    self._tabs.insertTab(idx, real_panel, "â—ˆ  AI QUERY")
                    
                    self._ai_panel = real_panel
                    self._ai_panel_loaded = True
                    
                    if old_widget:
                        old_widget.deleteLater()
                    
                    # Apply deferred or current session
                    sess_id = self._deferred_session_id or self._current_session_id
                    if sess_id:
                        self._ai_panel.set_session(sess_id)
                        self._deferred_session_id = None
            except Exception as e:
                import traceback as _tb
                print(f"[ForensicAmp] Failed to lazy-load AIPanel: {e}\n{_tb.format_exc()}", file=sys.stderr)

        def _tab_index_for(self, needle: str, missing_ok: bool = False) -> int:
            needle = needle.upper()
            for i in range(self._tabs.count()):
                if needle in self._tabs.tabText(i).upper():
                    return i
            if missing_ok:
                return -1
            return 0

        def _on_workspace_changed(self, index: int) -> None:
            tab_text = self._tabs.tabText(index) if index >= 0 else ""
            if "AI QUERY" in tab_text.upper():
                self._ensure_ai_panel_loaded()
            self._sync_nav_to_page(index)

        def _sync_nav_to_page(self, index: int) -> None:
            if not hasattr(self, "_workspace_title"):
                return
            tab_text = self._tabs.tabText(index) if index >= 0 else "Dashboard"
            normalized = tab_text.replace("â–£", "").replace("â±", "")
            normalized = normalized.replace("âš ", "").replace("â—ˆ", "")
            normalized = normalized.replace("â¬¡", "").replace("âŠž", "")
            normalized = normalized.replace("âš™", "").strip()
            titles = {
                "DASHBOARD": ("Command Center", "Case overview, risk, severity, and recent activity."),
                "TIMELINE": ("Incident Timeline", "Chronological investigation stream."),
                "FINDINGS": ("Findings", "Search, filter, inspect, and export detections."),
                "AI QUERY": ("AI Query", "Ask case-aware questions without loading heavy AI at startup."),
                "ATTACK GRAPH": ("Attack Graph", "Pivot through hosts, IPs, and lateral movement paths."),
                "MITRE MAP": ("MITRE Map", "ATT&CK tactic and technique coverage."),
                "TOOLS": ("Tools", "Reports, Sigma, UEBA, canaries, and export utilities."),
            }
            title, subtitle = titles.get(normalized.upper(), (normalized.title(), ""))
            self._workspace_title.setText(title)
            self._workspace_subtitle.setText(subtitle)

            for key, btn in getattr(self, "_nav_buttons", {}).items():
                btn.setChecked(key in tab_text.upper())

        def _setup_statusbar(self) -> None:
            sb = QStatusBar(self)
            sb.setStyleSheet(f"""
                QStatusBar {{
                    background-color: {P.get('bg_void', P['bg_base'])};
                    color: {P['text_secondary']};
                    border-top: 1px solid {P['border_mid']};
                    font-family: {_MONO};
                    font-size: 9px;
                }}
            """)
            self.setStatusBar(sb)

            self._status_label = QLabel("READY", self)
            self._status_label.setStyleSheet(f"""
                color: {P['text_secondary']};
                font-family: {_MONO};
                font-size: 9px;
                letter-spacing: 0.5px;
                padding: 0 8px;
            """)
            sb.addWidget(self._status_label)

            self._progress = QProgressBar(self)
            self._progress.setFixedWidth(200)
            self._progress.setFixedHeight(14)
            self._progress.setVisible(False)
            self._progress.setTextVisible(False)
            sb.addWidget(self._progress)

            self._progress_text = QLabel("", self)
            self._progress_text.setStyleSheet(f"""
                color: {P['cyan']};
                font-family: {_MONO};
                font-size: 8px;
                padding: 0 4px;
            """)
            self._progress_text.setVisible(False)
            sb.addWidget(self._progress_text)

            _sb_spacer = QWidget()
            _sb_spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
            sb.addPermanentWidget(_sb_spacer)

            self._threat_badge = _ThreatBadge(self)
            sb.addPermanentWidget(self._threat_badge)

            sep = QLabel("|", self)
            sep.setStyleSheet(f"color: {P['border_mid']}; padding: 0 4px;")
            sb.addPermanentWidget(sep)

            self._finding_label = QLabel("  0 FINDINGS  ", self)
            self._finding_label.setStyleSheet(f"""
                color: {P['text_secondary']};
                font-family: {_MONO};
                font-size: 9px;
                letter-spacing: 1px;
                padding: 0 8px;
            """)
            sb.addPermanentWidget(self._finding_label)

        # â”€â”€ Session management â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        # Command palette -------------------------------------------------

        def _setup_shortcuts(self) -> None:
            self._shortcut_palette = QShortcut(QKeySequence("Ctrl+K"), self)
            self._shortcut_palette.setContext(Qt.ApplicationShortcut)
            self._shortcut_palette.activated.connect(self._open_command_palette)

            self._shortcut_graph = QShortcut(QKeySequence("Ctrl+G"), self)
            self._shortcut_graph.setContext(Qt.ApplicationShortcut)
            self._shortcut_graph.activated.connect(self._show_attack_graph_tab)

            self._shortcut_search = QShortcut(QKeySequence("/"), self)
            self._shortcut_search.setContext(Qt.ApplicationShortcut)
            self._shortcut_search.activated.connect(self._focus_global_search)

        def _command_definitions(self) -> list[tuple[str, str, object]]:
            return [
                ("open_log", "Open log file", self._open_log_file),
                ("new_case", "New case database", self._new_case),
                ("open_case", "Open case database", self._open_case),
                ("severity", "Set minimum severity", self._set_severity),
                ("dashboard", "Go to dashboard", lambda: self._switch_tab_matching("DASHBOARD")),
                ("timeline", "Go to timeline", lambda: self._switch_tab_matching("TIMELINE")),
                ("findings", "Go to findings", lambda: self._switch_tab_matching("FINDINGS")),
                ("ai", "Go to AI query", lambda: self._switch_tab_matching("AI QUERY")),
                ("graph", "Go to attack graph", self._show_attack_graph_tab),
                ("mitre", "Go to MITRE map", lambda: self._switch_tab_matching("MITRE MAP")),
                ("tools", "Go to tools", lambda: self._switch_tab_matching("TOOLS")),
                ("pdf", "Export PDF report", lambda: self._export_report("pdf")),
                ("stix", "Export STIX bundle", self._export_stix),
                ("ioc", "Export IOC CSV", lambda: self._export_iocs("csv")),
                ("sigma", "Export Sigma rules", self._export_sigma),
                ("ai_report", "Generate AI report", self._generate_ai_report),
            ]

        def _focus_global_search(self) -> None:
            if getattr(self, "_global_search", None):
                self._global_search.setFocus(Qt.ShortcutFocusReason)
                self._global_search.selectAll()

        def _switch_tab_matching(self, needle: str) -> None:
            needle = needle.upper()
            if "AI QUERY" in needle:
                self._ensure_ai_panel_loaded()
            for i in range(self._tabs.count()):
                if needle in self._tabs.tabText(i).upper():
                    self._tabs.setCurrentIndex(i)
                    return

        def _open_command_palette(self) -> None:
            dialog = QDialog(self)
            dialog.setObjectName("CommandPalette")
            dialog.setWindowTitle("Command Palette")
            dialog.setModal(True)
            dialog.resize(560, 430)

            layout = QVBoxLayout(dialog)
            layout.setContentsMargins(18, 18, 18, 18)
            layout.setSpacing(12)

            title = QLabel("Command Palette")
            title.setStyleSheet(
                f"color: {P['text_primary']}; font-size: 18px; "
                "font-weight: 700; background: transparent;"
            )
            subtitle = QLabel("Type a command. Press Enter to run. Esc closes.")
            subtitle.setStyleSheet(
                f"color: {P['text_secondary']}; background: transparent;"
            )
            search = QLineEdit(dialog)
            search.setObjectName("CommandSearch")
            search.setPlaceholderText("Search actions, views, exports...")

            results = QListWidget(dialog)
            results.setObjectName("CommandList")

            layout.addWidget(title)
            layout.addWidget(subtitle)
            layout.addWidget(search)
            layout.addWidget(results, 1)

            commands = self._command_definitions()
            command_map = {cid: action for cid, _label, action in commands}

            def populate(query: str = "") -> None:
                results.clear()
                terms = query.strip().lower().split()
                for cid, label, _action in commands:
                    haystack = f"{label} {cid}".lower()
                    if terms and not all(term in haystack for term in terms):
                        continue
                    item = QListWidgetItem(label)
                    item.setData(Qt.UserRole, cid)
                    results.addItem(item)
                if results.count():
                    results.setCurrentRow(0)

            def run_current() -> None:
                item = results.currentItem()
                if not item:
                    return
                action = command_map.get(item.data(Qt.UserRole))
                dialog.accept()
                if action:
                    action()

            search.textChanged.connect(populate)
            search.returnPressed.connect(run_current)
            results.itemActivated.connect(lambda _item: run_current())
            populate()
            search.setFocus(Qt.OtherFocusReason)
            dialog.exec()

        def _load_sessions(self) -> None:
            try:
                from storage.case_db import CaseDB
                with CaseDB(self._case_db) as db:
                    for sess in db.list_sessions():
                        sid  = sess["session_id"]
                        name = Path(sess.get("source_file", "?")).name
                        ts   = sess.get("created_at", "")[:10]
                        summ = db.get_findings_summary(session_id=sid)
                        sev  = max(
                            summ.get("by_severity", {}).items(),
                            key=lambda x: _SEV_RANK.get(x[0], 0),
                            default=("INFO", 0)
                        )[0]
                        self._side.add_session(
                            sid, f"{name}  ({ts})",
                            summ.get("total", 0), sev)
            except Exception as e:
                import traceback as _tb
                print(f"[ForensicAmp] _load_sessions: {e}\n{_tb.format_exc()}",
                      file=sys.stderr)

        def _on_session_selected(self, session_id: str) -> None:
            self._current_session_id = session_id
            self.session_changed.emit(session_id)
            self._dashboard.load_session(session_id)
            self._timeline.load_session(session_id, self._case_db)
            self._findings.load_session(session_id)
            try:
                from storage.case_db import CaseDB
                with CaseDB(self._case_db) as _db:
                    self._findings_data = _db.get_findings(session_id=session_id, limit=2000)
                
                if getattr(self, "_attack_graph", None):
                    self._attack_graph.load_findings(self._findings_data)
                if getattr(self, "_mitre_heatmap", None):
                    self._mitre_heatmap.load_findings(self._findings_data)
                if getattr(self, "_tools_panel", None):
                    self._tools_panel.set_context(
                        self._case_db, session_id, self._findings_data)
            except Exception:
                self._findings_data = []
            if self._ai_panel_loaded and self._ai_panel:
                self._ai_panel.set_session(session_id)
            else:
                self._deferred_session_id = session_id
            # Propagate to new panels
            self._refresh_new_panels(session_id)
            self._tabs.setCurrentIndex(0)

        def _refresh_new_panels(self, session_id: str) -> None:
            """Load findings into Attack Graph, Tools Panel, etc."""
            try:
                from storage.case_db import CaseDB
                with CaseDB(self._case_db) as db:
                    self._findings_data = db.get_findings(session_id=session_id, limit=2000)
                if self._attack_graph:
                    self._attack_graph.load_findings(self._findings_data)
                if self._tools_panel:
                    self._tools_panel.set_context(
                        self._case_db, session_id, self._findings_data)
            except Exception:
                pass

        # â”€â”€ Analysis â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def _open_log_file(self) -> None:
            path, _ = QFileDialog.getOpenFileName(
                self, "Open Log File", "",
                "Log Files (*.log *.txt *.json *.jsonl *.evtx *.csv);;"
                "All Files (*.*)"
            )
            if path:
                self._start_analysis(path)

        def _start_analysis(self, log_path: str) -> None:
            if self._worker and self._worker.isRunning():
                QMessageBox.warning(self, "Busy",
                    "Analysis already in progress.")
                return

            self._finding_count = 0
            # FIX: reset threat badge before the new analysis begins.
            # Without this, the badge kept showing the previous run's highest
            # severity level until the first finding of the new run arrived.
            self._threat_badge.reset()

            self._progress.setVisible(True)
            self._progress_text.setVisible(True)
            self._progress.setValue(0)
            fname = Path(log_path).name
            self._status_label.setText(f"ANALYSING: {fname}")

            self._worker = _AnalysisWorker(
                log_path  = log_path,
                case_path = self._case_db,
                analyst   = "analyst",
            )
            self._worker.progress.connect(self._on_progress)
            self._worker.finding_found.connect(self._on_finding_found)
            self._worker.finished.connect(self._on_analysis_done)
            self._worker.error.connect(self._on_analysis_error)
            self._worker.start()

        @Slot(int, str)
        def _on_progress(self, pct: int, msg: str) -> None:
            self._progress.setValue(pct)
            self._progress_text.setText(msg)
            self._status_label.setText(msg.upper())

        @Slot(dict)
        def _on_finding_found(self, f: dict) -> None:
            self._finding_count += 1
            self._finding_label.setText(
                f"  {self._finding_count:,} FINDINGS  ")
            # FIX: use public current_level() instead of accessing _level
            sev     = f.get("severity", "")
            current = self._threat_badge.current_level()
            if _SEV_RANK.get(sev, 0) > _SEV_RANK.get(current, -1):
                self._threat_badge.set_level(sev)

        @Slot(dict)
        def _on_analysis_done(self, result: dict) -> None:
            self._progress.setVisible(False)
            self._progress_text.setVisible(False)
            sid    = result.get("session_id", "")
            self._current_session_id = sid
            n      = len(result.get("findings", []))
            chains = len(result.get("chains",   []))
            msg    = f"COMPLETE â€” {n:,} FINDINGS  |  {chains} CHAINS"
            self._status_label.setText(msg)
            self._finding_label.setText(f"  {n:,} FINDINGS  ")
            self.analysis_complete.emit(result)

            self._side.clear_sessions()
            self._load_sessions()

            if sid:
                self._dashboard.load_session(sid)
                self._timeline.load_session(sid, self._case_db)
                self._findings.load_session(sid)
                self._refresh_new_panels(sid)
                self._tabs.setCurrentIndex(0)

            QMessageBox.information(
                self, "Analysis Complete",
                f"{n:,} findings detected\n{chains} attack chain(s) identified")

        @Slot(str)
        def _on_analysis_error(self, err: str) -> None:
            self._progress.setVisible(False)
            self._progress_text.setVisible(False)
            self._status_label.setText("ERROR â€” ANALYSIS FAILED")
            QMessageBox.critical(self, "Analysis Error",
                f"Analysis failed:\n\n{err[:500]}")

        # â”€â”€ Exports â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def _export_report(self, fmt: str) -> None:
            ext_map = {"pdf": "pdf", "markdown": "md",
                       "json": "json", "text": "txt"}
            ext     = ext_map.get(fmt, "txt")

            from datetime import datetime
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Determine prefix based on current session if available
            prefix = "forensic_report"
            if self._current_session_id:
                try:
                    from storage.case_db import CaseDB
                    with CaseDB(self._case_db) as db:
                        sess = db.get_session(self._current_session_id)
                        if sess and sess.get("source_file"):
                            prefix = Path(sess["source_file"]).stem
                except Exception:
                    pass
            
            default_fn = f"{prefix}_{ts}.{ext}"
            
            # Use File Dialog for saving
            path, _ = QFileDialog.getSaveFileName(
                self, f"Export {fmt.upper()} Report", default_fn,
                f"{fmt.upper()} Files (*.{ext})")
            
            if not path:
                return

            try:
                from storage.case_db import CaseDB
                with CaseDB(self._case_db) as db:
                    if fmt == "pdf":
                        from output.pdf_report import PDFReport
                        from ioc_extractor import IOCExtractor
                        # Build specific to current session if selected
                        sid = self._current_session_id
                        findings = self._findings_data or db.get_findings(session_id=sid, limit=5000)
                        iocs = IOCExtractor().extract(findings)
                        
                        report = PDFReport(
                            db=db, 
                            session_id=sid, 
                            findings=findings,
                            iocs=iocs,
                            case_ref=f"CASE-{prefix.upper()}"
                        )
                        report.build(path)
                    else:
                        from output.report_builder import ReportBuilder
                        sid = self._current_session_id
                        builder = ReportBuilder(db, session_id=sid)
                        content = {
                            "json":     builder.to_json,
                            "markdown": builder.to_markdown,
                            "text":     builder.to_text,
                        }[fmt]()
                        Path(path).write_text(content, encoding="utf-8")
                QMessageBox.information(
                    self, "Exported", f"Report saved to:\n{path}")
            except Exception as e:
                import traceback
                print(f"[Export] Error: {e}\n{traceback.format_exc()}")
                QMessageBox.critical(self, "Export Error", str(e))

        def _export_stix(self) -> None:
            from datetime import datetime
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_fn = f"forensic_stix_{ts}.json"

            # AUTOMATED: Save to workspace output/ directory
            out_dir = Path(_ROOT) / "output"
            out_dir.mkdir(parents=True, exist_ok=True)
            path = str(out_dir / default_fn)
            try:
                from storage.case_db import CaseDB
                from ioc_extractor import IOCExtractor
                from output.stix_export import STIXExport
                with CaseDB(self._case_db) as db:
                    findings = db.get_findings(limit=5000)
                iocs = IOCExtractor().extract(findings)
                sx   = STIXExport(findings=findings, iocs=iocs,
                                  case_ref="IR-EXPORT")
                sx.write(path)
                summ = sx.summary()
                QMessageBox.information(
                    self, "STIX Exported",
                    f"Bundle written to:\n{path}\n\n"
                    f"Objects: {summ['bundle_objects']}  "
                    f"Indicators: {summ['indicators']}")
            except Exception as e:
                QMessageBox.critical(self, "STIX Export Error", str(e))

        def _export_sigma(self) -> None:
            """Export all findings as Sigma YAML rules."""
            try:
                from storage.case_db import CaseDB
                from detection.sigma_exporter import SigmaExporter
                from PySide6.QtWidgets import QFileDialog
                from datetime import datetime
                directory = QFileDialog.getExistingDirectory(
                    self, "Select output directory for Sigma rules")
                if not directory:
                    return
                with CaseDB(self._case_db) as db:
                    findings = db.get_findings(limit=2000)
                paths = SigmaExporter().export_bundle(findings, directory)
                QMessageBox.information(
                    self, "Sigma Export",
                    f"Exported {len(paths)} Sigma rules to:\n{directory}")
            except Exception as e:
                QMessageBox.critical(self, "Sigma Export Error", str(e))

        def _generate_ai_report(self) -> None:
            """Switch to Tools tab and trigger AI Report generation."""
            if self._tools_panel:
                # Find the Tools tab index
                for i in range(self._tabs.count()):
                    if "TOOLS" in self._tabs.tabText(i).upper():
                        self._tabs.setCurrentIndex(i)
                        break
            else:
                QMessageBox.information(
                    self, "AI Report",
                    "Tools panel not available. Check PySide6 installation.")


        def _export_iocs(self, fmt: str) -> None:
            if fmt == "all":
                directory = QFileDialog.getExistingDirectory(
                    self, "Select Export Directory")
                if not directory:
                    return
                try:
                    from storage.case_db import CaseDB
                    from ioc_extractor import IOCExtractor
                    from output.ioc_csv import IOCExporter
                    with CaseDB(self._case_db) as db:
                        findings = db.get_findings(limit=5000)
                    iocs  = IOCExtractor().extract(findings)
                    paths = IOCExporter(iocs, case_ref="IR-EXPORT") \
                                .write_all(directory)
                    QMessageBox.information(
                        self, "IOC Export Complete",
                        f"Written {len(paths)} files to:\n{directory}")
                except Exception as e:
                    QMessageBox.critical(self, "IOC Export Error", str(e))
            else:
                from datetime import datetime
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                default_fn = f"forensic_iocs_{ts}.csv"

                # AUTOMATED: Save to workspace output/ directory
                out_dir = Path(_ROOT) / "output"
                out_dir.mkdir(parents=True, exist_ok=True)
                path = str(out_dir / default_fn)
                try:
                    from storage.case_db import CaseDB
                    from ioc_extractor import IOCExtractor
                    from output.ioc_csv import IOCExporter
                    with CaseDB(self._case_db) as db:
                        findings = db.get_findings(limit=5000)
                    iocs = IOCExtractor().extract(findings)
                    IOCExporter(iocs, case_ref="IR-EXPORT").write_csv(path)
                    QMessageBox.information(
                        self, "Exported", f"IOC CSV saved to:\n{path}")
                except Exception as e:
                    QMessageBox.critical(self, "Export Error", str(e))

        # â”€â”€ Dialogs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def _new_case(self) -> None:
            from datetime import datetime
            ts = datetime.now().strftime("%Y%m%d")
            default_fn = f"case_{ts}.facase"

            path, _ = QFileDialog.getSaveFileName(
                self, "New Case Database", default_fn,
                "NexLog Case (*.facase)")
            if path:
                self._case_db = path
                name = Path(path).name
                self._top_bar.set_case(name)
                self._case_label_tb.setText(f"CASE: {name.upper()}")
                self._side.clear_sessions()

        def _open_case(self) -> None:
            path, _ = QFileDialog.getOpenFileName(
                self, "Open Case Database", "",
                "NexLog Case (*.facase)")
            if path:
                self._case_db = path
                name = Path(path).name
                self._top_bar.set_case(name)
                self._case_label_tb.setText(f"CASE: {name.upper()}")
                self._side.clear_sessions()
                self._load_sessions()

        def _set_severity(self) -> None:
            sev, ok = QInputDialog.getItem(
                self, "Minimum Severity",
                "Filter findings at or above:",
                ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                1, False)
            if ok:
                self._min_severity = sev
                self._status_label.setText(f"MIN SEVERITY: {sev}")

        # â”€â”€ New tool actions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def _run_ai_report(self) -> None:
            """Switch to Tools tab and trigger AI report generation."""
            if getattr(self, "_tools_panel", None):
                # Find the tools tab index
                for i in range(self._tabs.count()):
                    if "TOOLS" in self._tabs.tabText(i):
                        self._tabs.setCurrentIndex(i)
                        break
            else:
                QMessageBox.information(self, "AI Report",
                    "Install the AI layer first: pip install sentence-transformers\n"
                    "Then set GROQ_API_KEY or OLLAMA_HOST for LLM access.")

        def _export_sigma(self) -> None:
            """Export all session findings as Sigma rules."""
            try:
                from storage.case_db import CaseDB
                from detection.sigma_exporter import SigmaExporter
                from PySide6.QtWidgets import QFileDialog
                with CaseDB(self._case_db) as db:
                    findings = db.get_findings(limit=2000)
                if not findings:
                    QMessageBox.warning(self, "Sigma Export", "No findings to export.")
                    return
                directory = QFileDialog.getExistingDirectory(
                    self, "Select output directory for Sigma rules")
                if directory:
                    paths = SigmaExporter().export_bundle(findings, directory)
                    QMessageBox.information(self, "Sigma Export",
                        f"Exported {len(paths)} Sigma rules to:\n{directory}")
            except Exception as e:
                QMessageBox.critical(self, "Sigma Export Error", str(e))

        def _run_ueba_quick(self) -> None:
            """Quick UEBA score dialog."""
            try:
                from storage.case_db import CaseDB
                from detection.ueba import UEBAEngine
                with CaseDB(self._case_db) as db:
                    findings = db.get_findings(limit=2000)
                if not findings:
                    QMessageBox.warning(self, "UEBA", "No findings in current case.")
                    return
                engine    = UEBAEngine(threshold=4.0)
                results   = engine.score_findings(findings)
                anomalies = engine.get_anomalies()
                if not anomalies:
                    QMessageBox.information(self, "UEBA Result",
                        "No behavioral anomalies detected above threshold.")
                    return
                lines = ["Anomaly score >= 4.0:\n"]
                for a in anomalies[:10]:
                    lines.append(f"  {a['entity']}: {a['score']:.1f}/10 â€” {a['label']}")
                    for flag in a.get("flags", [])[:2]:
                        lines.append(f"    â€¢ {flag}")
                QMessageBox.warning(self, "UEBA â€” Anomalies Detected",
                    "\n".join(lines))
            except Exception as e:
                QMessageBox.critical(self, "UEBA Error", str(e))

        def _open_canary_tab(self) -> None:
            """Switch to Tools â†’ Canary tab."""
            for i in range(self._tabs.count()):
                if "TOOLS" in self._tabs.tabText(i):
                    self._tabs.setCurrentIndex(i)
                    if getattr(self, "_tools_panel", None):
                        self._tools_panel._tabs.setCurrentIndex(2)  # Canary tab
                    break

        def _show_attack_graph_tab(self) -> None:
            """Switch to Attack Graph tab."""
            for i in range(self._tabs.count()):
                if "ATTACK GRAPH" in self._tabs.tabText(i):
                    self._tabs.setCurrentIndex(i)
                    break

        def _show_about(self) -> None:
            QMessageBox.about(
                self, "About NexLog v2",
                "<b style='color:#00C8FF'>NexLog v2</b><br>"
                "Deep Space Command Center<br><br>"
                "162 detection rules Â· 19 ATT&CK categories<br>"
                "Layer 1: Parse Â· Layer 2: Detect<br>"
                "Layer 3: Store Â· Layer 4: Report<br>"
                "Layer 5: GUI + API<br><br>"
                "<small>B.E. Computer Engineering Portfolio Project</small>")

        # â”€â”€ Glass refresh â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def _refresh_all_glass(self) -> None:
            """
            Iterate through all GlassPanel children and trigger a re-capture.
            Redundant for auto-refreshing children, but essential for layout-driven position shifts.
            """
            if not _HAS_PYSIDE6 or not self._glass_refresh_enabled:
                return
            try:
                from interface.gui.glass_widget import GlassPanel
            except ImportError:
                return

            for child in self.findChildren(GlassPanel):
                if hasattr(child, "refresh_glass"):
                    child.refresh_glass()

        def _schedule_glass_refresh(self, delay_ms: int = 180) -> None:
            """Debounce expensive glass captures; disabled by default for speed."""
            if not self._glass_refresh_enabled:
                return
            self._glass_refresh_timer.start(delay_ms)

        def resizeEvent(self, event) -> None:
            """Debounced global glass refresh on window resize."""
            super().resizeEvent(event)
            self._schedule_glass_refresh(180)

        # â”€â”€ Lifecycle â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def closeEvent(self, event) -> None:
            if self._worker and self._worker.isRunning():
                self._worker.terminate()
                self._worker.wait(2000)
            self._settings.setValue("geometry", self.saveGeometry())
            super().closeEvent(event)


# â”€â”€ No-op stubs when PySide6 is absent â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

if not _HAS_PYSIDE6:
    class _AnalysisWorker:
        def __init__(self, *a, **kw): pass
        def start(self): pass
        def isRunning(self): return False
        def terminate(self): pass
        def wait(self, *a): pass

    class _SidePanel:
        def __init__(self, *a, **kw): pass
        def add_session(self, *a, **kw): pass
        def clear_sessions(self): pass

    class MainWindow:
        def __init__(self, *a, **kw): pass
        def show(self): pass
        def close(self): pass


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# LAUNCH
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def launch(case_db_path: str = "nexlog.facase") -> None:
    """Launch the legacy NexLog Widgets GUI."""
    if not _HAS_PYSIDE6:
        print("PySide6 is not installed. Run: pip install PySide6")
        sys.exit(1)

    try:
        QApplication.setHighDpiScaleFactorRoundingPolicy(
            Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    except AttributeError:
        pass

    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName("NexLog")
    app.setApplicationDisplayName("NexLog")
    app.setApplicationVersion("1.0.0")
    icon_path = Path(_ROOT) / "interface" / "gui" / "assets" / "nexlog-icon.png"
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))

    window = MainWindow(case_db_path=case_db_path)
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", default="nexlog.facase")
    args = parser.parse_args()

    from pathconfig import WORKSPACE_DIR
    case_path = Path(args.case)
    if case_path.parent == Path(""):
        case_path = Path(WORKSPACE_DIR) / case_path

    launch(str(case_path))
