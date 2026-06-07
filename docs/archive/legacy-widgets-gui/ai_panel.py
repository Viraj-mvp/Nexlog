"""
interface/gui/ai_panel.py â€” NexLog v2  [Deep Space Command Center]
=========================================================================
AI query panel â€” natural language questions over indexed findings.

Visual Design:
  â€¢ Chat bubbles: user right (neon cyan tint), AI left (deep space card)
  â€¢ Source citations: left-border severity neon, monospace type labels
  â€¢ Engine badge: status indicator with tier colour coding
  â€¢ Suggested questions: tactical pill buttons
  â€¢ Input: terminal-style with neon focus glow + [ SEND âš¡ ] button
  â€¢ All monospace (JetBrains Mono throughout)

Fixes v2.1:
  â€¢ CRITICAL: _StatusBar.update() â†’ renamed to _StatusBar.set_status().
    The original name 'update' shadows QWidget.update() (Qt's repaint
    scheduler). Every call self._status_bar.update({...}) was passing a dict
    into Qt's C++ repaint system instead of the custom method, causing silent
    failures or crashes depending on Qt version.  All callers updated.

  â€¢ _IndexWorker.run: sys.path mutation moved OUT of the thread.
    Modifying sys.path from a QThread is not thread-safe â€” CPython's import
    lock and the GIL do not fully protect concurrent sys.path writes.
    The storage subpackage path is now added at module load time.

  â€¢ _QueryWorker.run: self._engine.llm.tier attribute chain guarded with
    getattr to prevent AttributeError if engine.llm is None or tier is absent.

  â€¢ Removed duplicated path-walk block â€” single clean setup at module top.
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

# FIX: add all subpackage paths at module load time (not inside a thread)
for _pkg in ["ai", "detection", "storage"]:
    _p2 = os.path.join(_ROOT, _pkg)
    if _p2 not in sys.path:
        sys.path.insert(0, _p2)

try:
    from PySide6.QtCore import Qt, QThread, Signal, Slot, QSize
    from PySide6.QtGui import QColor, QFont, QTextCharFormat, QTextCursor
    from PySide6.QtWidgets import (
        QApplication, QFrame, QGroupBox, QHBoxLayout,
        QLabel, QPushButton, QScrollArea, QSizePolicy,
        QSplitter, QTextEdit, QVBoxLayout, QWidget,
        QLineEdit,
    )
    _HAS_PYSIDE6 = True
except ImportError:
    _HAS_PYSIDE6 = False

# â”€â”€ Theme â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
try:
    from interface.gui.theme import PALETTE as P, sev_fg, FONT_MONO_CSS, SEV_RANK
except ImportError:
    try:
        from theme import PALETTE as P, sev_fg, FONT_MONO_CSS, SEV_RANK
    except ImportError:
        P = {
            "bg_base": "#080C14", "bg_surface": "#0D1420",
            "bg_raised": "#111C2E", "bg_void": "#04080F",
            "bg_hover": "#162238", "bg_input": "#0A1628",
            "border_dim": "#1A2A3F", "border_mid": "#1E3A5A",
            "cyan": "#00C8FF", "cyan_dim": "#007A9C",
            "green": "#00FF9D", "green_dim": "#009960",
            "amber": "#FFB700", "purple": "#B060FF",
            "critical": "#FF3B5C", "high": "#FF6B35",
            "medium": "#FFB700", "low": "#00FF9D", "info": "#4A8FA8",
            "text_primary": "#C8DFF0", "text_secondary": "#5A8FA8",
            "text_mono": "#8ECFAA", "text_dim": "#2A4A5E",
        }
        def sev_fg(s): return P.get(s.lower(), P["text_primary"])

_SEV_C = {
    "CRITICAL": P["critical"], "HIGH": P["high"],
    "MEDIUM":   P["medium"],   "LOW":  P["low"], "INFO": P["info"],
}
_MONO = FONT_MONO_CSS  # from theme

_SUGGESTED = [
    "What IP addresses are attacking us?",
    "What MITRE ATT&CK techniques were used?",
    "Which hosts are most affected?",
    "Summarise the most critical findings",
    "Are there any signs of persistence?",
    "What evidence of credential theft is there?",
    "What is the highest risk finding?",
    "Which findings suggest lateral movement?",
]


if _HAS_PYSIDE6:

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # WORKER THREADS
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    class _QueryWorker(QThread):
        result   = Signal(dict)
        error    = Signal(str)
        progress = Signal(str)

        def __init__(self, engine, question: str,
                     session_id: Optional[str] = None):
            super().__init__()
            self._engine     = engine
            self._question   = question
            self._session_id = session_id

        def run(self):
            try:
                self.progress.emit("Retrieving relevant findingsâ€¦")
                answer = self._engine.ask(
                    self._question, session_id=self._session_id)
                r = answer.to_dict()
                # FIX: guard the attribute chain â€” engine.llm may be None
                # or may not have a 'tier' attribute in all implementations.
                llm  = getattr(self._engine, "llm", None)
                tier = getattr(llm, "tier", 0) if llm else 0
                r["llm_tier_number"] = tier
                self.result.emit(r)
            except Exception as e:
                self.error.emit(str(e))


    class _IndexWorker(QThread):
        done     = Signal(int)
        error    = Signal(str)
        progress = Signal(int, str)

        def __init__(self, engine, db_path: str,
                     session_id: Optional[str] = None):
            super().__init__()
            self._engine     = engine
            self._db_path    = db_path
            self._session_id = session_id

        def run(self):
            # FIX: sys.path is NOT modified here â€” it was already set at
            # module load time. Mutating sys.path from inside a QThread
            # is not thread-safe and caused intermittent import errors.
            try:
                from case_db import CaseDB
                self.progress.emit(20, "Loading findings from databaseâ€¦")
                with CaseDB(self._db_path) as db:
                    n = self._engine.ensure_indexed(
                        db, session_id=self._session_id,
                        on_progress=lambda p, m: self.progress.emit(p, m),
                    )
                self.done.emit(n)
            except Exception as e:
                self.error.emit(str(e))


    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # ENGINE STATUS BADGE
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    class _StatusBar(QWidget):
        """
        Engine status badge row:
          â— ENGINE: Ollama / Anthropic / Template   INDEXED: N

        FIX v2.1: renamed update() â†’ set_status().
        The original method was named 'update', which shadows QWidget.update()
        â€” Qt's C++ repaint scheduler. Every call to
        self._status_bar.update({...}) was passing a dict into Qt's repaint
        system instead of executing the custom logic. Renamed to set_status()
        and all callers updated accordingly.
        """
        def __init__(self, parent=None):
            super().__init__(parent)
            self.setFixedHeight(26)
            self.setStyleSheet(f"""
                background-color: {P.get('bg_void', P['bg_base'])};
                border-bottom: 1px solid {P['border_dim']};
            """)
            layout = QHBoxLayout(self)
            layout.setContentsMargins(10, 0, 10, 0)
            layout.setSpacing(12)

            self._engine_lbl = QLabel("â— ENGINE: --", self)
            self._engine_lbl.setStyleSheet(f"""
                color: {P['text_dim']};
                font-family: {_MONO};
                font-size: 8px;
                letter-spacing: 1px;
                background: transparent;
            """)
            layout.addWidget(self._engine_lbl)

            self._indexed_lbl = QLabel("INDEXED: --", self)
            self._indexed_lbl.setStyleSheet(f"""
                color: {P['text_dim']};
                font-family: {_MONO};
                font-size: 8px;
                letter-spacing: 1px;
                background: transparent;
            """)
            layout.addWidget(self._indexed_lbl)

            layout.addStretch()

        def set_status(self, status: dict) -> None:
            """Update the engine badge. Renamed from 'update' to avoid
            shadowing QWidget.update() (Qt's repaint scheduler)."""
            tier  = status.get("llm_tier", "unknown")
            n     = status.get("n_indexed", 0)
            tier_cols = {
                "anthropic": P["cyan"],
                "ollama":    P["green"],
                "template":  P["amber"],
            }
            col = tier_cols.get(tier.lower(), P["text_secondary"])
            self._engine_lbl.setText(f"â— ENGINE: {tier.upper()}")
            self._engine_lbl.setStyleSheet(f"""
                color: {col};
                font-family: {_MONO};
                font-size: 8px;
                letter-spacing: 1px;
                background: transparent;
            """)
            self._indexed_lbl.setText(f"INDEXED: {n:,}")
            self._indexed_lbl.setStyleSheet(f"""
                color: {P['text_secondary']};
                font-family: {_MONO};
                font-size: 8px;
                letter-spacing: 1px;
                background: transparent;
            """)


    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # SOURCE CITATION CARD
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    class _SourceWidget(QFrame):
        """One source citation card with neon severity left border."""
        def __init__(self, source: dict, parent=None):
            super().__init__(parent)
            col = _SEV_C.get(source.get("severity", ""), P["text_dim"])
            self.setStyleSheet(f"""
                QFrame {{
                    background: {P['bg_raised']};
                    border: 1px solid {P['border_dim']};
                    border-left: 3px solid {col};
                    border-radius: 3px;
                }}
            """)
            layout = QHBoxLayout(self)
            layout.setContentsMargins(8, 4, 8, 4)
            layout.setSpacing(8)

            rule_lbl = QLabel(source.get("rule_id", ""), self)
            rule_lbl.setStyleSheet(f"""
                color: {P['cyan']};
                font-family: {_MONO};
                font-size: 9px;
                font-weight: bold;
                background: transparent;
            """)
            layout.addWidget(rule_lbl)

            name_lbl = QLabel(source.get("rule_name", "")[:30], self)
            name_lbl.setStyleSheet(f"""
                color: {P['text_secondary']};
                font-family: {_MONO};
                font-size: 9px;
                background: transparent;
            """)
            layout.addWidget(name_lbl)

            ip_lbl = QLabel(source.get("source_ip", "")[:18], self)
            ip_lbl.setStyleSheet(f"""
                color: {P['text_primary']};
                font-family: {_MONO};
                font-size: 9px;
                background: transparent;
            """)
            layout.addWidget(ip_lbl)

            layout.addStretch()

            sev_lbl = QLabel(source.get("severity", ""), self)
            sev_lbl.setStyleSheet(f"""
                color: {col};
                font-family: {_MONO};
                font-size: 9px;
                font-weight: bold;
                background: transparent;
            """)
            layout.addWidget(sev_lbl)

            score = source.get("score", 0.0)
            score_lbl = QLabel(f"{score * 100:.0f}%", self)
            score_lbl.setStyleSheet(f"""
                color: {P['text_dim']};
                font-family: {_MONO};
                font-size: 9px;
                background: transparent;
            """)
            layout.addWidget(score_lbl)


    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # MESSAGE BUBBLE
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    try:
        from interface.gui.glass_widget import GlassPanel as _MsgBase, GlassPreset as _MsgPreset
        _GLASS_MSG_OK = True
    except ImportError:
        try:
            from glass_widget import GlassPanel as _MsgBase, GlassPreset as _MsgPreset
            _GLASS_MSG_OK = True
        except ImportError:
            _MsgBase    = QFrame       # type: ignore
            _GLASS_MSG_OK = False
            class _MsgPreset:          # type: ignore
                AI = INFO = MEDIUM = {}

    class _MessageWidget(_MsgBase):
        """
        Chat message bubble â€” user (right, INFO glass) or AI (left, AI glass).
        """
        _ROLE_STYLE = {
            "user":      ("YOU",         P["cyan"],   "INFO"),
            "assistant": ("FORENSIC-AI", "#9D5BDE",   "AI"),
        }

        def __init__(self, role: str, text: str,
                     sources: list = None,
                     meta:    dict = None,
                     parent=None):
            role_key = role if role in ("user", "assistant") else "assistant"
            label_text, accent_hex, preset_name = self._ROLE_STYLE.get(
                role_key, ("SYSTEM", P["amber"], "MEDIUM")
            )
            preset_map = {
                "INFO":   _MsgPreset.INFO,
                "AI":     _MsgPreset.AI,
                "MEDIUM": _MsgPreset.MEDIUM,
            }
            chosen_preset = preset_map.get(preset_name, {})

            if _GLASS_MSG_OK and chosen_preset:
                super().__init__(parent, preset=chosen_preset)
            else:
                super().__init__(parent)
                is_user    = role == "user"
                bg_col     = "rgba(0,200,255,0.08)" if is_user else P["bg_raised"]
                border_col = P["cyan_dim"]          if is_user else P["border_dim"]
                side_border = (
                    f"border-right: 2px solid {P['cyan']};" if is_user
                    else f"border-left: 2px solid {P.get('purple', '#B060FF')};"
                )
                self.setStyleSheet(f"""
                    QFrame {{
                        background: {bg_col};
                        border: 1px solid {border_col};
                        border-radius: 4px;
                        {side_border}
                    }}
                """)

            self._sources_visible = False
            layout = QVBoxLayout(self)
            layout.setContentsMargins(16, 10, 16, 12)
            layout.setSpacing(6)

            role_lbl = QLabel(label_text, self)
            role_lbl.setStyleSheet(
                f"color: {accent_hex}; font-family: {_MONO}; "
                "font-size: 8px; font-weight: bold; letter-spacing: 2px; "
                "background: transparent; border: none;"
            )
            layout.addWidget(role_lbl)

            txt = QLabel(text, self)
            txt.setWordWrap(True)
            txt.setStyleSheet(
                f"color: {P['text_primary']}; font-family: {_MONO}; "
                "font-size: 10px; background: transparent; border: none;"
            )
            layout.addWidget(txt)

            # Token/tier meta (AI only)
            if role != "user" and meta:
                tokens = meta.get("tokens_used", 0)
                tier   = meta.get("llm_tier", "")
                if tokens or tier:
                    meta_lbl = QLabel(
                        f"TOKENS: {tokens}  ENGINE: {tier.upper()}", self)
                    meta_lbl.setStyleSheet(
                        f"color: {P['text_dim']}; font-family: {_MONO}; "
                        "font-size: 8px; letter-spacing: 1px; "
                        "background: transparent; border: none;"
                    )
                    layout.addWidget(meta_lbl)

            # Sources toggle
            if sources and role != "user":
                toggle = QPushButton(f"[ SHOW {len(sources)} SOURCES ]", self)
                toggle.setStyleSheet(
                    f"QPushButton {{ background: transparent; color: {P['text_dim']}; "
                    f"border: none; font-family: {_MONO}; font-size: 8px; "
                    "letter-spacing: 1px; text-align: left; padding: 0; }}"
                    f"QPushButton:hover {{ color: {P['cyan']}; }}"
                )
                self._sources_panel = QWidget(self)
                sp_layout = QVBoxLayout(self._sources_panel)
                sp_layout.setContentsMargins(0, 4, 0, 0)
                sp_layout.setSpacing(3)
                for s in sources[:5]:
                    sp_layout.addWidget(_SourceWidget(s, self._sources_panel))
                self._sources_panel.setVisible(False)

                def _toggle():
                    self._sources_visible = not self._sources_visible
                    self._sources_panel.setVisible(self._sources_visible)
                    n = len(sources)
                    lbl = "HIDE" if self._sources_visible else "SHOW"
                    toggle.setText(f"[ {lbl} {n} SOURCES ]")

                toggle.clicked.connect(_toggle)
                layout.addWidget(toggle)
                layout.addWidget(self._sources_panel)


    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # AI PANEL
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    class AIPanel(QWidget):
        """
        Deep Space AI query panel â€” chat interface over indexed findings.
        """
        query_complete = Signal(dict)

        def __init__(self, case_db_path: str = "", parent=None):
            super().__init__(parent)
            self._case_db    = case_db_path
            self._session_id: Optional[str] = None
            self._engine     = None
            self._worker:    Optional[_QueryWorker]  = None
            self._idx_worker: Optional[_IndexWorker] = None
            self.setStyleSheet(f"background-color: {P['bg_base']};")
            self._build_ui()
            self._add_system_message(
                "AI engine loads on first use. Click [ INDEX SESSION ] when ready.")

        def _build_ui(self) -> None:
            outer = QVBoxLayout(self)
            outer.setContentsMargins(0, 0, 0, 0)
            outer.setSpacing(0)

            # â”€â”€ Header bar â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            hdr_bar = QWidget(self)
            hdr_bar.setFixedHeight(36)
            hdr_bar.setStyleSheet(f"""
                background-color: {P.get('bg_void', P['bg_base'])};
                border-bottom: 1px solid {P['border_mid']};
            """)
            hdr_layout = QHBoxLayout(hdr_bar)
            hdr_layout.setContentsMargins(12, 0, 12, 0)
            hdr_layout.setSpacing(10)

            title = QLabel("AI QUERY INTERFACE", hdr_bar)
            title.setStyleSheet(f"""
                color: {P.get('purple', '#B060FF')};
                font-family: {_MONO};
                font-size: 10px;
                font-weight: bold;
                letter-spacing: 3px;
                background: transparent;
            """)
            hdr_layout.addWidget(title)
            hdr_layout.addStretch()

            self._index_btn = QPushButton("[ INDEX SESSION ]", hdr_bar)
            self._index_btn.setStyleSheet(f"""
                QPushButton {{
                    background: transparent;
                    color: {P['green']};
                    border: 1px solid {P.get('green_dim', '#009960')};
                    border-radius: 2px;
                    padding: 4px 10px;
                    font-family: {_MONO};
                    font-size: 8px;
                    letter-spacing: 1px;
                }}
                QPushButton:hover {{
                    background: {P.get('green_dim', '#009960')};
                    color: {P.get('bg_void', P['bg_base'])};
                }}
                QPushButton:disabled {{
                    color: {P['text_dim']};
                    border-color: {P['border_dim']};
                }}
            """)
            self._index_btn.clicked.connect(self._on_index)
            hdr_layout.addWidget(self._index_btn)

            btn_clear = QPushButton("[ CLEAR ]", hdr_bar)
            btn_clear.setStyleSheet(f"""
                QPushButton {{
                    background: transparent;
                    color: {P['text_secondary']};
                    border: 1px solid {P['border_dim']};
                    border-radius: 2px;
                    padding: 4px 10px;
                    font-family: {_MONO};
                    font-size: 8px;
                    letter-spacing: 1px;
                }}
                QPushButton:hover {{
                    color: {P['amber']};
                    border-color: {P['amber']};
                }}
            """)
            btn_clear.clicked.connect(self._on_clear)
            hdr_layout.addWidget(btn_clear)

            outer.addWidget(hdr_bar)

            # Status bar (uses set_status, not update)
            self._status_bar = _StatusBar(self)
            outer.addWidget(self._status_bar)

            # â”€â”€ Chat area + input â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            splitter = QSplitter(Qt.Vertical)
            splitter.setHandleWidth(2)
            splitter.setStyleSheet(f"""
                QSplitter::handle {{
                    background-color: {P['border_dim']};
                }}
            """)

            scroll = QScrollArea(self)
            scroll.setWidgetResizable(True)
            scroll.setStyleSheet(f"""
                QScrollArea {{
                    border: none;
                    background-color: {P['bg_base']};
                }}
            """)
            scroll.viewport().setStyleSheet(f"background-color: {P['bg_base']};")

            self._msg_container = QWidget()
            self._msg_container.setStyleSheet(f"background-color: {P['bg_base']};")
            self._msg_layout = QVBoxLayout(self._msg_container)
            self._msg_layout.setContentsMargins(16, 12, 16, 12)
            self._msg_layout.setSpacing(6)

            # Suggested questions
            self._suggestions = QWidget(self._msg_container)
            self._suggestions.setStyleSheet("background-color: transparent;")
            sg_layout = QVBoxLayout(self._suggestions)
            sg_layout.setContentsMargins(0, 0, 0, 0)
            sg_layout.setSpacing(6)

            hint = QLabel("SUGGESTED QUERIES", self._suggestions)
            hint.setStyleSheet(f"""
                color: {P['text_dim']};
                font-family: {_MONO};
                font-size: 8px;
                letter-spacing: 2px;
                background: transparent;
            """)
            sg_layout.addWidget(hint)

            pills_row = QWidget(self._suggestions)
            pills_row.setStyleSheet("background: transparent;")
            pills_layout = QVBoxLayout(pills_row)
            pills_layout.setContentsMargins(0, 0, 0, 0)
            pills_layout.setSpacing(4)

            for q in _SUGGESTED:
                pill = QPushButton(q, pills_row)
                pill.setStyleSheet(f"""
                    QPushButton {{
                        background: transparent;
                        color: {P['text_secondary']};
                        border: 1px solid {P['border_dim']};
                        border-radius: 2px;
                        padding: 5px 12px;
                        font-family: {_MONO};
                        font-size: 9px;
                        text-align: left;
                    }}
                    QPushButton:hover {{
                        color: {P['cyan']};
                        border-color: {P['cyan']};
                        background: rgba(0,200,255,0.05);
                    }}
                """)
                pill.clicked.connect(
                    lambda checked, question=q: self._submit(question))
                pills_layout.addWidget(pill)
            sg_layout.addWidget(pills_row)
            self._msg_layout.addWidget(self._suggestions)
            self._msg_layout.addStretch()

            scroll.setWidget(self._msg_container)
            splitter.addWidget(scroll)
            splitter.setSizes([500])
            outer.addWidget(splitter)

            # Input row (outside splitter â€” always visible)
            input_widget = QWidget(self)
            input_widget.setFixedHeight(52)
            input_widget.setStyleSheet(f"""
                background-color: {P.get('bg_void', P['bg_base'])};
                border-top: 1px solid {P['border_mid']};
            """)
            input_layout = QHBoxLayout(input_widget)
            input_layout.setContentsMargins(12, 8, 12, 8)
            input_layout.setSpacing(8)

            self._input = QLineEdit(self)
            self._input.setPlaceholderText(
                "Ask a question about the findingsâ€¦  (Enter to send)")
            self._input.setStyleSheet(f"""
                QLineEdit {{
                    background: {P.get('bg_input', P['bg_raised'])};
                    color: {P['text_primary']};
                    border: 1px solid {P['border_dim']};
                    border-radius: 2px;
                    padding: 6px 10px;
                    font-family: {_MONO};
                    font-size: 10px;
                }}
                QLineEdit:focus {{
                    border-color: {P.get('purple', '#B060FF')};
                    background: {P['bg_raised']};
                }}
            """)
            self._input.returnPressed.connect(self._on_send)
            input_layout.addWidget(self._input)

            send_btn = QPushButton("SEND âš¡", self)
            send_btn.setObjectName("send_btn")
            send_btn.setFixedWidth(80)
            send_btn.setStyleSheet(f"""
                QPushButton {{
                    background: transparent;
                    color: {P.get('purple', '#B060FF')};
                    border: 1px solid {P.get('purple', '#B060FF')};
                    border-radius: 2px;
                    padding: 6px 12px;
                    font-family: {_MONO};
                    font-size: 9px;
                    font-weight: bold;
                    letter-spacing: 1px;
                }}
                QPushButton:hover {{
                    background: rgba(176,96,255,0.12);
                    color: #C880FF;
                }}
                QPushButton:disabled {{
                    color: {P['text_dim']};
                    border-color: {P['border_dim']};
                }}
            """)
            send_btn.clicked.connect(self._on_send)
            self._send_btn = send_btn
            input_layout.addWidget(send_btn)
            outer.addWidget(input_widget)

            # Progress label
            self._progress_lbl = QLabel("", self)
            self._progress_lbl.setFixedHeight(22)
            self._progress_lbl.setStyleSheet(f"""
                color: {P['amber']};
                font-family: {_MONO};
                font-size: 8px;
                letter-spacing: 1px;
                padding: 0 12px;
                background: {P.get('bg_void', P['bg_base'])};
                border-top: 1px solid {P['border_dim']};
            """)
            self._progress_lbl.setVisible(False)
            outer.addWidget(self._progress_lbl)

        # â”€â”€ Engine initialisation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def _init_engine(self):
            try:
                from query_interface import AIQueryEngine
                ai_dir = ""
                if self._case_db:
                    from pathlib import Path
                    ai_dir = str(Path(self._case_db).with_suffix("")) + ".ai"
                self._engine = AIQueryEngine(
                    case_db_path=self._case_db,
                    persist_path=ai_dir,
                )
                self._refresh_status()
            except ImportError as e:
                pkg = getattr(e, "name", "required libraries")
                self._add_system_message(
                    f"AI engine unavailable: Missing dependency '{pkg}'.\n"
                    "Install with: pip install sentence-transformers chromadb"
                )
            except Exception as e:
                self._add_system_message(
                    f"AI engine unavailable: {e}\n"
                    "Check that the ai/ directory is on sys.path.")

        def _ensure_engine(self) -> bool:
            if self._engine:
                return True
            self._progress_lbl.setText("INITIALISING AI ENGINE...")
            self._progress_lbl.setVisible(True)
            QApplication.processEvents()
            self._init_engine()
            self._progress_lbl.setVisible(False)
            return self._engine is not None

        def _refresh_status(self):
            # FIX: call set_status(), NOT update() â€” update() is QWidget.update()
            if self._engine:
                self._status_bar.set_status(self._engine.status())

        # â”€â”€ Session management â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def set_session(self, session_id: str) -> None:
            self._session_id = session_id

        # â”€â”€ Message management â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def _add_message(self, role: str, text: str,
                         sources=None, meta=None):
            self._suggestions.setVisible(False)

            msg = _MessageWidget(role, text, sources, meta,
                                 self._msg_container)

            wrapper = QWidget(self._msg_container)
            wrapper.setStyleSheet("background: transparent;")
            outer_row = QHBoxLayout(wrapper)
            outer_row.setContentsMargins(0, 2, 0, 2)
            outer_row.setSpacing(0)
            is_user = (role == "user")
            if is_user:
                msg.setMaximumWidth(560)
                outer_row.addStretch(1)
                outer_row.addWidget(msg)
            else:
                msg.setMaximumWidth(640)
                outer_row.addWidget(msg)
                outer_row.addStretch(1)

            self._msg_layout.insertWidget(
                self._msg_layout.count() - 1, wrapper)
            QApplication.processEvents()
            scroll_area = self._msg_container.parent()
            if hasattr(scroll_area, "verticalScrollBar"):
                sb = scroll_area.verticalScrollBar()
                sb.setValue(sb.maximum())

        def _add_system_message(self, text: str):
            lbl = QLabel(text, self._msg_container)
            lbl.setStyleSheet(f"""
                color: {P['amber']};
                font-family: {_MONO};
                font-size: 9px;
                font-style: italic;
                padding: 4px 8px;
                background: transparent;
            """)
            lbl.setWordWrap(True)
            self._msg_layout.insertWidget(
                self._msg_layout.count() - 1, lbl)

        # â”€â”€ Query â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def _on_send(self):
            q = self._input.text().strip()
            if q:
                self._submit(q)

        def _submit(self, question: str):
            if not self._ensure_engine():
                self._add_system_message("AI engine not initialised.")
                return
            if self._engine.rag.n_indexed == 0:
                self._add_system_message(
                    "No findings indexed yet â€” click [ INDEX SESSION ] first.")
                return
            if self._worker and self._worker.isRunning():
                return

            self._input.clear()
            self._add_message("user", question)
            self._send_btn.setEnabled(False)
            self._progress_lbl.setText("PROCESSING QUERYâ€¦")
            self._progress_lbl.setVisible(True)

            self._worker = _QueryWorker(
                self._engine, question, self._session_id)
            self._worker.result.connect(self._on_result)
            self._worker.error.connect(self._on_error)
            self._worker.progress.connect(
                lambda m: self._progress_lbl.setText(m.upper()))
            self._worker.start()

        @Slot(dict)
        def _on_result(self, r: dict):
            self._add_message(
                "ai", r.get("text", ""),
                sources=r.get("sources", []),
                meta=r,
            )
            self._send_btn.setEnabled(True)
            self._progress_lbl.setVisible(False)
            self._refresh_status()
            self.query_complete.emit(r)

        @Slot(str)
        def _on_error(self, err: str):
            self._add_system_message(f"QUERY FAILED: {err}")
            self._send_btn.setEnabled(True)
            self._progress_lbl.setVisible(False)

        # â”€â”€ Indexing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def _on_index(self):
            if not self._case_db:
                self._add_system_message(
                    "No case database configured. Open a .facase file first.")
                return
            if not self._ensure_engine():
                self._add_system_message("AI engine not initialised.")
                return
            if self._idx_worker and self._idx_worker.isRunning():
                return

            self._index_btn.setEnabled(False)
            self._progress_lbl.setText("INDEXING FINDINGSâ€¦")
            self._progress_lbl.setVisible(True)

            self._idx_worker = _IndexWorker(
                self._engine, self._case_db, self._session_id)
            self._idx_worker.done.connect(self._on_index_done)
            self._idx_worker.error.connect(self._on_index_error)
            self._idx_worker.progress.connect(
                lambda p, m: self._progress_lbl.setText(
                    f"{p}%  {m.upper()}"))
            self._idx_worker.start()

        @Slot(int)
        def _on_index_done(self, n: int):
            self._index_btn.setEnabled(True)
            self._progress_lbl.setVisible(False)
            self._refresh_status()
            if n > 0:
                self._add_system_message(
                    f"âœ“ INDEXED {n:,} NEW FINDINGS â€” queries now available.")
            else:
                self._add_system_message("âœ“ INDEX UP TO DATE.")

        @Slot(str)
        def _on_index_error(self, err: str):
            self._index_btn.setEnabled(True)
            self._progress_lbl.setVisible(False)
            self._add_system_message(f"INDEXING FAILED: {err}")

        # â”€â”€ Clear â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def _on_clear(self):
            if self._engine:
                self._engine.clear_history()
            while self._msg_layout.count() > 2:
                item = self._msg_layout.takeAt(1)
                if item.widget() and item.widget() is not self._suggestions:
                    item.widget().deleteLater()
            self._suggestions.setVisible(True)
            self._refresh_status()

        # â”€â”€ Lifecycle â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def closeEvent(self, event):
            if self._worker and self._worker.isRunning():
                self._worker.terminate()
                self._worker.wait(2000)
            if self._idx_worker and self._idx_worker.isRunning():
                self._idx_worker.terminate()
                self._idx_worker.wait(2000)
            if self._engine:
                self._engine.close()
            super().closeEvent(event)


else:
    class AIPanel:
        def __init__(self, *a, **kw): pass
        def set_session(self, *a): pass
        def show(self): pass
        def close(self): pass
