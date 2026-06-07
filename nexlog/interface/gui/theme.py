"""
interface/gui/theme.py â€” NexLog v2 Deep Space SecOps Theme
================================================================
Two API surfaces in one module:

  1. QColor constants  (glass_widget.py, dashboard.py patch):
       VOID, BASE, SURFACE, RAISED
       CRITICAL, HIGH, MEDIUM, LOW, INFO, PURPLE
       FONT_MONO, FONT_UI, FONT_HEAD
       apply_global(app)
       MASTER_QSS

  2. Hex-dict palette  (all GUI panels):
       PALETTE  /  P   â€” 37 keys
       STYLESHEET       â€” f-string QSS
       sev_fg(sev) -> str
       sev_bg(sev) -> str
       sev_order() -> list[str]
"""

# â”€â”€ PySide6 optional â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
try:
    from PySide6.QtGui import QColor, QFont, QPalette
    from PySide6.QtWidgets import QApplication
    _HAS_PYSIDE6 = True
except ImportError:
    _HAS_PYSIDE6 = False
    QColor = QFont = QPalette = QApplication = None   # type: ignore


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# PART 1 â€” QColor constants  (master prompt spec â€” verbatim)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

if _HAS_PYSIDE6:
    VOID    = QColor("#090B10")
    BASE    = QColor("#0D1117")
    SURFACE = QColor("#111827")
    RAISED  = QColor("#182233")

    CRITICAL = QColor("#FB7185")
    HIGH     = QColor("#F97316")
    MEDIUM   = QColor("#FACC15")
    LOW      = QColor("#34D399")
    INFO     = QColor("#38BDF8")
    PURPLE   = QColor("#A78BFA")

    FONT_MONO = QFont("IBM Plex Mono", 10)
    FONT_UI   = QFont("Segoe UI Variable", 10)
    FONT_HEAD = QFont("Segoe UI Variable", 13, QFont.Bold)

    def sev_fg_color(severity: str) -> QColor:
        """QColor variant â€” used by glass_widget.py."""
        return {
            "CRITICAL": CRITICAL, "HIGH": HIGH,
            "MEDIUM":   MEDIUM,   "LOW":  LOW,
        }.get(severity.upper(), INFO)

    def sev_bg_color(severity: str) -> QColor:
        c = sev_fg_color(severity)
        bg = QColor(c)
        bg.setAlpha(28)
        return bg

    def apply_global(app: "QApplication") -> None:
        palette = QPalette()
        palette.setColor(QPalette.Window,          VOID)
        palette.setColor(QPalette.WindowText,      QColor("#D4DCE8"))
        palette.setColor(QPalette.Base,            BASE)
        palette.setColor(QPalette.AlternateBase,   SURFACE)
        palette.setColor(QPalette.Text,            QColor("#D4DCE8"))
        palette.setColor(QPalette.Button,          RAISED)
        palette.setColor(QPalette.ButtonText,      QColor("#D4DCE8"))
        palette.setColor(QPalette.Highlight,       INFO)
        palette.setColor(QPalette.HighlightedText, QColor("#FFFFFF"))
        app.setPalette(palette)
        app.setFont(FONT_UI)

else:
    VOID = BASE = SURFACE = RAISED = None
    CRITICAL = HIGH = MEDIUM = LOW = INFO = PURPLE = None
    FONT_MONO = FONT_UI = FONT_HEAD = None

    def sev_fg_color(severity: str): return None   # type: ignore
    def sev_bg_color(severity: str): return None   # type: ignore
    def apply_global(app): pass                    # type: ignore


# Master QSS â€” verbatim from master prompt spec
MASTER_QSS = """
QMainWindow, QDialog { background: #04080F; }
QWidget { color: #D4DCE8; font-family: 'JetBrains Mono'; }
QFrame  { background: #080C14; border: 1px solid rgba(255,255,255,0.06); border-radius: 8px; }
QLabel  { background: transparent; border: none; }
QLineEdit, QComboBox, QSpinBox {
    background: #0D1420; border: 1px solid rgba(255,255,255,0.10);
    border-radius: 6px; padding: 6px 10px; color: #D4DCE8;
}
QLineEdit:focus, QComboBox:focus {
    border: 1px solid #00B4FF;
}
QTableWidget {
    background: #080C14; gridline-color: rgba(255,255,255,0.05);
    border: none; selection-background-color: rgba(0,180,255,0.15);
}
QHeaderView::section {
    background: #0D1420; color: rgba(180,200,230,0.7);
    border: none; padding: 8px 12px;
    font-size: 9px; letter-spacing: 2px;
}
QScrollBar:vertical {
    background: #080C14; width: 6px; border-radius: 3px;
}
QScrollBar::handle:vertical {
    background: rgba(0,180,255,0.3); border-radius: 3px;
}
QPushButton {
    background: rgba(0,180,255,0.08);
    border: 1px solid rgba(0,180,255,0.25);
    border-radius: 6px; padding: 8px 16px; color: #00B4FF;
}
QPushButton:hover {
    background: rgba(0,180,255,0.15);
    border: 1px solid rgba(0,180,255,0.5);
}
QPushButton:pressed { background: rgba(0,180,255,0.25); }
QTabBar::tab {
    background: transparent; color: rgba(180,200,230,0.5);
    padding: 10px 20px; border-bottom: 2px solid transparent;
}
QTabBar::tab:selected {
    color: #00B4FF; border-bottom: 2px solid #00B4FF;
}
QProgressBar {
    background: #111C2E; border: none;
    border-radius: 5px; height: 10px;
}
QProgressBar::chunk { background: #00B4FF; border-radius: 5px; }
QSplitter::handle { background: rgba(255,255,255,0.05); }
QToolTip {
    background: #0D1420; border: 1px solid rgba(0,180,255,0.3);
    color: #D4DCE8; padding: 6px 10px; border-radius: 6px;
}
"""


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# PART 2 â€” Hex-dict PALETTE + f-string STYLESHEET
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

PALETTE = {
    "bg_void":     "#090B10",
    "bg_base":     "#0D1117",
    "bg_surface":  "#111827",
    "bg_raised":   "#182233",
    "bg_input":    "#0F1724",
    "bg_hover":    "#1F2A3D",
    "border_dim":  "#243044",
    "border_mid":  "#334155",
    "border_glow": "#38BDF8",
    "cyan":        "#38BDF8",
    "cyan_dim":    "#0EA5B7",
    "green":       "#34D399",
    "green_dim":   "#059669",
    "purple":      "#A78BFA",
    "amber":       "#FBBF24",
    "amber_dim":   "#B45309",
    "critical":    "#FB7185",
    "critical_bg": "#2A1018",
    "high":        "#F97316",
    "high_bg":     "#2A160B",
    "medium":      "#FACC15",
    "medium_bg":   "#241C05",
    "low":         "#22C55E",
    "low_bg":      "#052013",
    "info":        "#60A5FA",
    "info_bg":     "#0B162A",
    "text_primary":   "#E5EEF8",
    "text_secondary": "#A7B4C8",
    "text_dim":       "#64748B",
    "text_mono":      "#B8F7D4",
    "text_value":     "#7DD3FC",
    "chart_0": "#38BDF8",
    "chart_1": "#34D399",
    "chart_2": "#A78BFA",
    "chart_3": "#FBBF24",
    "chart_4": "#F97316",
    "chart_5": "#FB7185",
}

P = PALETTE

_SEV_FG = {
    "CRITICAL": P["critical"],
    "HIGH":     P["high"],
    "MEDIUM":   P["medium"],
    "LOW":      P["low"],
    "INFO":     P["info"],
}
_SEV_BG = {
    "CRITICAL": P["critical_bg"],
    "HIGH":     P["high_bg"],
    "MEDIUM":   P["medium_bg"],
    "LOW":      P["low_bg"],
    "INFO":     P["info_bg"],
}
_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def sev_fg(severity: str) -> str:
    return _SEV_FG.get(severity.upper(), P["text_primary"])


def sev_bg(severity: str) -> str:
    return _SEV_BG.get(severity.upper(), P["bg_base"])


def sev_order() -> list:
    return _SEV_ORDER[:]


STYLESHEET = f"""
QMainWindow, QWidget {{
    background-color: {P['bg_base']};
    color: {P['text_primary']};
    font-family: 'JetBrains Mono', 'Consolas', 'Courier New', monospace;
    font-size: 10px;
}}
QLabel {{
    font-family: 'JetBrains Mono', 'Consolas', 'Courier New', monospace;
    font-size: 10px;
    background: transparent;
    border: none;
}}
QMenuBar {{
    background-color: {P['bg_void']};
    color: {P['text_primary']};
    border-bottom: 1px solid {P['border_mid']};
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    padding: 2px 4px;
}}
QMenuBar::item:selected {{
    background-color: {P['bg_raised']};
    color: {P['cyan']};
}}
QMenu {{
    background-color: {P['bg_surface']};
    color: {P['text_primary']};
    border: 1px solid {P['border_mid']};
}}
QMenu::item:selected {{
    background-color: {P['bg_raised']};
    color: {P['cyan']};
}}
QToolBar {{
    background-color: {P['bg_void']};
    border-bottom: 1px solid {P['border_mid']};
    spacing: 4px;
    padding: 4px 8px;
}}
QPushButton {{
    background-color: {P['bg_raised']};
    color: {P['text_primary']};
    border: 1px solid {P['border_mid']};
    border-radius: 3px;
    padding: 5px 12px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    letter-spacing: 0.5px;
}}
QPushButton:hover {{
    background-color: {P['bg_hover']};
    border-color: {P['cyan']};
    color: {P['cyan']};
}}
QPushButton:pressed {{
    background-color: {P['cyan_dim']};
    color: {P['bg_void']};
}}
QPushButton#btn_analyse {{
    background-color: transparent;
    color: {P['green']};
    border: 1px solid {P['green_dim']};
    font-weight: bold;
    letter-spacing: 1px;
}}
QPushButton#btn_analyse:hover {{
    background-color: {P['green_dim']};
    color: {P['bg_void']};
    border-color: {P['green']};
}}
QPushButton#send_btn {{
    background-color: transparent;
    color: {P['cyan']};
    border: 1px solid {P['cyan_dim']};
    font-weight: bold;
}}
QPushButton#send_btn:hover {{
    background-color: {P['cyan_dim']};
    color: {P['bg_void']};
}}
QPushButton#send_btn:disabled {{
    background-color: {P['bg_raised']};
    color: {P['text_dim']};
    border-color: {P['border_dim']};
}}
QTabWidget::pane {{
    border: 1px solid {P['border_mid']};
    background-color: {P['bg_base']};
    top: -1px;
}}
QTabBar::tab {{
    background-color: {P['bg_void']};
    color: {P['text_secondary']};
    padding: 7px 16px;
    border: 1px solid {P['border_dim']};
    border-bottom: none;
    margin-right: 2px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    letter-spacing: 0.5px;
}}
QTabBar::tab:selected {{
    background-color: {P['bg_base']};
    color: {P['cyan']};
    border-color: {P['border_mid']};
    border-bottom: 2px solid {P['cyan']};
}}
QTabBar::tab:hover:!selected {{
    color: {P['text_primary']};
    border-color: {P['border_mid']};
}}
QStatusBar {{
    background-color: {P['bg_void']};
    color: {P['text_secondary']};
    border-top: 1px solid {P['border_mid']};
    font-family: 'JetBrains Mono', monospace;
    font-size: 9px;
}}
QProgressBar {{
    border: 1px solid {P['border_mid']};
    border-radius: 2px;
    background-color: {P['bg_raised']};
    text-align: center;
    color: {P['cyan']};
    height: 12px;
    font-size: 8px;
}}
QProgressBar::chunk {{
    background-color: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 {P['cyan_dim']}, stop:1 {P['cyan']});
    border-radius: 1px;
}}
QTreeWidget {{
    background-color: {P['bg_surface']};
    color: {P['text_primary']};
    border: 1px solid {P['border_dim']};
    alternate-background-color: {P['bg_raised']};
    font-family: 'JetBrains Mono', monospace;
    font-size: 9px;
    outline: none;
}}
QTreeWidget::item:selected {{
    background-color: {P['bg_hover']};
    color: {P['cyan']};
    border-left: 2px solid {P['cyan']};
}}
QTreeWidget::item:hover {{
    background-color: {P['bg_raised']};
}}
QTableWidget {{
    background-color: {P['bg_base']};
    color: {P['text_primary']};
    alternate-background-color: {P['bg_surface']};
    border: 1px solid {P['border_mid']};
    gridline-color: {P['border_dim']};
    font-family: 'JetBrains Mono', monospace;
    font-size: 9px;
    outline: none;
}}
QHeaderView::section {{
    background-color: {P['bg_void']};
    color: {P['text_secondary']};
    border: none;
    border-right: 1px solid {P['border_dim']};
    border-bottom: 1px solid {P['border_mid']};
    padding: 5px 6px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 8px;
    letter-spacing: 1px;
}}
QTableWidget::item:selected {{
    background-color: {P['bg_hover']};
    color: {P['cyan']};
}}
QTextEdit {{
    background-color: {P['bg_surface']};
    color: {P['text_mono']};
    border: 1px solid {P['border_dim']};
    font-family: 'JetBrains Mono', 'Courier New', monospace;
    font-size: 9px;
    selection-background-color: {P['bg_hover']};
}}
QLineEdit {{
    background-color: {P['bg_input']};
    color: {P['text_primary']};
    border: 1px solid {P['border_dim']};
    border-radius: 3px;
    padding: 4px 8px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
}}
QLineEdit:focus {{
    border-color: {P['cyan']};
    background-color: {P['bg_raised']};
}}
QComboBox {{
    background-color: {P['bg_input']};
    color: {P['text_primary']};
    border: 1px solid {P['border_dim']};
    border-radius: 3px;
    padding: 3px 8px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
}}
QComboBox:focus {{ border-color: {P['cyan']}; }}
QComboBox::drop-down {{ border: none; width: 18px; }}
QComboBox QAbstractItemView {{
    background-color: {P['bg_surface']};
    color: {P['text_primary']};
    selection-background-color: {P['bg_hover']};
    border: 1px solid {P['border_mid']};
}}
QGroupBox {{
    color: {P['text_secondary']};
    font-family: 'JetBrains Mono', monospace;
    font-size: 9px;
    letter-spacing: 1px;
    border: 1px solid {P['border_dim']};
    border-radius: 4px;
    margin-top: 8px;
    padding-top: 8px;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 6px;
    color: {P['cyan_dim']};
    letter-spacing: 2px;
}}
QScrollBar:vertical {{
    background: {P['bg_base']}; width: 6px; border: none;
}}
QScrollBar::handle:vertical {{
    background: {P['border_mid']}; border-radius: 3px; min-height: 20px;
}}
QScrollBar::handle:vertical:hover {{ background: {P['cyan_dim']}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0; width: 0; border: none; background: none;
}}
QScrollBar:horizontal {{
    background: {P['bg_base']}; height: 6px; border: none;
}}
QScrollBar::handle:horizontal {{
    background: {P['border_mid']}; border-radius: 3px; min-width: 20px;
}}
QScrollBar::handle:horizontal:hover {{ background: {P['cyan_dim']}; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    height: 0; width: 0; border: none; background: none;
}}
QSplitter::handle {{ background-color: {P['border_dim']}; }}
QSplitter::handle:hover {{ background-color: {P['cyan_dim']}; }}
QLabel#label_title {{
    color: {P['cyan']}; font-size: 11px; font-weight: bold; letter-spacing: 2px;
}}
QFrame#glass_card {{
    background-color: {P['bg_surface']};
    border: 1px solid {P['border_mid']};
    border-radius: 4px;
}}
"""

STYLESHEET += f"""
/* Modern analyst cockpit overrides. Keep the existing cyber style, but
   improve readability with UI fonts, softer cards, and larger controls. */
QMainWindow, QWidget {{
    font-family: 'Segoe UI Variable', 'Segoe UI', 'IBM Plex Sans', sans-serif;
    font-size: 11px;
}}
QLabel {{
    font-family: 'Segoe UI Variable', 'Segoe UI', 'IBM Plex Sans', sans-serif;
    font-size: 11px;
}}
QMenuBar, QMenu, QToolBar, QStatusBar {{
    font-family: 'Segoe UI Variable', 'Segoe UI', 'IBM Plex Sans', sans-serif;
}}
QPushButton {{
    border-radius: 8px;
    padding: 7px 14px;
    font-family: 'Segoe UI Variable', 'Segoe UI', 'IBM Plex Sans', sans-serif;
    font-size: 11px;
}}
QPushButton#btn_analyse, QPushButton#send_btn {{
    border-radius: 10px;
    letter-spacing: 0.4px;
}}
QTabBar::tab {{
    border-radius: 10px 10px 0 0;
    padding: 10px 18px;
    font-family: 'Segoe UI Variable', 'Segoe UI', 'IBM Plex Sans', sans-serif;
    font-size: 11px;
}}
QLineEdit, QComboBox {{
    border-radius: 9px;
    padding: 7px 10px;
    font-family: 'Segoe UI Variable', 'Segoe UI', 'IBM Plex Sans', sans-serif;
    font-size: 11px;
}}
QTextEdit, QTreeWidget, QTableWidget {{
    font-family: 'IBM Plex Mono', 'JetBrains Mono', 'Consolas', monospace;
}}
QFrame#glass_card {{
    background-color: {P['bg_surface']};
    border: 1px solid {P['border_dim']};
    border-radius: 14px;
}}
QDialog#CommandPalette {{
    background-color: {P['bg_surface']};
    border: 1px solid {P['border_glow']};
    border-radius: 18px;
}}
QLineEdit#CommandSearch {{
    background-color: {P['bg_input']};
    border: 1px solid {P['border_mid']};
    border-radius: 14px;
    color: {P['text_primary']};
    font-size: 14px;
    padding: 12px 14px;
}}
QListWidget#CommandList {{
    background-color: transparent;
    border: none;
    outline: none;
    padding: 4px;
}}
QListWidget#CommandList::item {{
    border-radius: 12px;
    color: {P['text_secondary']};
    padding: 10px 12px;
}}
QListWidget#CommandList::item:selected,
QListWidget#CommandList::item:hover {{
    background-color: {P['bg_hover']};
    color: {P['text_primary']};
}}
"""


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# PART 3 â€” Centralized shared constants (import these instead of redefining)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

# CSS font-family string â€” import this in every GUI module instead of copy-pasting
FONT_MONO_CSS = "'IBM Plex Mono', 'JetBrains Mono', 'Consolas', 'Courier New', monospace"

# Severity rank dict for sorting/comparison â€” import instead of redefining
SEV_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

FONT_UI_CSS = "'Segoe UI Variable', 'Segoe UI', 'IBM Plex Sans', sans-serif"

CYBER_TOKENS = {
    "radius_sm": 8,
    "radius_md": 12,
    "radius_lg": 18,
    "space_xs": 4,
    "space_sm": 8,
    "space_md": 12,
    "space_lg": 18,
    "space_xl": 24,
}


def card_style(accent: str = "") -> str:
    border = accent or P["border_dim"]
    return f"""
        QFrame {{
            background-color: {P['bg_surface']};
            border: 1px solid {border};
            border-radius: {CYBER_TOKENS['radius_lg']}px;
        }}
    """


def nav_button_style() -> str:
    return f"""
        QPushButton {{
            background-color: transparent;
            color: {P['text_secondary']};
            border: 1px solid transparent;
            border-radius: 12px;
            padding: 10px 12px;
            text-align: left;
            font-family: {FONT_UI_CSS};
            font-size: 12px;
            font-weight: 600;
        }}
        QPushButton:hover {{
            background-color: {P['bg_hover']};
            color: {P['text_primary']};
            border-color: {P['border_dim']};
        }}
        QPushButton:checked {{
            background-color: {P['bg_hover']};
            color: {P['cyan']};
            border-color: {P['border_glow']};
        }}
    """


def primary_button_style() -> str:
    return f"""
        QPushButton {{
            background-color: {P['cyan']};
            color: {P['bg_void']};
            border: 1px solid {P['cyan']};
            border-radius: 12px;
            padding: 9px 14px;
            font-family: {FONT_UI_CSS};
            font-size: 12px;
            font-weight: 700;
        }}
        QPushButton:hover {{
            background-color: {P['text_value']};
            border-color: {P['text_value']};
        }}
    """


def ghost_button_style(accent: str | None = None) -> str:
    color = accent or P["text_secondary"]
    return f"""
        QPushButton {{
            background-color: {P['bg_input']};
            color: {color};
            border: 1px solid {P['border_dim']};
            border-radius: 12px;
            padding: 9px 13px;
            font-family: {FONT_UI_CSS};
            font-size: 12px;
            font-weight: 600;
        }}
        QPushButton:hover {{
            background-color: {P['bg_hover']};
            color: {P['text_primary']};
            border-color: {accent or P['border_glow']};
        }}
    """


def severity_chip_style(severity: str) -> str:
    sev = severity.upper()
    return f"""
        QLabel {{
            background-color: {sev_bg(sev)};
            color: {sev_fg(sev)};
            border: 1px solid {sev_fg(sev)};
            border-radius: 10px;
            padding: 3px 8px;
            font-family: {FONT_MONO_CSS};
            font-size: 10px;
            font-weight: 700;
        }}
    """


def section_title_style() -> str:
    return f"""
        QLabel {{
            color: {P['text_primary']};
            background: transparent;
            border: none;
            font-family: {FONT_UI_CSS};
            font-size: 18px;
            font-weight: 800;
        }}
    """


def caption_style() -> str:
    return f"""
        QLabel {{
            color: {P['text_secondary']};
            background: transparent;
            border: none;
            font-family: {FONT_UI_CSS};
            font-size: 11px;
        }}
    """
