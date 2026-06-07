"""
interface/gui/dashboard.py â€” NexLog v2  [Bento Grid Command Center]
==========================================================================
Dashboard view â€” Command Center tab 1.

Bento Grid Layout (2026 SecOps aesthetic):
  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
  â”‚  [CRIT] [HIGH] [MED] [LOW] [CHAINS]   â† Neon KPI cards row  â”‚
  â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
  â”‚  Severity Distributionâ”‚  MITRE ATT&CK Tactic Coverage        â”‚
  â”‚  (stacked bar)        â”‚  (horizontal bars, GPU-style QPainter)â”‚
  â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
  â”‚  Findings by Category â”‚  Attack Chain Feed                   â”‚
  â”‚  (sortable table)     â”‚  (tactical chain cards, scrollable)  â”‚
  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

Fixes applied (v2.1):
  â€¢ KPI cards: added setSizePolicy(Fixed, Fixed) â†’ stops layout engine
    from renegotiating card bounds on every resize/repaint pass
  â€¢ KPI row: wrapped in QWidget container with setFixedHeight(90)
    and setAlignment(AlignLeft|AlignVCenter) â†’ anchors the row absolutely
  â€¢ P['bg_void'] KeyError â†’ P.get('bg_void', P['bg_base']) safe fallback
  â€¢ _SeverityBar.paintEvent: removed inner 'from theme import' (caused
    reimport on every paint); uses module-level P directly
  â€¢ _KPICard.set_value: replaced __import__ hack with direct QColor ref
  â€¢ Removed duplicated sys/os path-walk block (was defined twice)
  â€¢ Added QSizePolicy import guard throughout
"""

import os
import sys
from typing import Optional

# â”€â”€ Self-locating root (single, clean block) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

for _subpkg in ["core", "detection", "storage", "intelligence"]:
    _p = os.path.join(_ROOT, _subpkg)
    if _p not in sys.path:
        sys.path.insert(0, _p)

# â”€â”€ PySide6 guard â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
try:
    from PySide6.QtCore import Qt, QRect, QSize, QTimer
    from PySide6.QtGui import (
        QBrush, QColor, QFont, QPainter, QPen,
        QLinearGradient, QPainterPath,
    )
    from PySide6.QtWidgets import (
        QFrame, QGridLayout, QGroupBox, QHBoxLayout,
        QLabel, QScrollArea, QSizePolicy, QTableWidget,
        QTableWidgetItem, QVBoxLayout, QWidget,
        QHeaderView, QPushButton,
    )
    _HAS_PYSIDE6 = True
except ImportError:
    _HAS_PYSIDE6 = False
if os.environ.get("NEXLOG_GUI_STUBS", "").strip().lower() in {"1", "true", "yes", "on"}:
    _HAS_PYSIDE6 = False

# â”€â”€ Theme (with complete fallback palette) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
try:
    from interface.gui.theme import PALETTE as P, sev_fg, sev_bg, sev_order, FONT_MONO_CSS, SEV_RANK
except ImportError:
    try:
        from theme import PALETTE as P, sev_fg, sev_bg, sev_order, FONT_MONO_CSS, SEV_RANK
    except ImportError:
        P = {
            "bg_base":    "#080C14",
            "bg_void":    "#040608",        # â† added so key always exists
            "bg_surface": "#0D1420",
            "bg_raised":  "#111C2E",
            "bg_hover":   "#162238",
            "border_dim": "#1A2A3F",
            "border_mid": "#1E3A5A",
            "cyan":       "#00C8FF",
            "cyan_dim":   "#007A9C",
            "green":      "#00FF9D",
            "amber":      "#FFB700",
            "critical":   "#FF3B5C",
            "critical_bg":"#1A0510",
            "high":       "#FF6B35",
            "high_bg":    "#1A0D06",
            "medium":     "#FFB700",
            "medium_bg":  "#1A1100",
            "low":        "#00FF9D",
            "low_bg":     "#001A12",
            "info":       "#4A8FA8",
            "info_bg":    "#080C14",
            "text_primary":   "#C8DFF0",
            "text_secondary": "#5A8FA8",
            "text_dim":       "#2A4A5E",
            "text_value":     "#00E5FF",
            "chart_0": "#00C8FF",
            "chart_1": "#00FF9D",
            "chart_2": "#B060FF",
            "chart_3": "#FFB700",
            "chart_4": "#FF6B35",
            "chart_5": "#FF3B5C",
        }

        def sev_fg(s: str) -> str:
            return P.get(s.lower(), P["text_primary"])

        def sev_bg(s: str) -> str:
            return P.get(s.lower() + "_bg", P["bg_base"])

        def sev_order() -> list:
            return ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# â”€â”€ Module-level constants (computed once, not per-paint) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_SEV_NEON = {
    "CRITICAL": P["critical"],
    "HIGH":     P["high"],
    "MEDIUM":   P["medium"],
    "LOW":      P["low"],
    "INFO":     P["info"],
}
_SEV_COLOURS = _SEV_NEON
_SEV_ORDER = sev_order()

_CHART_COLS = [
    P["chart_0"], P["chart_1"], P["chart_2"],
    P["chart_3"], P["chart_4"], P["chart_5"],
]

_MONO = FONT_MONO_CSS  # from theme

# Safe palette accessor â€” never raises KeyError
def _p(key: str, fallback: str = None) -> str:
    return P.get(key, fallback or P["bg_base"])


def _card_css(accent: str) -> str:
    return f"""
        QFrame {{
            background-color: {_p('bg_surface')};
            border: 1px solid {_p('border_dim')};
            border-top: 2px solid {accent};
            border-radius: 4px;
        }}
        QFrame QLabel {{
            border: none;
            background: transparent;
        }}
    """


_GROUP_CSS = f"""
    QGroupBox {{
        color: {_p('text_secondary')};
        font-family: {_MONO};
        font-size: 8px;
        letter-spacing: 2px;
        border: 1px solid {_p('border_dim')};
        border-radius: 4px;
        margin-top: 8px;
        padding-top: 10px;
        background-color: {_p('bg_surface')};
    }}
    QGroupBox::title {{
        subcontrol-origin: margin;
        subcontrol-position: top left;
        padding: 0 6px;
        color: {_p('cyan_dim')};
    }}
    QGroupBox QLabel {{
        border: none;
        background: transparent;
    }}
"""


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
if _HAS_PYSIDE6:

    # â”€â”€ GlassPanel import (with safe fallback) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    try:
        from interface.gui.glass_widget import GlassPanel as _GlassPanel, GlassPreset
        _GLASS_OK = True
    except ImportError:
        try:
            from glass_widget import GlassPanel as _GlassPanel, GlassPreset
            _GLASS_OK = True
        except ImportError:
            _GlassPanel = QFrame  # type: ignore

            _GLASS_OK = False

            class GlassPreset:    # type: ignore
                DEFAULT = CRITICAL = HIGH = MEDIUM = LOW = AI = PANEL = INFO = {}

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # KPI CARD
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    class _KPICard(_GlassPanel):
        """
        KPI metric card â€” glass backing + live pulse on value change.

        FIX v2.1:
          â€¢ setSizePolicy(Fixed, Fixed) added after setFixedSize â†’ layout
            engine now fully respects the 148Ã—82 constraint; no more drift.
          â€¢ set_value no longer uses __import__ hack; uses already-imported QColor.
          â€¢ Flash colour reset is always safe regardless of glass availability.
        """

        def __init__(
            self,
            label: str,
            value: str = "â€”",
            accent: str = None,
            parent=None,
        ):
            self._accent = accent or _p("cyan")

            if _GLASS_OK:
                super().__init__(parent, preset=GlassPreset.DEFAULT)
                self.setAutoFillBackground(False)
            else:
                super().__init__(parent)
                self.setStyleSheet(_card_css(self._accent))

            # â”€â”€ FIX 1: both size constraints must be set together â”€â”€â”€â”€â”€â”€
            self.setFixedSize(QSize(148, 82))
            self.setSizePolicy(
                QSizePolicy.Policy.Fixed,
                QSizePolicy.Policy.Fixed,
            )

            layout = QVBoxLayout(self)
            layout.setContentsMargins(14, 12, 14, 10)
            layout.setSpacing(4)

            self._val_label = QLabel(value, self)
            self._val_label.setStyleSheet(self._val_style(self._accent))
            self._val_label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            layout.addWidget(self._val_label)

            lbl = QLabel(label, self)
            lbl.setStyleSheet(
                f"color: {_p('text_secondary')}; font-family: {_MONO}; "
                "font-size: 8px; letter-spacing: 2px; "
                "background: transparent; border: none;"
            )
            lbl.setAlignment(Qt.AlignLeft)
            layout.addWidget(lbl)
            layout.addStretch()

            self._flash_timer = QTimer(self)
            self._flash_timer.setSingleShot(True)
            self._flash_timer.timeout.connect(self._end_flash)

        # â”€â”€ helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def _val_style(self, colour: str) -> str:
            return (
                f"color: {colour}; font-family: {_MONO}; "
                "font-size: 24px; font-weight: bold; "
                "background: transparent; border: none; letter-spacing: -0.5px;"
            )

        def set_value(self, val: str, severity: str = "") -> None:
            self._val_label.setText(val)

            # Glass preset + glow (uses already-imported QColor â€” no __import__)
            if _GLASS_OK and severity:
                self.set_severity(severity)
                if severity == "CRITICAL" and val not in ("0", "â€”"):
                    self.start_glow_pulse(QColor(_p("critical")))
                    self._glow_strength = 2
                elif severity == "HIGH" and val not in ("0", "â€”"):
                    self.start_glow_pulse(QColor(_p("high")))
                    self._glow_strength = 1
                else:
                    self.stop_glow_pulse()

            # White flash then restore accent colour
            self._val_label.setStyleSheet(self._val_style("#FFFFFF"))
            self._flash_timer.start(180)

            if _GLASS_OK:
                QTimer.singleShot(120, self.refresh_glass)

        def _end_flash(self) -> None:
            self._val_label.setStyleSheet(self._val_style(self._accent))

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # SEVERITY BAR
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    class _SeverityBar(QWidget):
        """
        Stacked horizontal severity bar drawn with QPainter.

        FIX v2.1:
          â€¢ Removed 'from theme import PALETTE as _P2' inside paintEvent
            (was triggering a module reimport on every repaint cycle).
            Module-level P is used directly throughout.
        """

        def __init__(self, parent=None):
            super().__init__(parent)
            self.setFixedHeight(36)
            self.setMinimumWidth(200)
            self.setSizePolicy(
                QSizePolicy.Policy.Expanding,
                QSizePolicy.Policy.Fixed,
            )
            self._data: dict[str, int] = {}

        def set_data(self, by_sev: dict[str, int]) -> None:
            self._data = by_sev
            self.update()

        def paintEvent(self, event) -> None:
            p = QPainter(self)
            p.setRenderHint(QPainter.Antialiasing)

            if not self._data:
                p.setBrush(QBrush(QColor(P["bg_raised"])))
                p.setPen(Qt.NoPen)
                p.drawRoundedRect(QRect(0, 7, self.width(), 22), 2, 2)
                p.setPen(QPen(QColor(P["text_dim"])))
                f = QFont("JetBrains Mono", 8)
                p.setFont(f)
                p.drawText(
                    QRect(0, 7, self.width(), 22),
                    Qt.AlignCenter,
                    "NO DATA",
                )
                p.end()
                return

            total = max(sum(self._data.values()), 1)
            x = 0
            w = self.width()
            h = 22
            y = 7

            # Background track
            p.setBrush(QBrush(QColor(P["bg_raised"])))
            p.setPen(Qt.NoPen)
            p.drawRoundedRect(QRect(0, y, w, h), 2, 2)

            for sev in _SEV_ORDER:
                count = self._data.get(sev, 0)
                if count == 0:
                    continue

                seg_w = max(int(count / total * w), 2)
                seg_w = min(seg_w, w - x)   # never overflow widget edge
                if seg_w <= 0:
                    continue

                col = _SEV_NEON.get(sev, P["info"])

                # Neon gradient fill
                grad = QLinearGradient(x, y, x, y + h)
                grad.setColorAt(0, QColor(col))
                c2 = QColor(col)
                c2.setAlpha(160)
                grad.setColorAt(1, c2)
                p.setBrush(QBrush(grad))
                p.setPen(Qt.NoPen)
                p.drawRect(QRect(x, y, seg_w, h))

                # Segment label
                if seg_w > 36:
                    p.setPen(QPen(QColor("#FFFFFF")))
                    f = QFont("JetBrains Mono", 8)
                    f.setBold(True)
                    p.setFont(f)
                    p.drawText(
                        QRect(x + 3, y, seg_w - 6, h),
                        Qt.AlignVCenter | Qt.AlignLeft,
                        f"{sev[0]} {count}",
                    )

                x += seg_w

            # Border
            p.setBrush(Qt.NoBrush)
            p.setPen(QPen(QColor(P["border_dim"]), 1))
            p.drawRoundedRect(QRect(0, y, w, h), 2, 2)
            p.end()

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # MITRE BARS
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    class _MitreBars(QWidget):
        """
        Horizontal bar chart of findings per MITRE tactic.
        Terminal-integrated: monospace axis labels, neon gradient bars.
        """

        def __init__(self, parent=None):
            super().__init__(parent)
            self.setMinimumHeight(200)
            self.setSizePolicy(
                QSizePolicy.Policy.Expanding,
                QSizePolicy.Policy.Expanding,
            )
            self._tactics: list[tuple[str, int]] = []

        def set_tactics(self, data: list[tuple[str, int]]) -> None:
            self._tactics = sorted(data, key=lambda x: -x[1])[:10]
            self.update()

        def paintEvent(self, event) -> None:
            p = QPainter(self)
            p.setRenderHint(QPainter.Antialiasing)

            if not self._tactics:
                p.setPen(QPen(QColor(P["text_dim"])))
                f = QFont("JetBrains Mono", 8)
                p.setFont(f)
                p.drawText(
                    self.rect(),
                    Qt.AlignCenter,
                    "NO DATA â€” RUN ANALYSIS FIRST",
                )
                p.end()
                return

            max_v   = max(v for _, v in self._tactics) or 1
            n       = len(self._tactics)
            w       = self.width()
            label_w = 148
            count_w = 28
            bar_area = w - label_w - count_w - 16
            bar_h   = min(15, max(10, (self.height() - 16) // max(n, 1) - 3))
            gap     = 3

            for i, (name, val) in enumerate(self._tactics):
                y   = 8 + i * (bar_h + gap)
                bw  = max(int(val / max_v * bar_area), 3)
                col = _CHART_COLS[i % len(_CHART_COLS)]

                # Track
                p.setBrush(QBrush(QColor(P["bg_raised"])))
                p.setPen(Qt.NoPen)
                p.drawRoundedRect(QRect(label_w, y, bar_area, bar_h), 2, 2)

                # Gradient fill
                grad = QLinearGradient(label_w, y, label_w + bw, y)
                c1 = QColor(col)
                c2 = QColor(col)
                c2.setAlpha(120)
                grad.setColorAt(0, c2)
                grad.setColorAt(1, c1)
                p.setBrush(QBrush(grad))
                p.drawRoundedRect(QRect(label_w, y, bw, bar_h), 2, 2)

                # Axis label
                p.setPen(QPen(QColor(P["text_secondary"])))
                f = QFont("JetBrains Mono", 8)
                p.setFont(f)
                p.drawText(
                    QRect(0, y, label_w - 6, bar_h),
                    Qt.AlignVCenter | Qt.AlignRight,
                    name[:24],
                )

                # Count
                p.setPen(QPen(QColor(col)))
                p.drawText(
                    QRect(label_w + bw + 4, y, count_w, bar_h),
                    Qt.AlignVCenter | Qt.AlignLeft,
                    str(val),
                )

            p.end()

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # ATTACK CHAIN CARD
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    class _ChainCard(QFrame):
        """
        Single attack chain card with left neon border, risk badge,
        source IP, and stage sequence.
        """

        def __init__(self, chain: dict, parent=None):
            super().__init__(parent)

            risk  = chain.get("max_risk_score", 0.0)
            name  = chain.get("chain_name", "UNKNOWN CHAIN")
            ip    = chain.get("source_ip", "?")
            cats  = chain.get("categories", [])

            if risk >= 8.5:
                accent = P["critical"]
            elif risk >= 6.0:
                accent = P["high"]
            elif risk >= 3.5:
                accent = P["medium"]
            else:
                accent = P["low"]

            self.setStyleSheet(f"""
                QFrame {{
                    background-color: {_p('bg_raised')};
                    border: 1px solid {_p('border_dim')};
                    border-left: 3px solid {accent};
                    border-radius: 3px;
                }}
            """)

            layout = QVBoxLayout(self)
            layout.setContentsMargins(10, 6, 10, 6)
            layout.setSpacing(3)

            # Row 1: name + risk badge
            r1 = QHBoxLayout()
            r1.setSpacing(8)

            name_lbl = QLabel(name.upper(), self)
            name_lbl.setStyleSheet(f"""
                color: {accent};
                font-family: {_MONO};
                font-size: 9px;
                font-weight: bold;
                letter-spacing: 1px;
                background: transparent;
            """)
            r1.addWidget(name_lbl)
            r1.addStretch()

            risk_lbl = QLabel(f"RISK {risk:.1f}", self)
            risk_lbl.setStyleSheet(f"""
                color: {_p('bg_base')};
                background-color: {accent};
                font-family: {_MONO};
                font-size: 8px;
                font-weight: bold;
                letter-spacing: 1px;
                padding: 2px 6px;
                border-radius: 2px;
            """)
            r1.addWidget(risk_lbl)
            layout.addLayout(r1)

            # Row 2: source IP
            ip_lbl = QLabel(f"SRC: {ip}", self)
            ip_lbl.setStyleSheet(f"""
                color: {_p('text_secondary')};
                font-family: {_MONO};
                font-size: 8px;
                background: transparent;
            """)
            layout.addWidget(ip_lbl)

            # Row 3: attack stage chain
            if cats:
                chain_str = "  â†’  ".join(
                    c.replace("_", " ").upper() for c in cats[:6]
                )
                chain_lbl = QLabel(chain_str, self)
                chain_lbl.setStyleSheet(f"""
                    color: {_p('text_dim')};
                    font-family: {_MONO};
                    font-size: 8px;
                    letter-spacing: 0.5px;
                    background: transparent;
                """)
                chain_lbl.setWordWrap(True)
                layout.addWidget(chain_lbl)

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # DASHBOARD VIEW â€” Bento Grid Command Center
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    class DashboardView(QWidget):
        """
        Bento Grid dashboard â€” the first tab shown after analysis.
        All charts QPainter-rendered (no matplotlib, no Qt Charts).

        FIX v2.1 â€” Layout stability:
          â€¢ KPI cards are parented to a locked QWidget container
            (setFixedHeight + setSizePolicy Fixed/Fixed) â€” they will
            never move regardless of window resize or DPI scaling.
          â€¢ QHBoxLayout.setAlignment(AlignLeft|AlignVCenter) pins cards
            to the left edge; stretch absorbs remaining space.
          â€¢ outer.addWidget(kpi_container) instead of addLayout â€” gives
            the layout engine a concrete anchor point.
          â€¢ P.get('bg_void', P['bg_base']) safe fallback everywhere.
        """

        def __init__(self, case_db_path: str, parent=None):
            super().__init__(parent)
            self._case_db    = case_db_path
            self._session_id: Optional[str] = None
            self.setStyleSheet(f"background-color: {_p('bg_base')};")
            self._build_ui()

        # â”€â”€ UI construction â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def _build_ui(self) -> None:
            outer = QVBoxLayout(self)
            outer.setContentsMargins(10, 10, 10, 10)
            outer.setSpacing(8)

            # â”€â”€ Section header â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            hdr = QHBoxLayout()
            title = QLabel("COMMAND CENTER", self)
            title.setStyleSheet(f"""
                color: {_p('cyan')};
                font-family: {_MONO};
                font-size: 12px;
                font-weight: bold;
                letter-spacing: 4px;
                background: transparent;
            """)
            hdr.addWidget(title)
            hdr.addStretch()

            sub = QLabel("THREAT INTELLIGENCE DASHBOARD", self)
            sub.setStyleSheet(f"""
                color: {_p('text_dim')};
                font-family: {_MONO};
                font-size: 8px;
                letter-spacing: 2px;
                background: transparent;
            """)
            hdr.addWidget(sub)

            self._btn_stop = QPushButton("[ STOP ]")
            self._btn_stop.setStyleSheet(f"""
                QPushButton {{
                    background: transparent; color: {P['text_secondary']};
                    border: 1px solid {P['border_dim']}; border-radius: 2px;
                    padding: 2px 8px; font-family: {_MONO}; font-size: 8px;
                }}
                QPushButton:hover {{ color: {P['amber']}; border-color: {P['amber']}; }}
            """)
            self._btn_stop.clicked.connect(self._on_stop)
            hdr.addWidget(self._btn_stop)

            self._btn_pdf = QPushButton("[ PDF ]")
            self._btn_pdf.setStyleSheet(f"""
                QPushButton {{
                    background: transparent; color: {P['text_secondary']};
                    border: 1px solid {P['border_dim']}; border-radius: 2px;
                    padding: 2px 8px; font-family: {_MONO}; font-size: 8px;
                }}
                QPushButton:hover {{ color: {P['cyan']}; border-color: {P['cyan']}; }}
            """)
            self._btn_pdf.clicked.connect(self._export_pdf)
            hdr.addWidget(self._btn_pdf)

            outer.addLayout(hdr)

            # â”€â”€ KPI row â€” FIX: anchored container â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            #
            # Root cause of "cards moving":
            #   Raw QHBoxLayout added directly to outer QVBoxLayout has no
            #   fixed anchor. On every resize/repaint the layout engine
            #   re-negotiates heights. Wrapping in a QWidget with both
            #   setFixedHeight AND setSizePolicy(Expanding, Fixed) gives
            #   the engine a concrete, immovable row to work with.
            #
            kpi_container = QWidget(self)
            kpi_container.setFixedHeight(90)
            kpi_container.setStyleSheet("background: transparent;")
            kpi_container.setSizePolicy(
                QSizePolicy.Policy.Expanding,
                QSizePolicy.Policy.Fixed,      # vertical: NEVER grow/shrink
            )

            kpi_row = QHBoxLayout(kpi_container)
            kpi_row.setSpacing(8)
            kpi_row.setContentsMargins(0, 0, 0, 0)
            # AlignLeft pins cards to the left; remaining space â†’ stretch
            kpi_row.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)

            self._kpi_total    = _KPICard("TOTAL FINDINGS",  "0",   _p("cyan"),     kpi_container)
            self._kpi_critical = _KPICard("CRITICAL",        "0",   _p("critical"), kpi_container)
            self._kpi_high     = _KPICard("HIGH",            "0",   _p("high"),     kpi_container)
            self._kpi_medium   = _KPICard("MEDIUM",          "0",   _p("medium"),   kpi_container)
            self._kpi_chains   = _KPICard("ATTACK CHAINS",   "0",   _p("low"),      kpi_container)
            self._kpi_risk     = _KPICard("MAX RISK SCORE",  "0.0", _p("amber"),    kpi_container)
            self._kpi_integrity= _KPICard("CASE INTEGRITY",  "--",  _p("cyan"),     kpi_container)

            for card in [
                self._kpi_total, self._kpi_critical, self._kpi_high,
                self._kpi_medium, self._kpi_chains, self._kpi_risk,
                self._kpi_integrity,
            ]:
                kpi_row.addWidget(card)

            kpi_row.addStretch(1)

            # addWidget, NOT addLayout â€” gives the engine a concrete anchor
            outer.addWidget(kpi_container)

            # â”€â”€ Severity bar â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            sev_grp = QGroupBox("SEVERITY DISTRIBUTION", self)
            sev_grp.setStyleSheet(_GROUP_CSS)
            sev_layout = QVBoxLayout(sev_grp)
            sev_layout.setContentsMargins(8, 4, 8, 6)
            sev_layout.setSpacing(4)

            self._sev_bar = _SeverityBar(sev_grp)
            sev_layout.addWidget(self._sev_bar)

            # Legend row
            leg = QHBoxLayout()
            for sev in _SEV_ORDER:
                col = _SEV_NEON.get(sev, P["info"])
                dot = QLabel(f"â–Œ {sev}", sev_grp)
                dot.setStyleSheet(f"""
                    color: {col};
                    font-family: {_MONO};
                    font-size: 8px;
                    background: transparent;
                    letter-spacing: 1px;
                """)
                leg.addWidget(dot)
            leg.addStretch()
            sev_layout.addLayout(leg)
            outer.addWidget(sev_grp)

            # â”€â”€ Bento lower section (2 columns) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            cols = QHBoxLayout()
            cols.setSpacing(8)

            # â”€â”€ Left column: category table â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            left_col = QVBoxLayout()
            left_col.setSpacing(8)

            cat_grp = QGroupBox("FINDINGS BY CATEGORY", self)
            cat_grp.setStyleSheet(_GROUP_CSS)
            cat_layout = QVBoxLayout(cat_grp)
            cat_layout.setContentsMargins(6, 4, 6, 6)

            self._cat_table = QTableWidget(0, 2, cat_grp)
            self._cat_table.setHorizontalHeaderLabels(["CATEGORY", "COUNT"])
            self._cat_table.horizontalHeader().setSectionResizeMode(
                0, QHeaderView.ResizeMode.Stretch)
            self._cat_table.horizontalHeader().setSectionResizeMode(
                1, QHeaderView.ResizeMode.Fixed)
            self._cat_table.horizontalHeader().resizeSection(1, 56)

            # FIX: P.get('bg_void', â€¦) prevents KeyError crash that was
            # aborting the layout pass and causing the jumpy render.
            _bg_void = _p("bg_void", P["bg_base"])
            self._cat_table.setStyleSheet(f"""
                QTableWidget {{
                    background-color: {_p('bg_surface')};
                    color: {_p('text_primary')};
                    border: none;
                    gridline-color: {_p('border_dim')};
                    font-family: {_MONO};
                    font-size: 9px;
                    alternate-background-color: {_p('bg_raised')};
                }}
                QHeaderView::section {{
                    background-color: {_bg_void};
                    color: {_p('text_secondary')};
                    border: none;
                    border-bottom: 1px solid {_p('border_mid')};
                    padding: 4px 6px;
                    font-family: {_MONO};
                    font-size: 8px;
                    letter-spacing: 1px;
                }}
                QTableWidget::item:selected {{
                    background-color: {_p('bg_hover')};
                    color: {_p('cyan')};
                }}
            """)
            self._cat_table.setAlternatingRowColors(True)
            self._cat_table.setEditTriggers(
                QTableWidget.EditTrigger.NoEditTriggers)
            self._cat_table.verticalHeader().setVisible(False)
            self._cat_table.setShowGrid(False)
            cat_layout.addWidget(self._cat_table)
            left_col.addWidget(cat_grp)
            cols.addLayout(left_col, 1)

            # â”€â”€ Right column: MITRE chart + chain feed â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            right_col = QVBoxLayout()
            right_col.setSpacing(8)

            mitre_grp = QGroupBox("MITRE ATT&CK TACTIC COVERAGE", self)
            mitre_grp.setStyleSheet(_GROUP_CSS)
            mitre_layout = QVBoxLayout(mitre_grp)
            mitre_layout.setContentsMargins(6, 4, 6, 6)
            self._mitre_chart = _MitreBars(mitre_grp)
            mitre_layout.addWidget(self._mitre_chart)
            right_col.addWidget(mitre_grp, 2)

            chain_grp = QGroupBox("ATTACK CHAINS DETECTED", self)
            chain_grp.setStyleSheet(_GROUP_CSS)
            chain_layout = QVBoxLayout(chain_grp)
            chain_layout.setContentsMargins(6, 4, 6, 6)

            self._chain_scroll = QScrollArea(chain_grp)
            self._chain_scroll.setWidgetResizable(True)
            self._chain_scroll.setStyleSheet(f"""
                QScrollArea {{
                    border: none;
                    background-color: {_p('bg_surface')};
                }}
                QScrollArea > QWidget > QWidget {{
                    background-color: {_p('bg_surface')};
                }}
            """)
            self._chain_scroll.viewport().setStyleSheet(
                f"background-color: {_p('bg_surface')};")

            self._chain_inner = QWidget()
            self._chain_inner.setStyleSheet(
                f"background-color: {_p('bg_surface')};")
            self._chain_vbox = QVBoxLayout(self._chain_inner)
            self._chain_vbox.setSpacing(5)
            self._chain_vbox.setContentsMargins(2, 2, 2, 2)
            self._chain_vbox.addStretch()
            self._chain_scroll.setWidget(self._chain_inner)
            chain_layout.addWidget(self._chain_scroll)
            right_col.addWidget(chain_grp, 1)

            cols.addLayout(right_col, 1)
            outer.addLayout(cols, 1)

        # â”€â”€ Data loading â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def load_session(self, session_id: Optional[str] = None) -> None:
            """Populate all dashboard widgets from the case DB."""
            self._session_id = session_id
            try:
                from storage.case_db import CaseDB
                with CaseDB(self._case_db) as db:
                    summ   = db.get_findings_summary(session_id=session_id)
                    chains = db.get_attack_chains(session_id=session_id)
                    finds  = db.get_findings(session_id=session_id, limit=5000)
                    integrity = db.verify_case_integrity(session_id=session_id)
            except Exception:
                return

            # â”€â”€ KPI cards â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            by_sev = summ.get("by_severity", {})
            self._kpi_total   .set_value(str(summ.get("total", 0)),         "INFO")
            self._kpi_critical.set_value(str(by_sev.get("CRITICAL", 0)),    "CRITICAL")
            self._kpi_high    .set_value(str(by_sev.get("HIGH", 0)),        "HIGH")
            self._kpi_medium  .set_value(str(by_sev.get("MEDIUM", 0)),      "MEDIUM")
            self._kpi_chains  .set_value(str(len(chains)),                   "LOW")
            self._kpi_risk    .set_value(f"{summ.get('max_risk_score', 0.0):.1f}")
            status = integrity.get("status", "unknown").upper()
            status_sev = {
                "TRUSTED": "LOW",
                "NO_EVIDENCE": "INFO",
                "WARNING": "HIGH",
                "COMPROMISED": "CRITICAL",
            }.get(status, "INFO")
            self._kpi_integrity.set_value(status, status_sev)

            # â”€â”€ Severity bar â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            self._sev_bar.set_data(by_sev)

            # â”€â”€ Category table â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            by_cat = summ.get("by_category", {})
            self._cat_table.setRowCount(0)
            for cat, cnt in sorted(by_cat.items(), key=lambda x: -x[1]):
                row = self._cat_table.rowCount()
                self._cat_table.insertRow(row)

                label_item = QTableWidgetItem(cat.replace("_", " ").upper())
                label_item.setForeground(QColor(_p("text_primary")))

                cnt_item = QTableWidgetItem(str(cnt))
                cnt_item.setTextAlignment(Qt.AlignCenter)
                cnt_item.setForeground(QColor(_p("text_value")))

                self._cat_table.setItem(row, 0, label_item)
                self._cat_table.setItem(row, 1, cnt_item)
                self._cat_table.setRowHeight(row, 20)

            # â”€â”€ MITRE tactic chart â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            tactic_counts: dict[str, int] = {}
            tactic_names:  dict[str, str] = {}
            for f in finds:
                for tag in f.mitre_tags:
                    tactic_counts[tag.tactic_id] = (
                        tactic_counts.get(tag.tactic_id, 0) + 1
                    )
                    tactic_names[tag.tactic_id] = tag.tactic_name[:24]

            self._mitre_chart.set_tactics([
                (tactic_names.get(k, k), v)
                for k, v in tactic_counts.items()
            ])

            # â”€â”€ Attack chain cards â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            # Clear existing cards (keep the trailing stretch at index -1)
            while self._chain_vbox.count() > 1:
                item = self._chain_vbox.takeAt(0)
                if item.widget():
                    item.widget().deleteLater()

            if not chains:
                lbl = QLabel("NO MULTI-STAGE ATTACK CHAINS DETECTED", self)
                lbl.setStyleSheet(f"""
                    color: {_p('text_dim')};
                    font-family: {_MONO};
                    font-size: 8px;
                    letter-spacing: 1px;
                    padding: 8px;
                    background: transparent;
                """)
                self._chain_vbox.insertWidget(0, lbl)
            else:
                for c in chains:
                    card = _ChainCard(c, self._chain_inner)
                    self._chain_vbox.insertWidget(
                        self._chain_vbox.count() - 1, card
                    )

        # â”€â”€ Public refresh helper (call after any new analysis run) â”€â”€â”€â”€â”€â”€â”€

        def refresh(self) -> None:
            """Re-load current session and force a full repaint."""
            self.load_session(self._session_id)
            self._sev_bar.update()
            self._mitre_chart.update()

        def _on_stop(self):
            # Optional: handle stop logic for dashboard animations or updates
            pass

        def _export_pdf(self):
            from PySide6.QtWidgets import QFileDialog, QMessageBox
            main_win = self.window()
            findings = getattr(main_win, "_findings_data", [])
            sid = getattr(main_win, "_current_session_id", None)
            
            if not findings:
                QMessageBox.warning(self, "Export Warning", "No findings available to export.")
                return
                
            from datetime import datetime
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_fn = f"dashboard_report_{ts}.pdf"
            
            path, _ = QFileDialog.getSaveFileName(
                self, "Export Dashboard PDF", default_fn, "PDF Files (*.pdf)")
            
            if not path:
                return
                
            try:
                from output.pdf_report import PDFReport
                from ioc_extractor import IOCExtractor
                iocs = IOCExtractor().extract(findings)
                
                report = PDFReport(
                    findings=findings,
                    iocs=iocs,
                    session_id=sid,
                    case_ref="IR-DASHBOARD-EXPORT"
                )
                report.build(path)
                QMessageBox.information(self, "Exported", f"Dashboard report saved to:\n{path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to generate PDF: {e}")


else:
    # â”€â”€ No-op stub when PySide6 is unavailable â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    class DashboardView:                         # type: ignore
        def __init__(self, *a, **kw):  pass
        def load_session(self, *a, **kw): pass
        def refresh(self, *a, **kw):   pass
