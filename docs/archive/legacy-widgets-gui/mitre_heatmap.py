"""
interface/gui/mitre_heatmap.py â€” NexLog v2  MITRE ATT&CK Heatmap
======================================================================
Deep Space styled MITRE ATT&CK matrix heatmap.
Renders the 14 MITRE tactics as columns with technique coverage
painted live as findings load. Tactic cells glow based on hit count.

Color scale:
  0 hits  â†’ bg_surface (dark)
  1-2     â†’ info color dim
  3-5     â†’ amber dim
  6+      â†’ critical/high glow

Usage:
    from interface.gui.mitre_heatmap import MITREHeatmapWidget
    widget = MITREHeatmapWidget(parent=self)
    widget.load_findings(findings)  # auto-paints
"""

import os
import sys
from collections import Counter

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
    from PySide6.QtCore import Qt, QRect, QSize
    from PySide6.QtGui import QColor, QFont, QPainter, QPen, QBrush, QLinearGradient
    from PySide6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel,
        QScrollArea, QSizePolicy, QFrame, QToolTip,
    )
    _HAS_PYSIDE6 = True
except ImportError:
    _HAS_PYSIDE6 = False

try:
    from interface.gui.theme import PALETTE as P, sev_fg, FONT_MONO_CSS
except ImportError:
    try:
        from theme import PALETTE as P, sev_fg, FONT_MONO_CSS
    except ImportError:
        P = {
            "bg_base": "#080C14", "bg_surface": "#0D1420",
            "bg_raised": "#111C2E", "bg_void": "#04080F",
            "border_dim": "#1A2A3F", "border_mid": "#1E3A5A",
            "cyan": "#00C8FF", "amber": "#FFB700",
            "critical": "#FF3B5C", "high": "#FF6B35",
            "info": "#4A8FA8", "text_primary": "#C8DFF0",
            "text_secondary": "#5A8FA8", "text_dim": "#2A4A5E",
        }
        FONT_MONO_CSS = "'JetBrains Mono', 'Consolas', monospace"
        def sev_fg(s): return P.get(s.lower(), P["text_primary"])

_MONO = FONT_MONO_CSS

# â”€â”€ 14 MITRE ATT&CK Tactics (Enterprise) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_TACTICS = [
    ("TA0043", "Reconnaissance",        ["T1595","T1592","T1589","T1590","T1591","T1598","T1597","T1596","T1593","T1594"]),
    ("TA0042", "Resource Development",  ["T1583","T1584","T1585","T1586","T1587","T1588","T1608"]),
    ("TA0001", "Initial Access",        ["T1189","T1190","T1091","T1200","T1566","T1195","T1199","T1078","T1133"]),
    ("TA0002", "Execution",             ["T1059","T1203","T1559","T1106","T1053","T1129","T1072","T1569","T1204","T1047"]),
    ("TA0003", "Persistence",           ["T1197","T1547","T1037","T1176","T1554","T1136","T1543","T1546","T1133","T1574","T1525","T1556","T1137","T1542","T1053","T1505","T1205","T1078"]),
    ("TA0004", "Privilege Escalation",  ["T1548","T1134","T1547","T1037","T1543","T1484","T1611","T1546","T1068","T1574","T1055","T1053","T1078"]),
    ("TA0005", "Defense Evasion",       ["T1548","T1134","T1197","T1622","T1140","T1006","T1484","T1480","T1211","T1222","T1564","T1574","T1562","T1070","T1202","T1036","T1556","T1578","T1112","T1601","T1599","T1027","T1647","T1542","T1055","T1207","T1014","T1218","T1216","T1553","T1221","T1205","T1497","T1600","T1220"]),
    ("TA0006", "Credential Access",     ["T1557","T1110","T1555","T1212","T1187","T1606","T1056","T1556","T1111","T1621","T1040","T1003","T1528","T1558","T1539","T1552","T1550"]),
    ("TA0007", "Discovery",             ["T1087","T1010","T1217","T1580","T1538","T1526","T1619","T1613","T1622","T1482","T1083","T1615","T1046","T1135","T1040","T1201","T1120","T1069","T1057","T1012","T1018","T1518","T1082","T1016","T1049","T1033","T1007","T1124","T1497"]),
    ("TA0008", "Lateral Movement",      ["T1210","T1534","T1570","T1563","T1021","T1091","T1072","T1080","T1550"]),
    ("TA0009", "Collection",            ["T1557","T1560","T1123","T1119","T1115","T1530","T1602","T1213","T1005","T1039","T1025","T1074","T1114","T1185","T1113","T1125"]),
    ("TA0011", "Command and Control",   ["T1071","T1092","T1132","T1001","T1568","T1573","T1008","T1105","T1104","T1095","T1571","T1572","T1090","T1219","T1205","T1102"]),
    ("TA0010", "Exfiltration",          ["T1020","T1030","T1048","T1041","T1011","T1052","T1567","T1029","T1537"]),
    ("TA0040", "Impact",                ["T1531","T1485","T1486","T1565","T1491","T1561","T1499","T1495","T1490","T1498","T1496","T1489","T1529"]),
]

_TACTIC_NAMES  = {t[0]: t[1] for t in _TACTICS}
_TACTIC_TECHS  = {t[0]: set(t[2]) for t in _TACTICS}
_TACTIC_ORDER  = [t[0] for t in _TACTICS]


if _HAS_PYSIDE6:
    class MITREHeatmapWidget(QWidget):
        """
        MITRE ATT&CK coverage heatmap widget.
        Paints tactic columns with heat based on finding hit counts.
        """

        def __init__(self, parent=None):
            super().__init__(parent)
            self._tactic_counts:   Counter = Counter()   # tactic_id â†’ hit count
            self._technique_counts: Counter = Counter()  # technique_id â†’ hit count
            self._max_count = 1
            self.setMinimumHeight(200)
            self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            self.setMouseTracking(True)
            self._hovered_tactic: str = ""

        def load_findings(self, findings: list) -> None:
            """
            Paint the heatmap from a list of findings.
            Call this after each analysis or session load.
            """
            self._tactic_counts.clear()
            self._technique_counts.clear()

            for f in findings:
                if isinstance(f, dict):
                    tags = f.get("mitre_tags", [])
                else:
                    tags = getattr(f, "mitre_tags", [])

                for t in tags:
                    if isinstance(t, dict):
                        tactic_id = t.get("tactic_id", "")
                        tech_id   = t.get("technique_id", "")
                    else:
                        tactic_id = getattr(t, "tactic_id", "")
                        tech_id   = getattr(t, "technique_id", "")

                    if tactic_id:
                        self._tactic_counts[tactic_id] += 1
                    if tech_id:
                        self._technique_counts[tech_id] += 1

            self._max_count = max(self._tactic_counts.values(), default=1)
            self.update()

        def _heat_color(self, count: int) -> QColor:
            """Return heat color for a hit count."""
            if count == 0:
                return QColor(P["bg_surface"])
            ratio = min(count / max(self._max_count, 1), 1.0)
            if ratio < 0.2:
                return QColor(P["info"]).darker(150)
            if ratio < 0.5:
                return QColor(P["amber"]).darker(140)
            if ratio < 0.8:
                return QColor(P["high"]).darker(120)
            return QColor(P["critical"])

        def paintEvent(self, event):
            if not _HAS_PYSIDE6:
                return
            painter = QPainter(self)
            painter.setRenderHint(QPainter.Antialiasing)

            w = self.width()
            h = self.height()

            # Background
            painter.fillRect(0, 0, w, h, QColor(P["bg_base"]))

            n      = len(_TACTIC_ORDER)
            margin = 4
            col_w  = max((w - margin * (n + 1)) // n, 30)
            head_h = 36
            bar_h  = h - head_h - margin * 2

            font_label = QFont("JetBrains Mono", 7)
            font_label.setWeight(QFont.Medium)
            font_count = QFont("JetBrains Mono", 9)
            font_count.setWeight(QFont.Bold)

            for i, tactic_id in enumerate(_TACTIC_ORDER):
                x      = margin + i * (col_w + margin)
                count  = self._tactic_counts.get(tactic_id, 0)
                color  = self._heat_color(count)
                name   = _TACTIC_NAMES.get(tactic_id, "")

                # Column background
                bg_color = QColor(P["bg_raised"]) if tactic_id == self._hovered_tactic else QColor(P["bg_surface"])
                painter.fillRect(x, margin, col_w, h - margin * 2, bg_color)

                # Heat fill bar (bottom-up)
                if count > 0:
                    fill_ratio = min(count / max(self._max_count, 1), 1.0)
                    fill_h     = int(bar_h * fill_ratio)
                    fill_y     = head_h + margin + (bar_h - fill_h)

                    grad = QLinearGradient(x, fill_y + fill_h, x, fill_y)
                    grad.setColorAt(0.0, color.darker(150))
                    grad.setColorAt(1.0, color)
                    painter.fillRect(x, fill_y, col_w, fill_h, grad)

                # Border
                border_col = QColor(P["cyan"]) if tactic_id == self._hovered_tactic \
                             else QColor(P["border_dim"])
                painter.setPen(QPen(border_col, 0.5))
                painter.drawRect(x, margin, col_w, h - margin * 2)

                # Count number
                painter.setFont(font_count)
                painter.setPen(QColor(color if count > 0 else P["text_dim"]))
                painter.drawText(
                    QRect(x, head_h - 20, col_w, 20),
                    Qt.AlignCenter,
                    str(count) if count > 0 else "â€”"
                )

                # Tactic name (rotated-like via short label)
                painter.setFont(font_label)
                painter.setPen(QColor(P["cyan"] if tactic_id == self._hovered_tactic
                                      else P["text_secondary"]))
                short_name = name[:10] + "â€¦" if len(name) > 10 else name
                painter.save()
                painter.translate(x + col_w // 2, margin + 14)
                painter.drawText(QRect(-col_w // 2, -12, col_w, 14),
                                 Qt.AlignCenter, short_name)
                painter.restore()

            painter.end()

        def mouseMoveEvent(self, event):
            w      = self.width()
            n      = len(_TACTIC_ORDER)
            margin = 4
            col_w  = max((w - margin * (n + 1)) // n, 30)
            mx     = event.position().x() if hasattr(event, "position") else event.x()

            hovered = ""
            for i, tactic_id in enumerate(_TACTIC_ORDER):
                x = margin + i * (col_w + margin)
                if x <= mx <= x + col_w:
                    hovered = tactic_id
                    name  = _TACTIC_NAMES.get(tactic_id, "")
                    count = self._tactic_counts.get(tactic_id, 0)
                    techs = [t for t in _TACTIC_TECHS.get(tactic_id, set())
                             if self._technique_counts.get(t, 0) > 0]
                    tip   = (f"{name}\nHits: {count}\n"
                             f"Techniques observed: {', '.join(sorted(techs)[:6]) or 'none'}")
                    QToolTip.showText(event.globalPosition().toPoint(), tip, self)
                    break

            if hovered != self._hovered_tactic:
                self._hovered_tactic = hovered
                self.update()

        def mousePressEvent(self, event):
            pass  # future: drill down to tactic findings

        def sizeHint(self) -> QSize:
            return QSize(800, 180)


    class MITREHeatmapPanel(QFrame):
        """
        Full panel: header label + heatmap + legend.
        Drop this into any tab or splitter.
        """

        def __init__(self, parent=None):
            super().__init__(parent)
            self.setObjectName("glass_card")
            self.setFrameShape(QFrame.StyledPanel)
            self.setStyleSheet(f"""
                QFrame#glass_card {{
                    background-color: {P['bg_surface']};
                    border: 1px solid {P['border_mid']};
                    border-radius: 4px;
                }}
            """)

            layout = QVBoxLayout(self)
            layout.setContentsMargins(8, 6, 8, 6)
            layout.setSpacing(4)

            hdr = QLabel("MITRE ATT&CK COVERAGE HEATMAP")
            hdr.setStyleSheet(f"""
                color: {P['cyan']}; font-family: {_MONO};
                font-size: 9px; letter-spacing: 2px;
                font-weight: bold;
            """)
            layout.addWidget(hdr)

            self._heatmap = MITREHeatmapWidget(self)
            layout.addWidget(self._heatmap)

            # Legend
            legend_row = QHBoxLayout()
            legend_row.setSpacing(12)
            for label, color in [("0 hits", P["bg_raised"]),
                                  ("low", P["info"]),
                                  ("medium", P["amber"]),
                                  ("high", P["high"]),
                                  ("critical", P["critical"])]:
                dot = QLabel("â—")
                dot.setStyleSheet(f"color: {color}; font-size: 10px;")
                lbl = QLabel(label)
                lbl.setStyleSheet(f"""
                    color: {P['text_secondary']};
                    font-family: {_MONO}; font-size: 8px;
                """)
                legend_row.addWidget(dot)
                legend_row.addWidget(lbl)
            legend_row.addStretch()
            layout.addLayout(legend_row)

        def load_findings(self, findings: list) -> None:
            self._heatmap.load_findings(findings)

else:
    class MITREHeatmapWidget:
        def __init__(self, *a, **kw): pass
        def load_findings(self, *a): pass

    class MITREHeatmapPanel:
        def __init__(self, *a, **kw): pass
        def load_findings(self, *a): pass
