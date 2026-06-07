"""
interface/gui/attack_graph_view.py â€” NexLog v2  Attack Graph View
=======================================================================
Force-directed attack graph rendered with QPainter.
Nodes represent hosts/IPs, edges represent attacker movement.

Color coding:
  Red   (#FF3B5C) â€” attacker/source node
  Cyan  (#00C8FF) â€” victim node
  Amber (#FFB700) â€” pivot node (both source and dest)

Node size scales with finding count.
Edge width scales with hit count.
Edge color maps to highest severity.
"""

import math
import os
import random
import sys
import time
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

try:
    from PySide6.QtCore import Qt, QPointF, QRectF, QTimer, Signal, QSize
    from PySide6.QtGui import (
        QColor, QFont, QPainter, QPen, QBrush, QPainterPath,
        QLinearGradient, QRadialGradient,
    )
    from PySide6.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel,
        QPushButton, QSizePolicy, QFrame, QScrollArea,
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
            "border_dim": "#1A2A3F", "border_mid": "#1E3A5A",
            "cyan": "#00C8FF", "cyan_dim": "#007A9C",
            "green": "#00FF9D", "amber": "#FFB700",
            "critical": "#FF3B5C", "high": "#FF6B35",
            "text_primary": "#C8DFF0", "text_secondary": "#5A8FA8",
            "text_dim": "#2A4A5E",
        }
        FONT_MONO_CSS = "'JetBrains Mono','Consolas',monospace"

_MONO = FONT_MONO_CSS

_NODE_COLORS = {
    "attacker": "#FF3B5C",
    "victim":   "#00C8FF",
    "pivot":    "#FFB700",
    "external": "#B060FF",
    "unknown":  "#5A8FA8",
}


if _HAS_PYSIDE6:

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # FORCE LAYOUT  (simple Fruchtermanâ€“Reingold approximation)
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    class _ForceLayout:
        """Minimal force-directed layout engine â€” pure Python."""

        def __init__(self, nodes: list, edges: list, w: int, h: int):
            self.nodes  = nodes
            self.edges  = edges
            self.w      = w
            self.h      = h
            self._init_positions()

        def _init_positions(self):
            random.seed(42)
            max_x = max(100, self.w - 80)
            max_y = max(100, self.h - 80)
            for n in self.nodes:
                if "x" not in n:
                    n["x"] = random.uniform(80, max_x)
                    n["y"] = random.uniform(80, max_y)
                n["vx"] = 0.0
                n["vy"] = 0.0

        def step(self, iterations: int = 1) -> None:
            if not self.nodes:
                return
            area = max(10000, self.w * self.h)
            k    = math.sqrt(area / max(len(self.nodes), 1)) * 0.8
            if k < 1.0: k = 1.0
            cool = 0.92

            for _ in range(iterations):
                # Repulsion between all pairs
                for i, a in enumerate(self.nodes):
                    fx = fy = 0.0
                    for j, b in enumerate(self.nodes):
                        if i == j:
                            continue
                        dx   = a["x"] - b["x"]
                        dy   = a["y"] - b["y"]
                        dist_sq = dx*dx + dy*dy
                        dist    = math.sqrt(dist_sq)
                        if dist < 0.1:
                            # Random nudge to break overlap
                            a["x"] += random.uniform(-1, 1)
                            a["y"] += random.uniform(-1, 1)
                            continue
                        
                        rep  = (k * k) / dist
                        fx  += rep * dx / dist
                        fy  += rep * dy / dist
                    
                    # Cap force to prevent explosion
                    f_mag = math.sqrt(fx*fx + fy*fy)
                    if f_mag > 50:
                        fx = (fx / f_mag) * 50
                        fy = (fy / f_mag) * 50
                        
                    a["vx"] = (a["vx"] + fx) * cool
                    a["vy"] = (a["vy"] + fy) * cool

                # Attraction along edges
                for e in self.edges:
                    src = next((n for n in self.nodes if n["id"] == e["source"]), None)
                    tgt = next((n for n in self.nodes if n["id"] == e["target"]), None)
                    if not src or not tgt:
                        continue
                    dx   = tgt["x"] - src["x"]
                    dy   = tgt["y"] - src["y"]
                    dist_sq = dx*dx + dy*dy
                    dist    = math.sqrt(dist_sq)
                    if dist < 0.1: continue
                    
                    att  = dist_sq / k
                    ax, ay = att * dx / dist, att * dy / dist
                    
                    # Cap attraction
                    a_mag = math.sqrt(ax*ax + ay*ay)
                    if a_mag > 40:
                        ax = (ax / a_mag) * 40
                        ay = (ay / a_mag) * 40

                    src["vx"] += ax;  src["vy"] += ay
                    tgt["vx"] -= ax;  tgt["vy"] -= ay

                # Apply velocities + boundary clamp + NaN check
                for n in self.nodes:
                    if not math.isfinite(n["vx"]): n["vx"] = 0
                    if not math.isfinite(n["vy"]): n["vy"] = 0
                    
                    # Cap velocity
                    v_mag = math.sqrt(n["vx"]*n["vx"] + n["vy"]*n["vy"])
                    if v_mag > 20:
                        n["vx"] = (n["vx"] / v_mag) * 20
                        n["vy"] = (n["vy"] / v_mag) * 20

                    n["x"] += n["vx"]
                    n["y"] += n["vy"]
                    
                    if not math.isfinite(n["x"]): n["x"] = self.w / 2
                    if not math.isfinite(n["y"]): n["y"] = self.h / 2
                    
                    n["x"] = max(40, min(self.w - 40, n["x"]))
                    n["y"] = max(40, min(self.h - 40, n["y"]))

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # ATTACK GRAPH CANVAS
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    class AttackGraphCanvas(QWidget):
        """QPainter-based force-directed attack graph canvas."""

        node_clicked = Signal(dict)   # emits node dict on click

        def __init__(self, parent=None):
            super().__init__(parent)
            self._nodes:   list = []
            self._edges:   list = []
            self._layout:  Optional[_ForceLayout] = None
            self._timer    = QTimer(self)
            self._timer.timeout.connect(self._tick)
            self._settle_ticks = 0
            self._max_settle_ticks = int(os.environ.get("NEXLOG_GRAPH_TICKS", "80"))
            self._selected: Optional[str] = None
            self.setMinimumSize(600, 400)
            self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            self.setMouseTracking(True)
            self._hovered: Optional[str] = None
            self._zoom = 1.0
            self._pan = QPointF(0, 0)
            self._dragging = False
            self._drag_last: Optional[QPointF] = None
            self._labels_visible = True

        def load_graph(self, graph: dict) -> None:
            """Load a graph dict from AttackGraphBuilder.build()."""
            self._timer.stop()
            self._nodes = [dict(n) for n in graph.get("nodes", [])]
            self._edges = [dict(e) for e in graph.get("edges", [])]
            self._layout = None
            self._selected = None
            self._hovered  = None

            if self._nodes:
                self._layout = _ForceLayout(
                    self._nodes, self._edges, self.width(), self.height())
                # Pre-run 80 iterations for initial layout
                self._layout.step(80)
                self.fit_to_view(update=False)
                self._settle_ticks = 0
                self._timer.start(100)  # light settlement without burning CPU
            self.update()

        def _event_pos(self, event) -> QPointF:
            return event.position() if hasattr(event, "position") else event.localPos()

        def _to_scene(self, view_pos: QPointF) -> QPointF:
            z = max(self._zoom, 0.01)
            return QPointF(
                (view_pos.x() - self._pan.x()) / z,
                (view_pos.y() - self._pan.y()) / z,
            )

        def _set_zoom(self, zoom: float, anchor: Optional[QPointF] = None) -> None:
            zoom = max(0.35, min(zoom, 3.0))
            if anchor is None:
                anchor = QPointF(self.width() / 2, self.height() / 2)
            scene_before = self._to_scene(anchor)
            self._zoom = zoom
            self._pan = QPointF(
                anchor.x() - scene_before.x() * self._zoom,
                anchor.y() - scene_before.y() * self._zoom,
            )
            self.update()

        def zoom_in(self) -> None:
            self._set_zoom(self._zoom * 1.18)

        def zoom_out(self) -> None:
            self._set_zoom(self._zoom / 1.18)

        def reset_view(self) -> None:
            self._zoom = 1.0
            self._pan = QPointF(0, 0)
            self.update()

        def fit_to_view(self, update: bool = True) -> None:
            if not self._nodes:
                self.reset_view()
                return

            xs = [float(n.get("x", 0)) for n in self._nodes]
            ys = [float(n.get("y", 0)) for n in self._nodes]
            min_x, max_x = min(xs), max(xs)
            min_y, max_y = min(ys), max(ys)
            graph_w = max(1.0, max_x - min_x)
            graph_h = max(1.0, max_y - min_y)
            view_w = max(1.0, self.width() - 96)
            view_h = max(1.0, self.height() - 96)
            self._zoom = max(0.35, min(min(view_w / graph_w, view_h / graph_h), 2.3))
            center_x = (min_x + max_x) / 2
            center_y = (min_y + max_y) / 2
            self._pan = QPointF(
                self.width() / 2 - center_x * self._zoom,
                self.height() / 2 - center_y * self._zoom,
            )
            if update:
                self.update()

        def set_labels_visible(self, visible: bool) -> None:
            self._labels_visible = bool(visible)
            self.update()

        def labels_visible(self) -> bool:
            return self._labels_visible

        def _tick(self):
            if self._layout:
                self._layout.step(2)
                self._settle_ticks += 1
                if self._settle_ticks >= self._max_settle_ticks:
                    self._timer.stop()
            self.update()

        def stop_animation(self):
            self._timer.stop()

        def paintEvent(self, event):
            if not self._nodes:
                p = QPainter(self)
                try:
                    p.fillRect(self.rect(), QColor(P["bg_base"]))
                    p.setPen(QColor(P["text_dim"]))
                    p.setFont(QFont("JetBrains Mono", 10))
                    p.drawText(self.rect(), Qt.AlignCenter,
                               "No findings loaded\nRun analysis first")
                finally:
                    p.end()
                return

            painter = QPainter(self)
            try:
                painter.setRenderHint(QPainter.Antialiasing)
                painter.setRenderHint(QPainter.SmoothPixmapTransform)
                painter.fillRect(self.rect(), QColor(P["bg_base"]))
                painter.save()
                painter.translate(self._pan)
                painter.scale(self._zoom, self._zoom)

                node_pos = {n["id"]: (n["x"], n["y"]) for n in self._nodes}

                # â”€â”€ Pulse animation for critical nodes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                # Use time.time() for animation; ensure it's available
                import time as _time
                pulse = (math.sin(_time.time() * 5) + 1) / 2  # 0 to 1

                # â”€â”€ Draw edges â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                for e in self._edges:
                    src_pos = node_pos.get(e["source"])
                    tgt_pos = node_pos.get(e["target"])
                    if not src_pos or not tgt_pos:
                        continue

                    color = QColor(e.get("color", P["border_mid"]))
                    width = max(1.2, min(float(e.get("weight", 1)) * 0.8, 6.0))
                    
                    # Gradient edge
                    sx, sy = src_pos
                    tx, ty = tgt_pos
                    
                    grad = QLinearGradient(sx, sy, tx, ty)
                    c1 = QColor(color); c1.setAlpha(180)
                    c2 = QColor(color); c2.setAlpha(60)
                    grad.setColorAt(0, c1)
                    grad.setColorAt(1, c2)
                    
                    pen = QPen(QBrush(grad), width)
                    pen.setCapStyle(Qt.RoundCap)
                    painter.setPen(pen)

                    # Draw curved edge
                    path = QPainterPath()
                    path.moveTo(sx, sy)
                    # Control point for curve
                    mx   = (sx + tx) / 2 + (ty - sy) * 0.18
                    my   = (sy + ty) / 2 - (tx - sx) * 0.18
                    path.quadTo(mx, my, tx, ty)
                    
                    # â”€â”€ ENHANCEMENT: Edge glow and precision rendering â”€â”€â”€â”€
                    glow_pen = QPen(QBrush(c1), width + 2.5)
                    glow_pen.setCapStyle(Qt.RoundCap)
                    c_glow = QColor(color)
                    c_glow.setAlpha(35)
                    glow_pen.setColor(c_glow)
                    painter.setPen(glow_pen)
                    painter.drawPath(path)
                    
                    painter.setPen(pen)
                    painter.drawPath(path)

                    # Arrowhead (closer to target)
                    angle  = math.atan2(ty - my, tx - mx)
                    arr_len = 10.0
                    painter.setPen(Qt.NoPen)
                    painter.setBrush(QBrush(c1))
                    arrow = QPainterPath()
                    # Offset arrow slightly from node center
                    atx = tx - 15 * math.cos(angle)
                    aty = ty - 15 * math.sin(angle)
                    arrow.moveTo(atx, aty)
                    arrow.lineTo(
                        atx - arr_len * math.cos(angle - 0.35),
                        aty - arr_len * math.sin(angle - 0.35))
                    arrow.lineTo(
                        atx - arr_len * math.cos(angle + 0.35),
                        aty - arr_len * math.sin(angle + 0.35))
                    arrow.closeSubpath()
                    painter.drawPath(arrow)

                    # Technique label on edge midpoint
                    if self._labels_visible and e.get("techniques"):
                        tech = e["techniques"][0]
                        painter.setFont(QFont("JetBrains Mono", 7))
                        tc = QColor(P["text_dim"])
                        tc.setAlpha(220)
                        painter.setPen(tc)
                        painter.drawText(
                            QRectF(mx - 40, my - 8, 80, 16),
                            Qt.AlignCenter, tech)

                # â”€â”€ Draw nodes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
                font_label = QFont("JetBrains Mono", 8)
                font_label.setWeight(QFont.Medium)

                for n in self._nodes:
                    nx, ny  = n["x"], n["y"]
                    ntype   = n.get("type", "unknown")
                    color   = QColor(_NODE_COLORS.get(ntype, P["text_dim"]))
                    count   = n.get("findings_count", 1)
                    radius  = max(14, min(14 + count * 1.8, 35))

                    is_sel  = (n["id"] == self._selected)
                    is_hov  = (n["id"] == self._hovered)
                    is_crit = (n.get("max_risk", 0) >= 8.0)

                    # Outer Glow
                    glow_col = QColor(color)
                    glow_alpha = 40
                    if is_sel: glow_alpha = 80
                    elif is_hov: glow_alpha = 60
                    
                    if is_crit:
                        # Pulsing glow for critical nodes
                        glow_alpha += int(20 * pulse)
                    
                    glow_col.setAlpha(glow_alpha)
                    painter.setPen(Qt.NoPen)
                    painter.setBrush(QBrush(glow_col))
                    painter.drawEllipse(QPointF(nx, ny), radius + 6, radius + 6)
                    
                    glow_col.setAlpha(glow_alpha // 2)
                    painter.drawEllipse(QPointF(nx, ny), radius + 12, radius + 12)

                    # Node Body (Radial Gradient)
                    grad = QRadialGradient(nx - radius/3, ny - radius/3, radius * 1.5)
                    c_light = QColor(color); c_light = c_light.lighter(120)
                    c_dark  = QColor(color); c_dark  = c_dark.darker(110)
                    grad.setColorAt(0, c_light)
                    grad.setColorAt(0.7, color)
                    grad.setColorAt(1, c_dark)
                    
                    painter.setPen(QPen(color, 2.0 if is_sel else 1.0))
                    painter.setBrush(QBrush(grad))
                    painter.drawEllipse(QPointF(nx, ny), radius, radius)

                    # Risk indicator (inner ring)
                    risk = n.get("max_risk", 0)
                    if risk > 0:
                        painter.setBrush(Qt.NoBrush)
                        r_col = QColor(P["critical"] if risk >= 7 else P["amber"] if risk >= 4 else P["green"])
                        r_col.setAlpha(150)
                        painter.setPen(QPen(r_col, 2))
                        # Draw partial arc based on risk
                        span = int((risk / 10.0) * 360 * 16)
                        painter.drawArc(QRectF(nx-radius+3, ny-radius+3, radius*2-6, radius*2-6), 90*16, -span)

                    # Label
                    painter.setFont(font_label)
                    painter.setPen(QColor(P["text_primary"]))
                    label = n.get("label") or n.get("id", "node")
                    if len(label) > 18:
                        label = label[:16] + "â€¦"
                    
                    # Label background for readability
                    lbl_rect = QRectF(nx - 70, ny + radius + 4, 140, 16)
                    if self._labels_visible:
                        painter.drawText(lbl_rect, Qt.AlignCenter, label)
                painter.restore()
            finally:
                painter.end()

        def mouseMoveEvent(self, event):
            pos = self._event_pos(event)
            if self._dragging and self._drag_last is not None:
                delta = pos - self._drag_last
                self._pan = QPointF(self._pan.x() + delta.x(), self._pan.y() + delta.y())
                self._drag_last = pos
                self.update()
                event.accept()
                return

            scene_pos = self._to_scene(pos)
            mx, my = scene_pos.x(), scene_pos.y()
            hov = None
            for n in self._nodes:
                dx = n["x"] - mx; dy = n["y"] - my
                r  = max(12, min(12 + n.get("findings_count", 1) * 1.5, 30))
                if dx*dx + dy*dy <= r*r:
                    hov = n["id"]; break
            if hov != self._hovered:
                self._hovered = hov
                self.update()

        def mousePressEvent(self, event):
            pos = self._event_pos(event)
            if event.button() in (Qt.MiddleButton, Qt.RightButton):
                self._dragging = True
                self._drag_last = pos
                event.accept()
                return

            if event.button() != Qt.LeftButton:
                return

            scene_pos = self._to_scene(pos)
            mx, my = scene_pos.x(), scene_pos.y()
            for n in self._nodes:
                dx = n["x"] - mx; dy = n["y"] - my
                r  = max(12, min(12 + n.get("findings_count", 1) * 1.5, 30))
                if dx*dx + dy*dy <= r*r:
                    self._selected = n["id"]
                    self.node_clicked.emit(n)
                    self.update()
                    return
            self._selected = None
            self.update()

        def mouseReleaseEvent(self, event):
            if event.button() in (Qt.MiddleButton, Qt.RightButton):
                self._dragging = False
                self._drag_last = None
                event.accept()

        def mouseDoubleClickEvent(self, event):
            self.fit_to_view()
            event.accept()

        def wheelEvent(self, event):
            pos = self._event_pos(event)
            delta = event.angleDelta().y()
            factor = 1.12 if delta > 0 else 1 / 1.12
            self._set_zoom(self._zoom * factor, pos)
            event.accept()

        def sizeHint(self) -> QSize:
            return QSize(800, 500)

        def resizeEvent(self, event):
            super().resizeEvent(event)
            if self._layout:
                self._layout.w = max(self.width(), 120)
                self._layout.h = max(self.height(), 120)
                self._layout.step(20)
                self.fit_to_view(update=False)
                self._settle_ticks = 0
                if self.isVisible():
                    self._timer.start(100)

        def hideEvent(self, event):
            self._timer.stop()
            super().hideEvent(event)

        def showEvent(self, event):
            super().showEvent(event)
            if self._layout and self._settle_ticks < self._max_settle_ticks:
                self._timer.start(100)


    class AttackGraphView(QFrame):
        """
        Full attack graph panel with header, canvas, legend, and stats.
        Integrates with the main window tab system.
        """

        def __init__(self, parent=None):
            super().__init__(parent)
            self.setObjectName("glass_card")
            self.setStyleSheet(f"""
                QFrame#glass_card {{
                    background-color: {P['bg_base']};
                    border: 1px solid {P['border_mid']};
                }}
            """)

            layout = QVBoxLayout(self)
            layout.setContentsMargins(8, 6, 8, 6)
            layout.setSpacing(6)

            # Header
            hdr_row = QHBoxLayout()
            hdr     = QLabel("ATTACK GRAPH  â€”  LATERAL MOVEMENT MAP")
            hdr.setStyleSheet(f"""
                color: {P['cyan']}; font-family: {_MONO};
                font-size: 9px; letter-spacing: 2px; font-weight: bold;
            """)
            hdr_row.addWidget(hdr)
            hdr_row.addStretch()

            self._stats_label = QLabel("")
            self._stats_label.setStyleSheet(f"""
                color: {P['text_secondary']}; font-family: {_MONO}; font-size: 8px;
            """)
            hdr_row.addWidget(self._stats_label)

            def _ctrl(label: str, tip: str) -> QPushButton:
                btn = QPushButton(label)
                btn.setToolTip(tip)
                btn.setStyleSheet(f"""
                    QPushButton {{
                        background: transparent; color: {P['text_secondary']};
                        border: 1px solid {P['border_dim']}; border-radius: 7px;
                        padding: 4px 9px; font-family: {_MONO}; font-size: 8px;
                    }}
                    QPushButton:hover {{ color: {P['cyan']}; border-color: {P['cyan']}; }}
                """)
                return btn

            btn_fit = _ctrl("[ FIT ]", "Fit the graph to the visible canvas")
            btn_fit.clicked.connect(self._on_fit)
            hdr_row.addWidget(btn_fit)

            btn_zoom_in = _ctrl("[ + ]", "Zoom in")
            btn_zoom_in.clicked.connect(self._canvas_zoom_in)
            hdr_row.addWidget(btn_zoom_in)

            btn_zoom_out = _ctrl("[ - ]", "Zoom out")
            btn_zoom_out.clicked.connect(self._canvas_zoom_out)
            hdr_row.addWidget(btn_zoom_out)

            self._btn_labels = _ctrl("[ LABELS ]", "Toggle node and technique labels")
            self._btn_labels.clicked.connect(self._toggle_labels)
            hdr_row.addWidget(self._btn_labels)

            btn_stop = QPushButton("[ STOP ]")
            btn_stop.setStyleSheet(f"""
                QPushButton {{
                    background: transparent; color: {P['text_secondary']};
                    border: 1px solid {P['border_dim']}; border-radius: 2px;
                    padding: 2px 8px; font-family: {_MONO}; font-size: 8px;
                }}
                QPushButton:hover {{ color: {P['amber']}; border-color: {P['amber']}; }}
            """)
            btn_stop.clicked.connect(self._on_stop)
            hdr_row.addWidget(btn_stop)

            btn_pdf = QPushButton("[ PDF ]")
            btn_pdf.setStyleSheet(f"""
                QPushButton {{
                    background: transparent; color: {P['text_secondary']};
                    border: 1px solid {P['border_dim']}; border-radius: 2px;
                    padding: 2px 8px; font-family: {_MONO}; font-size: 8px;
                }}
                QPushButton:hover {{ color: {P['cyan']}; border-color: {P['cyan']}; }}
            """)
            btn_pdf.clicked.connect(self._export_pdf)
            hdr_row.addWidget(btn_pdf)

            layout.addLayout(hdr_row)

            # Canvas
            self._canvas = AttackGraphCanvas(self)
            self._canvas.node_clicked.connect(self._on_node_clicked)
            layout.addWidget(self._canvas)

            # Detail label
            self._detail = QLabel("Click a node for details")
            self._detail.setStyleSheet(f"""
                color: {P['text_secondary']}; font-family: {_MONO}; font-size: 8px;
                padding: 4px;
            """)
            self._detail.setWordWrap(True)
            layout.addWidget(self._detail)

            # Legend
            legend_row = QHBoxLayout()
            for label, color in [
                ("Attacker", P["critical"]),
                ("Victim",   P["cyan"]),
                ("Pivot",    P["amber"]),
            ]:
                dot = QLabel("â—")
                dot.setStyleSheet(f"color: {color}; font-size: 11px;")
                lbl = QLabel(label)
                lbl.setStyleSheet(f"""
                    color: {P['text_secondary']}; font-family: {_MONO}; font-size: 8px;
                """)
                legend_row.addWidget(dot)
                legend_row.addWidget(lbl)
                legend_row.addSpacing(8)
            legend_row.addStretch()
            layout.addLayout(legend_row)

        def load_graph(self, graph: dict) -> None:
            self._canvas.load_graph(graph)
            stats = graph.get("stats", {})
            self._stats_label.setText(
                f"{stats.get('node_count',0)} nodes  "
                f"{stats.get('edge_count',0)} edges  "
                f"attackers: {len(stats.get('attacker_ips',[]))}"
            )

        def load_findings(self, findings: list) -> None:
            """Build graph from findings and display."""
            try:
                from output.attack_graph import AttackGraphBuilder
                builder = AttackGraphBuilder()
                graph   = builder.build(findings)
                self.load_graph(graph)
            except Exception as e:
                self._detail.setText(f"Graph build error: {e}")

        def _on_fit(self):
            self._canvas.fit_to_view()

        def _canvas_zoom_in(self):
            self._canvas.zoom_in()

        def _canvas_zoom_out(self):
            self._canvas.zoom_out()

        def _toggle_labels(self):
            visible = not self._canvas.labels_visible()
            self._canvas.set_labels_visible(visible)
            self._btn_labels.setText("[ LABELS ]" if visible else "[ LABELS OFF ]")

        def _on_stop(self):
            self._canvas.stop_animation()

        def _on_node_clicked(self, node: dict):
            tactics = ", ".join(node.get("tactics", [])[:4]) or "none observed"
            self._detail.setText(
                f"Node: {node['id']}  |  Type: {node['type']}  "
                f"|  Findings: {node['findings_count']}  "
                f"|  Max risk: {node['max_risk']:.1f}/10  "
                f"|  Tactics: {tactics}"
            )

        def _export_pdf(self):
            if not getattr(self._canvas, "_nodes", None):
                return
            from datetime import datetime
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_fn = f"attack_graph_{ts}.pdf"
            
            from PySide6.QtWidgets import QFileDialog, QMessageBox
            path, _ = QFileDialog.getSaveFileName(
                self, "Export Attack Graph PDF", default_fn, "PDF Files (*.pdf)")
            
            if not path:
                return
                
            try:
                from output.pdf_report import PDFReport
                from storage.case_db import CaseDB
                
                # Attempt to get full findings from DB if possible
                findings = []
                main_win = self.window()
                sid = getattr(main_win, "_current_session_id", None)
                db_path = getattr(main_win, "_case_db", None)
                findings = getattr(main_win, "_findings_data", [])
                
                if not findings and db_path and sid:
                    with CaseDB(db_path) as db:
                        findings = db.get_findings(session_id=sid, limit=2000)
                
                # Fallback to local data if findings empty (not recommended but safe)
                if not findings:
                    # Construct mock findings from node/edge data? No, better to error
                    QMessageBox.warning(self, "Export Warning", "Could not retrieve full findings for detailed PDF.")
                    return

                report = PDFReport(
                    findings=findings,
                    session_id=sid,
                    case_ref="IR-GRAPH-EXPORT"
                )
                report.build(path)
                QMessageBox.information(self, "Exported", f"Attack graph data exported to PDF:\n{path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Error", f"Failed to generate PDF: {e}")

else:
    class AttackGraphCanvas:
        def __init__(self, *a, **kw): pass
        def load_graph(self, *a): pass

    class AttackGraphView:
        def __init__(self, *a, **kw): pass
        def load_graph(self, *a): pass
        def load_findings(self, *a): pass
