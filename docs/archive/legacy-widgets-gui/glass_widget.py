"""
interface/gui/glass_widget.py â€” NexLog v2
================================================
Real glass morphism for PySide6.
Uses screen capture + software blur â€” no OpenGL, no compositor required.
Integrates with theme.py colour palette.

Key rule from master prompt:
  "GlassPanel NEVER uses QSS for transparency.
   All transparency through QPainter + screen.grabWindow()."

Fixes v2.1:
  â€¢ GlassPreset else-branch: each preset now has its own distinct {} dict â€”
    the original code used `A = B = C = {}` which made all presets the same
    object, so mutating one mutated all.
  â€¢ GlassPanel.paintEvent: added w/h size guard â€” painting on a 0Ã—0 widget
    causes Qt warnings and noop QPainter operations that can corrupt state.
  â€¢ GlassPanel._capture_background: grabWindow(0,...) is deprecated in Qt6
    and silently returns a null pixmap on some Wayland compositors even when
    _COMPOSITOR_OK=True. Added explicit null-pixmap guard + legacy fallback.
  â€¢ GlassPanel._capture_background: null pixmap from grabWindow now properly
    sets _capture_valid=False rather than storing a null QPixmap.
"""

from __future__ import annotations
import platform
import math
import os
from typing import Optional

try:
    from PySide6.QtWidgets import (
        QWidget, QApplication, QGraphicsScene,
        QGraphicsPixmapItem, QGraphicsBlurEffect,
    )
    from PySide6.QtCore  import Qt, QRect, QPoint, QTimer, QRectF
    from PySide6.QtGui   import (
        QPainter, QColor, QLinearGradient, QPainterPath,
        QPixmap, QPen, QRadialGradient, QBrush,
    )
    _HAS_PYSIDE6 = True
except ImportError:
    _HAS_PYSIDE6 = False


# â”€â”€ Palette mirrors theme.py exactly â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_SURFACE = "#0D1420"
_RAISED  = "#111C2E"
_GLASS_CAPTURE_ENABLED = os.environ.get(
    "NEXLOG_ENABLE_GLASS", ""
).strip().lower() in {"1", "true", "yes", "on"}


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# GLASS PRESETS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class GlassPreset:
    """
    Named presets keyed to theme.py severity palette.
    Each preset is a plain dict â€” no class instantiation overhead.

    FIX v2.1: each attribute is now a separate dict literal.
    The original `DEFAULT = CRITICAL = HIGH = ... = {}` made every
    attribute point to the SAME object â€” mutating one mutated all.
    """

    if _HAS_PYSIDE6:
        DEFAULT  = dict(tint=QColor(13, 20, 32, 185),   border=QColor(255, 255, 255, 22),  highlight=QColor(255, 255, 255, 12),  blur_radius=22, corner=14)
        CRITICAL = dict(tint=QColor(80, 12, 24, 200),   border=QColor(255, 59, 92, 85),    highlight=QColor(255, 59, 92, 20),    blur_radius=24, corner=14)
        HIGH     = dict(tint=QColor(80, 40, 8, 200),    border=QColor(255, 107, 53, 85),   highlight=QColor(255, 107, 53, 20),   blur_radius=22, corner=14)
        MEDIUM   = dict(tint=QColor(70, 55, 5, 200),    border=QColor(255, 183, 0, 75),    highlight=QColor(255, 183, 0, 18),    blur_radius=22, corner=14)
        LOW      = dict(tint=QColor(5, 60, 35, 200),    border=QColor(0, 255, 157, 65),    highlight=QColor(0, 255, 157, 15),    blur_radius=22, corner=14)
        AI       = dict(tint=QColor(30, 12, 55, 200),   border=QColor(157, 91, 222, 85),   highlight=QColor(157, 91, 222, 18),   blur_radius=26, corner=16)
        PANEL    = dict(tint=QColor(8, 12, 20, 215),    border=QColor(255, 255, 255, 14),  highlight=QColor(255, 255, 255, 8),   blur_radius=18, corner=10)
        INFO     = dict(tint=QColor(0, 50, 80, 200),    border=QColor(0, 180, 255, 75),    highlight=QColor(0, 180, 255, 18),    blur_radius=22, corner=14)
        PDF      = dict(tint=QColor(60, 20, 20, 210),   border=QColor(255, 80, 80, 90),    highlight=QColor(255, 100, 100, 25),  blur_radius=24, corner=14)
    else:
        # FIX: each is its own dict â€” no shared-object mutation risk
        DEFAULT  = {}
        CRITICAL = {}
        HIGH     = {}
        MEDIUM   = {}
        LOW      = {}
        AI       = {}
        PANEL    = {}
        INFO     = {}
        PDF      = {}


# â”€â”€ Compositor detection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _compositor_available() -> bool:
    """
    Returns True if screen capture will yield real pixel content.
    Windows: always True (DWM).
    macOS:   always True (Quartz).
    Linux:   check XDG_SESSION_TYPE and compositor presence.
    """
    system = platform.system()
    if system in ("Windows", "Darwin"):
        return True

    # Linux / BSD
    session = os.environ.get("XDG_SESSION_TYPE", "").lower()
    if "wayland" in session:
        return False   # grabWindow(0) not reliable on Wayland

    display = os.environ.get("DISPLAY", "")
    if not display:
        return False

    try:
        import subprocess
        result = subprocess.run(
            ["xprop", "-root", "_NET_SUPPORTING_WM_CHECK"],
            capture_output=True, timeout=1,
        )
        return result.returncode == 0
    except Exception:
        return True   # assume compositor present if xprop unavailable


_COMPOSITOR_OK = _compositor_available()


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# GLASS PANEL
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

if _HAS_PYSIDE6:

    class GlassPanel(QWidget):
        """
        Real glass morphism base class for PySide6.

        Rendering pipeline (per paintEvent):
          1. Temporarily hide self â†’ grab screen pixels behind widget
          2. Software-blur the capture (QGraphicsBlurEffect, no GPU needed)
          3. Paint: blurred_bg â†’ tint gradient â†’ inner highlight â†’ border
          4. Optional: radial outer glow (animated via QTimer)

        Usage â€” as base class:
            class MyCard(GlassPanel):
                def __init__(self, parent):
                    super().__init__(parent, preset=GlassPreset.CRITICAL)

        Usage â€” standalone:
            panel = GlassPanel(parent=self, preset=GlassPreset.AI)
            panel.setGeometry(10, 10, 300, 200)

        Hot-swap preset at runtime:
            card.set_preset(GlassPreset.HIGH)
            card.set_severity("CRITICAL")   # convenience wrapper

        Glow pulse:
            card.start_glow_pulse(QColor("#FF3B5C"))
            card.stop_glow_pulse()
        """

        def __init__(
            self,
            parent: Optional[QWidget] = None,
            *,
            preset:         Optional[dict]   = None,
            tint:           Optional[QColor] = None,
            border:         Optional[QColor] = None,
            highlight:      Optional[QColor] = None,
            blur_radius:    int  = 22,
            corner:         int  = 14,
            glow_color:     Optional[QColor] = None,
            glow_strength:  int  = 0,
            auto_refresh:   bool = True,
        ):
            super().__init__(parent)

            p = preset or GlassPreset.DEFAULT
            self._tint        = tint      or p.get("tint",      QColor(13, 20, 32, 185))
            self._border      = border    or p.get("border",    QColor(255, 255, 255, 22))
            self._highlight   = highlight or p.get("highlight", QColor(255, 255, 255, 12))
            self._blur_radius = p.get("blur_radius", blur_radius)
            self._corner      = p.get("corner",      corner)
            self._glow_color  = glow_color
            self._glow_strength  = glow_strength
            self._auto_refresh   = auto_refresh and _GLASS_CAPTURE_ENABLED

            # Qt transparency â€” lets us paint a custom background
            self.setAttribute(Qt.WA_TranslucentBackground)
            self.setAttribute(Qt.WA_NoSystemBackground)
            self.setAutoFillBackground(False)

            self._cached_bg: Optional[QPixmap] = None
            self._capture_valid = False

            # Glow pulse animation
            self._glow_timer = QTimer(self)
            self._glow_timer.timeout.connect(self._pulse_tick)
            self._glow_phase = 0.0

            # â”€â”€ FIX v2.1: refresh debouncing â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            self._refresh_timer = QTimer(self)
            self._refresh_timer.setSingleShot(True)
            self._refresh_timer.timeout.connect(self._do_refresh_glass)
            self._refresh_pending = False

        # â”€â”€ Public API â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def set_preset(self, preset: dict) -> None:
            """Hot-swap preset at runtime."""
            self._tint        = preset.get("tint",      self._tint)
            self._border      = preset.get("border",    self._border)
            self._highlight   = preset.get("highlight", self._highlight)
            self._blur_radius = preset.get("blur_radius", self._blur_radius)
            self._corner      = preset.get("corner",    self._corner)
            self._capture_valid = False
            self.update()

        def set_severity(self, severity: str) -> None:
            """Convenience: 'CRITICAL'/'HIGH'/'MEDIUM'/'LOW'/'INFO'."""
            mapping = {
                "CRITICAL": GlassPreset.CRITICAL,
                "HIGH":     GlassPreset.HIGH,
                "MEDIUM":   GlassPreset.MEDIUM,
                "LOW":      GlassPreset.LOW,
                "INFO":     GlassPreset.INFO,
            }
            p = mapping.get(severity.upper(), GlassPreset.DEFAULT)
            if p:   # guard: preset may be {} in the no-PySide6 stub branch
                self.set_preset(p)

        def start_glow_pulse(self, color: QColor, interval_ms: int = 1200) -> None:
            """Animate a radial glow halo."""
            self._glow_color = color
            self._glow_timer.start(16)   # ~60 fps
            self._glow_phase = 0.0

        def stop_glow_pulse(self) -> None:
            self._glow_timer.stop()
            self._glow_color = None
            self.update()

        def refresh_glass(self) -> None:
            """
            Schedule a screen re-capture.
            Restarts the timer on every call so that captures only happen
            80ms AFTER the last movement (prevents blinking during dragging).
            """
            if not _GLASS_CAPTURE_ENABLED:
                self._capture_valid = False
                self.update()
                return
            self._refresh_pending = True
            self._refresh_timer.start(80)   # 80ms delay

        def _do_refresh_glass(self) -> None:
            """Internal capture + paint update."""
            self._cached_bg = self._capture_background()
            # FIX: guard against null pixmap returned by grabWindow on some platforms
            self._capture_valid = (
                self._cached_bg is not None
                and not self._cached_bg.isNull()
                and self._cached_bg.width() > 0
                and self._cached_bg.height() > 0
            )
            self._refresh_pending = False
            self.update()

        # â”€â”€ Qt Events â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def showEvent(self, event):
            super().showEvent(event)
            if self._auto_refresh:
                QTimer.singleShot(60, self.refresh_glass)

        def moveEvent(self, event):
            super().moveEvent(event)
            if self._auto_refresh:
                self._capture_valid = False
                self.refresh_glass()

        def resizeEvent(self, event):
            super().resizeEvent(event)
            if self._auto_refresh:
                self._capture_valid = False
                self.refresh_glass()

        def paintEvent(self, event):
            # FIX: guard zero-size widget â€” painting on 0Ã—0 generates Qt
            # warnings and can corrupt QPainter state on some platforms.
            w = self.width()
            h = self.height()
            if w <= 0 or h <= 0:
                return

            painter = QPainter(self)
            painter.setRenderHint(QPainter.Antialiasing)
            painter.setRenderHint(QPainter.SmoothPixmapTransform)

            r = self._corner

            # â”€â”€ Optional outer glow â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            if self._glow_color and self._glow_strength > 0:
                self._paint_outer_glow(painter, w, h, r)

            # â”€â”€ Rounded clip region â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            clip = QPainterPath()
            clip.addRoundedRect(QRectF(0, 0, w, h), r, r)
            painter.setClipPath(clip)

            # â”€â”€ Layer 1: blurred screen capture â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            if self._capture_valid and self._cached_bg:
                blurred = self._blur(self._cached_bg)
                painter.drawPixmap(0, 0, blurred)
            else:
                # Fallback: solid surface (Wayland / no compositor / null grab)
                fallback = QColor(_SURFACE)
                fallback.setAlpha(230)
                painter.fillPath(clip, QBrush(fallback))

            # â”€â”€ Layer 2: tint gradient â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            grad = QLinearGradient(0, 0, 0, h)
            c_top = QColor(self._tint)
            c_bot = QColor(self._tint)
            c_top.setAlpha(min(255, self._tint.alpha() + 20))
            c_bot.setAlpha(max(0,   self._tint.alpha() - 30))
            grad.setColorAt(0.0, c_top)
            grad.setColorAt(1.0, c_bot)
            painter.fillPath(clip, QBrush(grad))

            # â”€â”€ Layer 3: inner highlight shimmer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            shimmer = QPainterPath()
            shimmer.addRoundedRect(QRectF(1, 1, w - 2, h * 0.28), r, r)
            painter.fillPath(shimmer, QBrush(self._highlight))

            # â”€â”€ Layer 4: border â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            painter.setClipping(False)
            painter.setPen(QPen(self._border, 1.0))
            painter.setBrush(Qt.NoBrush)
            border_path = QPainterPath()
            border_path.addRoundedRect(QRectF(0.5, 0.5, w - 1, h - 1), r, r)
            painter.drawPath(border_path)

            painter.end()

        # â”€â”€ Private â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        def _capture_background(self) -> Optional[QPixmap]:
            """
            Captures pixels 'behind' the widget for the glass effect.

            FIX v2.2: Removed visible blinking and layout jitter.
            We use setRetainSizeWhenHidden(True) so that hiding the widget
            during capture does not trigger a layout recalculation that
            moves siblings (the cause of 'moving' and 'blinking').
            """
            if not _GLASS_CAPTURE_ENABLED:
                return None
            if not _HAS_PYSIDE6:
                return None

            parent = self.parentWidget()
            w, h = self.width(), self.height()
            if w <= 0 or h <= 0:
                return None

            # Temporarily hide but KEEP our spot in the layout
            sp = self.sizePolicy()
            old_retain = sp.retainSizeWhenHidden()
            sp.setRetainSizeWhenHidden(True)
            self.setSizePolicy(sp)

            # â”€â”€ Method A: Internal Render (Blink-Free) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            if parent:
                try:
                    self.hide()
                    px = QPixmap(self.size())
                    px.fill(Qt.transparent)
                    parent.render(px, QPoint(), QRect(self.pos(), self.size()))
                    self.show()

                    sp.setRetainSizeWhenHidden(old_retain)
                    self.setSizePolicy(sp)

                    if not px.isNull():
                        return px
                except Exception:
                    pass

            # â”€â”€ Method B: Screen Grab (Fallback) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            if not _COMPOSITOR_OK:
                return None

            screen = QApplication.primaryScreen()
            if screen:
                try:
                    gp = self.mapToGlobal(QPoint(0, 0))
                    self.hide()
                    px = screen.grabWindow(0, gp.x(), gp.y(), w, h)
                    self.show()

                    sp.setRetainSizeWhenHidden(old_retain)
                    self.setSizePolicy(sp)

                    return px if (px and not px.isNull()) else None
                except Exception:
                    pass

            sp.setRetainSizeWhenHidden(old_retain)
            self.setSizePolicy(sp)
            return None

        def _blur(self, source: QPixmap) -> QPixmap:
            """
            Software Gaussian blur via QGraphicsBlurEffect.
            No OpenGL needed â€” pure Qt raster pipeline.
            """
            scene  = QGraphicsScene()
            item   = QGraphicsPixmapItem(source)
            effect = QGraphicsBlurEffect()
            effect.setBlurRadius(self._blur_radius)
            effect.setBlurHints(QGraphicsBlurEffect.QualityHint)
            item.setGraphicsEffect(effect)
            scene.addItem(item)

            result = QPixmap(source.size())
            result.fill(Qt.transparent)
            p = QPainter(result)
            p.setRenderHint(QPainter.SmoothPixmapTransform)
            scene.render(p, source=scene.itemsBoundingRect())
            p.end()
            return result

        def _paint_outer_glow(
            self, painter: QPainter, w: int, h: int, r: int
        ) -> None:
            """Animated radial glow halo outside the card boundary."""
            alpha = int(40 + 50 * abs(math.sin(self._glow_phase)))
            gc = QColor(self._glow_color)
            gc.setAlpha(alpha)

            spread = max(12, self._glow_strength * 8)
            cx, cy = w / 2, h / 2

            glow = QRadialGradient(cx, cy, max(w, h) / 2 + spread)
            glow.setColorAt(0.0,  Qt.transparent)
            glow.setColorAt(0.55, Qt.transparent)
            glow.setColorAt(0.80, gc)
            glow.setColorAt(1.0,  Qt.transparent)

            gp = QPainterPath()
            s = spread
            gp.addRoundedRect(QRectF(-s, -s, w + s * 2, h + s * 2), r + s, r + s)
            painter.fillPath(gp, QBrush(glow))

        def _pulse_tick(self) -> None:
            self._glow_phase += 0.045    # full cycle â‰ˆ 2.3s at 60fps
            if self._glow_phase > math.pi:
                self._glow_phase = 0.0
            self.update()


else:
    # No PySide6 â€” stub so the module is always importable
    class GlassPanel:                      # type: ignore[no-redef]
        def __init__(self, *args, **kwargs): pass
        def set_preset(self, *a): pass
        def set_severity(self, *a): pass
        def start_glow_pulse(self, *a): pass
        def stop_glow_pulse(self): pass
        def refresh_glass(self): pass

    class GlassPreset:                     # type: ignore[no-redef]
        # FIX: each is its own dict object (not a shared reference)
        DEFAULT  = {}
        CRITICAL = {}
        HIGH     = {}
        MEDIUM   = {}
        LOW      = {}
        AI       = {}
        PANEL    = {}
        INFO     = {}
