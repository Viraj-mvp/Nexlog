"""Runtime configuration and hardware-mode defaults for NexLog."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any


_VALID_MODES = {"adaptive", "performance", "conservative"}
_VALID_GPU = {"auto", "on", "off"}


@dataclass(frozen=True)
class RuntimeConfig:
    hardware_mode: str = "adaptive"
    profile: str = "balanced"
    max_workers: int = 2
    batch_size: int = 5000
    max_memory_mb: int = 2048
    max_cpu_percent: int = 75
    max_line_bytes: int = 1_048_576
    gpu_gui: str = "auto"
    graph_node_limit: int = 360
    reduced_motion: bool = False

    @property
    def is_conservative(self) -> bool:
        return self.hardware_mode == "conservative"

    @property
    def is_performance(self) -> bool:
        return self.hardware_mode == "performance"

    def apply_gui_environment(self) -> None:
        """Set Qt/QML render hints before QGuiApplication is created."""
        if self.gpu_gui == "off" or self.is_conservative:
            os.environ.setdefault("QT_QUICK_BACKEND", "software")
            os.environ.setdefault("QSG_RHI_BACKEND", "software")
            os.environ.setdefault("NEXLOG_REDUCED_MOTION", "1")
            return
        if self.gpu_gui == "on":
            os.environ.pop("QT_QUICK_BACKEND", None)
            os.environ.setdefault("QSG_RHI_BACKEND", "opengl")
        elif self.gpu_gui == "auto":
            # Let Qt choose the safest renderer. Forcing OpenGL in adaptive mode
            # crashes on some Windows GPU/driver combinations.
            os.environ.pop("QSG_RHI_BACKEND", None)

    def resource_status(self, workspace: str | Path = ".") -> dict[str, Any]:
        """Return a lightweight, dependency-optional resource snapshot."""
        memory = {"available_mb": 0, "percent": 0.0, "ok": True}
        cpu = {"percent": 0.0, "ok": True}
        try:
            import psutil  # type: ignore

            vm = psutil.virtual_memory()
            memory = {
                "available_mb": int(vm.available / (1024 * 1024)),
                "percent": float(vm.percent),
                "ok": int(vm.available / (1024 * 1024)) >= min(256, self.max_memory_mb // 8),
            }
            cpu_percent = float(psutil.cpu_percent(interval=0.0))
            cpu = {"percent": cpu_percent, "ok": cpu_percent <= max(95, self.max_cpu_percent + 20)}
        except Exception:
            pass

        try:
            usage = shutil.disk_usage(str(workspace))
            disk_free_mb = int(usage.free / (1024 * 1024))
        except Exception:
            disk_free_mb = 0
        return {
            "hardware_mode": self.hardware_mode,
            "profile": self.profile,
            "max_workers": self.max_workers,
            "batch_size": self.batch_size,
            "max_line_bytes": self.max_line_bytes,
            "gpu_gui": self.gpu_gui,
            "graph_node_limit": self.graph_node_limit,
            "reduced_motion": self.reduced_motion,
            "memory": memory,
            "cpu": cpu,
            "disk": {"free_mb": disk_free_mb, "ok": disk_free_mb == 0 or disk_free_mb >= 256},
        }


def _read_toml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        import tomllib
    except ImportError:
        return {}
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except Exception:
        return {}
    runtime = data.get("runtime", data)
    return runtime if isinstance(runtime, dict) else {}


def _int_value(value: Any, default: int, min_value: int = 1) -> int:
    try:
        return max(min_value, int(value))
    except Exception:
        return default


def _bool_value(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def load_runtime_config(config_path: str | Path = "") -> RuntimeConfig:
    """Load runtime config from TOML, then override with NEXLOG_* env vars."""
    root = Path(__file__).resolve().parents[2]
    toml_path = Path(config_path) if config_path else root / "config" / "nexlog.runtime.toml"
    cfg = _read_toml(toml_path)

    mode = str(os.environ.get("NEXLOG_HARDWARE_MODE", cfg.get("hardware_mode", "adaptive"))).strip().lower()
    if mode not in _VALID_MODES:
        mode = "adaptive"

    defaults = {
        "adaptive": {
            "profile": "balanced",
            "max_workers": 2,
            "batch_size": 5000,
            "max_memory_mb": 2048,
            "max_cpu_percent": 75,
            "max_line_bytes": 1_048_576,
            "gpu_gui": "auto",
            "graph_node_limit": 48,
            "reduced_motion": False,
        },
        "performance": {
            "profile": "balanced",
            "max_workers": max(2, (os.cpu_count() or 4) // 2),
            "batch_size": 10000,
            "max_memory_mb": 4096,
            "max_cpu_percent": 90,
            "max_line_bytes": 2_097_152,
            "gpu_gui": "on",
            "graph_node_limit": 120,
            "reduced_motion": False,
        },
        "conservative": {
            "profile": "fast",
            "max_workers": 1,
            "batch_size": 2000,
            "max_memory_mb": 1024,
            "max_cpu_percent": 55,
            "max_line_bytes": 524_288,
            "gpu_gui": "off",
            "graph_node_limit": 24,
            "reduced_motion": True,
        },
    }[mode]

    profile = str(os.environ.get("NEXLOG_PROFILE", cfg.get("profile", defaults["profile"]))).strip().lower()
    if profile not in {"fast", "balanced", "deep"}:
        profile = defaults["profile"]

    gpu_gui = str(os.environ.get("NEXLOG_GPU_GUI", cfg.get("gpu_gui", defaults["gpu_gui"]))).strip().lower()
    if gpu_gui not in _VALID_GPU:
        gpu_gui = defaults["gpu_gui"]

    return RuntimeConfig(
        hardware_mode=mode,
        profile=profile,
        max_workers=_int_value(os.environ.get("NEXLOG_MAX_WORKERS", cfg.get("max_workers", defaults["max_workers"])), defaults["max_workers"]),
        batch_size=_int_value(os.environ.get("NEXLOG_BATCH_SIZE", cfg.get("batch_size", defaults["batch_size"])), defaults["batch_size"]),
        max_memory_mb=_int_value(os.environ.get("NEXLOG_MAX_MEMORY_MB", cfg.get("max_memory_mb", defaults["max_memory_mb"])), defaults["max_memory_mb"]),
        max_cpu_percent=_int_value(os.environ.get("NEXLOG_MAX_CPU_PERCENT", cfg.get("max_cpu_percent", defaults["max_cpu_percent"])), defaults["max_cpu_percent"], 10),
        max_line_bytes=_int_value(os.environ.get("NEXLOG_MAX_LINE_BYTES", cfg.get("max_line_bytes", defaults["max_line_bytes"])), defaults["max_line_bytes"]),
        gpu_gui=gpu_gui,
        graph_node_limit=_int_value(os.environ.get("NEXLOG_GRAPH_NODE_LIMIT", cfg.get("graph_node_limit", defaults["graph_node_limit"])), defaults["graph_node_limit"]),
        reduced_motion=_bool_value(os.environ.get("NEXLOG_REDUCED_MOTION", cfg.get("reduced_motion", defaults["reduced_motion"])), defaults["reduced_motion"]),
    )
