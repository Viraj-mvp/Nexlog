"""GUI-oriented multi-file analysis controller.

The core analyzer already supports multiple paths and creates one session per
source log. This wrapper keeps the GUI contract explicit: a parent run owns a
set of child file jobs, while the underlying analyzer remains the single source
of truth for parsing, detection, and persistence.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable


ProgressCallback = Callable[[dict[str, Any]], None]


class MultiFileAnalysisEngine:
    """Run a bounded multi-file GUI job through the existing analyzer."""

    def __init__(self, runtime: Any) -> None:
        self.runtime = runtime

    @property
    def worker_limit(self) -> int:
        mode = str(getattr(self.runtime, "hardware_mode", "adaptive") or "adaptive").lower()
        if mode == "performance":
            return max(1, min(4, int((getattr(self.runtime, "max_workers", 2) or 2))))
        if mode == "conservative":
            return 1
        return max(1, min(2, int((getattr(self.runtime, "max_workers", 2) or 2))))

    @property
    def execution_mode(self) -> str:
        # SQLite case writes are safest when committed in analyzer order. The
        # UI still treats this as one parent multi-file job with child sessions.
        return "sequential-safe"

    def run(
        self,
        *,
        log_paths: list[str],
        case_path: str,
        rules_dir: Path,
        min_severity: str,
        category: str | None,
        analyst: str,
        profile: str,
        progress_callback: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        from main import analyse

        return analyse(
            log_paths=[Path(p) for p in log_paths],
            case_path=Path(case_path),
            rules_dir=rules_dir,
            min_severity=min_severity,
            category=category,
            analyst=analyst,
            run_chains=True,
            quiet=True,
            profile=profile,
            batch_size=max(1000, min(int(getattr(self.runtime, "batch_size", 2000) or 2000), 5000)),
            no_enrich=True,
            defer_graph=True,
            max_line_bytes=int(getattr(self.runtime, "max_line_bytes", 1048576) or 1048576),
            progress_callback=progress_callback,
        )
