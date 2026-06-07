"""
NexLog QML bridge.

This layer exposes the existing analyzer, case database, and exporters to the
Qt Quick interface without loading heavyweight AI backends during startup.
"""

from __future__ import annotations

import json
import math
import os
import sys
import uuid
import zipfile
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from PySide6.QtCore import QObject, Property, QThread, Signal, Slot
from PySide6.QtGui import QGuiApplication
from interface.gui.crash_guard import (
    get_existing_directory,
    get_open_file_name,
    get_open_file_names,
    get_save_file_name,
    log_event,
    safe_slot,
    validate_log_paths,
)
from utils.runtime_config import load_runtime_config

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

try:
    from pathconfig import REPO_ROOT_PATH, WORKSPACE_DIR, load_env_profile
except Exception:  # pragma: no cover - startup fallback only
    REPO_ROOT_PATH = _ROOT
    WORKSPACE_DIR = str(_ROOT / "workspace")
    def load_env_profile(profile: str | None = None) -> dict[str, object]:
        return {"profile": profile or "default", "loaded": []}

_EXPORT_DIR = Path(WORKSPACE_DIR) / "exports"
_GUI_ENV_PATH = Path(REPO_ROOT_PATH) / ".env.gui"
_SEV_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class _AnalysisWorker(QThread):
    """Run the existing CLI analyzer in a background thread for QML."""

    progress = Signal(int, str)
    progressData = Signal(dict)
    completed = Signal(dict)
    failed = Signal(str)

    def __init__(
        self,
        log_paths: list[str],
        case_path: str,
        min_severity: str = "LOW",
        category: str = "",
        analyst: str = "analyst",
        profile: str = "fast",
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.log_paths = [str(Path(p)) for p in log_paths if str(p).strip()]
        self.case_path = case_path
        self.min_severity = min_severity
        self.category = category or None
        self.analyst = analyst
        self.profile = profile or "fast"
        self.runtime = load_runtime_config()

    def run(self) -> None:  # pragma: no cover - exercised by GUI smoke
        try:
            self.progress.emit(0, "Preparing analysis job")
            from interface.gui.multi_file_engine import MultiFileAnalysisEngine

            file_count = max(1, len(self.log_paths))
            controller = MultiFileAnalysisEngine(self.runtime)
            self.progressData.emit({
                "phase": "queued",
                "lines_parsed": 0,
                "line_number": 0,
                "byte_offset": 0,
                "source_size": 0,
                "findings_saved": 0,
                "file_index": 0,
                "file_count": file_count,
                "worker_limit": controller.worker_limit,
                "execution_mode": controller.execution_mode,
            })

            def progress(payload: dict[str, Any]) -> None:
                if self.isInterruptionRequested():
                    raise InterruptedError("Analysis cancelled by user")
                payload = dict(payload or {})
                payload.setdefault("worker_limit", controller.worker_limit)
                payload.setdefault("execution_mode", controller.execution_mode)
                source_size = int(payload.get("source_size") or 0)
                byte_offset = int(payload.get("byte_offset") or 0)
                file_index = max(1, int(payload.get("file_index") or 1))
                current_fraction = (
                    max(0.0, min(1.0, byte_offset / source_size))
                    if source_size > 0
                    else 0.0
                )
                percent = int((((file_index - 1) + current_fraction) / file_count) * 100)
                payload["percent"] = max(0, min(98, percent))
                self.progressData.emit(payload)
                self.progress.emit(
                    int(payload["percent"]),
                    f"File {file_index}/"
                    f"{int(payload.get('file_count') or file_count)} "
                    f"{payload.get('source_name') or 'log'} - "
                    f"{payload.get('phase', 'analysing').title()}: "
                    f"{int(payload.get('lines_parsed') or 0):,} lines, "
                    f"{int(payload.get('findings_saved') or 0):,} findings",
                )

            result = controller.run(
                log_paths=self.log_paths,
                case_path=Path(self.case_path),
                rules_dir=_ROOT / "detection" / "rules",
                min_severity=self.min_severity,
                category=self.category,
                analyst=self.analyst,
                profile=self.profile,
                progress_callback=progress,
            )
            result = dict(result or {})
            result["execution_mode"] = controller.execution_mode
            result["worker_limit"] = controller.worker_limit
            self.progress.emit(98, "Refreshing case workspace")
            self.completed.emit(result)
        except InterruptedError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:
            self.failed.emit(str(exc))


class CyberBridge(QObject):
    sessionsChanged = Signal(list)
    dashboardChanged = Signal(dict)
    findingsChanged = Signal(list)
    timelineChanged = Signal(list)
    graphChanged = Signal(dict)
    mitreChanged = Signal(list)
    toolsChanged = Signal(dict)
    performanceChanged = Signal()
    analysisProgress = Signal(int, str)
    analysisComplete = Signal(dict)
    analysisError = Signal(str)
    statusChanged = Signal()
    activeScreenChanged = Signal()
    busyChanged = Signal()
    selectedLogChanged = Signal()
    lastAnalysisChanged = Signal()
    analysisQueueChanged = Signal(dict)

    def __init__(self, case_db_path: str, parent: QObject | None = None):
        super().__init__(parent)
        self._runtime = load_runtime_config()
        self._case_path = str(case_db_path)
        self._current_session_id = ""
        self._fresh_start = True
        self._session_scope_label = "Fresh Investigation"
        self._selected_log_path = ""
        self._selected_log_paths: list[str] = []
        self._selected_log_meta: dict[str, dict[str, Any]] = {}
        self._status_text = "Initializing parser"
        self._progress_value = 0
        self._finding_count = 0
        self._threat_level = "READY"
        self._min_severity = "LOW"
        self._active_screen = "dashboard"
        self._busy = False
        self._rules_loaded = 0
        self._sessions: list[dict[str, Any]] = []
        self._dashboard: dict[str, Any] = {}
        self._findings: list[dict[str, Any]] = []
        self._timeline: list[dict[str, Any]] = []
        self._graph: dict[str, Any] = {"nodes": [], "edges": []}
        self._mitre: list[dict[str, Any]] = []
        self._tools: dict[str, Any] = {
            "lastAction": "Ready",
            "lastOutput": "",
            "resultPath": "",
            "resultKind": "",
            "preview": "",
            "count": 0,
            "error": False,
            "running": False,
        }
        self._last_analysis: dict[str, Any] = {
            "state": "idle",
            "message": "No analysis run yet",
            "total_findings": 0,
            "session_ids": [],
            "case_path": self._case_path,
            "log_path": "",
            "log_name": "",
            "threat_level": "READY",
            "completed_at": "",
            "files": [],
        }
        self._analysis_queue: dict[str, Any] = self._new_queue_state("idle")
        self._worker: _AnalysisWorker | None = None

    @Property(str, notify=statusChanged)
    def casePath(self) -> str:
        return self._case_path

    @Property(str, notify=statusChanged)
    def currentSessionId(self) -> str:
        return self._current_session_id

    @Property(str, notify=statusChanged)
    def sessionScopeLabel(self) -> str:
        return self._session_scope_label or "All Logs"

    @Property(str, notify=selectedLogChanged)
    def selectedLogPath(self) -> str:
        return self._selected_log_path

    @Property("QVariant", notify=selectedLogChanged)
    def selectedLogPaths(self) -> list[str]:
        return list(self._selected_log_paths)

    @Property(str, notify=selectedLogChanged)
    def selectedLogName(self) -> str:
        if len(self._selected_log_paths) > 1:
            return f"{len(self._selected_log_paths)} logs selected"
        return Path(self._selected_log_path).name if self._selected_log_path else "No log selected"

    @Property(str, notify=statusChanged)
    def statusText(self) -> str:
        return self._status_text

    @Property(int, notify=statusChanged)
    def progressValue(self) -> int:
        return self._progress_value

    @Property(int, notify=statusChanged)
    def findingCount(self) -> int:
        return self._finding_count

    @Property(str, notify=statusChanged)
    def threatLevel(self) -> str:
        return self._threat_level

    @Property(str, notify=statusChanged)
    def minSeverity(self) -> str:
        return self._min_severity

    @Property(str, notify=activeScreenChanged)
    def activeScreen(self) -> str:
        return self._active_screen

    @Property(bool, notify=busyChanged)
    def busy(self) -> bool:
        return self._busy

    @Property("QVariant", notify=lastAnalysisChanged)
    def lastAnalysisSummary(self) -> dict[str, Any]:
        return dict(self._last_analysis)

    @Property(bool, notify=performanceChanged)
    def reducedMotion(self) -> bool:
        value = (
            os.environ.get("NEXLOG_REDUCED_MOTION")
            or os.environ.get("NEXLOG_REDUCED_MOTION")
            or ""
        )
        return self._runtime.reduced_motion or value.strip().lower() in {"1", "true", "yes", "on"}

    @Property(str, notify=performanceChanged)
    def hardwareMode(self) -> str:
        return self._runtime.hardware_mode

    @Property("QVariant", notify=performanceChanged)
    def performanceConfig(self) -> dict[str, Any]:
        return {
            "hardwareMode": self._runtime.hardware_mode,
            "profile": self._runtime.profile,
            "maxWorkers": self._runtime.max_workers,
            "batchSize": self._runtime.batch_size,
            "maxMemoryMb": self._runtime.max_memory_mb,
            "maxCpuPercent": self._runtime.max_cpu_percent,
            "maxLineBytes": self._runtime.max_line_bytes,
            "gpuGui": self._runtime.gpu_gui,
            "graphNodeLimit": self._runtime.graph_node_limit,
            "reducedMotion": self._runtime.reduced_motion,
        }

    def _set_busy(self, busy: bool) -> None:
        if self._busy == busy:
            return
        self._busy = busy
        self.busyChanged.emit()

    def _set_status(self, text: str, progress: int | None = None) -> None:
        self._status_text = text
        if progress is not None:
            self._progress_value = max(0, min(100, int(progress)))
        self.statusChanged.emit()

    def _set_last_analysis(self, **updates: Any) -> None:
        self._last_analysis.update(updates)
        self.lastAnalysisChanged.emit()

    def _new_queue_state(self, state: str = "idle") -> dict[str, Any]:
        return {
            "parentJobId": "",
            "state": state,
            "phase": "idle",
            "message": "No active analysis",
            "currentPath": "",
            "currentName": "",
            "fileIndex": 0,
            "fileCount": 0,
            "linesParsed": 0,
            "findingsSaved": 0,
            "percent": 0,
            "startedAt": "",
            "completedAt": "",
            "elapsedSeconds": 0,
            "workerLimit": self._runtime.max_workers,
            "executionMode": "sequential-safe",
            "files": [],
        }

    def _emit_queue(self) -> None:
        self._analysis_queue["files"] = self._selected_evidence_rows()
        self.analysisQueueChanged.emit(dict(self._analysis_queue))
        if self._dashboard:
            self._dashboard["selectedEvidence"] = self._selected_evidence_rows()
            self._dashboard["selectedEvidenceCount"] = len(self._selected_log_paths)
            self._dashboard["analysisQueue"] = dict(self._analysis_queue)
            self.dashboardChanged.emit(dict(self._dashboard))

    def _set_selected_logs(self, paths: list[str]) -> None:
        unique: list[str] = []
        seen: set[str] = set()
        for raw in paths:
            if not raw:
                continue
            path = str(Path(raw))
            key = str(Path(path).resolve()) if Path(path).exists() else path
            if key in seen:
                continue
            seen.add(key)
            unique.append(path)
            meta = self._selected_log_meta.setdefault(path, {})
            meta.setdefault("selected", True)
            meta.setdefault("status", "ready")
            meta.setdefault("progress", 0)
            meta.setdefault("lastSessionId", "")
            meta.setdefault("findings", 0)
            meta.setdefault("lines", 0)
            meta.setdefault("phase", "queued")
        self._selected_log_meta = {p: self._selected_log_meta.get(p, {}) for p in unique}
        for order, path in enumerate(unique, start=1):
            self._selected_log_meta.setdefault(path, {})["runOrder"] = order
        self._selected_log_paths = unique
        self._selected_log_path = unique[0] if unique else ""
        self.selectedLogChanged.emit()
        self._analysis_queue["files"] = self._selected_evidence_rows()
        if self._dashboard:
            self._dashboard["selectedEvidence"] = self._selected_evidence_rows()
            self._dashboard["selectedEvidenceCount"] = len(self._selected_log_paths)
            self._dashboard["analysisQueue"] = dict(self._analysis_queue)
            self.dashboardChanged.emit(dict(self._dashboard))

    def _validate_selected_paths(self, paths: list[str]) -> list[str]:
        valid, errors = validate_log_paths(paths, self._runtime.max_line_bytes)
        if errors:
            self._set_tool_result(
                "Evidence validation warning",
                "",
                {
                    "resultKind": "validation",
                    "preview": "\n".join(errors[:8]),
                    "count": len(errors),
                    "error": True,
                },
            )
            log_event("EVIDENCE_VALIDATION_WARNING", errors=errors[:8])
        return valid

    def _selected_evidence_rows(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for path in self._selected_log_paths:
            p = Path(path)
            meta = self._selected_log_meta.get(path, {})
            exists = p.exists()
            rows.append({
                "path": path,
                "name": p.name,
                "exists": exists,
                "size": p.stat().st_size if exists else 0,
                "selected": bool(meta.get("selected", True)),
                "status": str(meta.get("status") or ("ready" if exists else "missing")),
                "phase": str(meta.get("phase") or "queued"),
                "progress": int(meta.get("progress", 0) or 0),
                "runOrder": int(meta.get("runOrder", len(rows) + 1) or len(rows) + 1),
                "lastSessionId": str(meta.get("lastSessionId") or ""),
                "findings": int(meta.get("findings", 0) or 0),
                "lines": int(meta.get("lines", 0) or 0),
            })
        return rows

    def _session_name(self, session_id: str) -> str:
        if not session_id:
            return "All Logs"
        for session in self._sessions:
            if session.get("id") == session_id:
                return str(session.get("name") or session_id)
        return session_id

    def _analysis_result_rows(self, session_ids: list[Any]) -> list[dict[str, Any]]:
        wanted = {str(session_id) for session_id in session_ids if str(session_id)}
        rows: list[dict[str, Any]] = []
        for session in self._sessions:
            sid = str(session.get("id") or "")
            if wanted and sid not in wanted:
                continue
            findings = int(session.get("findings", 0) or 0)
            rows.append(
                {
                    "session_id": sid,
                    "name": session.get("name", "log"),
                    "source": session.get("source", ""),
                    "entries": int(session.get("entries", 0) or 0),
                    "findings": findings,
                    "status": "complete" if findings else "complete_zero_findings",
                }
            )
        order = {str(session_id): idx for idx, session_id in enumerate(session_ids)}
        return sorted(rows, key=lambda row: order.get(str(row.get("session_id")), 9999))

    @staticmethod
    def _history_time_label(created: str) -> tuple[str, str]:
        try:
            dt = datetime.fromisoformat(str(created).replace("Z", "+00:00")[:19])
        except Exception:
            return "Earlier", str(created or "")[:16]
        today = datetime.now().date()
        if dt.date() == today:
            group = "Today"
        elif dt.date() == today - timedelta(days=1):
            group = "Yesterday"
        elif dt.date() >= today - timedelta(days=6):
            group = dt.strftime("%A")
        else:
            group = dt.strftime("%d %b %Y")
        return group, dt.strftime("%H:%M")

    def _group_history(self, sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
        grouped: dict[str, dict[str, Any]] = {}
        order: list[str] = []
        for session in sessions:
            group, time_label = self._history_time_label(str(session.get("created", "")))
            if group not in grouped:
                grouped[group] = {"label": group, "rows": []}
                order.append(group)
            row = dict(session)
            row["time"] = time_label
            grouped[group]["rows"].append(row)
        return [grouped[label] for label in order]

    def _emit_all_data(self) -> None:
        self.dashboardChanged.emit(dict(self._dashboard))
        self.findingsChanged.emit(list(self._findings))
        self.timelineChanged.emit(list(self._timeline))
        self.graphChanged.emit(dict(self._graph))
        self.mitreChanged.emit(list(self._mitre))
        self.toolsChanged.emit(dict(self._tools))

    @staticmethod
    def _finding_to_dict(finding: Any) -> dict[str, Any]:
        try:
            data = finding.to_dict()
        except Exception:
            data = dict(finding) if isinstance(finding, dict) else {}
        data["finding_id"] = getattr(finding, "_db_id", data.get("finding_id", ""))
        sev = data.get("severity", getattr(getattr(finding, "severity", None), "value", "INFO"))
        data["severity"] = str(sev or "INFO").upper()
        rule_id = str(data.get("rule_id", getattr(finding, "rule_id", "")) or "")
        rule_name = str(data.get("rule_name", getattr(finding, "rule_name", "")) or "")
        category = str(data.get("category", getattr(finding, "category", "")) or "uncategorized")
        data["rule_id"] = rule_id or rule_name or "finding"
        data["rule_name"] = rule_name or rule_id or "Detection finding"
        data["category"] = category
        data["source_ip"] = str(data.get("source_ip") or getattr(finding, "source_ip", "") or "")
        data["hostname"] = str(data.get("hostname") or getattr(finding, "hostname", "") or "")
        data["risk_score"] = float(data.get("risk_score") or getattr(finding, "risk_score", 0.0) or 0.0)
        data["source_display"] = data["source_ip"] or data["hostname"] or "unknown"
        data["trigger_line"] = str(data.get("trigger_line") or getattr(finding, "trigger_line", "") or "")
        data["summary"] = str(
            data.get("summary")
            or data.get("description")
            or data["trigger_line"][:180]
            or f"{data['rule_name']} matched {data['category']}"
        )
        timestamp = data.get("timestamp", getattr(finding, "timestamp", ""))
        data["timestamp"] = timestamp.isoformat() if hasattr(timestamp, "isoformat") else str(timestamp or "")
        tags = data.get("mitre_ids") or data.get("technique_ids") or []
        data["mitre_ids"] = [str(tag) for tag in tags]
        data.setdefault("triage_state", "NEW")
        return data

    def _load_case_data(self) -> None:
        sessions: list[dict[str, Any]] = []
        findings_data: list[dict[str, Any]] = []
        timeline_data: list[dict[str, Any]] = []
        chains: list[dict[str, Any]] = []
        summary: dict[str, Any] = {
            "total": 0,
            "by_severity": {},
            "by_category": {},
            "top_source_ips": [],
            "top_hostnames": [],
            "max_risk_score": 0,
            "avg_risk_score": 0,
        }
        integrity: dict[str, Any] = {"status": "no_evidence"}

        try:
            from storage.case_db import CaseDB

            with CaseDB(self._case_path) as db:
                raw_sessions = db.list_sessions()
                session_ids = {str(session.get("session_id", "")) for session in raw_sessions}
                if self._current_session_id and self._current_session_id not in session_ids:
                    self._current_session_id = ""
                for session in raw_sessions:
                    sid = session.get("session_id", "")
                    sess_summary = db.get_findings_summary(session_id=sid)
                    sess_sev = {
                        str(k).upper(): int(v)
                        for k, v in dict(sess_summary.get("by_severity", {})).items()
                    }
                    top_sev = next(
                        (sev for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] if sess_sev.get(sev, 0)),
                        "INFO",
                    )
                    sessions.append(
                        {
                            "id": sid,
                            "name": Path(session.get("source_file", "?")).name,
                            "source": session.get("source_file", ""),
                            "created": session.get("created_at", "")[:19],
                            "findings": int(sess_summary.get("total", 0)),
                            "severity": top_sev,
                            "severityCounts": sess_sev,
                            "rules": int(session.get("rules_loaded", 0) or 0),
                            "entries": int(session.get("entries_parsed", 0) or 0),
                        }
                    )
                if self._current_session_id:
                    self._session_scope_label = next(
                        (
                            str(session.get("name") or self._current_session_id)
                            for session in sessions
                            if session.get("id") == self._current_session_id
                        ),
                        self._current_session_id,
                    )
                elif self._fresh_start:
                    self._session_scope_label = "Fresh Investigation"
                else:
                    self._session_scope_label = "All Logs"
                scope = self._current_session_id or None
                if self._fresh_start and not self._current_session_id:
                    integrity = db.verify_case_integrity(session_id=None)
                else:
                    summary = db.get_findings_summary(session_id=scope)
                    chains = db.get_attack_chains(session_id=scope)
                    integrity = db.verify_case_integrity(session_id=scope)
                    for finding in db.get_findings(
                        session_id=scope,
                        min_severity=self._min_severity if self._min_severity != "INFO" else None,
                        limit=1500,
                    ):
                        item = self._finding_to_dict(finding)
                        fid = item.get("finding_id", "")
                        if fid:
                            item["triage_state"] = db.get_finding_state(fid)
                        findings_data.append(item)
                    timeline_data = sorted(
                        [item for item in findings_data if item.get("timestamp")],
                        key=lambda item: item.get("timestamp", ""),
                        reverse=True,
                    )[:300]
        except Exception as exc:
            self._set_status(f"Case refresh warning: {exc}", self._progress_value)

        sev_counts = {str(k).upper(): int(v) for k, v in dict(summary.get("by_severity", {})).items()}
        cat_counts = {str(k): int(v) for k, v in dict(summary.get("by_category", {})).items()}
        mitre_counter: Counter[str] = Counter()
        mitre_details: dict[str, dict[str, Any]] = {}
        for item in findings_data:
            for tid in item.get("mitre_ids", []):
                technique = str(tid)
                mitre_counter[technique] += 1
                detail = mitre_details.setdefault(
                    technique,
                    {
                        "technique": technique,
                        "count": 0,
                        "rules": Counter(),
                        "sources": Counter(),
                        "severities": Counter(),
                        "maxRisk": 0.0,
                        "evidence": "",
                    },
                )
                detail["count"] += 1
                detail["rules"][str(item.get("rule_name") or item.get("rule_id") or "finding")] += 1
                detail["sources"][str(item.get("source_display") or "unknown")] += 1
                detail["severities"][str(item.get("severity") or "INFO").upper()] += 1
                detail["maxRisk"] = max(float(detail["maxRisk"]), float(item.get("risk_score") or 0.0))
                if not detail["evidence"]:
                    detail["evidence"] = str(item.get("summary") or item.get("trigger_line") or "")[:260]
        normalized_chains = chains or self._derive_attack_chains(findings_data)
        graph_payload = self._build_graph_payload(findings_data, normalized_chains)
        mitre_rows = self._build_mitre_rows(mitre_details, mitre_counter)

        self._sessions = sessions
        self._findings = findings_data
        self._timeline = timeline_data
        self._graph = graph_payload
        self._mitre = mitre_rows
        self._finding_count = int(summary.get("total", len(findings_data)) or 0)
        self._threat_level = self._derive_threat_level(sev_counts)
        self._dashboard = {
            "caseName": Path(self._case_path).name,
            "casePath": self._case_path,
            "sessionId": self._current_session_id,
            "sessionScopeLabel": self._session_scope_label,
            "freshStart": self._fresh_start,
            "selectedEvidence": self._selected_evidence_rows(),
            "selectedEvidenceCount": len(self._selected_log_paths),
            "analysisQueue": dict(self._analysis_queue),
            "sessions": sessions,
            "historyGroups": self._group_history(sessions),
            "sessionCount": len(sessions),
            "rulesLoaded": self._rules_loaded or max([s.get("rules", 0) for s in sessions] or [0]),
            "totalFindings": self._finding_count,
            "critical": sev_counts.get("CRITICAL", 0),
            "high": sev_counts.get("HIGH", 0),
            "medium": sev_counts.get("MEDIUM", 0),
            "low": sev_counts.get("LOW", 0),
            "info": sev_counts.get("INFO", 0),
            "chains": len(normalized_chains),
            "maxRisk": float(summary.get("max_risk_score", 0) or 0),
            "avgRisk": float(summary.get("avg_risk_score", 0) or 0),
            "integrity": integrity.get("status", "unknown"),
            "topSources": list(summary.get("top_source_ips", []))[:6],
            "topHosts": list(summary.get("top_hostnames", []))[:6],
            "categories": [
                {"name": name, "count": count}
                for name, count in sorted(cat_counts.items(), key=lambda kv: -kv[1])[:10]
            ],
            "recentFindings": findings_data[:8],
            "attackChains": normalized_chains[:12],
            "mitre": self._mitre[:8],
            "analysisResults": self._analysis_result_rows(
                self._last_analysis.get("session_ids", [])
            ),
        }

    @staticmethod
    def _build_mitre_rows(
        mitre_details: dict[str, dict[str, Any]],
        mitre_counter: Counter[str],
    ) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for technique, count in mitre_counter.most_common(30):
            detail = mitre_details.get(str(technique), {})
            sev_counts = detail.get("severities", Counter())
            rules = [name for name, _ in detail.get("rules", Counter()).most_common(5)]
            sources = [name for name, _ in detail.get("sources", Counter()).most_common(5)]
            top_severity = next(
                (sev for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] if sev_counts.get(sev, 0)),
                "INFO",
            )
            rows.append(
                {
                    "technique": str(technique),
                    "count": int(count),
                    "topSeverity": top_severity,
                    "severityRollup": dict(sev_counts),
                    "rules": rules,
                    "sources": sources,
                    "maxRisk": round(float(detail.get("maxRisk", 0.0) or 0.0), 2),
                    "evidence": str(detail.get("evidence") or "No trigger preview stored."),
                    "insight": (
                        f"{technique} appeared in {count} finding(s). "
                        f"Review {', '.join(rules[:3]) if rules else 'the mapped rules'} "
                        f"and validate affected source(s): {', '.join(sources[:3]) if sources else 'unknown'}."
                    ),
                    "response": (
                        "Prioritize containment and credential review."
                        if top_severity in {"CRITICAL", "HIGH"}
                        else "Correlate with nearby events and tune if benign."
                    ),
                }
            )
        return rows

    @staticmethod
    def _derive_attack_chains(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Build useful graph/story chains even when DB correlation has no rows."""
        source_groups: dict[str, list[dict[str, Any]]] = {}
        for item in findings:
            source = item.get("source_ip") or item.get("hostname") or "unknown-source"
            source_groups.setdefault(str(source), []).append(item)

        chains: list[dict[str, Any]] = []
        for source, items in source_groups.items():
            if not items:
                continue
            categories: list[str] = []
            rules: list[str] = []
            techniques: list[str] = []
            max_risk = 0.0
            for item in sorted(items, key=lambda row: str(row.get("timestamp", ""))):
                cat = str(item.get("category") or "uncategorized")
                rule = str(item.get("rule_id") or item.get("rule_name") or "rule")
                if cat not in categories:
                    categories.append(cat)
                if rule not in rules:
                    rules.append(rule)
                for technique in item.get("mitre_ids", [])[:4]:
                    if technique not in techniques:
                        techniques.append(str(technique))
                max_risk = max(max_risk, float(item.get("risk_score") or 0.0))
            if len(categories) > 1 or techniques or max_risk:
                chain_name = f"{source}: " + " -> ".join(c.replace("_", " ").title() for c in categories[:5])
                chains.append(
                    {
                        "chain_id": f"derived:{source}",
                        "chain_name": chain_name,
                        "source": source,
                        "categories": categories[:8],
                        "rules": rules[:12],
                        "techniques": techniques[:12],
                        "finding_count": len(items),
                        "max_risk_score": round(max_risk, 2),
                        "derived": True,
                    }
                )

        if not chains and findings:
            top = sorted(findings, key=lambda row: float(row.get("risk_score") or 0.0), reverse=True)[:10]
            categories = []
            rules = []
            techniques = []
            for item in top:
                cat = str(item.get("category") or "uncategorized")
                rule = str(item.get("rule_id") or item.get("rule_name") or "rule")
                if cat not in categories:
                    categories.append(cat)
                if rule not in rules:
                    rules.append(rule)
                for technique in item.get("mitre_ids", [])[:4]:
                    if technique not in techniques:
                        techniques.append(str(technique))
            chains.append(
                {
                    "chain_id": "derived:highest-risk",
                    "chain_name": "Highest-risk detection path",
                    "source": "case",
                    "categories": categories[:8],
                    "rules": rules[:12],
                    "techniques": techniques[:12],
                    "finding_count": len(top),
                    "max_risk_score": round(max([float(row.get("risk_score") or 0.0) for row in top] or [0.0]), 2),
                    "derived": True,
                }
            )

        return sorted(
            chains,
            key=lambda chain: (
                -float(chain.get("max_risk_score", 0.0) or 0.0),
                -int(chain.get("finding_count", 0) or 0),
                str(chain.get("chain_name", "")),
            ),
        )[:20]

    @staticmethod
    def _derive_threat_level(sev_counts: dict[str, int]) -> str:
        if sev_counts.get("CRITICAL", 0):
            return "CRITICAL"
        if sev_counts.get("HIGH", 0):
            return "HIGH"
        if sev_counts.get("MEDIUM", 0):
            return "MEDIUM"
        if sev_counts.get("LOW", 0):
            return "LOW"
        return "READY"

    def _graph_limits(self) -> tuple[int, int, int]:
        """Resolve graph caps with mode-aware defaults and env overrides."""
        mode = str(self._runtime.hardware_mode or "adaptive").lower()
        if mode == "performance":
            default_nodes, default_edges = 2000, 5000
        elif mode == "conservative":
            default_nodes, default_edges = 300, 800
        else:
            default_nodes, default_edges = 900, 2200

        configured_nodes = max(int(self._runtime.graph_node_limit or 0), default_nodes)
        node_limit = configured_nodes
        edge_limit = max(default_edges, int(round(node_limit * 2.4)))

        try:
            node_limit = max(120, int(os.environ.get("NEXLOG_GRAPH_NODE_LIMIT", node_limit)))
        except Exception:
            pass
        try:
            edge_limit = max(200, int(os.environ.get("NEXLOG_GRAPH_EDGE_LIMIT", edge_limit)))
        except Exception:
            pass
        try:
            source_limit = max(1000, int(os.environ.get("NEXLOG_GRAPH_SOURCE_LIMIT", max(3000, node_limit * 4))))
        except Exception:
            source_limit = max(3000, node_limit * 4)

        return min(node_limit, 2000), min(edge_limit, 5000), min(source_limit, 20000)

    def _build_graph_payload(self, findings: list[dict[str, Any]], chains: list[dict[str, Any]]) -> dict[str, Any]:
        nodes: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, Any]] = []
        edge_seen: set[tuple[str, str, str]] = set()
        node_limit, edge_limit, source_limit = self._graph_limits()
        findings_scan = findings[:source_limit]

        def severity_rank(severity: str) -> int:
            return _SEV_ORDER.get(str(severity).upper(), 0)

        def add_node(
            node_id: str,
            label: str,
            kind: str,
            severity: str = "INFO",
            risk: float = 0.0,
            tactic: str = "",
        ) -> None:
            if not node_id:
                return
            if node_id not in nodes:
                nodes[node_id] = {
                    "id": node_id,
                    "label": label,
                    "kind": kind,
                    "severity": str(severity).upper(),
                    "weight": 0,
                    "risk": 0.0,
                    "tactics": [],
                    "cluster": kind,
                    "layer": {"source": 0, "category": 1, "rule": 2, "technique": 3}.get(kind, 2),
                }
            node = nodes[node_id]
            node["weight"] += 1
            node["risk"] = max(float(node.get("risk", 0.0)), float(risk or 0.0))
            if severity_rank(severity) > severity_rank(node.get("severity", "INFO")):
                node["severity"] = str(severity).upper()
            if tactic and tactic not in node["tactics"]:
                node["tactics"].append(tactic)

        def add_edge(src: str, dst: str, severity: str, relation: str, risk: float = 0.0) -> None:
            if not src or not dst:
                return
            key = (src, dst, relation)
            if key in edge_seen:
                for edge in edges:
                    if edge["from"] == src and edge["to"] == dst and edge["relation"] == relation:
                        edge["weight"] += 1
                        edge["risk"] = max(float(edge.get("risk", 0.0)), float(risk or 0.0))
                        if severity_rank(severity) > severity_rank(edge.get("severity", "INFO")):
                            edge["severity"] = str(severity).upper()
                        break
                return
            edge_seen.add(key)
            edges.append(
                {
                    "from": src,
                    "to": dst,
                    "severity": str(severity).upper(),
                    "relation": relation,
                    "weight": 1,
                    "risk": float(risk or 0.0),
                }
            )

        for item in findings_scan:
            sev = item.get("severity", "INFO")
            risk = float(item.get("risk_score") or 0.0)
            src = item.get("source_ip") or item.get("hostname") or "unknown-source"
            rule = item.get("rule_id") or item.get("rule_name") or "rule"
            cat = item.get("category") or "uncategorized"
            src_id = f"src:{src}"
            cat_id = f"cat:{cat}"
            rule_id = f"rule:{rule}"
            add_node(src_id, src, "source", sev, risk)
            add_node(cat_id, cat.replace("_", " ").title(), "category", sev, risk)
            add_node(rule_id, rule, "rule", sev, risk)
            add_edge(src_id, cat_id, sev, "triggered", risk)
            add_edge(cat_id, rule_id, sev, "matched", risk)
            for technique in item.get("mitre_ids", [])[:4]:
                tech_id = f"tech:{technique}"
                add_node(tech_id, technique, "technique", sev, risk, technique)
                add_edge(rule_id, tech_id, sev, "maps_to", risk)
        for chain in chains[:20]:
            cats = chain.get("categories", [])
            for idx in range(len(cats) - 1):
                add_edge(
                    f"cat:{cats[idx]}",
                    f"cat:{cats[idx + 1]}",
                    "HIGH",
                    "chain",
                    float(chain.get("max_risk_score", 0.0) or 0.0),
                )
            source = chain.get("source", "")
            if source and cats:
                src_id = f"src:{source}"
                add_node(src_id, source, "source", "HIGH", float(chain.get("max_risk_score", 0.0) or 0.0))
                add_edge(src_id, f"cat:{cats[0]}", "HIGH", "chain_start", float(chain.get("max_risk_score", 0.0) or 0.0))
            last_rule_id = ""
            for rule in chain.get("rules", [])[:8]:
                rule_id = f"rule:{rule}"
                add_node(rule_id, rule, "rule", "HIGH", float(chain.get("max_risk_score", 0.0) or 0.0))
                if cats:
                    add_edge(f"cat:{cats[-1]}", rule_id, "HIGH", "chain_rule", float(chain.get("max_risk_score", 0.0) or 0.0))
                last_rule_id = rule_id
            for technique in chain.get("techniques", [])[:8]:
                tech_id = f"tech:{technique}"
                add_node(tech_id, technique, "technique", "HIGH", float(chain.get("max_risk_score", 0.0) or 0.0), technique)
                if last_rule_id:
                    add_edge(last_rule_id, tech_id, "HIGH", "chain_technique", float(chain.get("max_risk_score", 0.0) or 0.0))

        all_nodes = list(nodes.values())
        all_edges = list(edges)

        def node_score(node: dict[str, Any]) -> float:
            kind_bonus = {"source": 4.0, "category": 2.2, "rule": 2.8, "technique": 2.5}.get(str(node.get("kind")), 1.0)
            return (
                severity_rank(str(node.get("severity", "INFO"))) * 6.0
                + float(node.get("risk", 0.0)) * 2.8
                + float(node.get("weight", 0.0)) * 0.7
                + kind_bonus
            )

        ordered_nodes = sorted(
            all_nodes,
            key=lambda node: (
                {"source": 0, "category": 1, "rule": 2, "technique": 3}.get(node.get("kind"), 9),
                -float(node.get("risk", 0.0)),
                str(node.get("label", "")),
            ),
        )
        top_nodes = sorted(
            ordered_nodes,
            key=lambda node: (-node_score(node), str(node.get("id", ""))),
        )[:node_limit]
        kept_ids = {str(node.get("id")) for node in top_nodes}
        ordered_nodes = sorted(
            top_nodes,
            key=lambda node: (
                {"source": 0, "category": 1, "rule": 2, "technique": 3}.get(node.get("kind"), 9),
                -float(node.get("risk", 0.0)),
                str(node.get("label", "")),
            ),
        )

        relation_bonus = {
            "chain": 3.0,
            "chain_start": 3.0,
            "chain_rule": 2.6,
            "chain_technique": 2.6,
            "maps_to": 2.2,
            "matched": 1.8,
            "triggered": 1.6,
        }

        def edge_score(edge: dict[str, Any]) -> float:
            return (
                severity_rank(str(edge.get("severity", "INFO"))) * 5.0
                + float(edge.get("risk", 0.0)) * 2.2
                + float(edge.get("weight", 0.0)) * 0.8
                + relation_bonus.get(str(edge.get("relation", "")), 1.0)
            )

        filtered_edges = [
            edge
            for edge in all_edges
            if str(edge.get("from")) in kept_ids and str(edge.get("to")) in kept_ids
        ]
        filtered_edges = sorted(
            filtered_edges,
            key=lambda edge: (-edge_score(edge), str(edge.get("from", "")), str(edge.get("to", ""))),
        )[:edge_limit]
        max_edge_weight = max([float(edge.get("weight", 1.0) or 1.0) for edge in filtered_edges] or [1.0])
        for edge in filtered_edges:
            edge["weight_norm"] = round(min(1.0, float(edge.get("weight", 1.0) or 1.0) / max_edge_weight), 3)

        kind_groups: dict[str, list[dict[str, Any]]] = {
            "source": [],
            "category": [],
            "rule": [],
            "technique": [],
        }
        for node in ordered_nodes:
            kind = str(node.get("kind") or "rule")
            kind_groups.setdefault(kind, []).append(node)

        layer_x = {"source": -360.0, "category": -120.0, "rule": 120.0, "technique": 360.0}
        for kind, bucket in kind_groups.items():
            bucket.sort(key=lambda node: (-float(node.get("risk", 0.0)), -int(node.get("weight", 0)), str(node.get("id", ""))))
            total = len(bucket)
            if total == 0:
                continue
            rows = max(6, min(26, int(math.ceil(math.sqrt(total)))))
            cols = int(math.ceil(total / rows))
            for idx, node in enumerate(bucket):
                col = idx // rows
                row = idx % rows
                y = (row - (rows - 1) / 2.0) * 64.0
                z = (col - (cols - 1) / 2.0) * 84.0
                node["pos"] = {
                    "x": round(layer_x.get(kind, 0.0), 2),
                    "y": round(y, 2),
                    "z": round(z, 2),
                }
                if not node.get("cluster"):
                    node["cluster"] = kind

        reduced_nodes = len(all_nodes) > len(ordered_nodes)
        reduced_edges = len(all_edges) > len(filtered_edges)
        stats = {
            "node_count": len(all_nodes),
            "edge_count": len(all_edges),
            "visible_node_count": len(ordered_nodes),
            "visible_edge_count": len(filtered_edges),
            "source_count": sum(1 for node in all_nodes if node.get("kind") == "source"),
            "category_count": sum(1 for node in all_nodes if node.get("kind") == "category"),
            "rule_count": sum(1 for node in all_nodes if node.get("kind") == "rule"),
            "technique_count": sum(1 for node in all_nodes if node.get("kind") == "technique"),
            "chain_count": len(chains),
            "max_risk": max([float(node.get("risk", 0.0)) for node in all_nodes] or [0.0]),
        }
        return {
            "nodes": ordered_nodes,
            "edges": filtered_edges,
            "chains": chains[:20],
            "derivedChains": [chain for chain in chains[:20] if chain.get("derived")],
            "story": CyberBridge._chains_to_story(chains),
            "stats": stats,
            "layout": "layered-3d",
            "layout_version": "2",
            "meta": {
                "reduced": reduced_nodes or reduced_edges,
                "node_limit": node_limit,
                "edge_limit": edge_limit,
                "source_limit": source_limit,
                "nodes_raw": len(all_nodes),
                "edges_raw": len(all_edges),
                "nodes_dropped": max(0, len(all_nodes) - len(ordered_nodes)),
                "edges_dropped": max(0, len(all_edges) - len(filtered_edges)),
            },
        }

    @staticmethod
    def _chains_to_story(chains: list[dict[str, Any]]) -> str:
        if not chains:
            return "No attack chains are available yet. The graph needs findings with source, category, rule, or MITRE metadata."
        lines = []
        for idx, chain in enumerate(chains[:6], start=1):
            name = chain.get("chain_name") or "Attack chain"
            findings = chain.get("finding_count", 0)
            risk = chain.get("max_risk_score", 0)
            source = chain.get("source") or "case"
            techniques = ", ".join(chain.get("techniques", [])[:4]) or "no MITRE technique"
            lines.append(f"{idx}. {name} | source {source} | findings {findings} | risk {risk} | {techniques}")
        return "\n".join(lines)

    @Slot()
    def bootstrap(self) -> None:
        self._set_status("Indexing rules", 30)
        self._rules_loaded = self._count_rule_metadata(_ROOT / "detection" / "rules")

        self._set_status("Opening case", 65)
        self.refreshSessions()
        self._set_status("Ready", 100)

    @staticmethod
    def _count_rule_metadata(rules_dir: Path) -> int:
        """Count rules without compiling regexes during GUI startup."""
        total = 0
        try:
            for yaml_file in sorted(rules_dir.glob("*.yaml")):
                try:
                    doc = yaml.safe_load(yaml_file.read_text(encoding="utf-8")) or {}
                    total += len(doc.get("rules", []) or [])
                except Exception as exc:
                    log_event("RULE_METADATA_COUNT_FAILED", file=str(yaml_file), error=str(exc))
        except Exception as exc:
            log_event("RULE_METADATA_DIR_FAILED", dir=str(rules_dir), error=str(exc))
        return total

    @Slot(result="QVariant")
    def dashboardSnapshot(self) -> dict[str, Any]:
        if not self._dashboard:
            self.refreshSessions()
        return dict(self._dashboard)

    @Slot(result="QVariant")
    def sessionsSnapshot(self) -> list[dict[str, Any]]:
        if not self._sessions:
            self.refreshSessions()
        return list(self._sessions)

    @Slot(result="QVariant")
    def selectedEvidenceSnapshot(self) -> list[dict[str, Any]]:
        return self._selected_evidence_rows()

    @Slot(result="QVariant")
    def analysisQueueSnapshot(self) -> dict[str, Any]:
        return dict(self._analysis_queue)

    @Slot(result="QVariant")
    def historySnapshot(self) -> list[dict[str, Any]]:
        if not self._sessions:
            self.refreshSessions()
        return self._group_history(self._sessions)

    @Slot(result="QVariant")
    def findingsSnapshot(self) -> list[dict[str, Any]]:
        if not self._findings:
            self.refreshSessions()
        return list(self._findings)

    @Slot(int, int, str, result="QVariant")
    def findingsPage(self, offset: int = 0, limit: int = 100, query: str = "") -> list[dict[str, Any]]:
        try:
            from storage.case_db import CaseDB

            with CaseDB(self._case_path) as db:
                if query:
                    findings = db.search_findings(query, session_id=self._current_session_id or None, limit=limit)
                else:
                    findings = db.get_findings(
                        session_id=self._current_session_id or None,
                        min_severity=self._min_severity if self._min_severity != "INFO" else None,
                        limit=limit,
                        offset=offset,
                    )
                return [self._finding_to_dict(finding) for finding in findings]
        except Exception as exc:
            self._set_status(f"Findings page unavailable: {exc}", self._progress_value)
            return []

    @Slot(result="QVariant")
    def timelineSnapshot(self) -> list[dict[str, Any]]:
        if not self._timeline:
            self.refreshSessions()
        return list(self._timeline)

    @Slot(int, int, result="QVariant")
    def timelinePage(self, offset: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        try:
            from storage.case_db import CaseDB

            with CaseDB(self._case_path) as db:
                return db.get_timeline(
                    session_id=self._current_session_id or None,
                    min_severity=self._min_severity if self._min_severity != "INFO" else None,
                    limit=limit,
                    offset=offset,
                )
        except Exception as exc:
            self._set_status(f"Timeline page unavailable: {exc}", self._progress_value)
            return []

    @Slot(result="QVariant")
    def graphSnapshot(self) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            if not isinstance(self._graph, dict):
                self._graph = {"nodes": [], "edges": [], "chains": [], "stats": {}, "story": "", "meta": {}}
            if not self._graph.get("nodes"):
                self.refreshSessions()
            graph = dict(self._graph)
            graph.setdefault("nodes", [])
            graph.setdefault("edges", [])
            graph.setdefault("chains", [])
            graph.setdefault("stats", {})
            graph.setdefault("story", "")
            graph.setdefault("layout", "layered-3d")
            graph.setdefault("layout_version", "2")
            graph.setdefault("meta", {"reduced": False})
            return graph

        return safe_slot("graphSnapshot", {"nodes": [], "edges": [], "chains": [], "stats": {}, "story": "", "meta": {}}, run)

    @Slot(result="QVariant")
    def mitreSnapshot(self) -> list[dict[str, Any]]:
        if not self._mitre:
            self.refreshSessions()
        return list(self._mitre)

    @Slot(result="QVariant")
    def toolsSnapshot(self) -> dict[str, Any]:
        return dict(self._tools)

    @Slot(result="QVariant")
    def resourceSnapshot(self) -> dict[str, Any]:
        data = self._runtime.resource_status()
        data.update(self.performanceConfig)
        data["busy"] = self._busy
        data["activeWorkers"] = 1 if self._worker and self._worker.isRunning() else 0
        data["cpuPercent"] = data.get("cpu", {}).get("percent", 0)
        data["memoryPercent"] = data.get("memory", {}).get("percent", 0)
        data["diskFreeMb"] = data.get("disk", {}).get("free_mb", 0)
        return data

    @Slot(str)
    def setHardwareMode(self, mode: str) -> None:
        mode = (mode or "adaptive").strip().lower()
        if mode not in {"adaptive", "performance", "conservative"}:
            self._set_status(f"Unknown hardware mode: {mode}", self._progress_value)
            return
        if self._busy:
            self._set_status("Performance mode is locked while analysis is running", self._progress_value)
            self._set_tool_result(
                "Performance change blocked",
                "",
                {
                    "resultKind": "performance",
                    "preview": "Stop or finish the current analysis before changing hardware/performance mode.",
                    "error": True,
                },
            )
            return
        os.environ["NEXLOG_HARDWARE_MODE"] = mode
        if mode == "conservative":
            os.environ["NEXLOG_REDUCED_MOTION"] = "1"
            os.environ["NEXLOG_GPU_GUI"] = "off"
        elif mode == "performance":
            os.environ.pop("NEXLOG_REDUCED_MOTION", None)
            os.environ["NEXLOG_GPU_GUI"] = "on"
        else:
            os.environ.pop("NEXLOG_REDUCED_MOTION", None)
            os.environ["NEXLOG_GPU_GUI"] = "auto"
        self._runtime = load_runtime_config()
        self._runtime.apply_gui_environment()
        self.performanceChanged.emit()
        self._set_status(f"Hardware mode set to {mode}", self._progress_value)
        self._set_tool_result(
            "Performance mode updated",
            "",
            {
                "message": (
                    f"NexLog is now using {mode} limits. Restart the GUI if you changed "
                    "GPU acceleration mode and want Qt to fully reload the renderer."
                ),
                "mode": mode,
            },
        )

    @Slot(result=str)
    def cycleHardwareMode(self) -> str:
        """Cycle adaptive -> performance -> conservative from compact UI controls."""
        current = (self._runtime.hardware_mode or "adaptive").lower()
        next_mode = {
            "adaptive": "performance",
            "performance": "conservative",
            "conservative": "adaptive",
        }.get(current, "adaptive")
        self.setHardwareMode(next_mode)
        return next_mode

    @Slot()
    def refreshSessions(self) -> None:
        def run() -> None:
            self._load_case_data()
            self.sessionsChanged.emit(list(self._sessions))
            self._emit_all_data()
            self.statusChanged.emit()

        safe_slot("refreshSessions", None, run)

    @Slot(str)
    def setActiveScreen(self, screen: str) -> None:
        if screen == self._active_screen:
            return
        self._active_screen = screen
        self.activeScreenChanged.emit()

    @Slot()
    def openLogDialog(self) -> None:
        def run() -> None:
            paths = get_open_file_names(
                "Open Log Files",
                "",
                "Log Files (*.log *.txt *.json *.jsonl *.evtx *.csv *.xml *.gz *.zip);;All Files (*.*)",
            )
            paths = self._validate_selected_paths(paths)
            if paths:
                self._set_selected_logs(paths)
                self._set_status(f"Selected {len(paths)} log file(s)", 100)

        safe_slot("openLogDialog", None, run)

    @Slot()
    @Slot(str)
    def analyseLog(self, log_path: str = "") -> None:
        if log_path:
            self._set_selected_logs([log_path])
        self.analyseSelectedLogs()

    @Slot()
    def analyseSelectedLogs(self) -> None:
        if self._busy:
            self._set_status("Analysis already in progress", self._progress_value)
            return
        targets = [
            path for path in self._selected_log_paths
            if self._selected_log_meta.get(path, {}).get("selected", True)
        ]
        if not targets:
            if self._selected_log_paths:
                self._set_status("No queued files selected for analysis", 100)
                return
            paths = get_open_file_names(
                "Analyse Log Files",
                "",
                "Log Files (*.log *.txt *.json *.jsonl *.evtx *.csv *.xml *.gz *.zip);;All Files (*.*)",
            )
            targets = self._validate_selected_paths(paths)
            self._set_selected_logs(targets)
        targets = self._validate_selected_paths(targets)
        if not targets:
            self._set_status("Analysis cancelled", 100)
            return
        missing = [p for p in targets if not Path(p).exists()]
        if missing:
            self._set_status("One or more selected logs do not exist", 100)
            self.analysisError.emit(f"Log file not found: {missing[0]}")
            return

        for path in self._selected_log_paths:
            meta = self._selected_log_meta.setdefault(path, {})
            if path in targets:
                meta.update({"status": "queued", "phase": "queued", "progress": 0, "findings": 0, "lines": 0})
            elif meta.get("status") in {"queued", "running"}:
                meta.update({"status": "not_run", "phase": "not selected", "progress": 0})
        parent_id = f"gui-{uuid.uuid4().hex[:10]}"
        started_at = datetime.now()
        self._analysis_queue = {
            "parentJobId": parent_id,
            "state": "running",
            "phase": "queued",
            "message": f"Queued {len(targets)} selected file(s)",
            "currentPath": "",
            "currentName": "",
            "fileIndex": 0,
            "fileCount": len(targets),
            "linesParsed": 0,
            "findingsSaved": 0,
            "percent": 0,
            "startedAt": started_at.strftime("%Y-%m-%d %H:%M:%S"),
            "completedAt": "",
            "elapsedSeconds": 0,
            "workerLimit": self._runtime.max_workers,
            "executionMode": "sequential-safe",
            "files": self._selected_evidence_rows(),
        }
        self._emit_queue()
        self._set_busy(True)
        count = len(targets)
        self._set_status(f"Queued {count} log file(s) for analysis", 0)
        self._set_last_analysis(
            state="running",
            message=f"Analysing {count} log file(s)",
            total_findings=0,
            session_ids=[],
            case_path=self._case_path,
            log_path=self._selected_log_path,
            log_name=f"{count} selected log(s)",
            files=self._selected_evidence_rows(),
            threat_level="ANALYSING",
            completed_at="",
        )
        self.analysisProgress.emit(0, self._status_text)
        self._worker = _AnalysisWorker(
            log_paths=targets,
            case_path=self._case_path,
            min_severity=self._min_severity,
            profile="balanced" if self._runtime.hardware_mode == "performance" else "fast",
        )
        self._worker.progress.connect(self._on_analysis_progress)
        self._worker.progressData.connect(self._on_analysis_progress_data)
        self._worker.completed.connect(self._on_analysis_finished)
        self._worker.failed.connect(self._on_analysis_failed)
        self._worker.completed.connect(self._worker.deleteLater)
        self._worker.failed.connect(self._worker.deleteLater)
        self._worker.start()

    @Slot()
    def analyseAllLogs(self) -> None:
        for path in self._selected_log_paths:
            self._selected_log_meta.setdefault(path, {})["selected"] = True
        self.selectedLogChanged.emit()
        self._emit_queue()
        self.analyseSelectedLogs()

    @Slot()
    def stopAnalysis(self) -> None:
        if not self._worker or not self._worker.isRunning():
            self._set_status("No active analysis", 100)
            return
        self._worker.requestInterruption()
        self._set_status("Stop requested; current analyzer pass will finish safely", self._progress_value)

    @Slot()
    def cancelAnalysis(self) -> None:
        self.stopAnalysis()

    @Slot()
    def clearSelectedLogs(self) -> None:
        self._set_selected_logs([])
        self._set_status("Selected evidence cleared", 100)
        self.refreshSessions()

    @Slot(str)
    def removeSelectedLog(self, path: str) -> None:
        target = str(Path(path))
        remaining = [p for p in self._selected_log_paths if p != path and str(Path(p)) != target]
        self._set_selected_logs(remaining)
        self._set_status("Evidence removed from queue", 100)
        self.refreshSessions()

    @Slot(str, bool)
    def toggleSelectedLog(self, path: str, selected: bool) -> None:
        target = next((p for p in self._selected_log_paths if p == path or str(Path(p)) == str(Path(path))), "")
        if not target:
            return
        self._selected_log_meta.setdefault(target, {})["selected"] = bool(selected)
        self._set_status(
            f"{'Selected' if selected else 'Skipped'} {Path(target).name}",
            self._progress_value,
        )
        self.selectedLogChanged.emit()
        self._emit_queue()

    @Slot(int, str)
    def _on_analysis_progress(self, pct: int, message: str) -> None:
        self._set_status(message, pct)
        self._set_last_analysis(state="running", message=message)
        self.analysisProgress.emit(pct, message)

    @Slot(dict)
    def _on_analysis_progress_data(self, payload: dict[str, Any]) -> None:
        data = dict(payload or {})
        path = str(data.get("source_file") or data.get("path") or "")
        if path:
            meta = self._selected_log_meta.setdefault(path, {})
            meta["status"] = "running"
            meta["phase"] = str(data.get("phase") or "analysing")
            meta["lines"] = int(data.get("lines_parsed") or data.get("line_number") or 0)
            meta["findings"] = int(data.get("findings_saved") or 0)
            source_size = int(data.get("source_size") or 0)
            byte_offset = int(data.get("byte_offset") or 0)
            meta["progress"] = (
                min(99, int((byte_offset / source_size) * 100))
                if source_size > 0
                else int(data.get("percent") or 0)
            )
        started = self._analysis_queue.get("startedAt", "")
        elapsed = 0
        try:
            elapsed = int((datetime.now() - datetime.strptime(started, "%Y-%m-%d %H:%M:%S")).total_seconds())
        except Exception:
            pass
        file_count = max(1, int(data.get("file_count") or self._analysis_queue.get("fileCount") or 1))
        file_index = max(1, int(data.get("file_index") or 1))
        source_size = int(data.get("source_size") or 0)
        byte_offset = int(data.get("byte_offset") or 0)
        if "percent" in data:
            percent = int(data.get("percent") or 0)
        elif source_size > 0:
            percent = int((((file_index - 1) + max(0.0, min(1.0, byte_offset / source_size))) / file_count) * 100)
        else:
            percent = int(((file_index - 1) / file_count) * 100)
        percent = max(0, min(99, percent))
        self._analysis_queue.update(
            {
                "state": "running",
                "phase": str(data.get("phase") or "analysing"),
                "message": self._status_text,
                "currentPath": path,
                "currentName": str(data.get("source_name") or (Path(path).name if path else "")),
                "fileIndex": file_index,
                "fileCount": file_count,
                "linesParsed": int(data.get("lines_parsed") or data.get("line_number") or 0),
                "findingsSaved": int(data.get("findings_saved") or 0),
                "percent": percent,
                "elapsedSeconds": elapsed,
                "workerLimit": int(data.get("worker_limit") or self._analysis_queue.get("workerLimit") or 1),
                "executionMode": str(data.get("execution_mode") or self._analysis_queue.get("executionMode") or "sequential-safe"),
            }
        )
        self._emit_queue()

    @Slot(dict)
    def _on_analysis_finished(self, result: dict[str, Any]) -> None:
        session_ids = result.get("session_ids") or []
        self._fresh_start = False
        if session_ids:
            # Show the newly analysed log by default. Older sessions remain in
            # history and only load when the analyst selects them.
            self._current_session_id = str(session_ids[0])
            self._session_scope_label = self._session_name(self._current_session_id)
        else:
            self._current_session_id = ""
            self._session_scope_label = "Current Analysis"
        self.refreshSessions()
        self._set_busy(False)
        total = int(result.get("total_findings", 0) or 0)
        result_rows = self._analysis_result_rows(session_ids)
        result_by_source = {str(row.get("source") or ""): row for row in result_rows}
        result_by_name = {str(row.get("name") or ""): row for row in result_rows}
        for path in self._selected_log_paths:
            meta = self._selected_log_meta.setdefault(path, {})
            if meta.get("status") in {"queued", "running"}:
                row = result_by_source.get(path) or result_by_name.get(Path(path).name)
                if row:
                    meta.update(
                        {
                            "status": str(row.get("status") or "complete"),
                            "phase": "complete",
                            "progress": 100,
                            "lastSessionId": str(row.get("session_id") or ""),
                            "findings": int(row.get("findings", 0) or 0),
                            "lines": int(row.get("entries", 0) or 0),
                        }
                    )
                else:
                    meta.update({"status": "not_run", "phase": "not run", "progress": 0})
        completed_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._analysis_queue.update(
            {
                "state": "complete",
                "phase": "complete",
                "message": f"Analysis complete: {total} findings",
                "percent": 100,
                "completedAt": completed_at,
                "findingsSaved": total,
                "files": self._selected_evidence_rows(),
                "workerLimit": int(result.get("worker_limit") or self._analysis_queue.get("workerLimit") or 1),
                "executionMode": str(result.get("execution_mode") or self._analysis_queue.get("executionMode") or "sequential-safe"),
            }
        )
        self._set_status(f"Analysis complete: {total} findings", 100)
        summary = {
            "state": "complete",
            "message": f"Analysis complete: {total} findings",
            "total_findings": total,
            "session_ids": session_ids,
            "case_path": self._case_path,
            "log_path": self._selected_log_path,
            "log_name": self.selectedLogName,
            "files": result_rows or self._selected_evidence_rows(),
            "selectedEvidence": self._selected_evidence_rows(),
            "threat_level": self._threat_level,
            "completed_at": completed_at,
        }
        self._set_last_analysis(**summary)
        self._emit_queue()
        if self._dashboard:
            self._dashboard["analysisResults"] = result_rows
            self._dashboard["analysisQueue"] = dict(self._analysis_queue)
            self._dashboard["historyGroups"] = self._group_history(self._sessions)
            self.dashboardChanged.emit(dict(self._dashboard))
        self.analysisComplete.emit(summary)

    @Slot(result="QVariant")
    def lastAnalysisSnapshot(self) -> dict[str, Any]:
        return dict(self._last_analysis)

    @Slot(result="QVariant")
    def detectionDetailsSnapshot(self) -> dict[str, Any]:
        return {
            "dashboard": dict(self._dashboard),
            "findings": list(self._findings),
            "timeline": list(self._timeline),
            "graph": dict(self._graph),
            "mitre": list(self._mitre),
            "sessions": list(self._sessions),
            "lastAnalysis": dict(self._last_analysis),
        }

    @Slot(str)
    def _on_analysis_failed(self, message: str) -> None:
        self._set_busy(False)
        cancelled = "cancel" in str(message).lower() or "interrupt" in str(message).lower()
        state = "cancelled" if cancelled else "error"
        for path in self._selected_log_paths:
            meta = self._selected_log_meta.setdefault(path, {})
            if meta.get("status") in {"queued", "running"}:
                meta.update({
                    "status": "cancelled" if cancelled else "error",
                    "phase": "cancelled" if cancelled else "error",
                })
        self._analysis_queue.update(
            {
                "state": state,
                "phase": state,
                "message": str(message),
                "completedAt": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "files": self._selected_evidence_rows(),
            }
        )
        self._set_status(f"Analysis error: {message}", 100)
        self._set_last_analysis(
            state=state,
            message=f"Analysis error: {message}",
            log_path=self._selected_log_path,
            log_name=Path(self._selected_log_path).name if self._selected_log_path else "",
            completed_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )
        self._emit_queue()
        self.analysisError.emit(message)

    @Slot()
    def openCaseDialog(self) -> None:
        def run() -> None:
            path = get_open_file_name(
                "Open Case Database",
                "",
                "NexLog Case (*.facase);;SQLite DB (*.db *.sqlite);;All Files (*.*)",
            )
            if path:
                self._case_path = path
                self._fresh_start = True
                self._current_session_id = ""
                self.refreshSessions()
                self._set_status(f"Case opened: {Path(path).name}", 100)

        safe_slot("openCaseDialog", None, run)

    @Slot()
    def newCaseDialog(self) -> None:
        def run() -> None:
            path = get_save_file_name(
                "New Case Database",
                "nexlog.facase",
                "NexLog Case (*.facase)",
            )
            if path:
                self._case_path = path
                self._fresh_start = True
                self._current_session_id = ""
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                self.refreshSessions()
                self._set_status(f"New case: {Path(path).name}", 100)

        safe_slot("newCaseDialog", None, run)

    @Slot(str)
    def switchSession(self, session_id: str) -> None:
        if not session_id:
            self.showAllLogs()
            return
        self._fresh_start = False
        self._current_session_id = session_id
        self.refreshSessions()
        self._set_status(f"Session loaded: {self._session_scope_label}", 100)

    @Slot(str)
    def openSessionFindings(self, session_id: str) -> None:
        self.switchSession(session_id)

    @Slot()
    def showAllLogs(self) -> None:
        self._fresh_start = False
        self._current_session_id = ""
        self._session_scope_label = "All Logs"
        self.refreshSessions()
        self._set_status("All logs loaded", 100)

    @Slot(str)
    def deleteSession(self, session_id: str) -> None:
        if not session_id:
            self._set_status("No session selected for delete", 100)
            return
        try:
            from storage.case_db import CaseDB

            with CaseDB(self._case_path) as db:
                deleted = db.delete_session(session_id)
            if self._current_session_id == session_id:
                self._current_session_id = ""
            self.refreshSessions()
            self._set_tool_result(
                "Session deleted",
                "",
                {
                    "resultKind": "case",
                    "count": int(deleted.get("sessions", 0) or 0),
                    "preview": f"Removed session {session_id} from this case. Original log files were not deleted.",
                },
            )
            self._set_status("Session deleted", 100)
        except Exception as exc:
            self._set_tool_error("Session delete failed", exc)

    @Slot(str)
    def setMinSeverity(self, severity: str) -> None:
        sev = (severity or "LOW").upper()
        if sev not in _SEV_ORDER:
            sev = "LOW"
        self._min_severity = sev
        self.refreshSessions()
        self._set_status(f"Minimum severity: {sev}", 100)

    def _case_findings(self, limit: int = 5000) -> list[Any]:
        from storage.case_db import CaseDB

        with CaseDB(self._case_path) as db:
            return db.get_findings(session_id=self._current_session_id or None, limit=limit)

    def _default_export_path(self, suffix: str, prefix: str = "nexlog") -> Path:
        _EXPORT_DIR.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return _EXPORT_DIR / f"{prefix}_{stamp}.{suffix}"

    @Slot(str)
    def exportReport(self, fmt: str) -> None:
        fmt = (fmt or "text").lower()
        ext_map = {"pdf": "pdf", "markdown": "md", "json": "json", "text": "txt"}
        ext = ext_map.get(fmt, "txt")
        default = self._default_export_path(ext, "nexlog_report")
        path = get_save_file_name(f"Export {fmt.upper()} Report", str(default), f"{fmt.upper()} (*.{ext})")
        if not path:
            return
        try:
            self._set_tool_running(f"Building {fmt.upper()} report", fmt)
            from storage.case_db import CaseDB

            with CaseDB(self._case_path) as db:
                if fmt == "pdf":
                    from intelligence.ioc_extractor import IOCExtractor
                    from output.pdf_report import PDFReport

                    findings = db.get_findings(session_id=self._current_session_id or None, limit=5000)
                    iocs = IOCExtractor().extract(findings)
                    PDFReport(
                        db=db,
                        session_id=self._current_session_id or None,
                        findings=findings,
                        iocs=iocs,
                        case_ref=f"NEXLOG-{Path(self._case_path).stem.upper()}",
                    ).build(path)
                else:
                    from output.report_builder import ReportBuilder

                    builder = ReportBuilder(db, session_id=self._current_session_id or None)
                    text = {
                        "json": builder.to_json(),
                        "markdown": builder.to_markdown(),
                        "text": builder.to_text(),
                    }.get(fmt, builder.to_text())
                    Path(path).write_text(text, encoding="utf-8")
            self._set_tool_result(
                f"{fmt.upper()} report exported",
                path,
                {"resultPath": str(path), "resultKind": fmt, "preview": f"Report written to {path}"},
            )
        except Exception as exc:
            self._set_tool_error("Report export failed", exc)

    @Slot()
    def exportPdf(self) -> None:
        self.exportReport("pdf")

    @Slot()
    def exportStix(self) -> None:
        default = self._default_export_path("json", "nexlog_stix")
        path = get_save_file_name("Export STIX 2.1", str(default), "STIX JSON (*.json)")
        if not path:
            return
        try:
            self._set_tool_running("Packaging STIX bundle", "stix")
            from intelligence.ioc_extractor import IOCExtractor
            from output.stix_export import STIXExport

            findings = self._case_findings()
            iocs = IOCExtractor().extract(findings)
            sx = STIXExport(findings=findings, iocs=iocs, case_ref="NEXLOG-EXPORT", org="NexLog")
            sx.write(path)
            self._set_tool_result(
                "STIX bundle exported",
                path,
                {"resultPath": str(path), "resultKind": "stix", "preview": "STIX 2.1 bundle is ready.", **sx.summary()},
            )
        except Exception as exc:
            self._set_tool_error("STIX export failed", exc)

    @Slot()
    @Slot(str)
    def exportIocs(self, fmt: str = "csv") -> None:
        fmt = (fmt or "csv").lower()
        try:
            from intelligence.ioc_extractor import IOCExtractor
            from output.ioc_csv import IOCExporter

            findings = self._case_findings()
            iocs = IOCExtractor().extract(findings)
            exporter = IOCExporter(iocs, case_ref="NEXLOG-EXPORT")
            if fmt == "all":
                directory = get_existing_directory("Export IOC Bundle", str(_EXPORT_DIR))
                if not directory:
                    return
                self._set_tool_running("Extracting IOCs", "ioc")
                paths = exporter.write_all(directory)
                self._set_tool_result(
                    "IOC bundle exported",
                    directory,
                    {"resultPath": str(directory), "resultKind": "ioc", "count": len(paths), "files": len(paths), "preview": f"{len(paths)} IOC files exported."},
                )
            else:
                default = self._default_export_path("csv", "nexlog_iocs")
                path = get_save_file_name("Export IOC CSV", str(default), "CSV (*.csv)")
                if not path:
                    return
                self._set_tool_running("Extracting IOCs", "ioc")
                exporter.write_csv(path)
                self._set_tool_result(
                    "IOC CSV exported",
                    path,
                    {"resultPath": str(path), "resultKind": "ioc", "count": len(iocs), "iocs": len(iocs), "preview": f"{len(iocs)} indicators exported."},
                )
        except Exception as exc:
            self._set_tool_error("IOC export failed", exc)

    @Slot()
    def exportSigma(self) -> None:
        directory = get_existing_directory("Export Sigma Rules", str(_EXPORT_DIR))
        if not directory:
            return
        try:
            self._set_tool_running("Exporting Sigma rules", "sigma")
            from detection.sigma_exporter import SigmaExporter

            paths = SigmaExporter(author="NexLog").export_bundle(self._case_findings(limit=2000), directory)
            self._set_tool_result(
                "Sigma rules exported",
                directory,
                {"resultPath": str(directory), "resultKind": "sigma", "count": len(paths), "files": len(paths), "preview": f"{len(paths)} Sigma files exported."},
            )
        except Exception as exc:
            self._set_tool_error("Sigma export failed", exc)

    @Slot(str)
    def exportGraph(self, fmt: str = "json") -> None:
        fmt = (fmt or "json").lower()
        ext_map = {
            "json": "json",
            "neo4j": "json",
            "graphml": "graphml",
            "svg": "svg",
            "png": "png",
            "pdf": "pdf",
        }
        ext = ext_map.get(fmt, "json")
        default = self._default_export_path(ext, f"nexlog_graph_{fmt}")
        path = get_save_file_name(f"Export Attack Graph {fmt.upper()}", str(default), f"{fmt.upper()} (*.{ext})")
        if not path:
            return
        try:
            self._set_tool_running(f"Rendering graph {fmt.upper()}", "graph")
            graph = self.graphSnapshot()
            if fmt in {"json", "neo4j"}:
                Path(path).write_text(json.dumps(graph, indent=2, default=str), encoding="utf-8")
            elif fmt == "graphml":
                Path(path).write_text(self._graph_to_graphml(graph), encoding="utf-8")
            elif fmt == "svg":
                Path(path).write_text(self._graph_to_svg(graph), encoding="utf-8")
            elif fmt == "png":
                self._graph_to_png(graph, Path(path))
            elif fmt == "pdf":
                pdf_path = Path(path)
                svg_path = pdf_path.with_suffix(".svg")
                svg_path.write_text(self._graph_to_svg(graph), encoding="utf-8")
                self._set_tool_result(
                    "Graph SVG exported for PDF workflow",
                    str(svg_path),
                    {"resultPath": str(svg_path), "resultKind": "graph", "preview": "SVG graph generated for PDF workflow."},
                )
                return
            self._set_tool_result(
                f"Attack graph {fmt.upper()} exported",
                path,
                {"resultPath": str(path), "resultKind": "graph", "preview": f"Attack graph exported as {fmt.upper()}."},
            )
        except Exception as exc:
            self._set_tool_error("Attack graph export failed", exc)

    @Slot(result=str)
    def graphStorySnapshot(self) -> str:
        return str(self._graph.get("story") or self._chains_to_story(self._graph.get("chains", [])))

    @Slot()
    def exportCaseBundle(self) -> None:
        default = self._default_export_path("nexlogcase", "nexlog_case_bundle")
        path = get_save_file_name("Export NexLog Case Bundle", str(default), "NexLog Case Bundle (*.nexlogcase)")
        if not path:
            return
        try:
            self._set_tool_running("Building case bundle", "bundle")
            bundle = Path(path)
            bundle.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as zf:
                case = Path(self._case_path)
                if case.exists():
                    zf.write(case, f"case/{case.name}")
                zf.writestr("manifest.json", json.dumps({
                    "product": "NexLog",
                    "exported_at": datetime.now().isoformat(timespec="seconds"),
                    "case_path": self._case_path,
                    "session_id": self._current_session_id,
                    "finding_count": self._finding_count,
                    "threat_level": self._threat_level,
                }, indent=2))
                zf.writestr("dashboard.json", json.dumps(self.dashboardSnapshot(), indent=2, default=str))
                zf.writestr("findings.json", json.dumps(self.findingsSnapshot(), indent=2, default=str))
                zf.writestr("timeline.json", json.dumps(self.timelineSnapshot(), indent=2, default=str))
                zf.writestr("attack_graph.json", json.dumps(self.graphSnapshot(), indent=2, default=str))
                zf.writestr("attack_graph.graphml", self._graph_to_graphml(self.graphSnapshot()))
            self._set_tool_result(
                "Case bundle exported",
                str(bundle),
                {"resultPath": str(bundle), "resultKind": "bundle", "preview": "Case bundle contains DB, manifest, findings, timeline, graph JSON, and GraphML."},
            )
        except Exception as exc:
            self._set_tool_error("Case bundle export failed", exc)

    @Slot()
    def runUeba(self) -> None:
        try:
            self._set_tool_running("Running UEBA", "ueba")
            from detection.ueba import UEBAEngine
            from storage.case_db import CaseDB

            with CaseDB(self._case_path) as db:
                engine = UEBAEngine(threshold=4.0)
                if self._current_session_id:
                    anomalies = engine.score_session(db, self._current_session_id)
                else:
                    findings = db.get_findings(limit=5000)
                    engine.score_findings(findings)
                    anomalies = engine.get_anomalies(threshold=4.0)
            self._set_tool_result(
                "UEBA analysis complete",
                "",
                {"resultKind": "ueba", "anomalies": anomalies[:10], "count": len(anomalies), "preview": f"{len(anomalies)} anomalies scored."},
            )
        except Exception as exc:
            self._set_tool_error("UEBA analysis failed", exc)

    @Slot()
    def importSigmaRules(self) -> None:
        self._set_tool_result(
            "Sigma importer staged",
            "",
            {"message": "The roadmap now tracks Sigma import; current QML build preserves existing Sigma export."},
        )

    @Slot()
    def runRuleTests(self) -> None:
        self._set_tool_result(
            "Rule harness staged",
            "",
            {"message": "Rule test harness is planned for the detection-quality milestone."},
        )

    def _ai_case_context(self, limit: int = 80) -> str:
        """Build a bounded evidence context for lazy LLM calls."""
        if not self._findings:
            self.refreshSessions()
        lines = [
            f"Case: {Path(self._case_path).name}",
            f"Scope: {self._session_scope_label}",
            f"Findings loaded: {len(self._findings)}",
            f"Threat level: {self._threat_level}",
        ]
        for idx, item in enumerate(self._findings[:limit], 1):
            lines.append(
                "Finding {idx}: Rule {rule} | Severity {sev} | risk score {risk} | "
                "Source {source} | Category {cat} | MITRE {mitre} | Evidence {evidence}".format(
                    idx=idx,
                    rule=item.get("rule_name") or item.get("rule_id") or "finding",
                    sev=item.get("severity") or "INFO",
                    risk=item.get("risk_score") or 0,
                    source=item.get("source_display") or item.get("source_ip") or item.get("hostname") or "unknown",
                    cat=item.get("category") or "uncategorized",
                    mitre=", ".join(item.get("mitre_ids", [])) or "none",
                    evidence=str(item.get("summary") or item.get("trigger_line") or "")[:260],
                )
            )
        if self._graph.get("story"):
            lines.append(f"Attack story: {self._graph.get('story')}")
        return "\n".join(lines)[:28000]

    def _llm_client(self):
        from ai.llm_client import LLMClient

        force_raw = os.environ.get("NEXLOG_LLM_FORCE_TIER", "").strip()
        force_tier = int(force_raw) if force_raw.isdigit() else None
        return LLMClient(
            model=os.environ.get("NEXLOG_MODEL", "mistral"),
            ollama_url=os.environ.get("OLLAMA_HOST", "http://localhost:11434"),
            groq_key=os.environ.get("GROQ_API_KEY", ""),
            gemini_key=os.environ.get("GEMINI_API_KEY", ""),
            anthropic_key=os.environ.get("ANTHROPIC_API_KEY", ""),
            force_tier=force_tier,
            timeout=45,
        )

    @staticmethod
    def _masked_configured(name: str) -> bool:
        return bool(os.environ.get(name, "").strip())

    @staticmethod
    def _normalise_ai_provider(name: str) -> str:
        value = (name or "").strip().lower().replace("_", "-")
        aliases = {
            "claude": "anthropic",
            "anthropic-claude": "anthropic",
            "google": "gemini",
            "google-gemini": "gemini",
            "local": "ollama",
            "openai compatible": "openai-compatible",
            "openai-compatible": "openai-compatible",
        }
        return aliases.get(value, value)

    @staticmethod
    def _provider_label(provider: str) -> str:
        labels = {
            "anthropic": "Claude / Anthropic",
            "groq": "Groq",
            "gemini": "Gemini",
            "ollama": "Ollama",
            "openai-compatible": "OpenAI-compatible",
            "custom": "Custom",
            "managed": "NexLog managed AI",
            "template": "Offline template",
        }
        return labels.get((provider or "").lower(), provider or "Not set")

    def _ai_provider_slot(self, idx: int) -> dict[str, Any]:
        provider = os.environ.get(f"NEXLOG_AI_PROVIDER_{idx}", "").strip()
        endpoint = os.environ.get(f"NEXLOG_AI_ENDPOINT_{idx}", "").strip()
        model = os.environ.get(f"NEXLOG_AI_MODEL_{idx}", "").strip()
        provider_id = self._normalise_ai_provider(provider)
        configured = bool(os.environ.get(f"NEXLOG_AI_KEY_{idx}", "").strip() or provider_id == "ollama")
        return {
            "slot": idx,
            "provider": provider_id,
            "label": self._provider_label(provider_id),
            "configured": configured,
            "endpointConfigured": bool(endpoint),
            "model": model or "auto-latest",
        }

    @staticmethod
    def _update_env_file(path: Path, updates: dict[str, str]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        existing = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
        keys = set(updates)
        written: set[str] = set()
        lines: list[str] = []
        for line in existing:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                lines.append(line)
                continue
            key = stripped.split("=", 1)[0].strip()
            if key in keys:
                lines.append(f"{key}={updates[key]}")
                written.add(key)
            else:
                lines.append(line)
        for key, value in updates.items():
            if key not in written:
                lines.append(f"{key}={value}")
        path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")

    @Slot(result="QVariant")
    def aiProviderConfigSnapshot(self) -> dict[str, Any]:
        managed_endpoint = os.environ.get("NEXLOG_MANAGED_AI_ENDPOINT", "").strip()
        return {
            "providers": [self._ai_provider_slot(1), self._ai_provider_slot(2)],
            "managedConfigured": bool(managed_endpoint),
            "managedEndpointConfigured": bool(managed_endpoint),
            "groqConfigured": self._masked_configured("GROQ_API_KEY") or any(
                self._ai_provider_slot(idx).get("provider") == "groq" and self._ai_provider_slot(idx).get("configured")
                for idx in (1, 2)
            ),
            "geminiConfigured": self._masked_configured("GEMINI_API_KEY") or any(
                self._ai_provider_slot(idx).get("provider") == "gemini" and self._ai_provider_slot(idx).get("configured")
                for idx in (1, 2)
            ),
            "legacyConfigured": {
                "groq": self._masked_configured("GROQ_API_KEY"),
                "gemini": self._masked_configured("GEMINI_API_KEY"),
                "anthropic": self._masked_configured("ANTHROPIC_API_KEY"),
            },
            "ollamaHost": os.environ.get("OLLAMA_HOST", "http://localhost:11434"),
            "model": os.environ.get("NEXLOG_MODEL", "mistral"),
            "envPath": str(_GUI_ENV_PATH),
            "warning": "Keys are stored only in your ignored local .env.gui file. Rotate any key that was pasted into chat or shared publicly.",
        }

    @Slot("QVariant", result=bool)
    def saveAiProviderConfig(self, config: Any) -> bool:
        try:
            data = dict(config or {})
            updates: dict[str, str] = {}
            for idx in (1, 2):
                provider = self._normalise_ai_provider(str(data.get(f"provider{idx}") or "").strip())
                key = str(data.get(f"apiKey{idx}") or "").strip()
                endpoint = str(data.get(f"endpoint{idx}") or "").strip()
                slot_model = str(data.get(f"model{idx}") or "").strip()
                if provider:
                    updates[f"NEXLOG_GUI_AI_PROVIDER_{idx}"] = provider
                if key:
                    updates[f"NEXLOG_GUI_AI_KEY_{idx}"] = key
                if endpoint:
                    updates[f"NEXLOG_GUI_AI_ENDPOINT_{idx}"] = endpoint
                if slot_model:
                    updates[f"NEXLOG_GUI_AI_MODEL_{idx}"] = slot_model
            ollama_host = str(data.get("ollamaHost") or "").strip()
            if ollama_host:
                updates["NEXLOG_GUI_OLLAMA_HOST"] = ollama_host
            managed_endpoint = str(data.get("managedEndpoint") or "").strip()
            managed_token = str(data.get("managedToken") or "").strip()
            if managed_endpoint:
                updates["NEXLOG_MANAGED_AI_ENDPOINT"] = managed_endpoint
            if managed_token:
                updates["NEXLOG_MANAGED_AI_TOKEN"] = managed_token
            if not updates:
                self._set_status("AI provider configuration unchanged", 100)
                return True
            self._update_env_file(_GUI_ENV_PATH, updates)
            self.reloadAiProviderConfig()
            self._set_tool_result(
                "AI provider configuration saved",
                str(_GUI_ENV_PATH),
                {
                    "resultKind": "ai-config",
                    "preview": "Saved local GUI AI provider slots. Key values are masked and are not shown in NexLog.",
                    "count": len(updates),
                },
            )
            return True
        except Exception as exc:
            self._set_tool_error("AI provider configuration failed", exc)
            return False

    @Slot("QVariant", result="QVariant")
    def testAiProvider(self, config: Any) -> dict[str, Any]:
        """Validate provider config shape without exposing or logging secrets."""
        try:
            data = dict(config or {})
            provider = self._normalise_ai_provider(str(data.get("provider") or data.get("provider1") or "").strip())
            key = str(data.get("apiKey") or data.get("apiKey1") or "").strip()
            endpoint = str(data.get("endpoint") or data.get("endpoint1") or "").strip()
            warnings: list[str] = []
            if provider not in {"anthropic", "groq", "gemini", "ollama", "openai-compatible", "custom", "managed"}:
                warnings.append("Choose a supported provider name.")
            if provider in {"anthropic", "groq", "gemini", "openai-compatible", "custom"} and not key:
                warnings.append("API key is required for this provider.")
            if provider in {"openai-compatible", "custom", "managed"} and not endpoint:
                warnings.append("Endpoint is required for this provider.")
            if provider == "groq" and key and not key.startswith("gsk_"):
                warnings.append("Groq keys usually start with gsk_.")
            if provider == "gemini" and key and not key.startswith("AIza"):
                warnings.append("Gemini keys usually start with AIza.")
            if provider == "anthropic" and key and not key.startswith("sk-ant-"):
                warnings.append("Claude/Anthropic keys usually start with sk-ant-.")
            return {
                "ok": not warnings,
                "provider": provider,
                "label": self._provider_label(provider),
                "warnings": warnings,
                "message": "Provider config looks usable." if not warnings else "Provider config needs attention.",
            }
        except Exception as exc:
            return {"ok": False, "warnings": [str(exc)], "message": "Provider validation failed."}

    @Slot(result=bool)
    def reloadAiProviderConfig(self) -> bool:
        try:
            load_env_profile("gui")
            self.toolsChanged.emit(dict(self._tools))
            self._set_status("AI provider configuration reloaded", 100)
            return True
        except Exception as exc:
            self._set_tool_error("AI provider reload failed", exc)
            return False

    @Slot(result="QVariant")
    def aiStatusSnapshot(self) -> dict[str, Any]:
        try:
            llm = self._llm_client()
            provider = getattr(llm, "tier_name", "template-synthesis")
            tier = int(getattr(llm, "tier", 3) or 3)
        except Exception as exc:
            provider = f"template-synthesis ({exc})"
            tier = 3
        return {
            "provider": provider,
            "tier": tier,
            "providers": [self._ai_provider_slot(1), self._ai_provider_slot(2)],
            "configuredProviderCount": sum(1 for idx in (1, 2) if self._ai_provider_slot(idx).get("configured")),
            "managedConfigured": bool(os.environ.get("NEXLOG_MANAGED_AI_ENDPOINT", "").strip()),
            "groqConfigured": bool(os.environ.get("GROQ_API_KEY")) or any(
                self._ai_provider_slot(idx).get("provider") == "groq" and self._ai_provider_slot(idx).get("configured")
                for idx in (1, 2)
            ),
            "geminiConfigured": bool(os.environ.get("GEMINI_API_KEY")) or any(
                self._ai_provider_slot(idx).get("provider") == "gemini" and self._ai_provider_slot(idx).get("configured")
                for idx in (1, 2)
            ),
            "legacyConfigured": {
                "groq": bool(os.environ.get("GROQ_API_KEY")),
                "gemini": bool(os.environ.get("GEMINI_API_KEY")),
                "anthropic": bool(os.environ.get("ANTHROPIC_API_KEY")),
            },
            "ollamaHost": os.environ.get("OLLAMA_HOST", "http://localhost:11434"),
            "model": os.environ.get("NEXLOG_MODEL", "mistral"),
        }

    @Slot()
    def generateAiReport(self) -> None:
        try:
            default = self._default_export_path("pdf", "nexlog_ai_report")
            path = get_save_file_name(
                "Export AI Report PDF",
                str(default),
                "PDF (*.pdf)",
            )
            if not path:
                return
            self._set_tool_running("Generating AI report PDF", "ai-report")
            from intelligence.ioc_extractor import IOCExtractor
            from output.pdf_report import PDFReport
            from storage.case_db import CaseDB

            with CaseDB(self._case_path) as db:
                session_id = self._current_session_id or None
                findings = db.get_findings(session_id=session_id, limit=5000)
                iocs = IOCExtractor().extract(findings)
                context = self._ai_case_context(limit=120)
                report = self._llm_client().generate(
                    query=(
                        "Generate a concise DFIR investigation report narrative. "
                        "Include executive summary, highest-risk findings, likely attack path, "
                        "MITRE interpretation, affected sources, and recommended next actions."
                    ),
                    context=context,
                    max_tokens=1200,
                    temperature=0.18,
                    task="ai_report_narrative",
                )
                PDFReport(
                    db=db,
                    session_id=session_id,
                    findings=findings,
                    iocs=iocs,
                    case_ref=f"NEXLOG-AI-{Path(self._case_path).stem.upper()}",
                    analyst="analyst",
                    ai_narrative=report,
                ).build(path)
            self._set_tool_result(
                "AI report PDF generated",
                str(path),
                {
                    "resultPath": str(path),
                    "resultKind": "pdf",
                    "preview": str(report)[:1600],
                    "count": len(str(report)),
                },
            )
        except Exception as exc:
            self._set_tool_error("AI report unavailable", exc)

    @Slot()
    def indexSession(self) -> None:
        self._set_tool_result("AI indexing is lazy", "", {"message": "Open the AI panel to index this session with optional local models."})

    @Slot(str, result=str)
    def askAi(self, question: str) -> str:
        question = (question or "").strip()
        if not question:
            return "Ask a case question first."
        try:
            context = self._ai_case_context(limit=80)
            answer = self._llm_client().generate(
                query=question,
                context=context,
                max_tokens=700,
                temperature=0.15,
                task="case_question",
            )
            status = self.aiStatusSnapshot()
            self._set_tool_result(
                "AI answer generated",
                "",
                {"resultKind": "ai", "provider": status.get("provider", ""), "preview": answer[:1200]},
            )
            return answer
        except Exception as exc:
            fallback = (
                f"AI provider failed: {exc}. "
                "NexLog could not generate an answer from the configured LLM. "
                "Check your AI provider setup, managed relay, or Ollama."
            )
            self._set_tool_error("AI answer failed", exc)
            return fallback

    @Slot()
    def clearAiHistory(self) -> None:
        self._set_tool_result("AI chat cleared", "")

    @Slot(str)
    def openResultFolder(self, path: str) -> None:
        try:
            target = Path(path)
            folder = target if target.is_dir() else target.parent
            if not folder.exists():
                self._set_tool_error("Open folder failed", FileNotFoundError(str(folder)))
                return
            os.startfile(str(folder))  # type: ignore[attr-defined]
            self._set_status(f"Opened folder: {folder}", 100)
        except Exception as exc:
            self._set_tool_error("Open folder failed", exc)

    @Slot(str)
    def copyText(self, text: str) -> None:
        try:
            clipboard = QGuiApplication.clipboard()
            if clipboard:
                clipboard.setText(str(text or ""))
                self._set_status("Copied to clipboard", 100)
        except Exception as exc:
            self._set_tool_error("Copy failed", exc)

    @Slot(str, str)
    def setFindingState(self, finding_id: str, state: str) -> None:
        action_map = {
            "NEW": "new",
            "ACK": "triaged",
            "TRIAGED": "triaged",
            "ESCALATE": "escalated",
            "ESCALATED": "escalated",
            "CONTAIN": "contained",
            "CONTAINED": "contained",
            "FP": "false_positive",
            "FALSE_POSITIVE": "false_positive",
        }
        action = action_map.get((state or "").upper(), "triaged")
        try:
            from storage.case_db import CaseDB

            with CaseDB(self._case_path) as db:
                db.add_analyst_action(finding_id, action, analyst="analyst", note=f"QML action: {action}")
            self.refreshSessions()
            self._set_status(f"Finding marked {action}", 100)
        except Exception as exc:
            self._set_tool_error("Finding action failed", exc)

    @Slot()
    def createCanaryToken(self) -> None:
        self._set_tool_result("Canary manager", "", {"message": "Canary token creation is queued for the QML Tools workflow."})

    @Slot()
    def startCanaryListener(self) -> None:
        self._set_tool_result("Canary listener", "", {"message": "Listener control is staged for the QML tools panel."})

    def _set_tool_running(self, action: str, kind: str = "") -> None:
        self._tools = {
            "lastAction": action,
            "lastOutput": "",
            "resultPath": "",
            "resultKind": kind,
            "preview": "",
            "count": 0,
            "error": False,
            "running": True,
        }
        self.toolsChanged.emit(dict(self._tools))
        self._set_status(action, self._progress_value)

    def _set_tool_result(self, action: str, output: str, extra: dict[str, Any] | None = None) -> None:
        payload = {
            "lastAction": action,
            "lastOutput": str(output),
            "resultPath": str(output) if output else "",
            "resultKind": "",
            "preview": str(output) if output else "",
            "count": 0,
            "error": False,
            "running": False,
        }
        payload.update(extra or {})
        self._tools = payload
        self.toolsChanged.emit(dict(self._tools))
        self._set_status(action, 100)

    def _set_tool_error(self, action: str, exc: Exception) -> None:
        message = f"{action}: {exc}"
        self._tools = {
            "lastAction": action,
            "lastOutput": str(exc),
            "resultPath": "",
            "resultKind": "",
            "preview": str(exc),
            "count": 0,
            "error": True,
            "running": False,
        }
        self.toolsChanged.emit(dict(self._tools))
        self._set_status(message, 100)
        self.analysisError.emit(message)

    @staticmethod
    def _graph_to_graphml(graph: dict[str, Any]) -> str:
        def esc(value: Any) -> str:
            return (
                str(value)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
            )

        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
            '<key id="label" for="node" attr.name="label" attr.type="string"/>',
            '<key id="kind" for="node" attr.name="kind" attr.type="string"/>',
            '<key id="severity" for="all" attr.name="severity" attr.type="string"/>',
            '<key id="risk" for="all" attr.name="risk" attr.type="double"/>',
            '<key id="relation" for="edge" attr.name="relation" attr.type="string"/>',
            '<graph id="NexLogAttackGraph" edgedefault="directed">',
        ]
        for node in graph.get("nodes", []):
            lines.append(f'<node id="{esc(node.get("id", ""))}">')
            lines.append(f'<data key="label">{esc(node.get("label", ""))}</data>')
            lines.append(f'<data key="kind">{esc(node.get("kind", ""))}</data>')
            lines.append(f'<data key="severity">{esc(node.get("severity", ""))}</data>')
            lines.append(f'<data key="risk">{esc(node.get("risk", 0))}</data>')
            lines.append("</node>")
        for idx, edge in enumerate(graph.get("edges", [])):
            lines.append(
                f'<edge id="e{idx}" source="{esc(edge.get("from", ""))}" target="{esc(edge.get("to", ""))}">'
            )
            lines.append(f'<data key="relation">{esc(edge.get("relation", ""))}</data>')
            lines.append(f'<data key="severity">{esc(edge.get("severity", ""))}</data>')
            lines.append(f'<data key="risk">{esc(edge.get("risk", 0))}</data>')
            lines.append("</edge>")
        lines.extend(["</graph>", "</graphml>"])
        return "\n".join(lines)

    @staticmethod
    def _graph_to_svg(graph: dict[str, Any]) -> str:
        nodes = graph.get("nodes", [])[:160]
        edges = graph.get("edges", [])[:320]
        width, height = 1400, 900
        layers = {"source": 0.12, "category": 0.38, "rule": 0.65, "technique": 0.88}
        grouped: dict[str, list[dict[str, Any]]] = {}
        for node in nodes:
            grouped.setdefault(node.get("kind", "rule"), []).append(node)
        positions: dict[str, tuple[float, float]] = {}
        for kind, group in grouped.items():
            total = max(1, len(group))
            for idx, node in enumerate(group):
                x = width * layers.get(kind, 0.5)
                y = 110 + idx * ((height - 220) / total)
                positions[node.get("id", "")] = (x, y)

        def esc(value: Any) -> str:
            return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        def color(sev: str, kind: str = "") -> str:
            if kind == "source":
                return "#ff4d7d"
            if kind == "category":
                return "#62f3ff"
            if kind == "rule":
                return "#a88cff"
            if kind == "technique":
                return "#7df9c7"
            return {"CRITICAL": "#ff4d7d", "HIGH": "#ff9f43", "MEDIUM": "#ffd166", "LOW": "#62f3ff"}.get(sev, "#93a4c7")

        parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
            '<rect width="100%" height="100%" fill="#080d1e"/>',
            '<text x="32" y="46" fill="#f4f8ff" font-size="28" font-family="Arial" font-weight="700">NexLog Attack Graph</text>',
        ]
        for edge in edges:
            a = positions.get(edge.get("from", ""))
            b = positions.get(edge.get("to", ""))
            if not a or not b:
                continue
            parts.append(
                f'<path d="M {a[0]:.1f} {a[1]:.1f} C {(a[0]+b[0])/2:.1f} {a[1]-40:.1f}, {(a[0]+b[0])/2:.1f} {b[1]-40:.1f}, {b[0]:.1f} {b[1]:.1f}" '
                f'stroke="{color(edge.get("severity", "INFO"))}" stroke-opacity="0.45" stroke-width="{1 + min(5, edge.get("weight", 1))}" fill="none"/>'
            )
        for node in nodes:
            pos = positions.get(node.get("id", ""))
            if not pos:
                continue
            c = color(node.get("severity", "INFO"), node.get("kind", ""))
            radius = 12 + min(18, int(node.get("weight", 1) or 1))
            parts.append(f'<circle cx="{pos[0]:.1f}" cy="{pos[1]:.1f}" r="{radius}" fill="{c}" opacity="0.92"/>')
            parts.append(f'<text x="{pos[0] + radius + 8:.1f}" y="{pos[1] + 4:.1f}" fill="#eaf7ff" font-size="12" font-family="Arial">{esc(node.get("label", ""))[:42]}</text>')
        parts.append("</svg>")
        return "\n".join(parts)

    @staticmethod
    def _graph_to_png(graph: dict[str, Any], path: Path) -> None:
        from PySide6.QtCore import QPointF
        from PySide6.QtGui import QColor, QFont, QImage, QPainter, QPen

        width, height = 1400, 900
        image = QImage(width, height, QImage.Format_ARGB32)
        image.fill(QColor("#080d1e"))
        painter = QPainter(image)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setFont(QFont("Arial", 11))

        nodes = graph.get("nodes", [])[:160]
        edges = graph.get("edges", [])[:320]
        layers = {"source": 0.12, "category": 0.38, "rule": 0.65, "technique": 0.88}
        grouped: dict[str, list[dict[str, Any]]] = {}
        for node in nodes:
            grouped.setdefault(node.get("kind", "rule"), []).append(node)
        positions: dict[str, QPointF] = {}
        for kind, group in grouped.items():
            total = max(1, len(group))
            for idx, node in enumerate(group):
                positions[node.get("id", "")] = QPointF(width * layers.get(kind, 0.5), 110 + idx * ((height - 220) / total))

        def qcolor(sev: str, kind: str = "") -> QColor:
            mapping = {
                "source": "#ff4d7d",
                "category": "#62f3ff",
                "rule": "#a88cff",
                "technique": "#7df9c7",
                "CRITICAL": "#ff4d7d",
                "HIGH": "#ff9f43",
                "MEDIUM": "#ffd166",
                "LOW": "#62f3ff",
            }
            return QColor(mapping.get(kind, mapping.get(sev, "#93a4c7")))

        painter.setPen(QColor("#f4f8ff"))
        painter.setFont(QFont("Arial", 24, QFont.Bold))
        painter.drawText(32, 48, "NexLog Attack Graph")
        for edge in edges:
            a = positions.get(edge.get("from", ""))
            b = positions.get(edge.get("to", ""))
            if not a or not b:
                continue
            pen = QPen(qcolor(edge.get("severity", "INFO")))
            pen.setWidth(1 + min(5, int(edge.get("weight", 1) or 1)))
            painter.setPen(pen)
            painter.drawLine(a, b)
        painter.setFont(QFont("Arial", 10))
        for node in nodes:
            pos = positions.get(node.get("id", ""))
            if not pos:
                continue
            color = qcolor(node.get("severity", "INFO"), node.get("kind", ""))
            painter.setBrush(color)
            painter.setPen(QColor("#ffffff"))
            radius = 12 + min(18, int(node.get("weight", 1) or 1))
            painter.drawEllipse(pos, radius, radius)
            painter.setPen(QColor("#eaf7ff"))
            painter.drawText(pos.x() + radius + 8, pos.y() + 4, str(node.get("label", ""))[:42])
        painter.end()
        image.save(str(path))
