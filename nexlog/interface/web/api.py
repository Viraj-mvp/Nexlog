"""
interface/web/api.py - NexLog web API
REST API server — wires all three analysis layers to HTTP endpoints.

Two execution modes:
  Mode A — FastAPI (recommended):
      pip install fastapi uvicorn
      python api.py            # starts on http://localhost:8000
      Docs at http://localhost:8000/docs (Swagger UI auto-generated)

  Mode B — stdlib http.server (zero dependencies):
      python api.py --stdlib   # starts on http://localhost:8000
      No docs UI, but all endpoints work identically.
      Useful in air-gapped environments where pip is not available.

Endpoints:
  GET  /api/health            Liveness + readiness check
  GET  /api/stats             Global detection statistics
  POST /api/analyse           Submit a log file for analysis
  GET  /api/sessions          List all analysis sessions
  GET  /api/sessions/{id}     Get one session with summary
  GET  /api/findings          Query findings (filters: severity, category, ip, host)
  POST /api/findings/{id}/action  Add append-only analyst action
  GET  /api/findings/{id}/actions Get analyst action trail
  GET  /api/iocs              Get extracted IOCs for a session
  GET  /api/case/integrity    Verify case/evidence integrity
  POST /api/evidence/verify   Verify one evidence file by id
  POST /api/report            Generate a report (json|text|markdown|pdf)
  GET  /api/report/download   Download a generated PDF
  POST /api/notes             Add an analyst note
  GET  /api/notes             Get analyst notes for a session
  GET  /api/chains            Get attack chains for a session
  POST /api/export/stix       Export STIX 2.1 bundle
  POST /api/export/iocs       Export IOC flat files (all formats)
  DELETE /api/cache           Clear AbuseIPDB / GeoIP enrichment caches

Usage:
    # FastAPI mode
    from interface.web.api import create_app
    app = create_app(case_db_path="case.facase")

    # stdlib mode (for testing / air-gap)
    from interface.web.api import run_stdlib_server
    run_stdlib_server(port=8000, case_db_path="case.facase")

    # CLI
    python api.py --port 8000 --case case.facase
"""

import json
import hashlib
import os
import sqlite3
import sys
import time
import threading
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs

# ── Self-locating path ────────────────────────────────────────────────────

_root = os.path.dirname(os.path.abspath(__file__))
for _ in range(8):
    if os.path.isfile(os.path.join(_root, 'pathconfig.py')):
        break
    _root = os.path.dirname(_root)
if _root not in sys.path:
    sys.path.insert(0, _root)
from pathconfig import ROOT, WORKSPACE_DIR, add_root
add_root()
_ROOT = ROOT
for _p in ['core','detection','storage','intelligence','output','interface/web']:
    sys.path.insert(0, os.path.join(_ROOT, _p))

from storage.case_db import CaseDB
from intelligence.ioc_extractor import IOCExtractor
from output.report_builder import ReportBuilder
from output.stix_export import STIXExport
from output.ioc_csv import IOCExporter
from schemas import (
    AnalyseRequest, AnalyseResponse, SessionSummary,
    FindingSchema, FindingListResponse,
    IOCSchema, IOCListResponse,
    ReportRequest, ReportResponse,
    HealthResponse, StatsResponse,
    NoteRequest,
)
try:
    import interface.web.auth as auth_mod
    from interface.web.auth import SECURITY_HEADERS, auth_status, check_auth, check_rate_limit, get_client_ip
except ImportError:
    auth_mod = None
    SECURITY_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store",
    }
    def check_auth(path, headers):
        if path in {"/api/health", "/api/v1/health"}:
            return True, 200, ""
        return False, 503, "API authentication unavailable"
    def check_rate_limit(ip): return True, ""
    def get_client_ip(headers, addr): return addr or "unknown"
    def auth_status():
        return {"auth_enabled": False, "primary_env": "NEXLOG_API_KEY"}

_START_TIME = time.monotonic()
_SEV_ORDER = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
_WEB_ENV_PATH = Path(ROOT) / ".env.web"


def _sha256_text(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _safe_name(path: str) -> str:
    return Path(path).name if path else ""


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = {sev: 0 for sev in _SEV_ORDER}
    for item in findings:
        sev = str(item.get("severity", "INFO")).upper()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _risk_level(severity_counts: dict[str, int]) -> str:
    if severity_counts.get("CRITICAL", 0):
        return "CRITICAL"
    if severity_counts.get("HIGH", 0):
        return "HIGH"
    if severity_counts.get("MEDIUM", 0):
        return "ELEVATED"
    if severity_counts.get("LOW", 0):
        return "LOW"
    return "QUIET"


def _llm_provider_from_tier_name(tier_name: str) -> str:
    raw = str(tier_name or "").strip().lower()
    if not raw:
        return "unknown"
    provider = raw.split(":", 1)[0]
    if provider in {"template-synthesis", "template"}:
        return "template"
    return provider


def _normalise_ai_provider(name: str) -> str:
    value = (name or "").strip().lower().replace("_", "-")
    aliases = {
        "claude": "anthropic",
        "anthropic-claude": "anthropic",
        "google": "gemini",
        "google-gemini": "gemini",
        "local": "ollama",
        "openai compatible": "openai-compatible",
    }
    return aliases.get(value, value)


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
    return labels.get(provider or "", provider or "Not set")


def _ai_provider_slot(idx: int) -> dict:
    provider = _normalise_ai_provider(os.environ.get(f"NEXLOG_AI_PROVIDER_{idx}", ""))
    return {
        "slot": idx,
        "provider": provider,
        "label": _provider_label(provider),
        "configured": bool(os.environ.get(f"NEXLOG_AI_KEY_{idx}", "").strip() or provider == "ollama"),
        "endpointConfigured": bool(os.environ.get(f"NEXLOG_AI_ENDPOINT_{idx}", "").strip()),
        "model": os.environ.get(f"NEXLOG_AI_MODEL_{idx}", "").strip() or "auto-latest",
    }


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


def _ai_provider_config_snapshot() -> dict:
    return {
        "providers": [_ai_provider_slot(1), _ai_provider_slot(2)],
        "configuredProviderCount": sum(1 for idx in (1, 2) if _ai_provider_slot(idx).get("configured")),
        "managedConfigured": bool(os.environ.get("NEXLOG_MANAGED_AI_ENDPOINT", "").strip()),
        "ollamaHost": os.environ.get("OLLAMA_HOST", "http://localhost:11434"),
        "envPath": str(_WEB_ENV_PATH),
    }


def _ai_error(code: str, message: str, *, detail: str = "") -> dict:
    payload = {
        "ok": False,
        "error": {
            "code": code,
            "message": message,
        },
    }
    if detail:
        payload["error"]["detail"] = detail
    return payload


def _finding_to_web_dict(finding) -> dict:
    data = FindingSchema.from_finding(finding).to_dict()
    data["id"] = data.get("finding_id") or data.get("rule_id") or ""
    data["title"] = data.get("rule_name") or data.get("rule_id") or "Finding"
    data["source"] = data.get("source_ip") or data.get("hostname") or "unknown"
    data["mitre_ids"] = data.get("technique_ids") or []
    return data


def _derive_attack_chains(findings: list[dict]) -> list[dict]:
    """Derive useful story chains when explicit DB chain rows are unavailable."""
    if not findings:
        return []
    grouped: dict[str, list[dict]] = {}
    for item in findings:
        source = item.get("source_ip") or item.get("hostname") or "Unknown source"
        grouped.setdefault(source, []).append(item)

    chains = []
    for source, rows in grouped.items():
        rows = sorted(rows, key=lambda r: float(r.get("risk_score") or 0), reverse=True)
        categories = []
        rules = []
        techniques = []
        max_risk = 0.0
        for row in rows:
            cat = row.get("category") or "Detection"
            rule = row.get("rule_name") or row.get("rule_id") or "Rule"
            if cat not in categories:
                categories.append(cat)
            if rule not in rules:
                rules.append(rule)
            for tid in row.get("mitre_ids") or row.get("technique_ids") or []:
                if tid not in techniques:
                    techniques.append(tid)
            max_risk = max(max_risk, float(row.get("risk_score") or 0))
        if rows:
            chain_name = " -> ".join(categories[:4]) if categories else "Attack activity"
            chains.append({
                "chain_name": chain_name,
                "source": source,
                "stages": categories[:8],
                "rules": rules[:8],
                "techniques": techniques[:8],
                "findings": len(rows),
                "max_risk": round(max_risk, 2),
                "summary": (
                    f"{source} triggered {len(rows)} finding(s) across "
                    f"{len(categories)} stage(s): {chain_name}."
                ),
            })
    return sorted(chains, key=lambda c: (c["max_risk"], c["findings"]), reverse=True)[:20]


def _build_graph(findings: list[dict], chains: list[dict]) -> dict:
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def node(node_id: str, label: str, kind: str, severity: str = "INFO", risk: float = 0.0):
        if not node_id:
            return
        existing = nodes.get(node_id)
        if existing:
            existing["count"] += 1
            existing["risk"] = max(existing["risk"], risk)
            return
        nodes[node_id] = {
            "id": node_id,
            "label": label,
            "type": kind,
            "severity": severity,
            "risk": risk,
            "count": 1,
        }

    for item in findings[:500]:
        source = item.get("source_ip") or item.get("hostname") or "Unknown source"
        category = item.get("category") or "Detection"
        rule = item.get("rule_name") or item.get("rule_id") or "Rule"
        sev = str(item.get("severity", "INFO"))
        risk = float(item.get("risk_score") or 0)
        source_id = f"source:{source}"
        category_id = f"category:{category}"
        rule_id = f"rule:{rule}"
        node(source_id, source, "source", sev, risk)
        node(category_id, category, "stage", sev, risk)
        node(rule_id, rule, "rule", sev, risk)
        edges.append({"from": source_id, "to": category_id, "label": "triggered", "severity": sev, "risk": risk})
        edges.append({"from": category_id, "to": rule_id, "label": "matched", "severity": sev, "risk": risk})
        for tid in item.get("mitre_ids") or item.get("technique_ids") or []:
            tech_id = f"mitre:{tid}"
            node(tech_id, tid, "mitre", sev, risk)
            edges.append({"from": rule_id, "to": tech_id, "label": "maps", "severity": sev, "risk": risk})

    return {
        "nodes": list(nodes.values()),
        "edges": edges[:1000],
        "chains": chains,
        "stats": {"nodes": len(nodes), "edges": len(edges), "chains": len(chains)},
    }


def _web_snapshot(state: "_AppState", session_id: Optional[str] = None) -> dict:
    """Build a dashboard-ready snapshot from the case DB."""
    with CaseDB(state.case_db_path) as db:
        sessions = [
            SessionSummary.from_db(s, db.get_findings_summary(session_id=s["session_id"])).to_dict()
            for s in db.list_sessions()
        ]
        active_session = session_id or (sessions[0]["session_id"] if sessions else None)
        raw_findings = db.get_findings(session_id=active_session, limit=1500)
        findings = [_finding_to_web_dict(f) for f in raw_findings]
        summary = db.get_findings_summary(session_id=active_session)
        timeline = db.get_timeline(session_id=active_session, limit=500)
        for row in timeline:
            if isinstance(row.get("mitre_ids"), str):
                try:
                    row["mitre_ids"] = json.loads(row["mitre_ids"])
                except Exception:
                    row["mitre_ids"] = []
        chains = db.get_attack_chains(session_id=active_session) or _derive_attack_chains(findings)
        notes = db.get_notes(session_id=active_session)

    sev_counts = _severity_counts(findings)
    categories = Counter(f.get("category") or "Uncategorized" for f in findings)
    sources = Counter(f.get("source_ip") or f.get("hostname") or "unknown" for f in findings)
    mitre = Counter()
    for item in findings:
        for tid in item.get("mitre_ids") or []:
            mitre[tid] += 1

    dashboard = {
        "active_session": active_session,
        "latest_session": sessions[0] if sessions else None,
        "sessions": sessions[:20],
        "total_sessions": len(sessions),
        "total_findings": len(findings),
        "severity": sev_counts,
        "threat_level": _risk_level(sev_counts),
        "top_categories": [{"name": k, "count": v} for k, v in categories.most_common(10)],
        "top_sources": [{"name": k, "count": v} for k, v in sources.most_common(10)],
        "mitre": [{"technique": k, "count": v} for k, v in mitre.most_common(20)],
        "recent_findings": findings[:12],
        "timeline_preview": timeline[-20:],
        "attack_chains": chains[:12],
        "summary": summary,
    }
    return {
        "dashboard": dashboard,
        "sessions": sessions,
        "findings": findings,
        "timeline": timeline,
        "graph": _build_graph(findings, chains),
        "mitre": dashboard["mitre"],
        "notes": notes,
        "chains": chains,
    }


class _JobManager:
    """Small in-process analysis job manager for the local web cockpit."""

    def __init__(self) -> None:
        self._jobs: dict[str, dict] = {}
        self._lock = threading.Lock()

    def create(self, state: "_AppState", body: dict) -> dict:
        job_id = uuid.uuid4().hex
        job = {
            "job_id": job_id,
            "status": "queued",
            "progress": 0,
            "message": "Queued",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "events": [],
            "result": None,
            "error": "",
            "cancel_requested": False,
        }
        with self._lock:
            self._jobs[job_id] = job

        thread = threading.Thread(target=self._run, args=(state, job_id, body), daemon=True)
        thread.start()
        return self.get(job_id)

    def _event(self, job_id: str, status: str, progress: int, message: str, extra: dict | None = None) -> None:
        with self._lock:
            job = self._jobs[job_id]
            job.update({
                "status": status,
                "progress": progress,
                "message": message,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            })
            if extra:
                job.update(extra)
            job["events"].append({
                "status": status,
                "progress": progress,
                "message": message,
                "ts": job["updated_at"],
            })
            job["events"] = job["events"][-100:]

    def _run(self, state: "_AppState", job_id: str, body: dict) -> None:
        try:
            self._event(job_id, "running", 8, "Validating evidence")
            req = AnalyseRequest.from_dict(body)
            self._event(job_id, "running", 18, "Loading parser and rules")
            result = state.analyse(req, async_postprocess=True)
            if not result.success:
                self._event(job_id, "failed", 100, result.error or "Analysis failed", {"error": result.error or ""})
                return
            self._event(job_id, "running", 88, "Refreshing investigation snapshots")
            snapshot = _web_snapshot(state, result.session_id)
            payload = result.to_dict()
            payload["snapshot"] = snapshot
            self._event(job_id, "complete", 100, "Analysis complete", {"result": payload})
        except Exception as exc:
            self._event(job_id, "failed", 100, "Analysis failed", {"error": f"{type(exc).__name__}: {exc}"})

    def get(self, job_id: str) -> dict:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return {}
            return json.loads(json.dumps(job, default=str))

    def cancel(self, job_id: str) -> dict:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return {}
            job["cancel_requested"] = True
            if job["status"] in {"queued", "running"}:
                job["status"] = "cancelling"
                job["message"] = "Cancellation requested"
            return json.loads(json.dumps(job, default=str))


_JOBS = _JobManager()

# ══════════════════════════════════════════════════════════════════════════
# APPLICATION STATE
# ══════════════════════════════════════════════════════════════════════════

class _AppState:
    """
    Shared application state — rule engine, case DB path, enrichment clients.
    Thread-safe: analysis runs are serialised via a lock.
    """
    def __init__(self, case_db_path: str = "nexlog.facase",
                 rules_dir: str = ""):
        self.case_db_path  = case_db_path
        self.rules_dir     = rules_dir or os.path.join(_ROOT, "detection", "rules")
        self._lock         = threading.Lock()
        self._rule_engine  = None
        self._rules_loaded = 0
        self._ai_engine    = None
        self._load_rules()

    def _load_rules(self) -> None:
        try:
            from rule_engine import RuleEngine
            self._rule_engine  = RuleEngine(self.rules_dir)
            self._rules_loaded = self._rule_engine._rules_loaded
        except Exception as e:
            print(f"[API] Warning: could not load rules: {e}")

    def analyse(self, req: AnalyseRequest, *, async_postprocess: bool = False) -> AnalyseResponse:
        """
        Run Layer 1 → Layer 2 → Layer 3 analysis.
        Serialised with a lock — one analysis at a time.
        """
        import main as fa_main
        t0 = time.monotonic()

        errors = req.validate()
        if errors:
            return AnalyseResponse(success=False, error="; ".join(errors))

        log_paths = [Path(p) for p in (req.log_paths or ([req.log_path] if req.log_path else []))]
        missing = [str(p) for p in log_paths if not p.exists()]
        if missing:
            return AnalyseResponse(
                success=False, error=f"File not found: {missing[0]}")

        case_path = Path(req.case_id or self.case_db_path)

        with self._lock:
            try:
                old_enrich_async = os.environ.get("NEXLOG_ENRICH_ASYNC")
                old_graph_async = os.environ.get("NEXLOG_GRAPH_ASYNC")
                os.environ["NEXLOG_ENRICH_ASYNC"] = "1" if async_postprocess else "0"
                os.environ["NEXLOG_GRAPH_ASYNC"] = "1" if async_postprocess else "0"
                result = fa_main.analyse(
                    log_paths    = log_paths,
                    case_path    = case_path,
                    rules_dir    = Path(self.rules_dir),
                    min_severity = req.min_severity,
                    category     = req.category,
                    analyst      = req.analyst,
                    run_chains   = req.run_chains,
                    quiet        = True,
                    profile      = req.profile,
                    batch_size   = req.batch_size,
                    no_enrich    = req.no_enrich,
                    defer_graph  = req.defer_graph,
                    async_postprocess = async_postprocess,
                    max_line_bytes = req.max_line_bytes,
                )
                if old_enrich_async is None:
                    os.environ.pop("NEXLOG_ENRICH_ASYNC", None)
                else:
                    os.environ["NEXLOG_ENRICH_ASYNC"] = old_enrich_async
                if old_graph_async is None:
                    os.environ.pop("NEXLOG_GRAPH_ASYNC", None)
                else:
                    os.environ["NEXLOG_GRAPH_ASYNC"] = old_graph_async
                session_ids = result.get("session_ids") or []
                sid = session_ids[-1] if session_ids else ""
                summaries = []
                with CaseDB(case_path) as db:
                    for item_sid in session_ids:
                        sess = db.get_session(item_sid) or {}
                        summ = db.get_findings_summary(session_id=item_sid)
                        chains = db.get_attack_chains(session_id=item_sid)
                        item_summary = SessionSummary.from_db(sess, summ)
                        item_summary.attack_chains = len(chains)
                        summaries.append(item_summary)
                    ss = summaries[-1] if summaries else None

                elapsed_ms = int((time.monotonic() - t0) * 1000)
                return AnalyseResponse(
                    success     = True,
                    session_id  = sid,
                    session_ids = session_ids,
                    case_path   = str(case_path),
                    summary     = ss,
                    summaries   = summaries,
                    duration_ms = elapsed_ms,
                )
            except Exception as e:
                if old_enrich_async is None:
                    os.environ.pop("NEXLOG_ENRICH_ASYNC", None)
                else:
                    os.environ["NEXLOG_ENRICH_ASYNC"] = old_enrich_async
                if old_graph_async is None:
                    os.environ.pop("NEXLOG_GRAPH_ASYNC", None)
                else:
                    os.environ["NEXLOG_GRAPH_ASYNC"] = old_graph_async
                return AnalyseResponse(
                    success=False,
                    error=f"{type(e).__name__}: {e}",
                )

    def health(self) -> HealthResponse:
        db_ok = False
        try:
            case_path = Path(self.case_db_path)
            if str(self.case_db_path) == ":memory:":
                with CaseDB(":memory:") as db:
                    db_ok = db.get_meta("schema_version") is not None
            elif case_path.exists() and case_path.stat().st_size > 0:
                uri = f"file:{case_path.resolve().as_posix()}?mode=ro"
                with sqlite3.connect(uri, uri=True, timeout=1.0) as conn:
                    conn.execute("SELECT name FROM sqlite_master LIMIT 1").fetchone()
                    db_ok = True
            else:
                parent = case_path.parent if case_path.parent != Path("") else Path.cwd()
                db_ok = parent.exists() and os.access(parent, os.W_OK)
        except Exception:
            db_ok = False

        return HealthResponse(
            status         = "ok" if self._rules_loaded > 0 else "degraded",
            rules_loaded   = self._rules_loaded,
            db_connected   = db_ok,
            uptime_seconds = int(time.monotonic() - _START_TIME),
            checks         = {
                "rules":    self._rules_loaded > 0,
                "database": db_ok,
            },
        )

    def get_ai_engine(self):
        if self._ai_engine is None:
            import sys as _sys
            _sys.path.insert(0, os.path.join(_ROOT, "ai"))
            from query_interface import AIQueryEngine
            self._ai_engine = AIQueryEngine(
                case_db_path=self.case_db_path,
                persist_path=str(Path(self.case_db_path).with_suffix("")) + ".ai",
            )
        return self._ai_engine

    def close(self) -> None:
        engine = getattr(self, "_ai_engine", None)
        if engine is not None:
            try:
                engine.close()
            except Exception:
                pass
            self._ai_engine = None
        try:
            import main as fa_main
            fa_main.shutdown_postprocess_executor(wait=True, cancel_futures=False)
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════
# FASTAPI APP FACTORY
# ══════════════════════════════════════════════════════════════════════════

def create_app(
    case_db_path: str = "nexlog.facase",
    rules_dir:    str = "",
    cors_origins: list[str] = None,
    api_key:      str = "",
):
    """
    Create and return a FastAPI application instance.
    Requires: pip install fastapi uvicorn

    Args:
        case_db_path: Path to the SQLite case database.
        rules_dir:    Path to YAML rules directory.
        cors_origins: List of allowed CORS origins. Default: ["*"]
        api_key:      Optional API key used by FastAPI auth middleware.
    """
    try:
        from fastapi import FastAPI, File, HTTPException, Query, Request, UploadFile, Path as PathParam
        from fastapi.middleware.cors import CORSMiddleware
        from fastapi.responses import (FileResponse, JSONResponse,
                                       PlainTextResponse, Response,
                                       StreamingResponse)
    except ImportError:
        raise ImportError(
            "FastAPI not installed. Run: pip install fastapi uvicorn\n"
            "Or use the stdlib fallback: python api.py --stdlib"
        )

    if api_key and auth_mod is not None:
        auth_mod._API_KEY = api_key

    state = _AppState(case_db_path, rules_dir)

    app = FastAPI(
        title       = "NexLog API",
        description = (
            "Attacker-Aware Log Analysis Platform. "
            "Layer 1 (Parse) → Layer 2 (Detect) → Layer 3 (Store) → "
            "Layer 4 (Report) → Layer 5 (API)."
        ),
        version     = "1.0.0",
        docs_url    = "/docs",
        redoc_url   = "/redoc",
    )

    @app.on_event("shutdown")
    def shutdown_cleanup():
        state.close()

    # CORS: Never use wildcard with credentials (security anti-pattern)
    _origins = cors_origins if cors_origins else []
    if not _origins:
        import warnings
        warnings.warn("CORS origins not configured — API will not accept cross-origin requests", stacklevel=2)

    app.add_middleware(
        CORSMiddleware,
        allow_origins     = _origins,
        allow_credentials = True,
        allow_methods     = ["GET", "POST", "DELETE"],
        allow_headers     = ["Content-Type", "Authorization", "X-API-Key"],
    )

    # Add middleware to enforce auth/rate limits and inject security headers.
    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next):
        headers = request.headers
        remote_addr = request.client.host if request.client else ""
        client_ip = get_client_ip(headers, remote_addr)

        rate_allowed, rate_msg = check_rate_limit(client_ip)
        if not rate_allowed:
            response = JSONResponse({"error": rate_msg}, status_code=429)
        else:
            auth_allowed, status_code, auth_msg = check_auth(request.url.path, headers)
            if not auth_allowed:
                response = JSONResponse({"error": auth_msg}, status_code=status_code)
            else:
                response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers[k] = v
        return response

    # ── Health & Stats ────────────────────────────────────────────────────

    @app.get("/api/health", response_model=None, tags=["System"])
    def health():
        """Liveness and readiness check."""
        return state.health().to_dict()

    @app.get("/api/v1/health", response_model=None, tags=["System"])
    def health_v1():
        return health()

    @app.get("/api/auth/status", response_model=None, tags=["System"])
    def auth_status_endpoint():
        info = auth_status()
        enabled = bool(info.get("auth_enabled"))
        return {
            "auth_enabled": enabled,
            "key_required": enabled,
            "message": "API key required" if enabled else "API key not configured",
            "primary_env": info.get("primary_env", "NEXLOG_API_KEY"),
        }

    @app.get("/api/v1/auth/status", response_model=None, tags=["System"])
    def auth_status_v1_endpoint():
        return auth_status_endpoint()

    @app.get("/api/stats", tags=["System"])
    def stats():
        """Global detection statistics across all sessions."""
        try:
            with CaseDB(state.case_db_path) as db:
                sessions  = db.list_sessions()
                summary   = db.get_findings_summary()
                ioc_count = 0  # IOCs are not stored, recomputed on demand
            return StatsResponse(
                total_sessions   = len(sessions),
                total_findings   = summary.get("total", 0),
                total_iocs       = ioc_count,
                rules_loaded     = state._rules_loaded,
                severity_summary = summary.get("by_severity", {}),
                last_analysis    = sessions[0]["created_at"] if sessions else None,
            ).to_dict()
        except Exception as e:
            raise HTTPException(500, str(e))

    @app.get("/api/v1/stats", tags=["System"])
    def stats_v1():
        return stats()

    # ── Analysis ──────────────────────────────────────────────────────────

    @app.post("/api/analyse", tags=["Analysis"])
    def analyse(body: dict):
        """
        Submit a log file for analysis.
        Runs the full Layer 1 → Layer 2 → Layer 3 pipeline.
        """
        try:
            req = AnalyseRequest.from_dict(body)
        except Exception as e:
            raise HTTPException(400, f"Invalid request: {e}")
        result = state.analyse(req)
        if not result.success:
            raise HTTPException(400, result.error)
        return result.to_dict()

    @app.post("/api/v1/jobs", tags=["Analysis"])
    def create_job(body: dict):
        """Start a background analysis job and return a job id immediately."""
        try:
            errors = AnalyseRequest.from_dict(body).validate()
            if errors:
                raise ValueError("; ".join(errors))
        except Exception as e:
            raise HTTPException(400, f"Invalid request: {e}")
        return _JOBS.create(state, body)

    @app.get("/api/v1/jobs/{job_id}", tags=["Analysis"])
    def get_job(job_id: str = PathParam(..., max_length=64, pattern=r"^[a-fA-F0-9]+$")):
        job = _JOBS.get(job_id)
        if not job:
            raise HTTPException(404, "Job not found")
        return job

    @app.post("/api/v1/jobs/{job_id}/cancel", tags=["Analysis"])
    def cancel_job(job_id: str = PathParam(..., max_length=64, pattern=r"^[a-fA-F0-9]+$")):
        job = _JOBS.cancel(job_id)
        if not job:
            raise HTTPException(404, "Job not found")
        return job

    @app.get("/api/v1/jobs/{job_id}/events", tags=["Analysis"])
    def job_events(job_id: str = PathParam(..., max_length=64, pattern=r"^[a-fA-F0-9]+$")):
        """Server-sent events stream for progress-aware web clients."""
        def _stream():
            last_count = 0
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                job = _JOBS.get(job_id)
                if not job:
                    yield "event: error\ndata: {\"error\":\"job not found\"}\n\n"
                    return
                events = job.get("events", [])
                for event in events[last_count:]:
                    yield f"data: {json.dumps(event)}\n\n"
                last_count = len(events)
                if job.get("status") in {"complete", "failed", "cancelled"}:
                    yield f"event: done\ndata: {json.dumps(job)}\n\n"
                    return
                time.sleep(0.5)
        return StreamingResponse(_stream(), media_type="text/event-stream")

    @app.post("/api/v1/uploads", tags=["Evidence"])
    async def upload_files(files: list[UploadFile] = File(...)):
        """Validate and quarantine one or more uploaded evidence files."""
        try:
            from interface.web.file_upload import FileUploadHandler
        except ImportError:
            from file_upload import FileUploadHandler

        handler = FileUploadHandler()
        results = []
        for item in files:
            saved = await handler.save_fastapi(item)
            results.append(saved.to_dict())
        return {
            "success": any(r.get("ok") for r in results),
            "count": len(results),
            "accepted": sum(1 for r in results if r.get("ok")),
            "rejected": sum(1 for r in results if not r.get("ok")),
            "uploads": results,
            "log_paths": [r["path"] for r in results if r.get("ok")],
        }

    @app.get("/api/v1/snapshot", tags=["Dashboard"])
    def web_snapshot(session_id: Optional[str] = Query(None, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")):
        return _web_snapshot(state, session_id)

    @app.get("/api/v1/dashboard", tags=["Dashboard"])
    def dashboard_snapshot(session_id: Optional[str] = Query(None, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")):
        return _web_snapshot(state, session_id)["dashboard"]

    @app.get("/api/v1/timeline", tags=["Timeline"])
    def timeline_snapshot(session_id: Optional[str] = Query(None, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")):
        return {"events": _web_snapshot(state, session_id)["timeline"]}

    @app.get("/api/v1/findings-page", tags=["Findings"])
    def findings_page(
        session_id: Optional[str] = Query(None, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$"),
        offset: int = Query(0, ge=0),
        limit: int = Query(100, ge=1, le=500),
        min_severity: Optional[str] = Query(None, pattern=r"^(INFO|LOW|MEDIUM|HIGH|CRITICAL)$"),
        query: str = Query("", max_length=120),
    ):
        with CaseDB(state.case_db_path) as db:
            if query:
                findings = db.search_findings(query, session_id=session_id, limit=limit)
            else:
                findings = db.get_findings(
                    session_id=session_id,
                    min_severity=min_severity,
                    limit=limit,
                    offset=offset,
                )
            return {
                "offset": offset,
                "limit": limit,
                "findings": [_finding_to_web_dict(finding) for finding in findings],
                "has_more": len(findings) == limit,
            }

    @app.get("/api/v1/timeline-page", tags=["Timeline"])
    def timeline_page(
        session_id: Optional[str] = Query(None, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$"),
        offset: int = Query(0, ge=0),
        limit: int = Query(100, ge=1, le=500),
        min_severity: Optional[str] = Query(None, pattern=r"^(INFO|LOW|MEDIUM|HIGH|CRITICAL)$"),
    ):
        with CaseDB(state.case_db_path) as db:
            return {
                "offset": offset,
                "limit": limit,
                "events": db.get_timeline(
                    session_id=session_id,
                    min_severity=min_severity,
                    limit=limit,
                    offset=offset,
                ),
            }

    @app.get("/api/v1/graph", tags=["Graph"])
    def graph_snapshot(session_id: Optional[str] = Query(None, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")):
        return _web_snapshot(state, session_id)["graph"]

    @app.get("/api/v1/mitre", tags=["MITRE"])
    def mitre_snapshot(session_id: Optional[str] = Query(None, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")):
        return {"techniques": _web_snapshot(state, session_id)["mitre"]}

    @app.get("/api/v1/attack-story", tags=["Graph"])
    def attack_story(session_id: Optional[str] = Query(None, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")):
        snap = _web_snapshot(state, session_id)
        chains = snap["chains"]
        if not chains:
            return {
                "story": "No attack chain is available yet. Run analysis on evidence that produces source, category, rule, and MITRE context.",
                "chains": [],
            }
        lines = []
        for chain in chains[:5]:
            lines.append(chain.get("summary") or chain.get("chain_name") or "Attack activity observed.")
        return {"story": "\n".join(lines), "chains": chains}

    @app.get("/api/v1/tools", tags=["Tools"])
    def tools_snapshot():
        return {
            "exports": [
                {"id": "pdf", "label": "PDF report", "endpoint": "/api/report", "method": "POST"},
                {"id": "markdown", "label": "Markdown report", "endpoint": "/api/report", "method": "POST"},
                {"id": "stix", "label": "STIX bundle", "endpoint": "/api/export/stix", "method": "POST"},
                {"id": "iocs", "label": "IOC package", "endpoint": "/api/export/iocs", "method": "POST"},
            ],
            "ai": {"status_endpoint": "/api/ai/status", "lazy": True},
            "case": {"integrity_endpoint": "/api/case/integrity"},
        }

    # ── Sessions ──────────────────────────────────────────────────────────

    @app.get("/api/sessions", tags=["Sessions"])
    @app.get("/api/v1/sessions", tags=["Sessions"])
    def list_sessions():
        """List all analysis sessions."""
        with CaseDB(state.case_db_path) as db:
            sessions = db.list_sessions()
            return [
                SessionSummary.from_db(
                    s, db.get_findings_summary(session_id=s["session_id"])
                ).to_dict()
                for s in sessions
            ]

    @app.get("/api/sessions/{session_id}", tags=["Sessions"])
    @app.get("/api/v1/sessions/{session_id}", tags=["Sessions"])
    def get_session(
        session_id: str = PathParam(..., max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    ):
        """Get one session with its summary."""
        with CaseDB(state.case_db_path) as db:
            sess = db.get_session(session_id)
            if not sess:
                raise HTTPException(404, "Session not found")
            summ = db.get_findings_summary(session_id=session_id)
            return SessionSummary.from_db(sess, summ).to_dict()

    @app.delete("/api/v1/sessions/{session_id}", tags=["Sessions"])
    def delete_session(
        session_id: str = PathParam(..., max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    ):
        """Delete one analysed session from the case database. Source files remain untouched."""
        with CaseDB(state.case_db_path) as db:
            if not db.get_session(session_id):
                raise HTTPException(404, "Session not found")
            deleted = db.delete_session(session_id)
            return {"success": True, "session_id": session_id, "deleted": deleted}

    # ── Findings ──────────────────────────────────────────────────────────

    @app.get("/api/findings", tags=["Findings"])
    def get_findings(
        session_id:    Optional[str] = Query(None, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$"),
        min_severity:  Optional[str] = Query(None, pattern=r"^(INFO|LOW|MEDIUM|HIGH|CRITICAL)$"),
        category:      Optional[str] = Query(None, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$"),
        source_ip:     Optional[str] = Query(None, max_length=45, pattern=r"^[0-9a-fA-F.:]+$"),  # IPv4/IPv6
        hostname:      Optional[str] = Query(None, max_length=253, pattern=r"^[a-zA-Z0-9.-]+$"),
        rule_id:       Optional[str] = Query(None, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$"),
        min_risk:      float         = Query(0.0, ge=0.0, le=100.0),
        page:          int           = Query(1, ge=1, le=10000),
        page_size:     int           = Query(50, ge=1, le=500),
    ):
        """
        Query findings with optional filters.
        Supports pagination via page / page_size.
        All string inputs validated for length and safe characters.
        """
        with CaseDB(state.case_db_path) as db:
            all_findings = db.get_findings(
                session_id     = session_id,
                min_severity   = min_severity,
                category       = category,
                source_ip      = source_ip,
                hostname       = hostname,
                rule_id        = rule_id,
                min_risk_score = min_risk,
                limit          = page_size + 1,
                offset         = (page - 1) * page_size,
            )
            total    = (page - 1) * page_size + len(all_findings)
            page_f   = all_findings[:page_size]
            for f in page_f:
                fid = getattr(f, "_db_id", None)
                if fid:
                    setattr(f, "_triage_state", db.get_finding_state(fid))
            schemas  = [FindingSchema.from_finding(f) for f in page_f]
            return FindingListResponse(
                findings   = schemas,
                total      = total,
                page       = page,
                page_size  = page_size,
                has_more   = len(all_findings) > page_size,
                session_id = session_id,
            ).to_dict()

    @app.post("/api/findings/{finding_id}/action", tags=["Findings"])
    def add_finding_action(
        finding_id: str = PathParam(..., max_length=80, pattern=r"^[a-zA-Z0-9_-]+$"),
        body: dict = None,
    ):
        """Append an analyst action without mutating the finding record."""
        body = body or {}
        action = str(body.get("action", "")).strip()
        analyst = str(body.get("analyst", "analyst")).strip() or "analyst"
        note = str(body.get("note", ""))
        metadata = body.get("metadata") or {}
        try:
            with CaseDB(state.case_db_path) as db:
                action_id = db.add_analyst_action(
                    finding_id=finding_id,
                    action=action,
                    analyst=analyst,
                    note=note,
                    metadata=metadata,
                )
                return {
                    "success": True,
                    "action_id": action_id,
                    "finding_id": finding_id,
                    "current_state": db.get_finding_state(finding_id),
                    "actions": db.get_analyst_actions(finding_id=finding_id),
                }
        except KeyError:
            raise HTTPException(404, "Finding not found")
        except ValueError as e:
            raise HTTPException(400, str(e))

    @app.get("/api/findings/{finding_id}/actions", tags=["Findings"])
    def get_finding_actions(
        finding_id: str = PathParam(..., max_length=80, pattern=r"^[a-zA-Z0-9_-]+$")
    ):
        """Return the append-only action trail for one finding."""
        with CaseDB(state.case_db_path) as db:
            if not db.get_finding_row(finding_id):
                raise HTTPException(404, "Finding not found")
            return {
                "finding_id": finding_id,
                "current_state": db.get_finding_state(finding_id),
                "actions": db.get_analyst_actions(finding_id=finding_id),
            }

    # -- Case Integrity -----------------------------------------------------

    @app.get("/api/case/integrity", tags=["Integrity"])
    def case_integrity(
        session_id: Optional[str] = Query(None, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")
    ):
        """Verify evidence hashes, case hash, and reportability signals."""
        with CaseDB(state.case_db_path) as db:
            return db.verify_case_integrity(session_id=session_id)

    @app.post("/api/evidence/verify", tags=["Integrity"])
    def verify_evidence(body: dict):
        """Verify one evidence artifact by its evidence_id."""
        evidence_id = str((body or {}).get("evidence_id", "")).strip()
        if not evidence_id:
            raise HTTPException(400, "evidence_id is required")
        with CaseDB(state.case_db_path) as db:
            result = db.verify_evidence(evidence_id)
        if result.get("status") == "not_found":
            raise HTTPException(404, result.get("error", "Evidence not found"))
        return result

    # ── IOCs ──────────────────────────────────────────────────────────────

    @app.get("/api/iocs", tags=["IOCs"])
    def get_iocs(
        session_id:     Optional[str] = Query(None),
        ioc_type:       Optional[str] = Query(None),
        min_confidence: float         = Query(0.0),
    ):
        """Extract and return IOCs for a session."""
        with CaseDB(state.case_db_path) as db:
            findings = db.get_findings(session_id=session_id, limit=5000)
        extractor = IOCExtractor()
        iocs      = extractor.extract(findings)
        if ioc_type:
            iocs = [i for i in iocs if i.ioc_type == ioc_type]
        if min_confidence > 0:
            iocs = [i for i in iocs if i.confidence >= min_confidence]
        by_type = Counter(i.ioc_type for i in iocs)
        schemas = [IOCSchema.from_ioc(i) for i in iocs]
        return IOCListResponse(
            iocs       = schemas,
            total      = len(schemas),
            by_type    = dict(by_type),
            session_id = session_id,
        ).to_dict()

    # ── Reports ───────────────────────────────────────────────────────────

    @app.post("/api/report", tags=["Reports"])
    def generate_report(body: dict):
        """
        Generate a report for a session.
        format: json | text | markdown | pdf
        """
        try:
            req = ReportRequest.from_dict(body)
        except Exception as e:
            raise HTTPException(400, f"Invalid request: {e}")
        errors = req.validate()
        if errors:
            raise HTTPException(400, "; ".join(errors))

        try:
            with CaseDB(state.case_db_path) as db:
                builder = ReportBuilder(db, session_id=req.session_id)

                if req.format == "json":
                    content = builder.to_json()
                    return ReportResponse(
                        success=True, format="json",
                        content=content, sha256=_sha256_text(content),
                        size_bytes=len(content.encode("utf-8"))
                    ).to_dict()

                elif req.format == "text":
                    content = builder.to_text()
                    return ReportResponse(
                        success=True, format="text",
                        content=content, sha256=_sha256_text(content),
                        size_bytes=len(content.encode("utf-8"))
                    ).to_dict()

                elif req.format == "markdown":
                    content = builder.to_markdown()
                    return ReportResponse(
                        success=True, format="markdown",
                        content=content, sha256=_sha256_text(content),
                        size_bytes=len(content.encode("utf-8"))
                    ).to_dict()

                elif req.format == "pdf":
                    from output.pdf_report import PDFReport
                    import tempfile
                    findings = db.get_findings(
                        session_id=req.session_id, limit=2000)
                    iocs = []
                    if req.include_iocs:
                        iocs = IOCExtractor().extract(findings)
                    ts_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                    pdf_path = Path(tempfile.gettempdir()) / f"nexlog_{ts_str}.pdf"
                    pdf = PDFReport(
                        db             = db,
                        session_id     = req.session_id,
                        iocs           = iocs,
                        case_ref       = req.case_ref,
                        analyst        = req.analyst,
                        org            = req.org,
                        classification = req.classification,
                    )
                    pdf.build(pdf_path)
                    return ReportResponse(
                        success   = True,
                        format    = "pdf",
                        file_path = str(pdf_path),
                        sha256    = _sha256_file(pdf_path),
                        size_bytes = pdf_path.stat().st_size,
                    ).to_dict()

        except Exception as e:
            raise HTTPException(500, str(e))

    @app.get("/api/report/download", tags=["Reports"])
    def download_report(file_path: str = Query(...)):
        """Download a previously generated PDF report."""
        import tempfile
        import os

        # Strict allowlist: only temp directory and NexLog workspaces are allowed.
        _ALLOWED_DIRS = [
            Path(tempfile.gettempdir()).resolve(),
            Path(WORKSPACE_DIR).resolve(),
            (Path(ROOT) / "workspace").resolve(),
        ]

        try:
            # Resolve the requested path to an absolute, normalized path
            p = Path(file_path).resolve()
            
            # Also resolve the allowed directories for comparison
            allowed_resolved = [d.resolve() for d in _ALLOWED_DIRS]
        except (OSError, ValueError) as e:
            print(f"[API] Path resolution error for {file_path}: {e}")
            raise HTTPException(400, "Invalid file path")

        # Path traversal protection: must be under allowed directories.
        is_allowed = False
        for allowed_dir in allowed_resolved:
            try:
                # On Windows, we need to handle case-insensitive drive letters and paths
                # os.path.commonpath is safer for this purpose
                common = os.path.commonpath([str(p), str(allowed_dir)])
                if Path(common).resolve() == allowed_dir:
                    is_allowed = True
                    break
            except (ValueError, OSError):
                continue

        if not is_allowed:
            print(f"[API] Download blocked (403): {p} is not in {allowed_resolved}")
            raise HTTPException(403, "Access denied: path outside allowed directories")

        if not p.exists():
            print(f"[API] Download failed (404): {p} does not exist")
            raise HTTPException(404, "File not found")
            
        if p.suffix.lower() != ".pdf":
            print(f"[API] Download failed (400): {p} is not a PDF")
            raise HTTPException(400, "Only PDF downloads are allowed via this endpoint")

        print(f"[API] Serving download: {p}")
        return FileResponse(
            str(p),
            media_type = "application/pdf",
            filename   = p.name,
        )

    # ── Notes ─────────────────────────────────────────────────────────────

    @app.post("/api/notes", tags=["Notes"])
    def add_note(body: dict):
        """Add an analyst note to a session."""
        req = NoteRequest(**{k: v for k, v in body.items()
                             if k in ("note","session_id","analyst")})
        errors = req.validate()
        if errors:
            raise HTTPException(400, "; ".join(errors))
        with CaseDB(state.case_db_path) as db:
            nid = db.add_note(req.note, req.session_id or "", req.analyst)
        return {"note_id": nid, "success": True}

    @app.get("/api/notes", tags=["Notes"])
    def get_notes(session_id: Optional[str] = Query(None)):
        """Get analyst notes, optionally filtered by session."""
        with CaseDB(state.case_db_path) as db:
            return {"notes": db.get_notes(session_id=session_id)}

    # ── Attack Chains ─────────────────────────────────────────────────────

    @app.post("/api/v1/case/journal", tags=["Case"])
    def add_journal_entry(body: dict):
        """Add a durable case journal entry."""
        text = str(body.get("body") or body.get("note") or "").strip()
        if not text:
            raise HTTPException(400, "body is required")
        with CaseDB(state.case_db_path) as db:
            entry_id = db.add_journal_entry(
                text,
                title=str(body.get("title") or ""),
                session_id=str(body.get("session_id") or ""),
                analyst=str(body.get("analyst") or "analyst"),
                tags=body.get("tags") if isinstance(body.get("tags"), list) else [],
                metadata=body.get("metadata") if isinstance(body.get("metadata"), dict) else {},
            )
        return {"success": True, "id": entry_id}

    @app.get("/api/v1/case/journal", tags=["Case"])
    def get_journal(session_id: Optional[str] = Query(None, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")):
        """Return durable case journal entries."""
        with CaseDB(state.case_db_path) as db:
            return {"entries": db.get_journal(session_id=session_id)}

    @app.post("/api/v1/saved-views", tags=["Case"])
    def save_view(body: dict):
        """Persist a saved Findings/Timeline/Graph/MITRE view."""
        name = str(body.get("name") or "").strip()
        view_type = str(body.get("view_type") or "findings").strip()
        if not name:
            raise HTTPException(400, "name is required")
        with CaseDB(state.case_db_path) as db:
            view_id = db.save_view(
                name,
                view_type,
                body.get("filters") if isinstance(body.get("filters"), dict) else {},
                session_id=str(body.get("session_id") or ""),
                analyst=str(body.get("analyst") or "analyst"),
                metadata=body.get("metadata") if isinstance(body.get("metadata"), dict) else {},
            )
        return {"success": True, "id": view_id}

    @app.get("/api/v1/saved-views", tags=["Case"])
    def get_saved_views(session_id: Optional[str] = Query(None, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")):
        """Return saved investigation views."""
        with CaseDB(state.case_db_path) as db:
            return {"views": db.get_saved_views(session_id=session_id)}

    @app.post("/api/v1/timeline/bookmarks", tags=["Timeline"])
    def add_timeline_bookmark(body: dict):
        """Bookmark a timeline event or finding."""
        label = str(body.get("label") or "").strip()
        if not label:
            raise HTTPException(400, "label is required")
        with CaseDB(state.case_db_path) as db:
            bookmark_id = db.add_timeline_bookmark(
                label,
                session_id=str(body.get("session_id") or ""),
                finding_id=str(body.get("finding_id") or ""),
                timestamp=str(body.get("timestamp") or ""),
                analyst=str(body.get("analyst") or "analyst"),
                note=str(body.get("note") or ""),
                metadata=body.get("metadata") if isinstance(body.get("metadata"), dict) else {},
            )
        return {"success": True, "id": bookmark_id}

    @app.get("/api/v1/timeline/bookmarks", tags=["Timeline"])
    def get_timeline_bookmarks(session_id: Optional[str] = Query(None, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$")):
        """Return timeline bookmarks."""
        with CaseDB(state.case_db_path) as db:
            return {"bookmarks": db.get_timeline_bookmarks(session_id=session_id)}

    @app.get("/api/chains", tags=["Analysis"])
    def get_chains(session_id: Optional[str] = Query(None)):
        """Get detected multi-stage attack chains."""
        with CaseDB(state.case_db_path) as db:
            return {"chains": db.get_attack_chains(session_id=session_id)}

    # ── Export ────────────────────────────────────────────────────────────

    @app.post("/api/export/stix", tags=["Export"])
    def export_stix(body: dict):
        """
        Export a STIX 2.1 bundle for a session.
        Returns the bundle JSON inline.
        """
        session_id = body.get("session_id")
        case_ref   = body.get("case_ref", "IR-UNKNOWN")
        analyst    = body.get("analyst",  "analyst")
        tlp        = body.get("tlp_level","amber")
        with CaseDB(state.case_db_path) as db:
            findings = db.get_findings(session_id=session_id, limit=5000)
        iocs = IOCExtractor().extract(findings)
        sx   = STIXExport(findings=findings, iocs=iocs,
                          case_ref=case_ref, analyst=analyst,
                          tlp_level=tlp)
        bundle = sx.build()
        return {
            "bundle":  bundle,
            "summary": sx.summary(),
        }

    @app.post("/api/export/iocs", tags=["Export"])
    def export_iocs(body: dict):
        """
        Export IOCs in all flat-file formats.
        Returns all formats as a dict of format_name → content_string.
        """
        session_id  = body.get("session_id")
        case_ref    = body.get("case_ref", "IR-UNKNOWN")
        analyst     = body.get("analyst",  "analyst")
        formats     = body.get("formats",  ["csv","jsonl","zeek_intel","misp_csv"])
        with CaseDB(state.case_db_path) as db:
            findings = db.get_findings(session_id=session_id, limit=5000)
        iocs = IOCExtractor().extract(findings)
        exp  = IOCExporter(iocs, case_ref=case_ref, analyst=analyst)
        out  = {}
        if "csv"        in formats: out["csv"]        = exp.to_csv()
        if "tsv"        in formats: out["tsv"]        = exp.to_tsv()
        if "jsonl"      in formats: out["jsonl"]      = exp.to_jsonl()
        if "zeek_intel" in formats: out["zeek_intel"] = exp.to_zeek_intel()
        if "misp_csv"   in formats: out["misp_csv"]   = exp.to_misp_csv()
        out["summary"] = exp.summary()
        return out

    # ── Cache management ──────────────────────────────────────────────────

    # Enterprise foundation endpoints: rules, Sigma, risk, hunt, case workflow.

    @app.get("/api/v1/rules", tags=["Rules"])
    def list_rules():
        """Return loaded rule inventory with lifecycle metadata."""
        from rule_coverage import RuleCoverage
        return RuleCoverage(state.rules_dir).build()

    @app.post("/api/v1/rules/validate", tags=["Rules"])
    def validate_rule(body: dict):
        """Validate one NexLog YAML rule document without installing it."""
        import yaml
        from rule_engine import RuleEngine

        try:
            if "yaml" in body:
                doc = yaml.safe_load(str(body.get("yaml") or "")) or {}
            elif "rule" in body:
                doc = {"rules": [body["rule"]]}
            else:
                doc = body
            rules = doc.get("rules", [])
            if not isinstance(rules, list) or not rules:
                raise ValueError("document must contain a non-empty rules list")
            engine = RuleEngine(state.rules_dir)
            loaded = []
            for rule in rules:
                engine.load_rule_from_dict(rule)
                loaded.append(rule.get("id"))
            return {"ok": True, "loaded": loaded, "count": len(loaded)}
        except Exception as exc:
            raise HTTPException(400, f"Rule validation failed: {exc}")

    @app.post("/api/v1/sigma/import", tags=["Rules"])
    def import_sigma(body: dict):
        """Convert Sigma YAML into reviewable NexLog rule YAML."""
        from sigma_importer import SigmaImporter

        importer = SigmaImporter()
        if body.get("path"):
            result = importer.from_file(body["path"])
        else:
            result = importer.from_text(str(body.get("sigma") or body.get("yaml") or ""), source_id="api")
        payload = result.to_dict()
        payload["yaml"] = importer.to_yaml(result) if result.ok else ""
        if body.get("write") and result.ok:
            target_name = str(body.get("filename") or f"imported_sigma_{uuid.uuid4().hex[:8]}.yaml")
            if Path(target_name).name != target_name or not target_name.endswith(".yaml"):
                raise HTTPException(400, "filename must be a safe .yaml basename")
            target = Path(state.rules_dir) / target_name
            target.write_text(payload["yaml"], encoding="utf-8")
            payload["written_path"] = str(target)
            state._load_rules()
        return payload

    @app.post("/api/v1/rules/test", tags=["Rules"])
    def run_rule_tests(body: dict):
        """Run manifest-based rule tests against sample logs."""
        from rule_tester import RuleTestHarness

        harness = RuleTestHarness(state.rules_dir)
        if body.get("manifest_path"):
            return harness.run_manifest_file(body["manifest_path"])
        return harness.run_manifest(body or {}, base_dir=ROOT)

    @app.get("/api/v1/coverage", tags=["Rules"])
    def coverage_report():
        """Rule coverage and MITRE maturity matrix."""
        from rule_coverage import RuleCoverage
        return RuleCoverage(state.rules_dir).build()

    @app.get("/api/v1/risk/entities", tags=["Risk"])
    def entity_risk(
        session_id: Optional[str] = Query(None, max_length=64, pattern=r"^[a-zA-Z0-9_-]+$"),
        limit: int = Query(100, ge=1, le=500),
    ):
        """Risk-based entity scoring for IPs, users, hosts, and processes."""
        from entity_risk import EntityRiskEngine

        with CaseDB(state.case_db_path) as db:
            findings = db.get_findings(session_id=session_id, limit=100000)
        result = EntityRiskEngine().score_findings(findings, limit=limit)
        result["session_id"] = session_id or "all"
        return result

    @app.post("/api/v1/hunt", tags=["Hunt"])
    def hunt_query(body: dict):
        """Run a safe parameterized hunt query over normalized findings."""
        from storage.hunt import hunt_findings

        limit = int(body.get("limit", 200) or 200)
        offset = int(body.get("offset", 0) or 0)
        filters = body.get("filters") if isinstance(body.get("filters"), dict) else body
        with CaseDB(state.case_db_path) as db:
            return hunt_findings(db._conn, filters or {}, limit=limit, offset=offset)

    @app.get("/api/v1/playbooks", tags=["Playbooks"])
    def list_playbooks():
        """List all built-in incident-response playbooks."""
        from playbook_engine import PlaybookEngine

        engine = PlaybookEngine()
        items = []
        for category in engine.all_categories():
            playbook = engine.get_playbook(category)
            items.append({
                "category": category,
                "title": playbook.get("title"),
                "severity": playbook.get("severity"),
                "mitre": playbook.get("mitre", []),
                "step_count": len(playbook.get("steps", [])),
                "description": playbook.get("description", ""),
            })
        return {"playbooks": items, "count": len(items)}

    @app.get("/api/v1/playbooks/{category}", tags=["Playbooks"])
    def get_playbook(category: str = PathParam(..., max_length=80, pattern=r"^[a-zA-Z0-9_-]+$")):
        """Return one incident-response playbook."""
        from playbook_engine import PlaybookEngine
        return PlaybookEngine().get_playbook(category)

    @app.post("/api/v1/case/bundle", tags=["Case"])
    def export_case_bundle(body: dict):
        """Export a portable .nexlogcase bundle."""
        from output.case_bundle import CaseBundleExporter

        session_id = body.get("session_id") or None
        output_name = str(body.get("filename") or f"nexlog_case_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.nexlogcase")
        if Path(output_name).name != output_name:
            raise HTTPException(400, "filename must be a safe basename")
        output_path = Path(WORKSPACE_DIR) / output_name
        return CaseBundleExporter(state.case_db_path).export(
            output_path,
            session_id=session_id,
            include_db=bool(body.get("include_db", True)),
        )

    @app.get("/api/v1/intel/status", tags=["Threat Intel"])
    def intel_status():
        """Show opt-in threat-intel provider readiness without making network calls."""
        providers = {
            "abuseipdb": bool(os.environ.get("ABUSEIPDB_API_KEY")),
            "misp": bool(os.environ.get("MISP_URL") and os.environ.get("MISP_API_KEY")),
            "opencti": bool(os.environ.get("OPENCTI_URL") and os.environ.get("OPENCTI_TOKEN")),
            "otx": bool(os.environ.get("OTX_API_KEY")),
            "virustotal": bool(os.environ.get("VIRUSTOTAL_API_KEY") or os.environ.get("VT_API_KEY")),
        }
        return {
            "network_calls_default": "disabled",
            "providers": [
                {"name": name, "configured": configured, "enabled": configured and os.environ.get("NEXLOG_ENABLE_INTEL") == "1"}
                for name, configured in providers.items()
            ],
            "cache": "sqlite",
            "rate_limits": "provider-managed",
        }

    @app.delete("/api/cache", tags=["System"])
    def clear_cache():
        """Clear enrichment caches (AbuseIPDB, GeoIP)."""
        return {"cleared": True, "message": "Enrichment caches cleared"}

    # ── AI endpoints ──────────────────────────────────────────────────────
    # Lazy-import ai/ so the API works without ai deps installed

    def _get_ai_engine():
        try:
            return state.get_ai_engine()
        except Exception as e:
            raise HTTPException(
                status_code=503,
                detail=_ai_error(
                    "provider_unavailable",
                    "AI engine not available",
                    detail=str(e),
                ),
            )

    @app.get("/api/ai/status", tags=["AI"])
    def ai_status():
        """AI engine status: tier, indexed count, recommendations."""
        try:
            engine = _get_ai_engine()
            payload = engine.status()
            payload["llm_provider"] = _llm_provider_from_tier_name(engine.llm.tier_name)
            payload["provider_config"] = _ai_provider_config_snapshot()
            return payload
        except HTTPException:
            return {
                "n_indexed": 0, "llm_tier": "unavailable",
                "llm_tier_number": 0, "embedder_tier": "unavailable",
                "embedder_tier_number": 0,
                "recommendations": ["Install ai/ dependencies"],
                "available": False,
                "llm_provider": "unavailable",
                "provider_config": _ai_provider_config_snapshot(),
            }

    @app.get("/api/v1/ai/provider-config", tags=["AI"])
    def ai_provider_config():
        """Safe AI provider metadata. Secret values are never returned."""
        return _ai_provider_config_snapshot()

    @app.post("/api/v1/ai/provider-config", tags=["AI"])
    def save_ai_provider_config(body: dict):
        """Save web AI provider slots to ignored .env.web without returning keys."""
        updates: dict[str, str] = {}
        for idx in (1, 2):
            provider = _normalise_ai_provider(str(body.get(f"provider{idx}") or "").strip())
            key = str(body.get(f"apiKey{idx}") or "").strip()
            endpoint = str(body.get(f"endpoint{idx}") or "").strip()
            model = str(body.get(f"model{idx}") or "").strip()
            if provider:
                updates[f"NEXLOG_WEB_AI_PROVIDER_{idx}"] = provider
                os.environ[f"NEXLOG_AI_PROVIDER_{idx}"] = provider
            if key:
                updates[f"NEXLOG_WEB_AI_KEY_{idx}"] = key
                os.environ[f"NEXLOG_AI_KEY_{idx}"] = key
            if endpoint:
                updates[f"NEXLOG_WEB_AI_ENDPOINT_{idx}"] = endpoint
                os.environ[f"NEXLOG_AI_ENDPOINT_{idx}"] = endpoint
            if model:
                updates[f"NEXLOG_WEB_AI_MODEL_{idx}"] = model
                os.environ[f"NEXLOG_AI_MODEL_{idx}"] = model
        managed_endpoint = str(body.get("managedEndpoint") or "").strip()
        managed_token = str(body.get("managedToken") or "").strip()
        if managed_endpoint:
            updates["NEXLOG_MANAGED_AI_ENDPOINT"] = managed_endpoint
            os.environ["NEXLOG_MANAGED_AI_ENDPOINT"] = managed_endpoint
        if managed_token:
            updates["NEXLOG_MANAGED_AI_TOKEN"] = managed_token
            os.environ["NEXLOG_MANAGED_AI_TOKEN"] = managed_token
        if updates:
            _update_env_file(_WEB_ENV_PATH, updates)
            state._ai_engine = None
        return {"saved": True, "updated": len(updates), "config": _ai_provider_config_snapshot()}

    @app.post("/api/ai/index", tags=["AI"])
    def ai_index(body: dict):
        """
        Index findings from a session into the vector store.
        Body: { session_id: str (optional) }
        """
        session_id = body.get("session_id")
        engine     = _get_ai_engine()
        with CaseDB(state.case_db_path) as db:
            n      = engine.ensure_indexed(db, session_id=session_id, force=False)
        if engine.rag.n_indexed == 0:
            raise HTTPException(
                status_code=409,
                detail=_ai_error(
                    "index_empty",
                    "No findings available to index",
                    detail="Run analysis and retry indexing.",
                ),
            )
        return {
            "new_indexed": n,
            "n_indexed":   engine.rag.n_indexed,
            "session_id":  session_id,
            "llm_provider": _llm_provider_from_tier_name(engine.llm.tier_name),
        }

    @app.post("/api/ai/query", tags=["AI"])
    def ai_query(body: dict):
        """
        Natural language query over indexed findings.
        Body: { question: str, session_id: str|null,
                severity: str|null, category: str|null,
                top_k: int=5 }
        Returns: RAGAnswer as dict with text, sources, timing.
        """
        q          = body.get("question", "").strip()
        if not q:
            raise HTTPException(
                status_code=400,
                detail=_ai_error("missing_question", "question is required"),
            )
        engine     = _get_ai_engine()
        if engine.rag.n_indexed == 0:
            raise HTTPException(
                status_code=409,
                detail=_ai_error(
                    "index_empty",
                    "No indexed findings available",
                    detail="Call /api/ai/index first.",
                ),
            )
        answer     = engine.ask(
            question   = q,
            session_id = body.get("session_id"),
            severity   = body.get("severity"),
            category   = body.get("category"),
            top_k      = body.get("top_k"),
        )
        result = answer.to_dict()
        result["llm_tier_number"] = engine.llm.tier
        result["llm_provider"] = _llm_provider_from_tier_name(engine.llm.tier_name)
        return result

    @app.get("/api/ai/history", tags=["AI"])
    def ai_history():
        """Return conversation history."""
        return {"turns": _get_ai_engine().get_history()}

    @app.post("/api/ai/clear_history", tags=["AI"])
    def ai_clear_history(body: dict = None):
        """Clear conversation history."""
        _get_ai_engine().clear_history()
        return {"cleared": True}

    @app.post("/api/ai/reset", tags=["AI"])
    def ai_reset(body: dict = None):
        """Reset the vector index (clear all indexed findings)."""
        _get_ai_engine().reset()
        return {"reset": True}

    return app


# ══════════════════════════════════════════════════════════════════════════
# STDLIB HTTP.SERVER FALLBACK
# ══════════════════════════════════════════════════════════════════════════

class _Handler:
    """
    Minimal HTTP request handler wrapping the same endpoint logic.
    Used when FastAPI is not installed.
    """
    def __init__(self, state: _AppState):
        self._state = state

    def _route(self, method: str, path: str,
               query: dict, body: dict) -> tuple[int, dict]:
        """
        Match method + path and return (status_code, response_dict).
        """
        s = self._state

        def _q(name: str, default=None):
            return query.get(name, [default])[0]

        def _to_int(value, default: int, *, minimum: int | None = None) -> int:
            try:
                ivalue = int(value)
            except (TypeError, ValueError):
                ivalue = default
            if minimum is not None and ivalue < minimum:
                return minimum
            return ivalue

        # v1 aliases
        if path == "/api/v1/health":
            path = "/api/health"
        elif path == "/api/v1/stats":
            path = "/api/stats"

        # Health
        if path == "/api/health" and method == "GET":
            return 200, s.health().to_dict()

        if path == "/api/auth/status" and method == "GET":
            info = auth_status()
            enabled = bool(info.get("auth_enabled"))
            return 200, {
                "auth_enabled": enabled,
                "key_required": enabled,
                "message": "API key required" if enabled else "API key not configured",
                "primary_env": info.get("primary_env", "NEXLOG_API_KEY"),
            }

        # Stats
        if path == "/api/stats" and method == "GET":
            try:
                with CaseDB(s.case_db_path) as db:
                    sessions = db.list_sessions()
                    summ     = db.get_findings_summary()
                return 200, StatsResponse(
                    total_sessions=len(sessions),
                    total_findings=summ.get("total",0),
                    total_iocs=0, rules_loaded=s._rules_loaded,
                ).to_dict()
            except Exception as e:
                return 500, {"error": str(e)}

        # Dashboard / v1 snapshot routes (stdlib parity with FastAPI)
        if path == "/api/v1/snapshot" and method == "GET":
            return 200, _web_snapshot(s, _q("session_id"))

        if path == "/api/v1/dashboard" and method == "GET":
            return 200, _web_snapshot(s, _q("session_id"))["dashboard"]

        if path == "/api/v1/timeline" and method == "GET":
            return 200, {"events": _web_snapshot(s, _q("session_id"))["timeline"]}

        if path == "/api/v1/graph" and method == "GET":
            return 200, _web_snapshot(s, _q("session_id"))["graph"]

        if path == "/api/v1/mitre" and method == "GET":
            return 200, {"techniques": _web_snapshot(s, _q("session_id"))["mitre"]}

        if path == "/api/v1/attack-story" and method == "GET":
            snap = _web_snapshot(s, _q("session_id"))
            chains = snap["chains"]
            if not chains:
                return 200, {
                    "story": "No attack chain is available yet. Run analysis on evidence that produces source, category, rule, and MITRE context.",
                    "chains": [],
                }
            lines = []
            for chain in chains[:5]:
                lines.append(chain.get("summary") or chain.get("chain_name") or "Attack activity observed.")
            return 200, {"story": "\n".join(lines), "chains": chains}

        if path == "/api/v1/tools" and method == "GET":
            return 200, {
                "exports": [
                    {"id": "pdf", "label": "PDF report", "endpoint": "/api/report", "method": "POST"},
                    {"id": "markdown", "label": "Markdown report", "endpoint": "/api/report", "method": "POST"},
                    {"id": "stix", "label": "STIX bundle", "endpoint": "/api/export/stix", "method": "POST"},
                    {"id": "iocs", "label": "IOC package", "endpoint": "/api/export/iocs", "method": "POST"},
                ],
                "ai": {"status_endpoint": "/api/ai/status", "lazy": True},
                "case": {"integrity_endpoint": "/api/case/integrity"},
            }

        if path == "/api/v1/findings-page" and method == "GET":
            session_id = _q("session_id")
            offset = _to_int(_q("offset", 0), 0, minimum=0)
            limit = min(500, _to_int(_q("limit", 100), 100, minimum=1))
            min_severity = _q("min_severity")
            search = str(_q("query", "") or "")
            with CaseDB(s.case_db_path) as db:
                if search:
                    findings = db.search_findings(search, session_id=session_id, limit=limit)
                else:
                    findings = db.get_findings(
                        session_id=session_id,
                        min_severity=min_severity,
                        limit=limit,
                        offset=offset,
                    )
            return 200, {
                "offset": offset,
                "limit": limit,
                "findings": [_finding_to_web_dict(finding) for finding in findings],
                "has_more": len(findings) == limit,
            }

        if path == "/api/v1/timeline-page" and method == "GET":
            session_id = _q("session_id")
            offset = _to_int(_q("offset", 0), 0, minimum=0)
            limit = min(500, _to_int(_q("limit", 100), 100, minimum=1))
            min_severity = _q("min_severity")
            with CaseDB(s.case_db_path) as db:
                return 200, {
                    "offset": offset,
                    "limit": limit,
                    "events": db.get_timeline(
                        session_id=session_id,
                        min_severity=min_severity,
                        limit=limit,
                        offset=offset,
                    ),
                }

        # Analyse
        if path == "/api/analyse" and method == "POST":
            try:
                req = AnalyseRequest.from_dict(body)
            except Exception as e:
                return 400, {"error": str(e)}
            result = s.analyse(req)
            return (200, result.to_dict()) if result.success else (400, result.to_dict())

        if path == "/api/v1/jobs" and method == "POST":
            try:
                errors = AnalyseRequest.from_dict(body).validate()
                if errors:
                    raise ValueError("; ".join(errors))
            except Exception as e:
                return 400, {"error": f"Invalid request: {e}"}
            return 200, _JOBS.create(s, body)

        if path.startswith("/api/v1/jobs/"):
            parts = path.strip("/").split("/")
            if len(parts) >= 4 and parts[0] == "api" and parts[1] == "v1" and parts[2] == "jobs":
                job_id = parts[3]
                if method == "GET" and len(parts) == 4:
                    job = _JOBS.get(job_id)
                    if not job:
                        return 404, {"error": "Job not found"}
                    return 200, job
                if method == "POST" and len(parts) == 5 and parts[4] == "cancel":
                    job = _JOBS.cancel(job_id)
                    if not job:
                        return 404, {"error": "Job not found"}
                    return 200, job
                if method == "GET" and len(parts) == 5 and parts[4] == "events":
                    job = _JOBS.get(job_id)
                    if not job:
                        return 404, {"error": "Job not found"}
                    return 200, {
                        "events": job.get("events", []),
                        "status": job.get("status", ""),
                    }

        # Sessions list
        if path == "/api/sessions" and method == "GET":
            with CaseDB(s.case_db_path) as db:
                sessions = db.list_sessions()
                return 200, {
                    "sessions": [
                        SessionSummary.from_db(
                            sess, db.get_findings_summary(session_id=sess["session_id"])
                        ).to_dict()
                        for sess in sessions
                    ]
                }

        # Findings
        if path == "/api/findings" and method == "GET":
            with CaseDB(s.case_db_path) as db:
                findings = db.get_findings(
                    session_id   = query.get("session_id",  [None])[0],
                    min_severity = query.get("min_severity",[None])[0],
                    category     = query.get("category",    [None])[0],
                    source_ip    = query.get("source_ip",   [None])[0],
                    hostname     = query.get("hostname",    [None])[0],
                    limit        = int((query.get("limit", ["100"])[0]))
                )
                for f in findings:
                    fid = getattr(f, "_db_id", None)
                    if fid:
                        setattr(f, "_triage_state", db.get_finding_state(fid))
            return 200, {
                "findings": [FindingSchema.from_finding(f).to_dict() for f in findings],
                "total": len(findings),
            }

        if path == "/api/case/integrity" and method == "GET":
            with CaseDB(s.case_db_path) as db:
                return 200, db.verify_case_integrity(
                    session_id=query.get("session_id", [None])[0])

        if path == "/api/evidence/verify" and method == "POST":
            evidence_id = str(body.get("evidence_id", "")).strip()
            if not evidence_id:
                return 400, {"error": "evidence_id is required"}
            with CaseDB(s.case_db_path) as db:
                result = db.verify_evidence(evidence_id)
            if result.get("status") == "not_found":
                return 404, result
            return 200, result

        if path.startswith("/api/findings/") and method in {"GET", "POST"}:
            parts = path.strip("/").split("/")
            if len(parts) == 4 and parts[0] == "api" and parts[1] == "findings":
                finding_id, tail = parts[2], parts[3]
                with CaseDB(s.case_db_path) as db:
                    if tail == "actions" and method == "GET":
                        if not db.get_finding_row(finding_id):
                            return 404, {"error": "Finding not found"}
                        return 200, {
                            "finding_id": finding_id,
                            "current_state": db.get_finding_state(finding_id),
                            "actions": db.get_analyst_actions(finding_id=finding_id),
                        }
                    if tail == "action" and method == "POST":
                        try:
                            action_id = db.add_analyst_action(
                                finding_id=finding_id,
                                action=str(body.get("action", "")).strip(),
                                analyst=str(body.get("analyst", "analyst")).strip() or "analyst",
                                note=str(body.get("note", "")),
                                metadata=body.get("metadata") or {},
                            )
                        except KeyError:
                            return 404, {"error": "Finding not found"}
                        except ValueError as e:
                            return 400, {"error": str(e)}
                        return 200, {
                            "success": True,
                            "action_id": action_id,
                            "finding_id": finding_id,
                            "current_state": db.get_finding_state(finding_id),
                            "actions": db.get_analyst_actions(finding_id=finding_id),
                        }

        # IOCs
        if path == "/api/iocs" and method == "GET":
            with CaseDB(s.case_db_path) as db:
                findings = db.get_findings(
                    session_id=query.get("session_id",[None])[0], limit=5000)
            iocs = IOCExtractor().extract(findings)
            return 200, {
                "iocs":  [IOCSchema.from_ioc(i).to_dict() for i in iocs],
                "total": len(iocs),
            }

        # Report
        if path == "/api/report" and method == "POST":
            try:
                req = ReportRequest.from_dict(body)
            except Exception as e:
                return 400, {"error": str(e)}
            
            with CaseDB(s.case_db_path) as db:
                if req.format == "pdf":
                    try:
                        from output.pdf_report import PDFReport
                        import tempfile
                        findings = db.get_findings(session_id=req.session_id, limit=2000)
                        iocs = []
                        if req.include_iocs:
                            iocs = IOCExtractor().extract(findings)
                        ts_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                        pdf_path = Path(tempfile.gettempdir()) / f"nexlog_{ts_str}.pdf"
                        pdf = PDFReport(
                            db             = db,
                            session_id     = req.session_id,
                            iocs           = iocs,
                            case_ref       = req.case_ref,
                            analyst        = req.analyst,
                        )
                        pdf.build(pdf_path)
                        return 200, {
                            "success":   True,
                            "format":    "pdf",
                            "file_path": str(pdf_path),
                            "sha256":    _sha256_file(pdf_path),
                            "size_bytes": pdf_path.stat().st_size,
                        }
                    except Exception as e:
                        return 500, {"error": f"PDF generation failed: {e}"}

                builder = ReportBuilder(db, session_id=req.session_id)
                fmt_map = {
                    "json":     builder.to_json,
                    "text":     builder.to_text,
                    "markdown": builder.to_markdown,
                }
                fn = fmt_map.get(req.format)
                if not fn:
                    return 400, {"error": f"Unsupported format: {req.format}"}
                content = fn()
            return 200, ReportResponse(
                success=True, format=req.format,
                content=content, sha256=_sha256_text(content),
                size_bytes=len(content.encode("utf-8"))
            ).to_dict()

        # Report Download
        if path == "/api/report/download" and method == "GET":
            # This is handled specially by the stdlib ReqHandler below
            # because it needs to serve binary data with specific headers.
            return 200, {"info": "Handled by specialized binary server"}

        # STIX export
        if path == "/api/export/stix" and method == "POST":
            with CaseDB(s.case_db_path) as db:
                findings = db.get_findings(
                    session_id=body.get("session_id"), limit=5000)
            iocs = IOCExtractor().extract(findings)
            sx   = STIXExport(findings=findings, iocs=iocs,
                              case_ref=body.get("case_ref","IR-UNKNOWN"),
                              analyst=body.get("analyst","analyst"))
            return 200, {"bundle": sx.build(), "summary": sx.summary()}

        if path == "/api/export/iocs" and method == "POST":
            session_id = body.get("session_id")
            case_ref = body.get("case_ref", "IR-UNKNOWN")
            analyst = body.get("analyst", "analyst")
            formats = body.get("formats", ["csv", "jsonl", "zeek_intel", "misp_csv"])
            with CaseDB(s.case_db_path) as db:
                findings = db.get_findings(session_id=session_id, limit=5000)
            iocs = IOCExtractor().extract(findings)
            exp = IOCExporter(iocs, case_ref=case_ref, analyst=analyst)
            out = {}
            if "csv" in formats:
                out["csv"] = exp.to_csv()
            if "tsv" in formats:
                out["tsv"] = exp.to_tsv()
            if "jsonl" in formats:
                out["jsonl"] = exp.to_jsonl()
            if "zeek_intel" in formats:
                out["zeek_intel"] = exp.to_zeek_intel()
            if "misp_csv" in formats:
                out["misp_csv"] = exp.to_misp_csv()
            out["summary"] = exp.summary()
            return 200, out

        # Notes
        if path == "/api/notes" and method == "POST":
            req = NoteRequest(**{k: body[k] for k in ("note","session_id","analyst")
                                 if k in body})
            errs = req.validate()
            if errs:
                return 400, {"error": "; ".join(errs)}
            with CaseDB(s.case_db_path) as db:
                nid = db.add_note(req.note, req.session_id or "", req.analyst)
            return 200, {"note_id": nid, "success": True}

        if path == "/api/notes" and method == "GET":
            with CaseDB(s.case_db_path) as db:
                return 200, {"notes": db.get_notes(
                    session_id=query.get("session_id",[None])[0])}

        # Chains
        if path == "/api/chains" and method == "GET":
            with CaseDB(s.case_db_path) as db:
                return 200, {"chains": db.get_attack_chains(
                    session_id=query.get("session_id",[None])[0])}

        # AI endpoints
        if path == "/api/ai/status" and method == "GET":
            try:
                engine = s.get_ai_engine()
                payload = engine.status()
                payload["llm_provider"] = _llm_provider_from_tier_name(engine.llm.tier_name)
                return 200, payload
            except Exception as e:
                return 200, {"n_indexed": 0, "available": False,
                             "error": str(e), "llm_provider": "unavailable"}

        if path == "/api/ai/index" and method == "POST":
            try:
                session_id = body.get("session_id")
                engine = s.get_ai_engine()
                with CaseDB(s.case_db_path) as db:
                    n = engine.ensure_indexed(db, session_id=session_id)
                if engine.rag.n_indexed == 0:
                    return 409, _ai_error(
                        "index_empty",
                        "No findings available to index",
                        detail="Run analysis and retry indexing.",
                    )
                return 200, {
                    "new_indexed": n,
                    "n_indexed": engine.rag.n_indexed,
                    "session_id": session_id,
                    "llm_provider": _llm_provider_from_tier_name(engine.llm.tier_name),
                }
            except Exception as e:
                return 503, _ai_error("provider_unavailable", "AI engine not available", detail=str(e))

        if path == "/api/ai/query" and method == "POST":
            try:
                q = body.get("question", "").strip()
                if not q:
                    return 400, _ai_error("missing_question", "question is required")
                engine = s.get_ai_engine()
                if engine.rag.n_indexed == 0:
                    return 409, _ai_error(
                        "index_empty",
                        "No indexed findings available",
                        detail="Call /api/ai/index first.",
                    )
                answer = engine.ask(
                    question   = q,
                    session_id = body.get("session_id"),
                    severity   = body.get("severity"),
                    category   = body.get("category"),
                    top_k      = body.get("top_k"),
                )
                result = answer.to_dict()
                result["llm_tier_number"] = engine.llm.tier
                result["llm_provider"] = _llm_provider_from_tier_name(engine.llm.tier_name)
                return 200, result
            except Exception as e:
                return 503, _ai_error("provider_unavailable", "AI engine not available", detail=str(e))

        if path == "/api/ai/history" and method == "GET":
            try:
                if hasattr(s, '_ai_engine') and s._ai_engine:
                    return 200, {"turns": s._ai_engine.get_history()}
            except Exception:
                pass
            return 200, {"turns": []}

        if path == "/api/ai/clear_history" and method == "POST":
            try:
                if hasattr(s, '_ai_engine') and s._ai_engine:
                    s._ai_engine.clear_history()
            except Exception:
                pass
            return 200, {"cleared": True}

        if path == "/api/ai/reset" and method == "POST":
            try:
                if hasattr(s, '_ai_engine') and s._ai_engine:
                    s._ai_engine.reset()
            except Exception:
                pass
            return 200, {"reset": True}

        return 404, {"error": f"Not found: {method} {path}"}


def run_stdlib_server(
    port:         int  = 8000,
    host:         str  = "127.0.0.1",
    case_db_path: str  = "nexlog.facase",
    rules_dir:    str  = "",
) -> None:
    """
    Run the API using Python's built-in http.server.
    No FastAPI required. All endpoints work identically.
    """
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import urllib.parse

    state   = _AppState(case_db_path, rules_dir)
    handler = _Handler(state)

    class _ReqHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):  # suppress default logging
            print(f"  [{self.address_string()}] {fmt % args}")

        def _respond(self, code: int, body: dict, extra_headers: dict = None) -> None:
            payload = json.dumps(body, default=str).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Access-Control-Allow-Origin", "*")
            # Security headers on every response
            for hk, hv in SECURITY_HEADERS.items():
                self.send_header(hk, hv)
            if extra_headers:
                for hk, hv in extra_headers.items():
                    self.send_header(hk, hv)
            self.end_headers()
            self.wfile.write(payload)

        def _read_body(self) -> dict:
            length = int(self.headers.get("Content-Length", 0))
            if length:
                try:
                    return json.loads(self.rfile.read(length).decode("utf-8"))
                except Exception:
                    return {}
            return {}

        def _parse_path(self):
            parsed = urllib.parse.urlparse(self.path)
            return parsed.path, parse_qs(parsed.query)

        def do_GET(self):
            path, query = self._parse_path()
            allowed, status, msg = check_auth(path, dict(self.headers))
            if not allowed:
                self._respond(status, {"error": msg})
                return
            
            # Special handling for binary report downloads in stdlib mode
            if path == "/api/report/download":
                file_path = query.get("file_path", [None])[0]
                if not file_path:
                    self._respond(400, {"error": "file_path is required"})
                    return
                
                import tempfile
                import os
                _ALLOWED_DIRS = [
                    Path(tempfile.gettempdir()).resolve(),
                    Path(WORKSPACE_DIR).resolve(),
                    (Path(ROOT) / "workspace").resolve(),
                ]
                try:
                    p = Path(file_path).resolve()
                    allowed_resolved = [d.resolve() for d in _ALLOWED_DIRS]
                    is_allowed = False
                    for allowed_dir in allowed_resolved:
                        common = os.path.commonpath([str(p), str(allowed_dir)])
                        if Path(common).resolve() == allowed_dir:
                            is_allowed = True
                            break
                    
                    if not is_allowed or not p.exists() or p.suffix.lower() != ".pdf":
                        self._respond(403, {"error": "Access denied or file not found"})
                        return
                    
                    # Serve binary PDF
                    with open(p, "rb") as f:
                        content = f.read()
                    
                    self.send_response(200)
                    self.send_header("Content-Type", "application/pdf")
                    self.send_header("Content-Disposition", f'attachment; filename="{p.name}"')
                    self.send_header("Content-Length", str(len(content)))
                    for hk, hv in SECURITY_HEADERS.items():
                        self.send_header(hk, hv)
                    self.end_headers()
                    self.wfile.write(content)
                    return
                except Exception as e:
                    self._respond(500, {"error": str(e)})
                    return

            code, resp  = handler._route("GET", path, query, {})
            self._respond(code, resp)

        def do_POST(self):
            path, query = self._parse_path()
            allowed, status, msg = check_auth(path, dict(self.headers))
            if not allowed:
                self._respond(status, {"error": msg})
                return
            body        = self._read_body()
            code, resp  = handler._route("POST", path, query, body)
            self._respond(code, resp)

        def do_DELETE(self):
            path, query = self._parse_path()
            allowed, status, msg = check_auth(path, dict(self.headers))
            if not allowed:
                self._respond(status, {"error": msg})
                return
            code, resp  = handler._route("DELETE", path, query, {})
            self._respond(code, resp)

        def do_OPTIONS(self):
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods",
                             "GET, POST, DELETE, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers()

    server = HTTPServer((host, port), _ReqHandler)
    print("\n  NexLog API (stdlib mode)")
    print(f"  Listening on http://{host}:{port}")
    print(f"  Case DB: {case_db_path}")
    print(f"  Rules:   {state.rules_dir}")
    print("  Press Ctrl+C to stop\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Server stopped.")
    finally:
        try:
            server.server_close()
        finally:
            state.close()


# ══════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        prog="nexlog-api",
        description="NexLog REST API Server",
    )
    parser.add_argument("--port",   type=int, default=8000)
    parser.add_argument("--host",   default="127.0.0.1")
    parser.add_argument("--case",   default="nexlog.facase",
                        metavar="FILE", help="Case database path")
    parser.add_argument("--rules",  default="",
                        metavar="DIR",  help="Custom rules directory")
    parser.add_argument("--stdlib", action="store_true",
                        help="Use stdlib http.server instead of FastAPI")
    parser.add_argument("--reload", action="store_true",
                        help="FastAPI: enable auto-reload (dev mode)")
    args = parser.parse_args()

    from pathconfig import WORKSPACE_DIR
    case_path = Path(args.case)
    if case_path.parent == Path(""):
        case_path = Path(WORKSPACE_DIR) / case_path
    args.case = str(case_path)

    if args.stdlib:
        run_stdlib_server(
            port=args.port, host=args.host,
            case_db_path=args.case, rules_dir=args.rules,
        )
    else:
        try:
            import uvicorn
            app = create_app(
                case_db_path = args.case,
                rules_dir    = args.rules,
            )
            print("\n  NexLog API (FastAPI mode)")
            print(f"  Docs:  http://{args.host}:{args.port}/docs")
            print(f"  Case DB: {args.case}\n")
            uvicorn.run(
                app,
                host   = args.host,
                port   = args.port,
                reload = args.reload,
            )
        except ImportError:
            print("FastAPI/uvicorn not installed. Falling back to stdlib mode.")
            print("To use FastAPI: pip install fastapi uvicorn\n")
            run_stdlib_server(
                port=args.port, host=args.host,
                case_db_path=args.case, rules_dir=args.rules,
            )
