#!/usr/bin/env python3
"""
main.py â€” NexLog CLI Entry Point
Wires Layer 1 (parse) â†’ Layer 2 (detect) â†’ Layer 3 (store + report + IOC)

Usage:
    python main.py <logfile> [options]

Examples:
    python main.py access.log
    python main.py access.log --severity HIGH --report markdown
    python main.py auth.log --case investigation.facase --ioc iocs.csv
    python main.py *.log --case case.facase --report all --out ./reports/
    python main.py access.log --rules /custom/rules/ --format apache

Options:
    --case FILE         Case database file (default: case_YYYYMMDD_HHMMSS.facase)
    --severity LEVEL    Minimum severity to report [INFO|LOW|MEDIUM|HIGH|CRITICAL]
    --category CAT      Filter findings to one category
    --rules DIR         Custom rules directory (default: detection/rules/)
    --format FMT        Force log format [apache|syslog|evtx|json|cloudtrail]
    --report FMT        Output report format [json|text|markdown|all] (default: text)
    --out DIR           Output directory for reports and IOC files (default: .)
    --ioc FILE          Export IOCs to CSV file
    --stix FILE         Export IOCs to STIX 2.1 bundle
    --analyst NAME      Analyst name for notes and reports (default: analyst)
    --no-chain          Skip attack chain detection
    --quiet             Suppress progress output
    --summary           Print detection summary only, no full report
"""

import argparse
import hashlib
import os
import sys
import atexit
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

try:
    sys.stdout.reconfigure(errors="replace")
    sys.stderr.reconfigure(errors="replace")
except AttributeError:
    pass


# â”€â”€ Self-locating path â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

_root = os.path.dirname(os.path.abspath(__file__))
for _ in range(8):
    if os.path.isfile(os.path.join(_root, 'pathconfig.py')):
        break
    _root = os.path.dirname(_root)
if _root not in sys.path:
    sys.path.insert(0, _root)
from pathconfig import ROOT, add_root, load_env_profile  # type: ignore
add_root()
load_env_profile("cli")
_ROOT = ROOT

from models import LogFormat             # type: ignore
from engine import Engine                # type: ignore
from rule_engine import RuleEngine       # type: ignore
from attck_tagger import detect_attack_chain  # type: ignore
from case_db import CaseDB               # type: ignore
from ioc_extractor import IOCExtractor   # type: ignore
from report_builder import ReportBuilder # type: ignore
from finding import Finding, Severity, MitreTag  # type: ignore
from utils.runtime_config import load_runtime_config  # type: ignore

_RUNTIME = load_runtime_config()
_POSTPROCESS_EXECUTOR = ThreadPoolExecutor(max_workers=max(1, _RUNTIME.max_workers))


def shutdown_postprocess_executor(wait: bool = True, cancel_futures: bool = False) -> None:
    """Cleanly stop the shared post-processing executor."""
    global _POSTPROCESS_EXECUTOR
    executor = _POSTPROCESS_EXECUTOR
    if executor is None:
        return
    try:
        executor.shutdown(wait=wait, cancel_futures=cancel_futures)
    except Exception:
        pass
    finally:
        _POSTPROCESS_EXECUTOR = None


atexit.register(shutdown_postprocess_executor)


# â”€â”€ Format map â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_FORMAT_MAP = {
    # Web / Proxy
    "apache":         LogFormat.APACHE_COMBINED,
    "apache-error":   LogFormat.APACHE_ERROR,
    "nginx":          LogFormat.NGINX_ACCESS,
    "nginx-error":    LogFormat.NGINX_ERROR,
    "iis":            LogFormat.IIS_W3C,
    "haproxy":        LogFormat.HAPROXY,
    "squid":          LogFormat.SQUID,
    "caddy":          LogFormat.CADDY,
    "traefik":        LogFormat.TRAEFIK,
    # System / OS
    "syslog":         LogFormat.SYSLOG,
    "syslog5424":     LogFormat.SYSLOG_RFC5424,
    "auth":           LogFormat.AUTH_LOG,
    "auditd":         LogFormat.AUDITD,
    "journald":       LogFormat.JOURNALD,
    "kern":           LogFormat.KERN_LOG,
    "dmesg":          LogFormat.DMESG,
    # Windows
    "evtx":           LogFormat.WINDOWS_EVTX,
    "sysmon":         LogFormat.WINDOWS_SYSMON,
    "wfas":           LogFormat.WINDOWS_FIREWALL,
    "powershell":     LogFormat.POWERSHELL_SCRIPT,
    # Network / Security
    "zeek-conn":      LogFormat.ZEEK_CONN,
    "zeek-dns":       LogFormat.ZEEK_DNS,
    "zeek-http":      LogFormat.ZEEK_HTTP,
    "zeek-ssl":       LogFormat.ZEEK_SSL,
    "zeek":           LogFormat.ZEEK_JSON,
    "suricata":       LogFormat.SURICATA_EVE,
    "snort":          LogFormat.SNORT_FAST,
    "cisco-asa":      LogFormat.CISCO_ASA,
    "cisco-ios":      LogFormat.CISCO_IOS,
    "paloalto":       LogFormat.PALOALTO,
    "fortinet":       LogFormat.FORTINET,
    "iptables":       LogFormat.IPTABLES,
    "cef":            LogFormat.CEF,
    "leef":           LogFormat.LEEF,
    "gelf":           LogFormat.GELF,
    # Cloud
    "cloudtrail":     LogFormat.AWS_CLOUDTRAIL,
    "vpcflow":        LogFormat.AWS_VPC_FLOW,
    "alb":            LogFormat.AWS_ALB,
    "azure":          LogFormat.AZURE_ACTIVITY,
    "gcp":            LogFormat.GCP_AUDIT,
    # Database
    "mysql":          LogFormat.MYSQL_ERROR,
    "postgres":       LogFormat.POSTGRESQL,
    "mongodb":        LogFormat.MONGODB,
    # Container
    "docker":         LogFormat.DOCKER_JSON,
    "k8s-audit":      LogFormat.KUBERNETES_AUDIT,
    "falco":          LogFormat.FALCO,
    # Email / DNS
    "postfix":        LogFormat.POSTFIX,
    "bind":           LogFormat.BIND_QUERY,
    # Mobile / Embedded
    "android":            LogFormat.ANDROID_LOGCAT,
    "android-logcat":     LogFormat.ANDROID_LOGCAT,
    "ios":                LogFormat.IOS_SYSLOG,
    # Big Data / Distributed
    "hadoop":             LogFormat.HADOOP,
    "spark":              LogFormat.SPARK,
    "kafka":              LogFormat.KAFKA,
    "zookeeper":          LogFormat.ZOOKEEPER,
    "elasticsearch":      LogFormat.ELASTICSEARCH,
    # Windows Application Logs
    "windows-cbs":        LogFormat.WINDOWS_CBS,
    "windows-setup":      LogFormat.WINDOWS_SETUP,
    "windows-update":     LogFormat.WINDOWS_UPDATE,
    # macOS
    "macos":              LogFormat.MACOS_INSTALL,
    "macos-install":      LogFormat.MACOS_INSTALL,
    # OpenStack / VMware
    "openstack":          LogFormat.OPENSTACK,
    "nova":               LogFormat.OPENSTACK_NOVA,
    "keystone":           LogFormat.OPENSTACK_KEYSTONE,
    "neutron":            LogFormat.OPENSTACK_NEUTRON,
    "vmware":             LogFormat.VMWARE_ESX,
    # Application / Framework
    "log4j":              LogFormat.LOG4J,
    "python":             LogFormat.PYTHON_LOGGING,
    "django":             LogFormat.DJANGO,
    "spring":             LogFormat.SPRING_BOOT,
    # Security Tools
    "ossec":              LogFormat.OSSEC,
    "fail2ban":           LogFormat.FAIL2BAN,
    "crowdstrike":        LogFormat.CROWDSTRIKE,
    # Healthcare
    "health":             LogFormat.HEALTH_APP,
    "healthapp":          LogFormat.HEALTH_APP,
    # Generic
    "json":               LogFormat.JSON_GENERIC,
    "ai":                 LogFormat.AI_PARSED,
}

_SEV_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

_SEV_COLOUR = {
    "CRITICAL": "\033[91m",  # red
    "HIGH":     "\033[93m",  # yellow
    "MEDIUM":   "\033[94m",  # blue
    "LOW":      "\033[96m",  # cyan
    "INFO":     "\033[0m",   # reset
}
_RESET = "\033[0m"


def _colour(sev: str, text: str) -> str:
    """Apply ANSI colour if stdout is a TTY."""
    if not sys.stdout.isatty():
        return text
    return f"{_SEV_COLOUR.get(sev, '')}{text}{_RESET}"


# â”€â”€ Progress printer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class _Progress:
    def __init__(self, quiet: bool):
        self.quiet = quiet

    def info(self, msg: str) -> None:
        if not self.quiet:
            print(f"  {msg}", flush=True)

    def finding(self, f) -> None:
        if not self.quiet:
            sev  = f.severity.value
            host = f.hostname or f.source_ip or "?"
            print(
                f"  {_colour(sev, f'[{sev:<8}]')} "
                f"{f.rule_id:<12} "
                f"{f.rule_name:<38} "
                f"src={host:<18} "
                f"conf={f.confidence:.0%} "
                f"risk={f.risk_score}",
                flush=True,
            )

    def section(self, title: str) -> None:
        if not self.quiet:
            print(f"\n{'â”€' * 64}\n  {title}\n{'â”€' * 64}", flush=True)

    def banner(self, title: str) -> None:
        if not self.quiet:
            print(f"\n{'â•' * 64}\n  {title}\n{'â•' * 64}", flush=True)


# â”€â”€ Core analysis function â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def _dedupe_findings_batch(
    findings: list[Finding],
    seen: set[tuple[str, str, str, str, int]],
) -> list[Finding]:
    """Bounded duplicate guard for progressive saves."""
    unique: list[Finding] = []
    for f in RuleEngine.deduplicate_findings(findings):
        minute = 0
        try:
            if f.timestamp:
                minute = int(f.timestamp.timestamp() // 60)
        except Exception:
            minute = 0
        key = (
            f.rule_id,
            f.source_ip or f.hostname or "",
            f.trigger_line or "",
            f.severity.value,
            minute,
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
    if len(seen) > 200_000:
        for key in list(seen)[:50_000]:
            seen.discard(key)
    return unique


def _source_fingerprint(path: Path, sample_bytes: int = 65536) -> str:
    """Fingerprint enough of a file to validate resume safety quickly."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        head = fh.read(sample_bytes)
        h.update(head)
        try:
            fh.seek(max(0, path.stat().st_size - sample_bytes))
            h.update(fh.read(sample_bytes))
        except OSError:
            pass
    stat = path.stat()
    h.update(str(stat.st_size).encode())
    h.update(str(int(stat.st_mtime)).encode())
    return h.hexdigest()


def _is_seekable_resume_format(path: Path) -> bool:
    return path.suffix.lower() not in {".gz", ".zip", ".evtx"}


def _async_postprocess(
    case_path: Path,
    session_id: str,
    *,
    enrich: bool,
    build_graph: bool,
    job_id: str,
) -> None:
    """Run enrichment and attack-chain graph work off the hot parse path."""
    try:
        with CaseDB(case_path) as db:
            if enrich:
                db.upsert_analysis_job(job_id, session_id=session_id, status="postprocessing", phase="enriching")
                findings = db.get_findings(session_id=session_id, limit=10000)
                try:
                    from intelligence.abuseipdb import AbuseIPDB
                    AbuseIPDB().enrich_findings(findings)
                    for finding in findings:
                        db.update_finding_payload(finding)
                except Exception as exc:
                    db.upsert_analysis_job(job_id, session_id=session_id, status="postprocessing", phase="enrichment skipped", error=str(exc))
            if build_graph:
                db.upsert_analysis_job(job_id, session_id=session_id, status="postprocessing", phase="building graph")
                findings = db.get_findings(session_id=session_id, limit=10000)
                chains = detect_attack_chain(findings)
                if chains:
                    db.save_attack_chains(chains, session_id)
            job = db.get_analysis_job(job_id) or {}
            db.upsert_analysis_job(
                job_id,
                session_id=session_id,
                source_file=str(job.get("source_file", "")),
                status="complete",
                profile=str(job.get("profile", "balanced")),
                phase="ready",
                lines_parsed=int(job.get("lines_parsed") or 0),
                line_number=int(job.get("line_number") or 1),
                findings_saved=int(job.get("findings_saved") or 0),
                byte_offset=int(job.get("byte_offset") or 0),
                source_size=int(job.get("source_size") or 0),
                source_mtime=float(job.get("source_mtime") or 0.0),
                source_fingerprint=str(job.get("source_fingerprint") or ""),
                metadata={**dict(job.get("metadata") or {}), "postprocess_complete": True},
            )
    except Exception:
        pass


def analyse(
    log_paths:   list[Path],
    case_path:   Path,
    rules_dir:   Path,
    min_severity: str       = "LOW",
    category:    Optional[str] = None,
    force_format: Optional[LogFormat] = None,
    analyst:     str        = "analyst",
    run_chains:  bool       = True,
    quiet:       bool       = False,
    profile:     Optional[str] = None,
    batch_size:  Optional[int] = None,
    no_enrich:   bool       = False,
    defer_graph: bool       = False,
    async_postprocess: bool = False,
    max_line_bytes: Optional[int] = None,
    resume:      str        = "",
    progress_callback: Optional[Callable[[dict[str, Any]], None]] = None,
) -> dict:
    """
    Run the full pipeline on one or more log files.
    Returns a summary dict. All findings written to case_path.
    """
    prog = _Progress(quiet)
    prog.banner("NexLog â€” Log Analysis")

    # â”€â”€ Layer 2: load rules once â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    prog.info(f"Loading rules from {rules_dir} â€¦")
    detect_engine = RuleEngine(rules_dir)
    prog.info(f"Loaded {detect_engine._rules_loaded} rules across "
              f"{len(detect_engine.get_loaded_categories())} categories")

    total_findings = []
    total_saved = 0
    session_ids    = []
    job_ids        = []

    with CaseDB(case_path) as db:
        db.set_meta("analyst",  analyst)
        db.set_meta("tool",     "NexLog")
        db.set_meta("started",  datetime.now(timezone.utc).isoformat())

        file_count = len(log_paths)
        for file_index, log_path in enumerate(log_paths, 1):
            prog.section(f"Analysing: {log_path.name}")

            profile_name = (profile or _RUNTIME.profile or "balanced").lower()
            if profile_name not in {"fast", "balanced", "deep"}:
                profile_name = "balanced"
            batch_size = max(1, int(batch_size or _RUNTIME.batch_size))
            effective_max_line_bytes = int(max_line_bytes or _RUNTIME.max_line_bytes)
            fast_meta = profile_name == "fast"
            allow_async_postprocess = bool(async_postprocess)
            async_enrich = (
                allow_async_postprocess
                and not no_enrich
                and profile_name != "fast"
                and os.environ.get("NEXLOG_ENRICH_ASYNC", "1").strip().lower()
                not in {"0", "false", "no", "off"}
            )
            async_graph = (
                allow_async_postprocess
                and
                run_chains
                and not defer_graph
                and profile_name != "fast"
                and os.environ.get("NEXLOG_GRAPH_ASYNC", "1").strip().lower()
                not in {"0", "false", "no", "off"}
            )
            sync_enrich = not no_enrich and profile_name != "fast" and not async_enrich
            sync_chains = run_chains and not defer_graph and profile_name != "fast" and not async_graph
            saved_count = 0
            returned_findings: list[Finding] = []
            returned_limit = 5000
            chain_seed: list[Finding] = []
            seen_keys: set[tuple[str, str, str, str, int]] = set()
            job_id = resume or f"cli-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
            job_ids.append(job_id)
            source_size = log_path.stat().st_size if log_path.exists() else 0
            source_mtime = log_path.stat().st_mtime if log_path.exists() else 0.0
            source_fingerprint = _source_fingerprint(log_path) if log_path.exists() else ""
            start_byte_offset = 0
            start_line_number = 1
            parse_engine = Engine()

            resume_job = db.get_analysis_job(resume) if resume else None
            if resume:
                if not resume_job:
                    print(f"  ERROR: resume job not found: {resume}", file=sys.stderr)
                    continue
                if not _is_seekable_resume_format(log_path):
                    db.upsert_analysis_job(
                        job_id,
                        session_id=str(resume_job.get("session_id") or ""),
                        source_file=str(log_path),
                        status="failed",
                        profile=profile_name,
                        phase="resume",
                        error="byte-offset resume is only available for seekable plain-text logs",
                    )
                    print(f"  ERROR: cannot byte-resume non-seekable log: {log_path}", file=sys.stderr)
                    continue
                if (
                    str(resume_job.get("source_file") or "") != str(log_path)
                    or int(resume_job.get("source_size") or 0) != int(source_size)
                    or int(float(resume_job.get("source_mtime") or 0.0)) != int(source_mtime)
                    or str(resume_job.get("source_fingerprint") or "") != source_fingerprint
                ):
                    db.upsert_analysis_job(
                        job_id,
                        session_id=str(resume_job.get("session_id") or ""),
                        source_file=str(log_path),
                        status="failed",
                        profile=profile_name,
                        phase="resume",
                        error="source file changed since the checkpoint",
                    )
                    print("  ERROR: source file changed since the resume checkpoint.", file=sys.stderr)
                    continue
                sid = str(resume_job.get("session_id") or "")
                start_byte_offset = int(resume_job.get("byte_offset") or 0)
                start_line_number = max(1, int(resume_job.get("line_number") or 1) + 1)
                saved_count = int(resume_job.get("findings_saved") or 0)
                evidence_rows = db.get_evidence(session_id=sid)
                evidence_id = str(evidence_rows[0]["id"]) if evidence_rows else db.record_evidence(
                    file_path=str(log_path),
                    sha256="",
                    file_size=source_size,
                    session_id=sid,
                    log_format="",
                    lines_parsed=max(0, start_line_number - 1),
                    findings_count=saved_count,
                )
                prog.info(f"Resuming job {job_id} from byte {start_byte_offset:,}, line {start_line_number:,}")
            else:
                sid = db.create_session(
                    source_file=str(log_path),
                    sha256="",
                    file_size=source_size,
                    rules_loaded=detect_engine._rules_loaded,
                    entries_parsed=0,
                )
                evidence_id = db.record_evidence(
                    file_path=str(log_path),
                    sha256="",
                    file_size=source_size,
                    session_id=sid,
                    log_format="",
                    lines_parsed=0,
                    findings_count=0,
                )
            session_ids.append(sid)
            db.upsert_analysis_job(
                job_id,
                session_id=sid,
                source_file=str(log_path),
                status="running",
                profile=profile_name,
                phase="parsing",
                line_number=max(1, start_line_number - 1),
                findings_saved=saved_count,
                byte_offset=start_byte_offset,
                source_size=source_size,
                source_mtime=source_mtime,
                source_fingerprint=source_fingerprint,
            )

            def _progress(payload: dict[str, Any]) -> None:
                lines = int(payload.get("lines") or 0)
                if lines:
                    prog.info(f"  {lines:,} lines parsed...")
                if progress_callback:
                    progress_callback({
                        "job_id": job_id,
                        "session_id": sid,
                        "phase": payload.get("phase", "parsing"),
                        "lines_parsed": lines,
                        "line_number": int(payload.get("line_number") or 0),
                        "byte_offset": int(payload.get("byte_offset") or 0),
                        "source_size": int(source_size or 0),
                        "findings_saved": saved_count,
                        "profile": profile_name,
                        "source_file": str(log_path),
                        "source_name": log_path.name,
                        "file_index": file_index,
                        "file_count": file_count,
                    })

            _progress({
                "phase": "parsing",
                "lines": max(0, start_line_number - 1),
                "line_number": max(1, start_line_number - 1),
                "byte_offset": start_byte_offset,
            })

            try:
                for entries in parse_engine.parse_batches(
                    log_path,
                    batch_size=batch_size,
                    force_format=force_format,
                    on_progress=_progress,
                    fast_meta=fast_meta,
                    max_line_bytes=effective_max_line_bytes,
                    start_byte_offset=start_byte_offset,
                    start_line_number=start_line_number,
                ):
                    batch_findings: list[Finding] = []
                    for entry in entries:
                        for f in detect_engine.evaluate(entry):
                            if f.severity.score() < _SEV_ORDER.get(min_severity.upper(), 0):
                                continue
                            if category and f.category != category:
                                continue
                            batch_findings.append(f)
                            prog.finding(f)

                    deduped = _dedupe_findings_batch(batch_findings, seen_keys)
                    if deduped and sync_enrich:
                        try:
                            prog.info("Enriching current batch with AbuseIPDB threat intelligence...")
                            from intelligence.abuseipdb import AbuseIPDB
                            AbuseIPDB().enrich_findings(deduped)
                        except Exception as exc:
                            prog.info(f"Threat enrichment skipped: {exc}")
                    if deduped:
                        db.save_findings_batch(deduped, sid)
                        saved_count += len(deduped)
                        if len(returned_findings) < returned_limit:
                            returned_findings.extend(deduped[: returned_limit - len(returned_findings)])
                        if len(chain_seed) < 2000:
                            chain_seed.extend(deduped[: 2000 - len(chain_seed)])

                    stats_now = parse_engine.stats
                    if stats_now:
                        meta_now = parse_engine.file_meta or {}
                        byte_offset = int(meta_now.get("byte_offset") or start_byte_offset)
                        line_number = int(
                            meta_now.get("line_number")
                            or (start_line_number + stats_now.total_lines - 1)
                        )
                        db.update_session(
                            sid,
                            entries_parsed=max(stats_now.total_lines, line_number),
                            sha256=meta_now.get("sha256", ""),
                            file_size=meta_now.get("size_bytes", 0),
                        )
                        db.update_evidence_stats(
                            evidence_id,
                            sha256=meta_now.get("sha256", ""),
                            lines_parsed=max(stats_now.total_lines, line_number),
                            findings_count=saved_count,
                            log_format=meta_now.get("detected_format", ""),
                        )
                        db.upsert_analysis_job(
                            job_id,
                            session_id=sid,
                            source_file=str(log_path),
                            status="running",
                            profile=profile_name,
                            phase="saving batch",
                            lines_parsed=max(stats_now.total_lines, line_number),
                            line_number=line_number,
                            findings_saved=saved_count,
                            byte_offset=byte_offset,
                            source_size=source_size,
                            source_mtime=source_mtime,
                            source_fingerprint=source_fingerprint,
                        )
                        _progress({
                            "phase": "saving batch",
                            "lines": max(stats_now.total_lines, line_number),
                            "line_number": line_number,
                            "byte_offset": byte_offset,
                        })

            except FileNotFoundError:
                print(f"  ERROR: file not found: {log_path}", file=sys.stderr)
                db.upsert_analysis_job(
                    job_id,
                    session_id=sid,
                    source_file=str(log_path),
                    status="failed",
                    profile=profile_name,
                    error="file not found",
                    source_size=source_size,
                    source_mtime=source_mtime,
                    source_fingerprint=source_fingerprint,
                )
                continue
            except Exception as e:
                print(f"  ERROR: {e}", file=sys.stderr)
                db.upsert_analysis_job(
                    job_id,
                    session_id=sid,
                    source_file=str(log_path),
                    status="failed",
                    profile=profile_name,
                    error=str(e),
                    source_size=source_size,
                    source_mtime=source_mtime,
                    source_fingerprint=source_fingerprint,
                )
                continue

            stats = parse_engine.stats
            meta = parse_engine.file_meta or {}
            final_byte_offset = int(meta.get("byte_offset") or source_size)
            final_line_number = max(1, int(
                meta.get("line_number")
                or (start_line_number + (stats.total_lines if stats else 0) - 1)
            ))
            if stats:
                db.update_session(
                    sid,
                    entries_parsed=max(stats.total_lines, final_line_number),
                    sha256=meta.get("sha256", ""),
                    file_size=meta.get("size_bytes", 0),
                )
                db.update_evidence_stats(
                    evidence_id,
                    sha256=meta.get("sha256", ""),
                    lines_parsed=max(stats.total_lines, final_line_number),
                    findings_count=saved_count,
                    log_format=meta.get("detected_format", ""),
                )
                prog.info(f"Parsed {stats.total_lines:,} lines -> {saved_count} findings ({stats.unique_ips} unique IPs)")

            if sync_chains and chain_seed:
                chains = detect_attack_chain(chain_seed)
                if chains:
                    db.save_attack_chains(chains, sid)
                    prog.info(f"Detected {len(chains)} attack chain(s)")

            postprocess_needed = bool((async_enrich or async_graph) and saved_count)

            db.upsert_analysis_job(
                job_id,
                session_id=sid,
                source_file=str(log_path),
                status="postprocessing" if postprocess_needed else "complete",
                profile=profile_name,
                phase="queued post-processing" if postprocess_needed else "ready",
                lines_parsed=max((stats.total_lines if stats else 0), final_line_number),
                line_number=final_line_number,
                findings_saved=saved_count,
                byte_offset=final_byte_offset,
                source_size=source_size,
                source_mtime=source_mtime,
                source_fingerprint=source_fingerprint,
                metadata={
                    "findings_returned": len(returned_findings),
                    "async_enrichment": bool(async_enrich),
                    "async_graph": bool(async_graph),
                    "graph_deferred": bool(defer_graph or async_graph),
                    "hardware_mode": _RUNTIME.hardware_mode,
                    "batch_size": batch_size,
                },
            )
            _progress({
                "phase": "queued post-processing" if postprocess_needed else "ready",
                "lines": max((stats.total_lines if stats else 0), final_line_number),
                "line_number": final_line_number,
                "byte_offset": final_byte_offset,
            })
            if postprocess_needed:
                if _POSTPROCESS_EXECUTOR is not None:
                    _POSTPROCESS_EXECUTOR.submit(
                        _async_postprocess,
                        case_path,
                        sid,
                        enrich=async_enrich,
                        build_graph=async_graph,
                        job_id=job_id,
                    )
            prog.info(f"Saved {saved_count} findings to {case_path.name}")
            total_findings.extend(returned_findings)
            total_saved += saved_count
            detect_engine.reset()
            continue

        db.set_meta("completed", datetime.now(timezone.utc).isoformat())
        db.set_meta("total_findings", str(total_saved or len(total_findings)))

    return {
        "session_ids":    session_ids,
        "job_ids":        job_ids,
        "total_findings": total_saved or len(total_findings),
        "findings":       total_findings,
        "findings_truncated": bool(total_saved and total_saved > len(total_findings)),
        "case_path":      str(case_path),
        "case_in_memory": getattr(db, "in_memory", False),
    }


# â”€â”€ Report + IOC output â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def write_outputs(
    case_path:   Path,
    session_id:  Optional[str]  = None,
    report_fmt:  str            = "text",
    out_dir:     Path           = Path("."),
    ioc_csv:     Optional[Path] = None,
    stix_file:   Optional[Path] = None,
    analyst:     str            = "analyst",
    quiet:       bool       = False,
) -> None:
    prog = _Progress(quiet)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = case_path.stem

    with CaseDB(case_path) as db:
        builder = ReportBuilder(db, session_id=session_id)
        fmts = (["json","text","markdown"] if report_fmt == "all"
                else [report_fmt])

        for fmt in fmts:
            if fmt == "json":
                out = out_dir / f"{stem}_report.json"
                out.write_text(builder.to_json(), encoding="utf-8")
                prog.info(f"JSON report â†’ {out}")
            elif fmt == "text":
                out = out_dir / f"{stem}_report.txt"
                out.write_text(builder.to_text(), encoding="utf-8")
                prog.info(f"Text report â†’ {out}")
                if not quiet:
                    print(builder.to_text())
            elif fmt == "markdown":
                out = out_dir / f"{stem}_report.md"
                out.write_text(builder.to_markdown(), encoding="utf-8")
                prog.info(f"Markdown report â†’ {out}")

        # IOC export
        findings = db.get_findings(session_id=session_id, limit=10000)
        if findings and (ioc_csv or stix_file):
            extractor = IOCExtractor()
            iocs      = extractor.extract(findings)
            prog.info(f"Extracted {len(iocs)} unique IOCs")

            if ioc_csv:
                ioc_path = Path(ioc_csv)
                ioc_path.parent.mkdir(parents=True, exist_ok=True)
                ioc_path.write_text(extractor.to_csv(iocs), encoding="utf-8")
                prog.info(f"IOC CSV â†’ {ioc_path}")

            if stix_file:
                stix_path = Path(stix_file)
                stix_path.parent.mkdir(parents=True, exist_ok=True)
                stix_path.write_text(
                    extractor.to_stix_bundle(iocs, analyst=analyst),
                    encoding="utf-8",
                )
                prog.info(f"STIX bundle â†’ {stix_path}")


def create_demo_case(case_path: Path, out_dir: Path, analyst: str = "analyst") -> dict:
    """Create a local-first sample case for SOC demos and reviewer screenshots."""
    out_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = out_dir / "demo_soc_evidence.log"
    evidence_lines = [
        '203.0.113.45 - - [09/May/2026:10:00:00 +0000] "GET /admin HTTP/1.1" 404 0 "-" "gobuster/3.0"',
        '203.0.113.45 - - [09/May/2026:10:00:12 +0000] "GET /login?user=admin%27+OR+1=1-- HTTP/1.1" 200 512 "-" "sqlmap/1.7"',
        '198.51.100.77 - - [09/May/2026:10:02:44 +0000] "POST /upload/shell.php HTTP/1.1" 201 42 "-" "curl/8.0"',
        '198.51.100.77 - - [09/May/2026:10:03:01 +0000] "GET /upload/shell.php?cmd=id HTTP/1.1" 200 88 "-" "curl/8.0"',
    ]
    evidence_path.write_text("\n".join(evidence_lines) + "\n", encoding="utf-8")
    import hashlib
    sha = hashlib.sha256(evidence_path.read_bytes()).hexdigest()

    findings = [
        Finding(
            rule_id="DEMO-RECON-001",
            rule_name="Directory Enumeration Burst",
            description="Automated discovery of administrative paths.",
            severity=Severity.MEDIUM,
            confidence=0.88,
            category="recon",
            mitre_tags=[MitreTag("TA0043", "Reconnaissance", "T1595", "Active Scanning")],
            source_ip="203.0.113.45",
            hostname="web01",
            process_name="apache2",
            timestamp=datetime(2026, 5, 9, 10, 0, 0, tzinfo=timezone.utc),
            trigger_line=evidence_lines[0],
            trigger_lineno=1,
            supporting_lines=evidence_lines[:2],
            source_file=str(evidence_path),
        ),
        Finding(
            rule_id="DEMO-WEB-002",
            rule_name="SQL Injection Login Bypass Attempt",
            description="SQL metacharacters observed in authentication parameter.",
            severity=Severity.HIGH,
            confidence=0.93,
            category="web_attack",
            mitre_tags=[MitreTag("TA0001", "Initial Access", "T1190", "Exploit Public-Facing Application")],
            source_ip="203.0.113.45",
            hostname="web01",
            process_name="apache2",
            timestamp=datetime(2026, 5, 9, 10, 0, 12, tzinfo=timezone.utc),
            trigger_line=evidence_lines[1],
            trigger_lineno=2,
            supporting_lines=evidence_lines[:2],
            source_file=str(evidence_path),
        ),
        Finding(
            rule_id="DEMO-PERSIST-003",
            rule_name="Web Shell Upload And Execution",
            description="Executable upload followed by command execution request.",
            severity=Severity.CRITICAL,
            confidence=0.96,
            category="persistence",
            mitre_tags=[MitreTag("TA0003", "Persistence", "T1505", "Server Software Component", ".003")],
            source_ip="198.51.100.77",
            hostname="web01",
            process_name="apache2",
            timestamp=datetime(2026, 5, 9, 10, 3, 1, tzinfo=timezone.utc),
            trigger_line=evidence_lines[3],
            trigger_lineno=4,
            supporting_lines=evidence_lines[2:],
            source_file=str(evidence_path),
        ),
    ]

    with CaseDB(case_path) as db:
        sid = db.create_session(
            source_file=str(evidence_path),
            sha256=sha,
            file_size=evidence_path.stat().st_size,
            rules_loaded=3,
            entries_parsed=len(evidence_lines),
        )
        db.record_evidence(str(evidence_path), sha, evidence_path.stat().st_size,
                           sid, "apache", len(evidence_lines), len(findings))
        db.save_findings(findings, sid)
        stored = db.get_findings(session_id=sid, limit=10)
        db.add_analyst_action(getattr(stored[0], "_db_id"), "triaged",
                              analyst, "Confirmed automated recon.")
        db.add_analyst_action(getattr(stored[-1], "_db_id"), "escalated",
                              analyst, "Web shell path needs containment.")
        db.add_note("Demo mode: all artifacts are local sample data.", sid, analyst)
        db.save_attack_chains([{
            "chain_name": "Recon To Web Shell",
            "source_ip": "198.51.100.77",
            "categories": ["recon", "web_attack", "persistence"],
            "finding_count": len(findings),
            "max_risk_score": max(f.risk_score for f in findings),
            "confidence_boost": 0.15,
        }], sid)

        builder = ReportBuilder(db, session_id=sid)
        (out_dir / "demo_report.json").write_text(builder.to_json(), encoding="utf-8")
        (out_dir / "demo_report.md").write_text(builder.to_markdown(), encoding="utf-8")
        (out_dir / "demo_report.txt").write_text(builder.to_text(), encoding="utf-8")
        iocs = IOCExtractor(include_private_ips=True).extract(stored)
        (out_dir / "demo_iocs.csv").write_text(
            IOCExtractor(include_private_ips=True).to_csv(iocs), encoding="utf-8")
        (out_dir / "demo_stix.json").write_text(
            IOCExtractor(include_private_ips=True).to_stix_bundle(iocs, analyst=analyst),
            encoding="utf-8",
        )
        try:
            from output.pdf_report import PDFReport
            PDFReport(db=db, session_id=sid, iocs=iocs,
                      case_ref="IR-DEMO", analyst=analyst).build(out_dir / "demo_report.pdf")
        except Exception:
            pass
        integrity = db.verify_case_integrity(sid)
    return {"case_path": str(case_path), "session_id": sid, "integrity": integrity}


# â”€â”€ Summary printer â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def print_summary(result: dict, quiet: bool = False) -> None:
    if quiet:
        return
    findings = result["findings"]
    if not findings:
        print("\n  No findings detected.")
        return

    from collections import Counter
    by_sev = Counter(f.severity.value for f in findings)
    by_cat = Counter(f.category      for f in findings)

    print(f"\n{'â•' * 64}")
    print(f"  SUMMARY  â€”  {result['total_findings']} findings  "
          f"â€”  Case: {Path(result['case_path']).name}")
    print(f"{'â•' * 64}")

    print("\n  By severity:")
    for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]:
        c = by_sev.get(sev, 0)
        if c:
            print(f"    {_colour(sev, f'{sev:<10}')}  {c}")

    print("\n  By category (top 10):")
    for cat, c in by_cat.most_common(10):
        print(f"    {cat:<28} {c}")

    sorted_findings: list = sorted(findings, key=lambda f: f.risk_score, reverse=True)
    top = sorted_findings[:5]  # type: ignore
    print("\n  Top 5 by risk score:")
    for f in top:
        print(f"    [{_colour(f.severity.value, f.severity.value):<8}] "
              f"risk={f.risk_score:<5} "
              f"{f.rule_id:<12} "
              f"src={f.source_ip or f.hostname or '?'}")
    print()


# â”€â”€ Argument parser â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nexlog",
        description="NexLog â€” Local-First DFIR Log Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("logs", nargs="*", metavar="LOG",
                   help="Log file(s) to analyse (glob patterns supported)")
    p.add_argument("--case", metavar="FILE",
                   help="Case database file (.facase)")
    p.add_argument("--severity", default="LOW", metavar="LEVEL",
                   choices=["INFO","LOW","MEDIUM","HIGH","CRITICAL"],
                   help="Minimum severity to include (default: LOW)")
    p.add_argument("--category", metavar="CAT",
                   help="Filter to one attack category")
    p.add_argument("--rules", metavar="DIR",
                   help="Custom rules directory")
    p.add_argument("--format", metavar="FMT", dest="log_format",
                   choices=list(_FORMAT_MAP),
                   help="Force log format detection")
    p.add_argument("--report", default="text", metavar="FMT",
                   choices=["json","text","markdown","all","none"],
                   help="Report format (default: text)")
    from pathconfig import WORKSPACE_DIR
    p.add_argument("--out", default=WORKSPACE_DIR, metavar="DIR",
                   help="Output directory (default: workspace dir)")
    p.add_argument("--ioc", metavar="FILE",
                   help="Export IOCs to CSV file")
    p.add_argument("--stix", metavar="FILE",
                   help="Export STIX 2.1 IOC bundle")
    p.add_argument("--analyst", default="analyst", metavar="NAME",
                   help="Analyst name for notes and reports")
    p.add_argument("--no-chain", action="store_true",
                   help="Skip attack chain detection")
    p.add_argument("--hardware-mode", choices=["adaptive", "performance", "conservative"], default=None,
                   help="Runtime hardware profile override for this process")
    p.add_argument("--profile", choices=["fast", "balanced", "deep"], default=None,
                   help="Analysis profile; defaults to the active runtime hardware mode")
    p.add_argument("--batch-size", type=int, default=None, metavar="N",
                   help="Parsed entries per detection/save batch; defaults to runtime config")
    p.add_argument("--resume", metavar="JOB_ID", default="",
                   help="Resume/update a stored analysis job id when possible")
    p.add_argument("--no-enrich", action="store_true",
                   help="Skip threat-intel enrichment during the hot analysis path")
    p.add_argument("--defer-graph", action="store_true",
                   help="Save findings first and defer attack-chain/graph generation")
    p.add_argument("--max-line-bytes", type=int, default=None, metavar="N",
                   help="Skip individual text lines larger than N bytes")
    p.add_argument("--quiet", "-q", action="store_true",
                   help="Suppress progress output")
    p.add_argument("--summary", "-s", action="store_true",
                   help="Print summary only")
    p.add_argument("--verify-case", action="store_true",
                   help="Verify evidence hashes and case integrity, then exit")
    p.add_argument("--demo-mode", action="store_true",
                   help="Create a local sample SOC case and demo reports, then exit")
    return p


# â”€â”€ Main â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def main(argv=None) -> int:
    global _RUNTIME
    parser = _build_parser()
    args   = parser.parse_args(argv)
    if args.hardware_mode:
        os.environ["NEXLOG_HARDWARE_MODE"] = args.hardware_mode
        _RUNTIME = load_runtime_config()

    # Case database path
    from pathconfig import WORKSPACE_DIR
    if args.case:
        case_path = Path(args.case)
        if case_path.parent == Path(""):
            case_path = Path(WORKSPACE_DIR) / case_path
    else:
        ts        = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        case_path = Path(WORKSPACE_DIR) / f"case_{ts}.facase"

    if args.demo_mode:
        result = create_demo_case(case_path, Path(args.out), args.analyst)
        if not args.quiet:
            print("DEMO CASE READY")
            print(f"  Case     : {result['case_path']}")
            print(f"  Session  : {result['session_id']}")
            print(f"  Integrity: {result['integrity'].get('status')}")
            print(f"  Reports  : {Path(args.out)}")
        return 0

    if args.verify_case:
        if not args.case:
            print("ERROR: --verify-case requires --case FILE.", file=sys.stderr)
            return 1
        try:
            from storage.case_db import CaseDB
            with CaseDB(case_path) as db:
                integrity = db.verify_case_integrity()
        except Exception as e:
            print(f"ERROR: case verification failed: {e}", file=sys.stderr)
            return 1
        print("CASE INTEGRITY")
        print(f"  Status          : {integrity.get('status')}")
        print(f"  Checked at      : {integrity.get('checked_at')}")
        print(f"  Case DB SHA-256 : {integrity.get('case_sha256') or 'n/a'}")
        print(
            "  Evidence        : "
            f"{integrity.get('verified_evidence', 0)} verified, "
            f"{integrity.get('changed_evidence', 0)} changed, "
            f"{integrity.get('missing_evidence', 0)} missing"
        )
        print(f"  Findings        : {integrity.get('finding_count', 0)}")
        print(f"  Analyst actions : {integrity.get('analyst_action_count', 0)}")
        return 1 if integrity.get("status") == "compromised" else 0

    # Resolve log paths (support glob)
    import glob
    log_paths = []
    for pattern in args.logs:
        matched = glob.glob(pattern)
        if matched:
            log_paths.extend(Path(p) for p in sorted(matched))
        else:
            log_paths.append(Path(pattern))

    if not log_paths:
        print("ERROR: no log files matched.", file=sys.stderr)
        return 1

    # Rules directory
    rules_dir = Path(args.rules) if args.rules else (
        Path(_ROOT) / "detection" / "rules"
    )
    if not rules_dir.exists():
        print(f"ERROR: rules directory not found: {rules_dir}", file=sys.stderr)
        return 1

    # Force format
    force_fmt = _FORMAT_MAP.get(args.log_format) if args.log_format else None

    # Run analysis
    result = analyse(
        log_paths    = log_paths,
        case_path    = case_path,
        rules_dir    = rules_dir,
        min_severity = args.severity,
        category     = args.category,
        force_format = force_fmt,
        analyst      = args.analyst,
        run_chains   = not args.no_chain,
        quiet        = args.quiet,
        profile      = args.profile,
        batch_size   = args.batch_size,
        resume       = args.resume,
        no_enrich    = args.no_enrich,
        defer_graph  = args.defer_graph,
        max_line_bytes = args.max_line_bytes,
    )

    # Summary
    print_summary(result, quiet=args.quiet)

    # Reports and exports
    if args.report != "none" and result.get("case_in_memory"):
        if not args.quiet:
            print(
                "Case database fell back to in-memory storage; "
                "skipping report/export files."
            )
    elif args.report != "none":
        write_outputs(
            case_path  = case_path,
            report_fmt = args.report,
            out_dir    = Path(args.out),
            ioc_csv    = args.ioc,
            stix_file  = args.stix,
            analyst    = args.analyst,
            quiet      = args.quiet or args.summary,
        )

    return 0 if result.get("error") is None else 1


if __name__ == "__main__":
    sys.exit(main())
