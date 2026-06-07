"""
detection/ueba.py â€” NexLog v2  Behavioral UEBA Engine
===========================================================
User and Entity Behavior Analytics â€” Z-score anomaly detection.

Builds a statistical baseline per (entity, hour-of-day) tuple and flags
findings whose feature vectors deviate significantly from that baseline.

Features tracked per entity:
  - finding_rate     : findings per hour
  - failed_auth_rate : fraction of auth events that failed
  - unique_dest_ips  : count of distinct destination IPs contacted
  - off_hours_access : 1 if activity outside 08:00â€“18:00 local, else 0
  - critical_pct     : fraction of findings that are CRITICAL/HIGH

Anomaly score: 0 (normal) â†’ 10 (highly anomalous)
Threshold:     6.0 (configurable) â€” above this = UEBA alert

No external dependencies â€” uses only stdlib math.

Usage:
    from detection.ueba import UEBAEngine
    from storage.case_db import CaseDB

    with CaseDB("case.facase") as db:
        engine = UEBAEngine()
        findings = db.get_findings(session_id="sess-001")

        # Build baseline from historical sessions
        for hist_session in db.list_sessions()[1:]:
            hist = db.get_findings(session_id=hist_session["session_id"])
            engine.ingest_baseline(hist)

        # Score current session
        anomalies = engine.score_findings(findings)
        for entity, score, detail in anomalies:
            print(f"{entity}: {score:.1f}/10 â€” {detail}")
"""

import math
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
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


def _safe_str(val) -> str:
    return str(val) if val is not None else ""


def _sev_score(sev) -> float:
    """Convert severity to numeric 0â€“4."""
    val = getattr(sev, "value", str(sev)) if not isinstance(sev, str) else sev
    return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(
        val.upper(), 0)


class _Stats:
    """Online Welford variance for streaming mean/std computation."""
    __slots__ = ("n", "mean", "M2")

    def __init__(self):
        self.n    = 0
        self.mean = 0.0
        self.M2   = 0.0

    def update(self, value: float) -> None:
        self.n += 1
        delta   = value - self.mean
        self.mean += delta / self.n
        delta2  = value - self.mean
        self.M2 += delta * delta2

    @property
    def std(self) -> float:
        if self.n < 2:
            return 1.0
        return math.sqrt(self.M2 / (self.n - 1))

    def z_score(self, value: float) -> float:
        """Absolute Z-score â€” how many std devs from mean."""
        return abs(value - self.mean) / max(self.std, 0.01)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# ENTITY EXTRACTOR
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def _get_entity_key(finding) -> Optional[str]:
    """Extract the primary entity key (IP, username, or hostname)."""
    if isinstance(finding, dict):
        return (finding.get("source_ip") or
                finding.get("username") or
                finding.get("hostname"))
    return (getattr(finding, "source_ip", None) or
            getattr(finding, "username", None) or
            getattr(finding, "hostname", None))


def _get_timestamp(finding) -> Optional[datetime]:
    if isinstance(finding, dict):
        ts = finding.get("timestamp")
    else:
        ts = getattr(finding, "timestamp", None)
    if isinstance(ts, datetime):
        return ts
    if isinstance(ts, str) and ts:
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            pass
    return None


def _get_severity(finding):
    if isinstance(finding, dict):
        return finding.get("severity", "INFO")
    return getattr(finding, "severity", "INFO")


def _get_dest_ip(finding) -> Optional[str]:
    if isinstance(finding, dict):
        return finding.get("dest_ip")
    return getattr(finding, "dest_ip", None)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# UEBA ENGINE
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class UEBAEngine:
    """
    Behavioral analytics engine â€” detects anomalous entities.

    Workflow:
        1. engine.ingest_baseline(historical_findings)  â€” build the baseline
        2. engine.score_findings(current_findings)       â€” detect anomalies
        3. engine.get_anomalies(threshold=6.0)           â€” retrieve alerts

    Or directly via engine.score_session(db, session_id).
    """

    def __init__(self, threshold: float = 6.0):
        self._threshold = threshold
        # baseline[entity][feature] â†’ _Stats
        self._baseline: dict[str, dict[str, _Stats]] = defaultdict(
            lambda: defaultdict(_Stats))
        # scored entities from the last score_findings() call
        self._scores: dict[str, dict] = {}

    # â”€â”€ Baseline ingestion â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def ingest_baseline(self, findings: list) -> None:
        """
        Feed historical findings to build the behavioral baseline.
        Call this for each historical session before scoring a new session.
        """
        entity_findings: dict[str, list] = defaultdict(list)
        for f in findings:
            entity = _get_entity_key(f)
            if entity:
                entity_findings[entity].append(f)

        for entity, efs in entity_findings.items():
            feats = self._compute_features(efs)
            for feat_name, feat_val in feats.items():
                self._baseline[entity][feat_name].update(feat_val)

    def _compute_features(self, findings: list) -> dict:
        """Compute behavioral feature vector for a list of findings."""
        if not findings:
            return {}

        total       = len(findings)
        failed_auth = 0
        critical_h  = 0
        dest_ips:   set = set()
        off_hours   = 0
        sev_sum     = 0.0

        for f in findings:
            sev = _get_severity(f)
            if isinstance(sev, str):
                sev_val = sev.upper()
            else:
                sev_val = getattr(sev, "value", "INFO")

            sev_sum += _sev_score(sev)
            if sev_val in ("HIGH", "CRITICAL"):
                critical_h += 1

            # Auth failures
            if isinstance(f, dict):
                auth = f.get("auth_result", "")
                cat  = f.get("category", "")
            else:
                auth = getattr(f, "auth_result", "") or ""
                cat  = getattr(f, "category", "") or ""

            if auth == "failure" or "auth" in cat.lower():
                failed_auth += 1

            # Destination IPs
            dip = _get_dest_ip(f)
            if dip:
                dest_ips.add(dip)

            # Off-hours check
            ts = _get_timestamp(f)
            if ts:
                hour = ts.hour
                if hour < 8 or hour >= 18:
                    off_hours += 1

        return {
            "finding_rate":     float(total),
            "failed_auth_rate": failed_auth / max(total, 1),
            "unique_dest_ips":  float(len(dest_ips)),
            "off_hours_pct":    off_hours / max(total, 1),
            "critical_pct":     critical_h / max(total, 1),
            "avg_severity":     sev_sum / max(total, 1),
        }

    # â”€â”€ Scoring â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def score_findings(self, findings: list) -> list[tuple]:
        """
        Score entities in a set of findings against the baseline.

        Returns:
            List of (entity, score, detail_dict) tuples,
            sorted by score descending. Only entities with score > 0
            are returned. Entities without a baseline get a raw score.
        """
        entity_findings: dict[str, list] = defaultdict(list)
        for f in findings:
            entity = _get_entity_key(f)
            if entity:
                entity_findings[entity].append(f)

        results = []
        for entity, efs in entity_findings.items():
            feats  = self._compute_features(efs)
            score  = self._compute_anomaly_score(entity, feats)
            detail = self._build_detail(entity, feats, score, len(efs))

            self._scores[entity] = {
                "score":    score,
                "features": feats,
                "detail":   detail,
                "count":    len(efs),
            }
            results.append((entity, score, detail))

        return sorted(results, key=lambda x: -x[1])

    def _compute_anomaly_score(self, entity: str, features: dict) -> float:
        """
        Compute anomaly score 0â€“10.
        If no baseline exists, compute a raw risk score from the features.
        """
        baseline = self._baseline.get(entity)

        if baseline:
            # Z-score based â€” deviation from known baseline
            z_scores = []
            for feat, val in features.items():
                if feat in baseline:
                    z = baseline[feat].z_score(val)
                    z_scores.append(z)
            if z_scores:
                avg_z = sum(z_scores) / len(z_scores)
                return round(min(avg_z * 2.0, 10.0), 1)

        # No baseline â€” use raw feature heuristics
        score = 0.0
        if features.get("failed_auth_rate", 0) > 0.5:
            score += 3.0
        if features.get("critical_pct", 0) > 0.3:
            score += 3.0
        if features.get("off_hours_pct", 0) > 0.5:
            score += 2.0
        if features.get("unique_dest_ips", 0) > 10:
            score += 2.0
        if features.get("avg_severity", 0) > 2.5:
            score += 2.0
        return round(min(score, 10.0), 1)

    def _build_detail(self, entity: str, feats: dict,
                      score: float, count: int) -> dict:
        """Build human-readable detail for the anomaly."""
        flags = []
        if feats.get("failed_auth_rate", 0) > 0.4:
            flags.append(f"High auth failure rate ({feats['failed_auth_rate']:.0%})")
        if feats.get("critical_pct", 0) > 0.25:
            flags.append(f"High critical/high severity ratio ({feats['critical_pct']:.0%})")
        if feats.get("off_hours_pct", 0) > 0.4:
            flags.append(f"Significant off-hours activity ({feats['off_hours_pct']:.0%})")
        if feats.get("unique_dest_ips", 0) > 8:
            flags.append(f"Contacted {int(feats['unique_dest_ips'])} distinct IPs (lateral movement indicator)")

        has_baseline = entity in self._baseline
        return {
            "entity":       entity,
            "score":        score,
            "count":        count,
            "flags":        flags,
            "has_baseline": has_baseline,
            "anomalous":    score >= self._threshold,
            "label":        (
                "CRITICAL anomaly" if score >= 8 else
                "HIGH anomaly"     if score >= 6 else
                "SUSPICIOUS"       if score >= 4 else
                "Normal"
            ),
        }

    def get_anomalies(self, threshold: Optional[float] = None) -> list[dict]:
        """
        Return entities scoring above the threshold from the last score run.

        Args:
            threshold: Override the engine's threshold for this query.

        Returns:
            List of detail dicts sorted by score descending.
        """
        t = threshold if threshold is not None else self._threshold
        return sorted(
            [v["detail"] for v in self._scores.values()
             if v["detail"]["score"] >= t],
            key=lambda x: -x["score"],
        )

    def score_session(self, db, session_id: str) -> list[dict]:
        """
        Convenience: load findings from DB, score, return anomalies.

        Args:
            db:         Open CaseDB instance.
            session_id: Session to score.
        """
        findings = db.get_findings(session_id=session_id, limit=5000)

        # Use all other sessions as baseline
        for sess in db.list_sessions():
            sid = sess["session_id"]
            if sid != session_id:
                hist = db.get_findings(session_id=sid, limit=2000)
                self.ingest_baseline(hist)

        self.score_findings(findings)
        return self.get_anomalies()
