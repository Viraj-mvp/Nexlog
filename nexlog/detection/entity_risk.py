"""
Entity risk scoring for NexLog.

Aggregates findings into IP/user/host/process risk snapshots. This gives the
product a risk-based alerting layer without changing the existing finding
schema or analyzer pipeline.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any


_SEV_WEIGHT = {
    "INFO": 1.0,
    "LOW": 2.0,
    "MEDIUM": 4.0,
    "HIGH": 7.0,
    "CRITICAL": 10.0,
}

_TACTIC_BONUS = {
    "Initial Access": 1.2,
    "Execution": 1.1,
    "Persistence": 1.5,
    "Privilege Escalation": 1.6,
    "Defense Evasion": 1.4,
    "Credential Access": 1.7,
    "Lateral Movement": 1.8,
    "Collection": 1.2,
    "Command and Control": 1.6,
    "Exfiltration": 2.0,
    "Impact": 2.0,
}


class EntityRiskEngine:
    """Build host/IP/user/process risk from stored findings."""

    def score_findings(self, findings: list[Any], *, limit: int = 100) -> dict:
        entities: dict[tuple[str, str], dict] = {}
        for finding in findings:
            data = self._finding_dict(finding)
            base = float(data.get("risk_score") or 0)
            severity = str(data.get("severity") or "INFO").upper()
            base = max(base, _SEV_WEIGHT.get(severity, 2.0))
            confidence = float(data.get("confidence") or 0.75)
            tactic_bonus = self._tactic_bonus(data)
            chain_bonus = 1.15 if data.get("category") in {
                "lateral_movement", "persistence", "exfiltration", "privilege_escalation"
            } else 1.0
            contribution = base * confidence * tactic_bonus * chain_bonus

            for kind, value in self._entities(data):
                key = (kind, value)
                item = entities.setdefault(key, {
                    "kind": kind,
                    "value": value,
                    "score": 0.0,
                    "finding_count": 0,
                    "severities": Counter(),
                    "categories": Counter(),
                    "rules": Counter(),
                    "mitre_ids": Counter(),
                    "latest_timestamp": "",
                })
                item["score"] += contribution
                item["finding_count"] += 1
                item["severities"][severity] += 1
                item["categories"][str(data.get("category") or "unknown")] += 1
                item["rules"][str(data.get("rule_name") or data.get("rule_id") or "Rule")] += 1
                for tid in data.get("mitre_ids") or data.get("technique_ids") or []:
                    item["mitre_ids"][str(tid)] += 1
                ts = str(data.get("timestamp") or "")
                if ts > item["latest_timestamp"]:
                    item["latest_timestamp"] = ts

        scored = []
        for item in entities.values():
            normalized = min(100.0, round(item["score"] * 2.4, 2))
            scored.append({
                "kind": item["kind"],
                "value": item["value"],
                "risk_score": normalized,
                "risk_band": self._band(normalized),
                "finding_count": item["finding_count"],
                "severities": dict(item["severities"]),
                "top_categories": self._top(item["categories"]),
                "top_rules": self._top(item["rules"]),
                "mitre_ids": self._top(item["mitre_ids"]),
                "latest_timestamp": item["latest_timestamp"],
                "why": self._why(item, normalized),
            })
        scored.sort(key=lambda row: (row["risk_score"], row["finding_count"]), reverse=True)
        return {
            "entities": scored[: max(1, int(limit))],
            "total_entities": len(scored),
            "high_risk_entities": sum(1 for item in scored if item["risk_score"] >= 70),
        }

    def _finding_dict(self, finding: Any) -> dict:
        if isinstance(finding, dict):
            return finding
        if hasattr(finding, "to_dict"):
            return finding.to_dict()
        return {}

    def _entities(self, data: dict) -> list[tuple[str, str]]:
        candidates = [
            ("ip", data.get("source_ip")),
            ("ip", data.get("dest_ip")),
            ("user", data.get("username")),
            ("host", data.get("hostname")),
            ("process", data.get("process_name")),
        ]
        return [(kind, str(value)) for kind, value in candidates if value]

    def _tactic_bonus(self, data: dict) -> float:
        tactics = data.get("tactic_names") or []
        if not tactics and isinstance(data.get("mitre_tags"), list):
            tactics = [item.get("tactic_name") for item in data["mitre_tags"] if isinstance(item, dict)]
        return max([_TACTIC_BONUS.get(str(tactic), 1.0) for tactic in tactics if tactic] or [1.0])

    def _top(self, counter: Counter, limit: int = 5) -> list[dict]:
        return [{"value": key, "count": count} for key, count in counter.most_common(limit)]

    def _band(self, score: float) -> str:
        if score >= 85:
            return "CRITICAL"
        if score >= 70:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "INFO"

    def _why(self, item: dict, score: float) -> str:
        sev = ", ".join(f"{k}:{v}" for k, v in item["severities"].most_common(3))
        cats = ", ".join(k for k, _ in item["categories"].most_common(3))
        return f"{item['kind']} {item['value']} reached {round(score, 1)} risk from {item['finding_count']} findings ({sev}) across {cats or 'uncategorized activity'}."
