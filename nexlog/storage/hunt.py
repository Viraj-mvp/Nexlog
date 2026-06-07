"""
Safe hunt/query layer for NexLog case databases.

This intentionally exposes a filter builder, not raw SQL. Every value is bound
as a SQLite parameter so web/API/GUI hunt workflows cannot become SQL injection
surfaces.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any


_SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


def hunt_findings(conn: sqlite3.Connection, filters: dict[str, Any], *, limit: int = 200, offset: int = 0) -> dict:
    where: list[str] = []
    params: list[Any] = []

    session_id = filters.get("session_id")
    if session_id:
        where.append("session_id = ?")
        params.append(str(session_id))

    severity = str(filters.get("severity") or "").upper()
    min_severity = str(filters.get("min_severity") or "").upper()
    if severity in _SEVERITIES:
        where.append("severity = ?")
        params.append(severity)
    elif min_severity in _SEVERITIES:
        sev_slice = _SEVERITIES[_SEVERITIES.index(min_severity):]
        where.append("severity IN (" + ",".join("?" for _ in sev_slice) + ")")
        params.extend(sev_slice)

    for key in ("source_ip", "hostname", "username", "category", "rule_id", "event_id"):
        value = filters.get(key)
        if value:
            where.append(f"{key} = ?")
            params.append(str(value))

    mitre_id = filters.get("mitre_id")
    if mitre_id:
        where.append("mitre_ids LIKE ?")
        params.append(f"%{str(mitre_id)}%")

    start = filters.get("start")
    end = filters.get("end")
    if start:
        where.append("timestamp >= ?")
        params.append(str(start))
    if end:
        where.append("timestamp <= ?")
        params.append(str(end))

    text = str(filters.get("text") or "").strip()
    if text:
        pat = f"%{text[:160]}%"
        where.append("(LOWER(trigger_line) LIKE LOWER(?) OR LOWER(rule_name) LIKE LOWER(?) OR LOWER(payload_json) LIKE LOWER(?))")
        params.extend([pat, pat, pat])

    min_risk = filters.get("min_risk")
    if min_risk not in (None, ""):
        where.append("risk_score >= ?")
        params.append(float(min_risk))

    clause = "WHERE " + " AND ".join(where) if where else ""
    limit = max(1, min(int(limit), 1000))
    offset = max(0, int(offset))

    rows = conn.execute(
        f"""
        SELECT id, session_id, rule_id, rule_name, severity, confidence,
               risk_score, category, source_ip, hostname, username,
               process_name, event_id, timestamp, mitre_ids, trigger_line,
               payload_json
        FROM findings
        {clause}
        ORDER BY risk_score DESC, timestamp DESC
        LIMIT ? OFFSET ?
        """,
        (*params, limit + 1, offset),
    ).fetchall()

    items = []
    for row in rows[:limit]:
        d = dict(row)
        try:
            payload = json.loads(d.pop("payload_json") or "{}")
        except Exception:
            payload = {}
        d["payload"] = payload
        try:
            d["mitre_ids"] = json.loads(d.get("mitre_ids") or "[]")
        except Exception:
            d["mitre_ids"] = []
        items.append(d)

    return {
        "ok": True,
        "filters": filters,
        "limit": limit,
        "offset": offset,
        "has_more": len(rows) > limit,
        "findings": items,
    }
