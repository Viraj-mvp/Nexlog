"""
output/attack_graph.py â€” NexLog v2  Attack Graph Builder
==============================================================
Builds a directed graph of attacker lateral movement from findings.
Exports as JSON (for D3.js web view) and GraphML (for Gephi/Cytoscape).

No competitor produces an attack graph from log findings automatically.
This is the single biggest visual differentiator for enterprise demos.

Usage:
    from output.attack_graph import AttackGraphBuilder
    from storage.case_db import CaseDB

    with CaseDB("case.facase") as db:
        builder = AttackGraphBuilder()
        graph   = builder.build(db.get_findings())
        json_str = builder.to_json(graph)     # for D3.js
        graphml  = builder.to_graphml(graph)  # for Gephi
        builder.save(graph, "output/attack_graph.json")
"""

import json
import os
import sys
from pathlib import Path
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


# â”€â”€ Severity â†’ node color mapping â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_NODE_COLORS = {
    "attacker":  "#FF3B5C",
    "victim":    "#00C8FF",
    "pivot":     "#FFB700",
    "external":  "#B060FF",
    "unknown":   "#5A8FA8",
}

_SEV_EDGE_COLOR = {
    "CRITICAL": "#FF3B5C",
    "HIGH":     "#FF6B35",
    "MEDIUM":   "#FFB700",
    "LOW":      "#00FF9D",
    "INFO":     "#4A8FA8",
}


def _safe_str(val) -> str:
    return str(val) if val is not None else ""


def _get_sev_str(finding) -> str:
    if isinstance(finding, dict):
        s = finding.get("severity", "INFO")
        return s if isinstance(s, str) else getattr(s, "value", "INFO")
    s = getattr(finding, "severity", "INFO")
    return getattr(s, "value", str(s)) if not isinstance(s, str) else s


def _get_ts_float(finding) -> float:
    if isinstance(finding, dict):
        ts = finding.get("timestamp")
    else:
        ts = getattr(finding, "timestamp", None)
    if isinstance(ts, datetime):
        return ts.timestamp()
    if isinstance(ts, str) and ts:
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except Exception:
            pass
    return 0.0


def _target_label(finding, hostname, dest_ip, process_name, category) -> str:
    """Choose a useful victim/target label instead of collapsing to 'unknown'."""
    if hostname:
        return _safe_str(hostname)
    if dest_ip:
        return _safe_str(dest_ip)
    if process_name:
        return f"process:{_safe_str(process_name)}"
    source_file = (
        finding.get("source_file") if isinstance(finding, dict)
        else getattr(finding, "source_file", "")
    )
    if source_file:
        return f"log:{Path(_safe_str(source_file)).name}"
    if category:
        return f"target:{_safe_str(category)}"
    return "observed-target"


class AttackGraphBuilder:
    """Build and export attack graphs from NexLog findings."""

    def build(self, findings: list) -> dict:
        """
        Build the attack graph from a list of findings.

        Returns a dict with:
          nodes: list of {id, label, type, color, weight, findings_count}
          edges: list of {source, target, technique, severity, color, weight, timestamp}
          stats: summary stats
        """
        nodes: dict[str, dict] = {}
        # edge_key â†’ aggregated edge dict
        edges: dict[str, dict] = {}

        # Sort by timestamp so the graph reflects temporal order
        sorted_findings = sorted(findings, key=_get_ts_float)

        # Track which IPs are pivot points (both source and dest)
        all_sources: set = set()
        all_dests:   set = set()

        for f in sorted_findings:
            if isinstance(f, dict):
                src   = f.get("source_ip")  or "external"
                dst   = _target_label(
                    f, f.get("hostname"), f.get("dest_ip"),
                    f.get("process_name"), f.get("category", ""))
                rid   = f.get("rule_id", "")
                rname = f.get("rule_name", "")
                sev   = _get_sev_str(f)
                risk  = float(f.get("risk_score", 0) or 0)
                tags  = f.get("mitre_tags", [])
                cat   = f.get("category", "")
            else:
                src   = getattr(f, "source_ip", None) or "external"
                dst   = _target_label(
                    f, getattr(f, "hostname", None),
                    getattr(f, "dest_ip", None),
                    getattr(f, "process_name", None),
                    getattr(f, "category", ""))
                rid   = _safe_str(getattr(f, "rule_id", ""))
                rname = _safe_str(getattr(f, "rule_name", ""))
                sev   = _get_sev_str(f)
                risk  = float(getattr(f, "risk_score", 0) or 0)
                tags  = getattr(f, "mitre_tags", [])
                cat   = _safe_str(getattr(f, "category", ""))

            all_sources.add(src)
            all_dests.add(dst)

            # â”€â”€ Extract MITRE technique â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            technique = ""
            tactic    = ""
            if tags:
                t0 = tags[0]
                if isinstance(t0, dict):
                    technique = t0.get("full_id", t0.get("technique_id", ""))
                    tactic    = t0.get("tactic_name", "")
                else:
                    technique = _safe_str(getattr(t0, "full_id", ""))
                    tactic    = _safe_str(getattr(t0, "tactic_name", ""))

            # â”€â”€ Add / update nodes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            for nid, ntype in [(src, "attacker"), (dst, "victim")]:
                if nid not in nodes:
                    nodes[nid] = {
                        "id":            nid,
                        "label":         nid,
                        "type":          ntype,
                        "color":         _NODE_COLORS[ntype],
                        "weight":        1,
                        "findings_count": 0,
                        "max_risk":      0.0,
                        "tactics":       set(),
                    }
                nodes[nid]["findings_count"] += 1
                nodes[nid]["max_risk"]        = max(nodes[nid]["max_risk"], risk)
                if tactic:
                    nodes[nid]["tactics"].add(tactic)

            # â”€â”€ Add / update edge â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
            ekey = f"{src}â†’{dst}"
            if ekey not in edges:
                edges[ekey] = {
                    "id":         ekey,
                    "source":     src,
                    "target":     dst,
                    "techniques": [],
                    "rules":      [],
                    "severity":   sev,
                    "color":      _SEV_EDGE_COLOR.get(sev, "#5A8FA8"),
                    "weight":     0,
                    "max_risk":   0.0,
                    "timestamp":  _get_ts_float(f),
                    "category":   cat,
                }
            e = edges[ekey]
            e["weight"]   += 1
            e["max_risk"]  = max(e["max_risk"], risk)
            if technique and technique not in e["techniques"]:
                e["techniques"].append(technique)
            if rid and rid not in e["rules"]:
                e["rules"].append(rid)
            # Escalate severity
            sev_rank = {"INFO":0,"LOW":1,"MEDIUM":2,"HIGH":3,"CRITICAL":4}
            if sev_rank.get(sev, 0) > sev_rank.get(e["severity"], 0):
                e["severity"] = sev
                e["color"]    = _SEV_EDGE_COLOR.get(sev, "#5A8FA8")

        # â”€â”€ Mark pivot nodes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        pivot_ips = all_sources & all_dests
        for nid in pivot_ips:
            if nid in nodes and nid not in ("external", "unknown"):
                nodes[nid]["type"]  = "pivot"
                nodes[nid]["color"] = _NODE_COLORS["pivot"]

        # Serialise sets to lists
        nodes_list = []
        for n in nodes.values():
            n["tactics"] = list(n.get("tactics", set()))
            nodes_list.append(n)

        edges_list = list(edges.values())

        stats = {
            "node_count":   len(nodes_list),
            "edge_count":   len(edges_list),
            "attacker_ips": [n["id"] for n in nodes_list if n["type"] == "attacker"][:10],
            "pivot_hosts":  [n["id"] for n in nodes_list if n["type"] == "pivot"][:10],
            "victim_hosts": [n["id"] for n in nodes_list if n["type"] == "victim"][:10],
        }

        return {"nodes": nodes_list, "edges": edges_list, "stats": stats}

    def to_json(self, graph: dict, indent: int = 2) -> str:
        """Serialise graph to JSON (D3.js / web interface compatible)."""
        return json.dumps(graph, indent=indent, default=str)

    def to_graphml(self, graph: dict) -> str:
        """
        Export graph to GraphML XML format.
        Compatible with Gephi, Cytoscape, yEd, and networkx.
        """
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<graphml xmlns="http://graphml.graphdrawing.org/graphml">',
            '  <key id="type"  for="node" attr.name="type"  attr.type="string"/>',
            '  <key id="color" for="node" attr.name="color" attr.type="string"/>',
            '  <key id="risk"  for="node" attr.name="risk"  attr.type="double"/>',
            '  <key id="sev"   for="edge" attr.name="severity" attr.type="string"/>',
            '  <key id="weight" for="edge" attr.name="weight" attr.type="int"/>',
            '  <graph id="G" edgedefault="directed">',
        ]

        for n in graph["nodes"]:
            nid = n["id"].replace("&", "&amp;").replace("<", "&lt;")
            lines.append(f'    <node id="{nid}">')
            lines.append(f'      <data key="type">{n["type"]}</data>')
            lines.append(f'      <data key="color">{n["color"]}</data>')
            lines.append(f'      <data key="risk">{n["max_risk"]}</data>')
            lines.append('    </node>')

        for i, e in enumerate(graph["edges"]):
            src = e["source"].replace("&", "&amp;").replace("<", "&lt;")
            tgt = e["target"].replace("&", "&amp;").replace("<", "&lt;")
            lines.append(f'    <edge id="e{i}" source="{src}" target="{tgt}">')
            lines.append(f'      <data key="sev">{e["severity"]}</data>')
            lines.append(f'      <data key="weight">{e["weight"]}</data>')
            lines.append('    </edge>')

        lines += ['  </graph>', '</graphml>']
        return "\n".join(lines)

    def save(self, graph: dict, path: str) -> str:
        """Save graph as JSON. Creates parent dirs automatically."""
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json(graph))
        return path
