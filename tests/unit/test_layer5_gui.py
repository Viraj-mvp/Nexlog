"""Active NexLog QML GUI smoke tests.

The legacy PySide6 Widgets GUI is archived under docs/archive and is no longer
part of the active desktop runtime.
"""

from __future__ import annotations

import argparse
import ast
from pathlib import Path

import pathconfig


ROOT = Path(pathconfig.ROOT)
QML_DIR = ROOT / "interface" / "gui" / "qml"


def test_active_gui_package_exports_qml_runtime_only():
    import interface.gui as gui_pkg

    assert "launch" in gui_pkg.__all__
    assert "CyberBridge" in gui_pkg.__all__
    assert "MainWindow" not in gui_pkg.__all__
    assert hasattr(gui_pkg, "launch")
    assert hasattr(gui_pkg, "CyberBridge")


def test_main_gui_help_has_no_legacy_flag():
    import main_gui

    parser = argparse.ArgumentParser(description="probe")
    assert callable(main_gui.main)
    removed_flag = "--" + "legacy"
    assert removed_flag not in Path("main_gui.py").read_text(encoding="utf-8")


def test_qml_entrypoints_exist():
    assert (QML_DIR / "Main.qml").exists()
    for screen in [
        "DashboardScreen.qml",
        "FindingsScreen.qml",
        "TimelineScreen.qml",
        "AttackGraphScreen.qml",
        "AiScreen.qml",
        "MitreScreen.qml",
        "ToolsScreen.qml",
    ]:
        assert (QML_DIR / "screens" / screen).exists()


def test_active_gui_python_files_parse():
    active_files = [
        ROOT / "interface" / "gui" / "cyber_app.py",
        ROOT / "interface" / "gui" / "cyber_bridge.py",
        ROOT / "interface" / "gui" / "crash_guard.py",
        ROOT / "interface" / "gui" / "multi_file_engine.py",
        ROOT / "interface" / "gui" / "__init__.py",
    ]
    for file_path in active_files:
        ast.parse(file_path.read_text(encoding="utf-8-sig"), filename=str(file_path))


def test_bridge_ai_config_snapshot_is_masked():
    from interface.gui.cyber_bridge import CyberBridge

    bridge = CyberBridge(str(Path("workspace") / "gui_test_masked.facase"))
    snapshot = bridge.aiProviderConfigSnapshot()
    assert "groqApiKey" not in snapshot
    assert "geminiApiKey" not in snapshot
    assert isinstance(snapshot["groqConfigured"], bool)
    assert isinstance(snapshot["geminiConfigured"], bool)
    assert snapshot["envPath"].endswith(".env.gui")


def test_legacy_widgets_gui_is_archived_not_active():
    active_dir = ROOT / "interface" / "gui"
    archive_dir = Path(pathconfig.REPO_ROOT_PATH) / "docs" / "archive" / "legacy-widgets-gui"
    assert not (active_dir / "main_window.py").exists()
    assert not (active_dir / "dashboard.py").exists()
    assert not (active_dir / "glass_widget.py").exists()
    assert (archive_dir / "main_window.py").exists()
    assert (archive_dir / "glass_widget.py").exists()
    assert (archive_dir / "README.md").exists()


def _sample_findings(count: int = 80) -> list[dict[str, object]]:
    severities = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    rows: list[dict[str, object]] = []
    for i in range(count):
        rows.append(
            {
                "finding_id": f"f{i}",
                "severity": severities[i % len(severities)],
                "risk_score": float((i % 11) + (i % 3) * 0.25),
                "source_ip": f"10.0.{i % 7}.{(i % 23) + 1}",
                "rule_id": f"RULE-{i % 21}",
                "rule_name": f"Rule {i % 21}",
                "category": ["initial_access", "execution", "persistence", "lateral_movement"][i % 4],
                "mitre_ids": [f"T10{i % 30:02d}", f"T20{i % 17:02d}"],
            }
        )
    return rows


def _sample_chains() -> list[dict[str, object]]:
    return [
        {
            "chain_id": "c1",
            "chain_name": "Source to rule to MITRE",
            "source": "10.0.1.9",
            "categories": ["initial_access", "execution", "persistence"],
            "rules": ["RULE-1", "RULE-7", "RULE-13"],
            "techniques": ["T1003", "T1059"],
            "finding_count": 24,
            "max_risk_score": 9.5,
        }
    ]


def test_graph_payload_compat_and_extended_fields(monkeypatch):
    from interface.gui.cyber_bridge import CyberBridge

    monkeypatch.setenv("NEXLOG_GRAPH_NODE_LIMIT", "40")
    monkeypatch.setenv("NEXLOG_GRAPH_EDGE_LIMIT", "90")

    bridge = CyberBridge(str(Path("workspace") / "gui_graph_payload.facase"))
    payload = bridge._build_graph_payload(_sample_findings(120), _sample_chains())

    assert isinstance(payload.get("nodes"), list)
    assert isinstance(payload.get("edges"), list)
    assert isinstance(payload.get("stats"), dict)
    assert "layout" in payload
    assert payload.get("layout_version") == "2"
    assert isinstance(payload.get("meta"), dict)
    assert {"reduced", "node_limit", "edge_limit", "nodes_raw", "edges_raw"} <= set(payload["meta"].keys())

    if payload["nodes"]:
        node = payload["nodes"][0]
        assert {"id", "label", "kind", "severity", "weight", "risk"} <= set(node.keys())
        assert "cluster" in node
        assert "layer" in node
        assert isinstance(node.get("pos"), dict)
        assert {"x", "y", "z"} <= set(node["pos"].keys())

    if payload["edges"]:
        edge = payload["edges"][0]
        assert {"from", "to", "severity", "relation", "weight", "risk"} <= set(edge.keys())
        assert "weight_norm" in edge


def test_graph_payload_reduction_metadata(monkeypatch):
    from interface.gui.cyber_bridge import CyberBridge

    monkeypatch.setenv("NEXLOG_GRAPH_NODE_LIMIT", "18")
    monkeypatch.setenv("NEXLOG_GRAPH_EDGE_LIMIT", "24")
    monkeypatch.setenv("NEXLOG_GRAPH_SOURCE_LIMIT", "150")

    bridge = CyberBridge(str(Path("workspace") / "gui_graph_reduced.facase"))
    payload = bridge._build_graph_payload(_sample_findings(300), _sample_chains())
    meta = payload.get("meta", {})

    assert meta.get("reduced") is True
    assert int(meta.get("nodes_raw", 0)) >= len(payload.get("nodes", []))
    assert int(meta.get("edges_raw", 0)) >= len(payload.get("edges", []))
    assert int(meta.get("nodes_dropped", 0)) >= 0
    assert int(meta.get("edges_dropped", 0)) >= 0


def test_graph_payload_reduction_has_no_dangling_edges(monkeypatch):
    from interface.gui.cyber_bridge import CyberBridge

    monkeypatch.setenv("NEXLOG_GRAPH_NODE_LIMIT", "24")
    monkeypatch.setenv("NEXLOG_GRAPH_EDGE_LIMIT", "36")
    monkeypatch.setenv("NEXLOG_GRAPH_SOURCE_LIMIT", "220")

    bridge = CyberBridge(str(Path("workspace") / "gui_graph_no_dangling_edges.facase"))
    payload = bridge._build_graph_payload(_sample_findings(360), _sample_chains())
    visible_ids = {node["id"] for node in payload.get("nodes", [])}

    assert payload.get("meta", {}).get("reduced") is True
    assert visible_ids
    assert all(edge.get("from") in visible_ids for edge in payload.get("edges", []))
    assert all(edge.get("to") in visible_ids for edge in payload.get("edges", []))


def test_graph_payload_positions_are_deterministic(monkeypatch):
    from interface.gui.cyber_bridge import CyberBridge

    monkeypatch.setenv("NEXLOG_GRAPH_NODE_LIMIT", "60")
    monkeypatch.setenv("NEXLOG_GRAPH_EDGE_LIMIT", "160")

    findings = _sample_findings(120)
    chains = _sample_chains()
    bridge = CyberBridge(str(Path("workspace") / "gui_graph_deterministic.facase"))

    first = bridge._build_graph_payload(findings, chains)
    second = bridge._build_graph_payload(findings, chains)
    first_pos = {node["id"]: dict(node.get("pos") or {}) for node in first.get("nodes", [])}
    second_pos = {node["id"]: dict(node.get("pos") or {}) for node in second.get("nodes", [])}

    assert first_pos == second_pos
