"""
output/ â€” NexLog v2  Output Layer
Report generation, IOC export, STIX bundling, attack graph, AI IR report.

Modules:
    report_builder  â€” JSON / Text / Markdown reports
    pdf_report      â€” PDF report with ReportLab
    ioc_csv         â€” IOC export (CSV, JSONL, Zeek, MISP)
    stix_export     â€” STIX 2.1 bundle
    ai_report       â€” AI-generated narrative IR report (NEW)
    attack_graph    â€” Attack graph builder / GraphML exporter (NEW)
"""

try:
    from .report_builder import ReportBuilder
except Exception:
    pass

try:
    from .ai_report import AIReportBuilder
except Exception:
    pass

try:
    from .attack_graph import AttackGraphBuilder
except Exception:
    pass
