"""
NexLog case bundle export.

Creates a portable .nexlogcase ZIP containing the case DB, manifest, findings,
timeline, notes, attack chains, evidence metadata, and integrity hashes.
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from storage.case_db import CaseDB


class CaseBundleExporter:
    """Export a case database into a portable forensic bundle."""

    def __init__(self, case_db_path: str | Path):
        self.case_db_path = Path(case_db_path)

    def export(
        self,
        output_path: str | Path,
        *,
        session_id: Optional[str] = None,
        include_db: bool = True,
    ) -> dict:
        out = Path(output_path)
        if out.suffix.lower() != ".nexlogcase":
            out = out.with_suffix(".nexlogcase")
        out.parent.mkdir(parents=True, exist_ok=True)

        with CaseDB(self.case_db_path) as db:
            sessions = [db.get_session(session_id)] if session_id else db.list_sessions()
            sessions = [s for s in sessions if s]
            findings = [f.to_dict() for f in db.get_findings(session_id=session_id, limit=100000)]
            timeline = db.get_timeline(session_id=session_id, limit=100000)
            notes = db.get_notes(session_id=session_id)
            journal = db.get_journal(session_id=session_id)
            saved_views = db.get_saved_views(session_id=session_id)
            bookmarks = db.get_timeline_bookmarks(session_id=session_id)
            chains = db.get_attack_chains(session_id=session_id)
            evidence = db.get_evidence(session_id=session_id)
            integrity = db.verify_case_integrity(session_id=session_id)

        generated_at = datetime.now(timezone.utc).isoformat()
        manifest = {
            "product": "NexLog",
            "bundle_format": "nexlogcase-v1",
            "generated_at": generated_at,
            "session_id": session_id or "all",
            "case_db": str(self.case_db_path),
            "counts": {
                "sessions": len(sessions),
                "findings": len(findings),
                "timeline_events": len(timeline),
                "notes": len(notes),
                "journal_entries": len(journal),
                "saved_views": len(saved_views),
                "bookmarks": len(bookmarks),
                "attack_chains": len(chains),
                "evidence": len(evidence),
            },
            "integrity": integrity,
        }

        with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            self._write_json(zf, "manifest.json", manifest)
            self._write_json(zf, "sessions.json", sessions)
            self._write_json(zf, "findings.json", findings)
            self._write_json(zf, "timeline.json", timeline)
            self._write_json(zf, "notes.json", notes)
            self._write_json(zf, "journal.json", journal)
            self._write_json(zf, "saved_views.json", saved_views)
            self._write_json(zf, "timeline_bookmarks.json", bookmarks)
            self._write_json(zf, "attack_chains.json", chains)
            self._write_json(zf, "evidence.json", evidence)
            if include_db and self.case_db_path.exists() and str(self.case_db_path) != ":memory:":
                zf.write(self.case_db_path, "case/case.facase")

        return {
            "ok": True,
            "path": str(out),
            "size_bytes": out.stat().st_size,
            "sha256": self._sha256(out),
            "manifest": manifest,
        }

    def _write_json(self, zf: zipfile.ZipFile, name: str, data) -> None:
        zf.writestr(name, json.dumps(data, indent=2, default=str).encode("utf-8"))

    def _sha256(self, path: Path) -> str:
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
