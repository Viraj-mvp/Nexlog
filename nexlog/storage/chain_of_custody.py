"""
storage/chain_of_custody.py â€” NexLog Layer 3
Standalone SHA-256 evidence ledger for chain-of-custody tracking.

Designed to work WITHOUT a CaseDB â€” usable as a lightweight standalone
module for quick verification workflows or court-admissible evidence logs.

Two components:
  1. Low-level hash functions â€” hash_file(), hash_stream(), verify_file()
  2. EvidenceLedger class â€” append-only text ledger with HMAC tamper detection

Design decisions:
  - Zero external dependencies â€” pure Python stdlib only
  - EvidenceLedger stores records in a plain-text CSV-like file, not SQLite.
    This makes it human-readable, easy to attach to legal reports, and
    independent of any database schema.
  - Every write to the ledger is checksummed with HMAC-SHA256 so appending
    a fake entry or editing an existing one is detectable.
  - CaseDB.record_evidence / verify_evidence delegate to these functions
    for the hashing logic itself.

Usage:
    from storage.chain_of_custody import hash_file, verify_file, EvidenceLedger

    # Quick hash
    digest = hash_file("access.log")

    # Quick verify
    result = verify_file("access.log", expected_hash=digest)
    print(result["verified"])   # True / False

    # Full ledger
    ledger = EvidenceLedger("case_001.ledger", hmac_key="secret-analyst-key")
    eid = ledger.add("access.log", digest, size=204800, notes="Primary web log")

    # Verify entire ledger integrity
    report = ledger.verify_all()
    print(report["tampered"])   # []
    print(report["missing"])    # []

    # Export for court submission
    csv_text = ledger.to_csv()
    html_text = ledger.to_acquisition_report(analyst="Jane Smith", case="Case-2026-001")
"""

import csv
import hashlib
import hmac
import io
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Optional


# â”€â”€ Self-locating path â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

_root = os.path.dirname(os.path.abspath(__file__))
for _ in range(8):
    if os.path.isfile(os.path.join(_root, 'pathconfig.py')):
        break
    _root = os.path.dirname(_root)
if _root not in sys.path:
    sys.path.insert(0, _root)
from pathconfig import ROOT, add_root
add_root()
_ROOT = ROOT


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# LOW-LEVEL HASH FUNCTIONS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def hash_file(
    path: str | Path,
    algorithm: str = "sha256",
    chunk_size: int = 65536,
) -> str:
    """
    Compute the hex digest of a file using the given algorithm.
    Reads in chunks â€” safe for very large evidence files.

    Args:
        path:       Path to the file.
        algorithm:  Hash algorithm name (sha256, sha1, md5). Default: sha256.
        chunk_size: Read buffer size in bytes. Default: 64 KB.

    Returns:
        Lowercase hex digest string.

    Raises:
        FileNotFoundError if the file does not exist.
        ValueError if the algorithm is not supported.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Evidence file not found: {path}")

    try:
        h = hashlib.new(algorithm)
    except ValueError:
        raise ValueError(f"Unsupported hash algorithm: {algorithm!r}. "
                         f"Use: sha256, sha1, md5")

    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_stream(
    stream: BinaryIO,
    algorithm: str = "sha256",
    chunk_size: int = 65536,
) -> str:
    """
    Compute the hex digest of a binary stream.
    Stream position is restored after hashing.

    Useful for hashing file-like objects (BytesIO, network streams)
    without writing them to disk first.
    """
    try:
        h = hashlib.new(algorithm)
    except ValueError:
        raise ValueError(f"Unsupported hash algorithm: {algorithm!r}")

    start = stream.tell()
    for chunk in iter(lambda: stream.read(chunk_size), b""):
        h.update(chunk)
    stream.seek(start)
    return h.hexdigest()


def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    """Compute the hex digest of an in-memory byte string."""
    return hashlib.new(algorithm, data).hexdigest()


def verify_file(
    path: str | Path,
    expected_hash: str,
    algorithm: str = "sha256",
) -> dict:
    """
    Re-hash a file and compare against an expected digest.

    Returns a dict:
        {
            "verified":      bool,    # True if hashes match
            "path":          str,
            "algorithm":     str,
            "stored_hash":   str,     # the expected hash you passed in
            "current_hash":  str,     # the hash computed right now
            "file_size":     int,
            "checked_at":   str,      # ISO 8601 UTC timestamp
            "error":         str | None
        }
    """
    path = Path(path)
    result: dict = {
        "verified":     False,
        "path":         str(path),
        "algorithm":    algorithm,
        "stored_hash":  expected_hash.lower(),
        "current_hash": "",
        "file_size":    0,
        "checked_at":   _utcnow(),
        "error":        None,
    }

    if not path.exists():
        result["error"] = f"File not found: {path}"
        return result

    try:
        result["file_size"]    = path.stat().st_size
        result["current_hash"] = hash_file(path, algorithm)
        result["verified"]     = result["current_hash"] == result["stored_hash"]
    except Exception as e:
        result["error"] = str(e)

    return result


def multi_hash_file(path: str | Path) -> dict[str, str]:
    """
    Compute MD5, SHA-1, and SHA-256 of a file in a single pass.
    Useful for generating complete forensic hash sets.

    Returns: {"md5": "...", "sha1": "...", "sha256": "..."}
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5":    md5.hexdigest(),
        "sha1":   sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# EVIDENCE LEDGER
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

_LEDGER_VERSION  = "1"
_LEDGER_FIELDS   = [
    "entry_id", "acquired_at", "file_path", "file_size",
    "sha256", "sha1", "md5", "format", "notes",
    "analyst", "session_id", "entry_hmac",
]


class EvidenceLedger:
    """
    Append-only forensic evidence ledger stored as a text file.

    Each line is a JSON record containing the evidence metadata plus
    an HMAC-SHA256 signature over all fields. The ledger header is
    also HMAC-signed so adding/removing entries is detectable.

    File format: one JSON object per line (JSONL).
    First line is always the ledger header.

    Args:
        path:      Path to the .ledger file. Created if it doesn't exist.
        hmac_key:  Secret key for HMAC tamper detection.
                   If not provided, defaults to machine hostname.
                   For forensic integrity, use a consistent key and
                   document it in the case notes.

    Usage:
        ledger = EvidenceLedger("case.ledger", hmac_key="analyst-key")
        eid = ledger.add("access.log", sha256="abc...", size=1024)
        report = ledger.verify_all()
    """

    def __init__(self, path: str | Path, hmac_key: str = ""):
        self.path     = Path(path)
        self._key     = (hmac_key or os.uname().nodename).encode("utf-8")
        self._entries: list[dict] = []
        self._loaded  = False

        if self.path.exists():
            self._load()
        else:
            self._init_new()

    # â”€â”€ Lifecycle â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _init_new(self) -> None:
        """Create a new empty ledger file."""
        header = {
            "type":           "forensic_evidence_ledger",
            "version":        _LEDGER_VERSION,
            "created_at":     _utcnow(),
            "tool":           "NexLog v2",
        }
        header["header_hmac"] = self._sign(json.dumps(header, sort_keys=True))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(json.dumps(header) + "\n")
        self._loaded = True

    def _load(self) -> None:
        """Load existing ledger entries into memory."""
        with open(self.path, "r", encoding="utf-8") as f:
            lines = [l.strip() for l in f if l.strip()]

        if not lines:
            self._init_new()
            return

        # First line is the header â€” skip it for entries
        self._entries = []
        for line in lines[1:]:
            try:
                entry = json.loads(line)
                self._entries.append(entry)
            except json.JSONDecodeError:
                pass   # corrupt line â€” will surface in verify_all()
        self._loaded = True

    # â”€â”€ Add entry â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def add(
        self,
        file_path:  str | Path,
        sha256:     str         = "",
        sha1:       str         = "",
        md5:        str         = "",
        file_size:  int         = 0,
        log_format: str         = "",
        notes:      str         = "",
        analyst:    str         = "analyst",
        session_id: str         = "",
        compute_hashes: bool    = False,
    ) -> str:
        """
        Add an evidence file to the ledger. Returns entry_id.

        Args:
            file_path:      Path to the evidence file.
            sha256/sha1/md5: Pre-computed hashes. If all are empty and
                             compute_hashes=True, hashes are computed now.
            file_size:      File size in bytes (0 = auto-detect if file exists).
            log_format:     Detected format string (e.g. "apache_combined").
            notes:          Analyst notes about this piece of evidence.
            analyst:        Analyst name for attribution.
            session_id:     Link to CaseDB session (optional).
            compute_hashes: If True and no hashes provided, compute from file.
        """
        file_path = Path(file_path)

        # Auto-compute hashes if requested and not provided
        if compute_hashes and not sha256 and file_path.exists():
            hashes   = multi_hash_file(file_path)
            sha256   = hashes["sha256"]
            sha1     = hashes["sha1"]
            md5      = hashes["md5"]

        # Auto-detect file size
        if file_size == 0 and file_path.exists():
            file_size = file_path.stat().st_size

        import uuid as _uuid
        entry_id = str(_uuid.uuid4())

        entry: dict = {
            "entry_id":    entry_id,
            "acquired_at": _utcnow(),
            "file_path":   str(file_path),
            "file_size":   file_size,
            "sha256":      sha256.lower(),
            "sha1":        sha1.lower(),
            "md5":         md5.lower(),
            "format":      log_format,
            "notes":       notes,
            "analyst":     analyst,
            "session_id":  session_id,
        }
        # Sign the entry (exclude the hmac field itself)
        entry["entry_hmac"] = self._sign(
            json.dumps({k: v for k, v in entry.items()}, sort_keys=True)
        )

        self._entries.append(entry)

        # Append to file
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

        return entry_id

    # â”€â”€ Query â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def get(self, entry_id: str) -> Optional[dict]:
        """Return a single ledger entry by ID, or None."""
        return next(
            (e for e in self._entries if e.get("entry_id") == entry_id),
            None,
        )

    def list_entries(self) -> list[dict]:
        """Return all ledger entries in acquisition order."""
        return list(self._entries)

    def find_by_hash(self, sha256: str) -> Optional[dict]:
        """Look up an evidence entry by its SHA-256 hash."""
        sha256 = sha256.lower()
        return next(
            (e for e in self._entries if e.get("sha256") == sha256),
            None,
        )

    # â”€â”€ Verification â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def verify_entry(self, entry: dict) -> dict:
        """
        Verify one ledger entry:
          1. HMAC signature â€” detects in-file tampering
          2. File hash â€” detects file modification on disk

        Returns dict with keys: entry_id, hmac_ok, file_ok, verified, error
        """
        eid = entry.get("entry_id", "?")
        result = {
            "entry_id":  eid,
            "hmac_ok":   False,
            "file_ok":   False,
            "verified":  False,
            "error":     None,
        }

        # 1. HMAC check
        stored_hmac = entry.get("entry_hmac", "")
        payload     = {k: v for k, v in entry.items() if k != "entry_hmac"}
        expected    = self._sign(json.dumps(payload, sort_keys=True))
        result["hmac_ok"] = hmac.compare_digest(stored_hmac, expected)

        # 2. File hash check
        path = Path(entry.get("file_path", ""))
        stored_sha256 = entry.get("sha256", "")
        if not path.exists():
            result["error"] = f"File not found: {path}"
        elif stored_sha256:
            try:
                current = hash_file(path)
                result["file_ok"] = current == stored_sha256
                if not result["file_ok"]:
                    result["error"] = (
                        f"Hash mismatch: stored={stored_sha256[:12]}â€¦ "
                        f"current={current[:12]}â€¦"
                    )
            except Exception as e:
                result["error"] = str(e)
        else:
            # No hash stored â€” can't verify file, but HMAC still matters
            result["file_ok"] = True

        result["verified"] = result["hmac_ok"] and result["file_ok"]
        return result

    def verify_all(self) -> dict:
        """
        Verify every entry in the ledger.

        Returns:
            {
                "total":    int,
                "ok":       int,
                "tampered": list[dict],   # entries that failed HMAC
                "modified": list[dict],   # entries whose files changed on disk
                "missing":  list[dict],   # entries whose files don't exist
                "checked_at": str,
            }
        """
        total, ok = 0, 0
        tampered, modified, missing = [], [], []

        for entry in self._entries:
            total += 1
            r = self.verify_entry(entry)
            if r["verified"]:
                ok += 1
            else:
                if not r["hmac_ok"]:
                    tampered.append({"entry_id": r["entry_id"],
                                     "file":     entry.get("file_path")})
                if r["error"] and "not found" in r["error"]:
                    missing.append({"entry_id":  r["entry_id"],
                                    "file":      entry.get("file_path")})
                elif not r["file_ok"] and r["hmac_ok"]:
                    modified.append({"entry_id": r["entry_id"],
                                     "file":     entry.get("file_path"),
                                     "error":    r["error"]})

        return {
            "total":      total,
            "ok":         ok,
            "tampered":   tampered,
            "modified":   modified,
            "missing":    missing,
            "all_ok":     ok == total,
            "checked_at": _utcnow(),
        }

    # â”€â”€ Export â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def to_csv(self) -> str:
        """
        Export the ledger as a CSV string suitable for legal submission.
        Excludes the entry_hmac field (internal integrity field).
        """
        export_fields = [f for f in _LEDGER_FIELDS if f != "entry_hmac"]
        buf    = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=export_fields, extrasaction="ignore")
        writer.writeheader()
        for entry in self._entries:
            writer.writerow({k: entry.get(k, "") for k in export_fields})
        return buf.getvalue()

    def to_acquisition_report(
        self,
        analyst:   str = "Analyst",
        case:      str = "Case",
        agency:    str = "",
    ) -> str:
        """
        Generate a plain-text digital evidence acquisition report
        suitable for inclusion in legal or court submissions.
        """
        lines = [
            "=" * 72,
            "  DIGITAL EVIDENCE ACQUISITION REPORT",
            f"  Case:     {case}",
            f"  Analyst:  {analyst}",
            f"  Agency:   {agency or 'N/A'}",
            "  Tool:     NexLog v2",
            f"  Generated:{_utcnow()}",
            "=" * 72,
            "",
            f"  Evidence Items: {len(self._entries)}",
            "",
            "-" * 72,
            f"  {'#':<4} {'File':<40} {'Size':>10}  {'SHA-256 (first 16)':<16}",
            "-" * 72,
        ]
        for i, e in enumerate(self._entries, 1):
            sha_short = (e.get("sha256") or "N/A")[:16] + "â€¦"
            size_kb   = e.get("file_size", 0) // 1024
            lines.append(
                f"  {i:<4} {str(Path(e.get('file_path','')).name):<40} "
                f"{size_kb:>8} KB  {sha_short}"
            )
        lines += [
            "",
            "-" * 72,
            "  FULL HASH DETAILS",
            "-" * 72,
        ]
        for i, e in enumerate(self._entries, 1):
            lines += [
                f"  [{i}] {e.get('file_path','')}",
                f"      MD5    : {e.get('md5','N/A')}",
                f"      SHA-1  : {e.get('sha1','N/A')}",
                f"      SHA-256: {e.get('sha256','N/A')}",
                f"      Acquired : {e.get('acquired_at','')}",
                f"      Analyst  : {e.get('analyst','')}",
                f"      Notes    : {e.get('notes','') or 'None'}",
                "",
            ]
        lines += [
            "=" * 72,
            "  INTEGRITY VERIFICATION",
            "=" * 72,
        ]
        vr = self.verify_all()
        lines += [
            f"  Entries verified: {vr['ok']}/{vr['total']}",
            f"  Tampered:  {len(vr['tampered'])}",
            f"  Modified:  {len(vr['modified'])}",
            f"  Missing:   {len(vr['missing'])}",
            f"  Status:    {'INTEGRITY OK' if vr['all_ok'] else 'INTEGRITY COMPROMISED'}",
            f"  Checked:   {vr['checked_at']}",
            "=" * 72,
        ]
        return "\n".join(lines)

    # â”€â”€ Internal â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _sign(self, data: str) -> str:
        """Compute HMAC-SHA256 signature of a string."""
        return hmac.new(
            self._key, data.encode("utf-8"), hashlib.sha256
        ).hexdigest()

    def __len__(self) -> int:
        return len(self._entries)

    def merge(
        self,
        other: "EvidenceLedger",
        analyst: str = "analyst",
    ) -> int:
        """
        Merge another EvidenceLedger into this one.
        Entries are deduplicated by SHA-256 â€” duplicates are silently skipped.
        Raises ValueError if ANY entry HMAC in the source ledger is tampered
        (files being absent on this machine is acceptable and not an error).

        Args:
            other:   EvidenceLedger instance to read from.
            analyst: Name recorded in the merge note on each imported entry.

        Returns:
            Count of entries added (0 if all were duplicates).
        """
        result   = other.verify_all()
        tampered = result.get("tampered", [])
        if tampered:
            raise ValueError(
                f"Source ledger has {len(tampered)} HMAC-tampered "
                f"{'entry' if len(tampered) == 1 else 'entries'} â€” "
                f"refusing to merge. IDs: "
                f"{[t.get('entry_id', '?') for t in tampered[:3]]}"
            )

        existing: set[str] = {e.get("sha256", "") for e in self.list_entries()}
        added = 0
        for entry in other.list_entries():
            sha = entry.get("sha256", "")
            if sha and sha in existing:
                continue
            note       = entry.get("notes", "")
            merge_note = f"[merged from {other.path} by {analyst}]"
            self.add(
                file_path  = entry.get("file_path", ""),
                sha256     = sha,
                sha1       = entry.get("sha1", ""),
                md5        = entry.get("md5", ""),
                file_size  = int(entry.get("file_size", 0)),
                log_format = entry.get("log_format", ""),
                notes      = f"{note} {merge_note}".strip(),
                analyst    = entry.get("analyst", analyst),
                session_id = entry.get("session_id", ""),
            )
            if sha:
                existing.add(sha)
            added += 1
        return added

    def summary(self) -> dict:
        """
        Compact summary of ledger contents and HMAC integrity.

        Returns:
            {
              total:       int   â€” total entries
              hmac_ok:     int   â€” entries with valid HMAC
              tampered:    int   â€” entries with corrupted HMAC
              missing:     int   â€” entries where file is absent on disk
              total_bytes: int   â€” sum of recorded file_size values
              analysts:    list[str]
              sessions:    list[str]
              oldest:      str   â€” earliest acquired_at timestamp
              newest:      str   â€” latest acquired_at timestamp
            }
        """
        entries = self.list_entries()
        if not entries:
            return {
                "total": 0, "hmac_ok": 0, "tampered": 0, "missing": 0,
                "total_bytes": 0, "analysts": [], "sessions": [],
                "oldest": "", "newest": "",
            }
        v           = self.verify_all()
        total_bytes = sum(int(e.get("file_size", 0)) for e in entries)
        analysts    = list(dict.fromkeys(
            e.get("analyst", "") for e in entries if e.get("analyst")))
        sessions    = list(dict.fromkeys(
            e.get("session_id", "") for e in entries if e.get("session_id")))
        timestamps  = sorted(
            e.get("acquired_at", "") for e in entries if e.get("acquired_at"))
        return {
            "total":       len(entries),
            "hmac_ok":     v.get("ok", 0),
            "tampered":    len(v.get("tampered", [])),
            "missing":     len(v.get("missing", [])),
            "total_bytes": total_bytes,
            "analysts":    analysts,
            "sessions":    sessions,
            "oldest":      timestamps[0]  if timestamps else "",
            "newest":      timestamps[-1] if timestamps else "",
        }


    def __repr__(self) -> str:
        return f"<EvidenceLedger path={self.path} entries={len(self)}>"


# â”€â”€ Convenience function â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def quick_verify(path: str | Path, expected_sha256: str) -> bool:
    """
    One-liner file integrity check.
    Returns True if the file's SHA-256 matches expected_sha256.

    Usage:
        if not quick_verify("access.log", stored_hash):
            raise ValueError("Evidence file has been modified!")
    """
    return verify_file(path, expected_sha256)["verified"]


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()
