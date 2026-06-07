"""
reader.py â€” NexLog Layer 1
Streaming file reader. Yields raw lines one at a time.
Never loads the entire file into memory.

Handles:
- Plain text (.log, .txt, .csv)
- Gzip compressed (.log.gz)
- EVTX binary (Windows Event Log) â€” yields XML strings per event
- JSON lines (.jsonl) and JSON array files
- Encoding detection with fallback chain
"""

import gzip
import hashlib
import json
from pathlib import Path
from typing import Generator, Tuple


# â”€â”€ Encoding fallback chain â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Try these in order. Most logs are UTF-8. Windows EVTX is UTF-16.
# latin-1 (iso-8859-1) never fails â€” every byte is valid â€” so it's the last resort.
_ENCODINGS = ["utf-8", "utf-16", "latin-1"]


def _open_text(path: Path):
    """
    Open a text file with automatic encoding detection.
    Returns a file object or raises ValueError if all encodings fail
    (which can't happen since latin-1 accepts all bytes).
    """
    for enc in _ENCODINGS:
        try:
            # errors="replace" replaces undecodable bytes with ?
            # so a corrupt log doesn't crash the entire analysis
            fh = open(path, "r", encoding=enc, errors="replace")
            fh.read(512)   # probe â€” will raise if encoding is truly wrong
            fh.seek(0)
            return fh, enc
        except (UnicodeDecodeError, UnicodeError):
            continue
    # Absolute fallback â€” latin-1 accepts every possible byte value
    return open(path, "r", encoding="latin-1", errors="replace"), "latin-1"


def sha256_file(path: str | Path) -> str:
    """
    Compute SHA-256 of the file in streaming chunks.
    Call this BEFORE parsing â€” this is your chain of custody hash.

    Usage:
        hash_val = sha256_file("/var/log/auth.log")
        # Store hash_val in your case DB immediately
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        # 8MB chunks â€” fast on large files, low memory overhead
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def stream_lines(
    path: str | Path,
    encoding: str | None = None,
) -> Generator[Tuple[int, str], None, None]:
    """
    Core streaming generator. Yields (line_number, raw_line) tuples.
    line_number is 1-indexed to match what text editors show.

    Args:
        path:     path to any text-based log file
        encoding: force an encoding (None = auto-detect)

    Yields:
        (line_number: int, raw_line: str)  â€” raw_line has trailing newline stripped

    Example:
        for lineno, line in stream_lines("/var/log/auth.log"):
            print(lineno, line)
    """
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")

    # Gzip-compressed logs (.log.gz, .gz)
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
            for lineno, line in enumerate(f, start=1):
                yield lineno, line.rstrip("\n\r")
        return

    # EVTX â€” binary Windows Event Log â€” delegate to dedicated reader
    if path.suffix.lower() == ".evtx":
        yield from _stream_evtx(path)
        return

    # Standard text file
    if encoding:
        fh = open(path, "r", encoding=encoding, errors="replace")
        used_enc = encoding
    else:
        fh, used_enc = _open_text(path)

    try:
        for lineno, line in enumerate(fh, start=1):
            yield lineno, line.rstrip("\n\r")
    finally:
        fh.close()


def stream_line_offsets(
    path: str | Path,
    start_offset: int = 0,
    start_line: int = 1,
    encoding: str = "utf-8",
) -> Generator[Tuple[int, str, int], None, None]:
    """
    Stream seekable text logs as (line_number, raw_line, next_byte_offset).
    Used for true byte-offset resume. Compressed/binary formats should not use
    this helper because their byte offsets are not stable parser checkpoints.
    """
    path = Path(path)
    with open(path, "rb") as fh:
        if start_offset > 0:
            fh.seek(start_offset)
        line_no = max(1, int(start_line))
        while True:
            raw = fh.readline()
            if not raw:
                break
            next_offset = fh.tell()
            text = raw.decode(encoding, errors="replace").rstrip("\n\r")
            yield line_no, text, next_offset
            line_no += 1


def stream_json_array(
    path: str | Path,
) -> Generator[Tuple[int, dict], None, None]:
    """
    Streaming reader for JSON array files (e.g. AWS CloudTrail export).
    Yields (index, record_dict) without loading the whole array.

    For JSONL (one JSON object per line), use stream_lines() and
    json.loads() on each line in your parser instead.

    CloudTrail exports look like:
        {"Records": [ {...}, {...}, ... ]}

    This yields each record dict with its index.
    """
    path = Path(path)

    try:
        import ijson
    except ImportError:
        ijson = None

    if ijson is not None:
        with open(path, "rb") as f:
            for prefix in ("Records.item", "records.item", "events.item", "Events.item", "item"):
                f.seek(0)
                emitted = False
                try:
                    for idx, record in enumerate(ijson.items(f, prefix), start=1):
                        if isinstance(record, dict):
                            emitted = True
                            yield idx, record
                    if emitted:
                        return
                except Exception:
                    continue
        return

    if path.stat().st_size > 10 * 1024 * 1024:
        raise RuntimeError("ijson is required to stream JSON arrays larger than 10MB")

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        data = json.load(f)

    if isinstance(data, dict):
        records = data.get("Records") or data.get("records") or data.get("events") or data.get("Events") or []
    elif isinstance(data, list):
        records = data
    else:
        return

    for idx, record in enumerate(records, start=1):
        if isinstance(record, dict):
            yield idx, record


def quick_file_meta(path: str | Path, include_sha256: bool = False) -> dict:
    """
    Return cheap file metadata for instant-start analysis.
    Use include_sha256=True only when hashing must finish before parsing.
    """
    path = Path(path)
    stat = path.stat()
    size = stat.st_size

    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            size_human = f"{size:.2f} {unit}"
            break
        size /= 1024
    else:
        size_human = f"{size:.2f} PB"

    return {
        "path": str(path.absolute()),
        "size_bytes": stat.st_size,
        "size": stat.st_size,
        "size_human": size_human,
        "estimated_lines": stat.st_size // 200,
        "extension": path.suffix.lower(),
        "sha256": sha256_file(path) if include_sha256 else "",
    }


def _stream_evtx(path: Path) -> Generator[Tuple[int, str], None, None]:
    """
    Parse Windows EVTX binary format.
    Requires python-evtx: pip install python-evtx

    Yields (event_number, xml_string) â€” each event as raw XML.
    The XML string is then parsed by the EVTX field extractor.

    If python-evtx is not installed, yields an error message line
    and returns â€” so the rest of the pipeline degrades gracefully
    rather than crashing.
    """
    try:
        import Evtx.Evtx as evtx
        import Evtx.Views as e_views
    except ImportError:
        yield (
            0,
            "[EVTX-ERROR] python-evtx not installed. "
            "Run: pip install python-evtx"
        )
        return

    with evtx.Evtx(str(path)) as log:
        for record_num, record in enumerate(log.records(), start=1):
            try:
                xml_str = record.xml()
                yield record_num, xml_str
            except Exception as e:
                # Corrupt record â€” yield a marker and continue
                yield record_num, f"[EVTX-CORRUPT-RECORD] {e}"


def get_file_stats(path: str | Path) -> dict:
    """
    Return metadata about a log file before parsing.
    Useful for UI display and for choosing chunking strategy.

    Returns:
        {
          "path": str,
          "size_bytes": int,
          "size_human": str,        # e.g. "1.23 GB"
          "estimated_lines": int,   # approximation from file size
          "extension": str,
          "sha256": str             # chain of custody hash
        }
    """
    path = Path(path)
    stat = path.stat()
    size = stat.st_size

    # Human-readable size
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            size_human = f"{size:.2f} {unit}"
            break
        size /= 1024
    else:
        size_human = f"{size:.2f} PB"

    # Rough line estimate: average log line â‰ˆ 200 bytes
    estimated_lines = stat.st_size // 200

    return {
        "path":             str(path.absolute()),
        "size_bytes":       stat.st_size,
        "size":             stat.st_size,
        "size_human":       size_human,
        "estimated_lines":  estimated_lines,
        "extension":        path.suffix.lower(),
        "sha256":           sha256_file(path),
    }

def stream_evtx_xml(path: Path) -> "Generator[Tuple[int, str], None, None]":
    """
    Public alias for _stream_evtx â€” used by engine.py.
    Yields (record_number, xml_string) for each EVTX event.
    Requires: pip install python-evtx
    """
    yield from _stream_evtx(path)
