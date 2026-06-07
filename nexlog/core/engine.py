"""
engine.py â€” NexLog Layer 1
Single entry point for log parsing. Handles all 50+ formats.

Routing logic:
  - Binary EVTX     â†’ EVTX XML streamer (python-evtx)
  - JSONL/JSON array â†’ JSON array streamer
  - Zeek TSV        â†’ line streamer (stateful field-header parser)
  - CloudTrail JSON â†’ JSON array (Records[])
  - VPC Flow        â†’ line streamer (header-aware)
  - All others      â†’ line streamer â†’ per-line format detection if UNKNOWN

AI fallback:
  When format cannot be detected, AIParser is invoked.
  AIParser uses the LLM to extract fields from unknown log lines.
  Fields are mapped onto the standard LogEntry model so all downstream
  detection rules still apply.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Callable, Generator, Optional

from detector import detect_format, detect_format_from_line
from models import LogEntry, LogFormat
from parsers import get_parser, AIParser
from reader import get_file_stats, quick_file_meta, stream_line_offsets, stream_lines, stream_json_array


# â”€â”€ Formats that use JSON array (not JSONL) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_JSON_ARRAY_FORMATS = {
    LogFormat.AWS_CLOUDTRAIL,
    LogFormat.AZURE_ACTIVITY,
    LogFormat.AZURE_SIGNIN,
    LogFormat.AZURE_NSG_FLOW,
    LogFormat.GCP_AUDIT,
    LogFormat.GCP_VPC_FLOW,
}

# â”€â”€ Formats that use TSV with #fields headers (Zeek) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_ZEEK_TSV_FORMATS = {
    LogFormat.ZEEK_CONN,
    LogFormat.ZEEK_DNS,
    LogFormat.ZEEK_HTTP,
    LogFormat.ZEEK_SSL,
    LogFormat.ZEEK_FILES,
}

# â”€â”€ Year rollover formats (no year in timestamp) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_YEARLESS_FORMATS = {
    LogFormat.SYSLOG, LogFormat.AUTH_LOG, LogFormat.KERN_LOG,
    LogFormat.DMESG, LogFormat.POSTFIX, LogFormat.BIND_QUERY,
    LogFormat.CISCO_ASA, LogFormat.CISCO_IOS, LogFormat.PFSENSE,
}


class ParseStats:
    """Accumulated statistics from a parse run."""

    def __init__(self):
        self.total_lines:   int = 0
        self.parsed_ok:     int = 0
        self.parse_errors:  int = 0
        self.ai_parsed:     int = 0
        self.first_ts:      Optional[datetime] = None
        self.last_ts:       Optional[datetime] = None
        self.unique_ips:    set  = set()
        self.format_counts: dict = {}

    def update(self, entry: LogEntry) -> None:
        self.total_lines += 1
        if entry.source_ip:
            self.unique_ips.add(entry.source_ip)
        fmt_name = entry.log_format.value
        self.format_counts[fmt_name] = self.format_counts.get(fmt_name, 0) + 1
        if entry.log_format == LogFormat.AI_PARSED:
            self.ai_parsed += 1
        if entry.timestamp:
            self.parsed_ok += 1
            if self.first_ts is None or entry.timestamp < self.first_ts:
                self.first_ts = entry.timestamp
            if self.last_ts is None or entry.timestamp > self.last_ts:
                self.last_ts = entry.timestamp
        else:
            self.parse_errors += 1

    def summary(self) -> dict:
        span = str(self.last_ts - self.first_ts) if self.first_ts and self.last_ts else None
        return {
            "total_lines":   self.total_lines,
            "parsed_ok":     self.parsed_ok,
            "parse_errors":  self.parse_errors,
            "ai_parsed":     self.ai_parsed,
            "unique_ips":    len(self.unique_ips),
            "time_span":     span,
            "first_event":   self.first_ts.isoformat() if self.first_ts else None,
            "last_event":    self.last_ts.isoformat()  if self.last_ts  else None,
            "format_counts": self.format_counts,
        }


class Engine:
    """
    Layer 1 engine. Parses any log file into a stream of LogEntry.

    Usage:
        eng = Engine()
        for entry in eng.parse("access.log"):
            print(entry)

        # After exhaustion:
        print(eng.stats.summary())
        print(eng.file_meta)       # sha256, size, etc.
    """

    def __init__(self):
        self.stats:     Optional[ParseStats] = None
        self.file_meta: Optional[dict]       = None

    def parse(
        self,
        path: str | Path,
        force_format:   Optional[LogFormat]           = None,
        on_progress:    Optional[Callable[[int], None]] = None,
        progress_every: int = 10_000,
        fast_meta:      bool = False,
        max_line_bytes: Optional[int] = None,
        start_byte_offset: int = 0,
        start_line_number: int = 1,
    ) -> Generator[LogEntry, None, None]:
        """
        Main entry point. Yields LogEntry objects.

        Args:
            path:           Any supported log file path.
            force_format:   Skip detection, use this format.
            on_progress:    Callback called every progress_every lines.
            progress_every: Lines between progress callbacks.

        After exhausting the generator:
            self.stats     â€” ParseStats with counts and timing
            self.file_meta â€” dict with sha256, size, path, format
        """
        path = Path(path)
        self.stats = ParseStats()

        # â”€â”€ Chain of custody hash â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        self.file_meta = quick_file_meta(path) if fast_meta else get_file_stats(path)

        # â”€â”€ Format detection â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        fmt    = force_format or detect_format(path)
        parser = get_parser(fmt)

        self.file_meta["detected_format"] = fmt.value

        # â”€â”€ Route to correct reader â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

        # Binary EVTX
        if fmt == LogFormat.WINDOWS_EVTX:
            yield from self._parse_evtx(path, parser)
            return

        # JSON array formats (CloudTrail Records[], Azure, GCP)
        if fmt in _JSON_ARRAY_FORMATS:
            yield from self._parse_json_array(path, parser, fmt)
            return

        # Single JSON file (not JSONL) â€” wrap entire file
        if fmt == LogFormat.JSON_GENERIC and path.suffix.lower() == ".json":
            yield from self._parse_json_array(path, parser, fmt)
            return

        # Line-by-line (all other formats)
        year_tracker = _YearTracker()

        if start_byte_offset and path.suffix.lower() not in {".gz", ".evtx"}:
            line_iter = stream_line_offsets(path, start_byte_offset, start_line_number)
        else:
            line_iter = ((line_no, raw_line, 0) for line_no, raw_line in stream_lines(path))

        for line_no, raw_line, next_offset in line_iter:
            if not raw_line.strip():
                continue
            if max_line_bytes and len(raw_line.encode("utf-8", errors="ignore")) > max_line_bytes:
                self.stats.total_lines += 1
                self.stats.parse_errors += 1
                continue

            actual_fmt = fmt
            if fmt in (LogFormat.UNKNOWN, LogFormat.AI_PARSED):
                actual_fmt = detect_format_from_line(raw_line)
                parser     = get_parser(actual_fmt)

            entry            = parser.parse_line(raw_line, line_no, str(path))
            entry.log_format = actual_fmt

            if entry.timestamp and actual_fmt in _YEARLESS_FORMATS:
                entry.timestamp = year_tracker.fix(entry.timestamp)

            self.stats.update(entry)
            if next_offset:
                self.file_meta["byte_offset"] = next_offset
                self.file_meta["line_number"] = line_no

            if on_progress and self.stats.total_lines % progress_every == 0:
                on_progress(self.stats.total_lines)

            yield entry

    # â”€â”€ Specialised readers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def parse_batches(
        self,
        path: str | Path,
        batch_size: int = 5000,
        force_format: Optional[LogFormat] = None,
        on_progress: Optional[Callable[[dict], None]] = None,
        fast_meta: bool = False,
        max_line_bytes: Optional[int] = None,
        start_byte_offset: int = 0,
        start_line_number: int = 1,
    ) -> Generator[list[LogEntry], None, None]:
        """Yield parsed entries in bounded batches for large-file pipelines."""
        batch_size = max(1, int(batch_size or 5000))
        batch: list[LogEntry] = []

        def _progress(lines: int) -> None:
            if on_progress:
                meta = self.file_meta or {}
                on_progress({
                    "phase": "parsing",
                    "lines": lines,
                    "byte_offset": int(meta.get("byte_offset") or 0),
                    "line_number": int(meta.get("line_number") or lines),
                })

        for entry in self.parse(
            path,
            force_format=force_format,
            on_progress=_progress,
            progress_every=batch_size,
            fast_meta=fast_meta,
            max_line_bytes=max_line_bytes,
            start_byte_offset=start_byte_offset,
            start_line_number=start_line_number,
        ):
            batch.append(entry)
            if len(batch) >= batch_size:
                yield batch
                batch = []
        if batch:
            yield batch

    def _parse_evtx(self, path: Path, parser) -> Generator[LogEntry, None, None]:
        """Stream Windows EVTX binary file via python-evtx."""
        try:
            from reader import stream_evtx_xml
            for line_no, xml_str in stream_evtx_xml(path):
                entry = parser.parse_line(xml_str, line_no, str(path))
                entry.log_format = LogFormat.WINDOWS_EVTX
                self.stats.update(entry)
                yield entry
        except ImportError:
            # python-evtx not installed â€” try reading as XML text
            yield from self._parse_line_stream(path, parser, LogFormat.WINDOWS_EVTX)
        except Exception as e:
            # Emit an error entry and continue
            err_entry = LogEntry(
                raw_line=f"[EVTX-ERROR] {e}", line_number=0,
                source_file=str(path), log_format=LogFormat.WINDOWS_EVTX,
                message=str(e), severity="ERROR",
            )
            self.stats.update(err_entry)
            yield err_entry

    def _parse_json_array(
        self, path: Path, parser, fmt: LogFormat
    ) -> Generator[LogEntry, None, None]:
        """Handle JSON files where records are in an array using streaming parser."""
        try:
            # Try streaming JSON first (ijson) for large files
            try:
                import ijson
                yield from self._parse_json_streaming(path, parser, fmt)
                return
            except ImportError:
                # Fallback to standard JSON for small files (<10MB)
                if path.stat().st_size < 10 * 1024 * 1024:
                    yield from self._parse_json_standard(path, parser, fmt)
                else:
                    # Large file but no ijson - warn and use line stream fallback
                    import warnings
                    warnings.warn(
                        f"Large JSON file {path.name} ({path.stat().st_size/1024/1024:.1f}MB) "
                        "without ijson installed. Install with: pip install ijson",
                        RuntimeWarning,
                        stacklevel=2
                    )
                    yield from self._parse_line_stream(path, parser, fmt)

        except (IOError, OSError) as e:
            err = LogEntry(
                raw_line=f"[IO-ERROR] {e}", line_number=0,
                source_file=str(path), log_format=fmt,
                message=str(e), severity="ERROR",
            )
            self.stats.update(err)
            yield err

    def _parse_json_streaming(
        self, path: Path, parser, fmt: LogFormat
    ) -> Generator[LogEntry, None, None]:
        """Stream JSON using ijson to handle large files without memory exhaustion."""
        import ijson

        with open(path, "rb") as f:
            # Try to detect wrapper structure by peeking at first few bytes
            f.seek(0)
            first_bytes = f.read(100)
            f.seek(0)

            # CloudTrail and similar wrappers
            if b'"Records"' in first_bytes or b'"records"' in first_bytes:
                # Parse array items inside wrapper object
                for idx, item in enumerate(ijson.items(f, 'Records.item'), 1):
                    if isinstance(item, dict):
                        raw_line = json.dumps(item)
                        entry = parser.parse_line(raw_line, idx, str(path))
                        entry.log_format = fmt
                        self.stats.update(entry)
                        yield entry
            elif b'"events"' in first_bytes or b'"Events"' in first_bytes:
                for idx, item in enumerate(ijson.items(f, 'events.item'), 1):
                    if isinstance(item, dict):
                        raw_line = json.dumps(item)
                        entry = parser.parse_line(raw_line, idx, str(path))
                        entry.log_format = fmt
                        self.stats.update(entry)
                        yield entry
            else:
                # Direct array or single object
                try:
                    for idx, item in enumerate(ijson.items(f, 'item'), 1):
                        if isinstance(item, dict):
                            raw_line = json.dumps(item)
                            entry = parser.parse_line(raw_line, idx, str(path))
                            entry.log_format = fmt
                            self.stats.update(entry)
                            yield entry
                except ijson.JSONError:
                    # Not an array, try as single object
                    f.seek(0)
                    data = json.load(f)
                    entry = parser.parse_line(json.dumps(data), 1, str(path))
                    entry.log_format = fmt
                    self.stats.update(entry)
                    yield entry

    def _parse_json_standard(
        self, path: Path, parser, fmt: LogFormat
    ) -> Generator[LogEntry, None, None]:
        """Standard JSON parsing for small files (fallback)."""
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()

        # CloudTrail wraps records in {"Records": [...]}
        data = json.loads(raw)
        if isinstance(data, dict):
            # Try common wrapper keys
            for key in ("Records", "records", "events", "Events",
                        "value", "items", "logs", "Logs"):
                if key in data and isinstance(data[key], list):
                    data = data[key]
                    break
            else:
                # Single object â€” wrap in list
                data = [data]

        if isinstance(data, list):
            for idx, record in enumerate(data, 1):
                raw_line = json.dumps(record)
                entry = parser.parse_line(raw_line, idx, str(path))
                entry.log_format = fmt
                self.stats.update(entry)
                yield entry
        else:
            # Fallback: treat as JSONL
            yield from self._parse_line_stream(path, parser, fmt)

    def _parse_line_stream(
        self, path: Path, parser, fmt: LogFormat
    ) -> Generator[LogEntry, None, None]:
        """Generic line-by-line stream fallback."""
        for line_no, raw_line in stream_lines(path):
            if not raw_line.strip():
                continue
            entry = parser.parse_line(raw_line, line_no, str(path))
            entry.log_format = fmt
            self.stats.update(entry)
            yield entry


class _YearTracker:
    """
    Handles the missing-year problem in syslog and similar formats.
    Detects December â†’ January year rollovers.
    """
    def __init__(self):
        self._last: Optional[datetime] = None

    def fix(self, dt: datetime) -> datetime:
        if self._last is None:
            self._last = dt
            return dt
        if self._last.month == 12 and dt.month == 1:
            dt = dt.replace(year=dt.year + 1)
        self._last = dt
        return dt
