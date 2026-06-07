"""
output/ioc_csv.py â€” NexLog Layer 4
Multi-format flat-file IOC export.

Goes beyond a simple CSV dump â€” produces six distinct export formats
that cover every major threat-intel consumption pattern in use today:

  Format          Target consumer            Tool/Platform
  â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€  â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€  â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
  csv             Generic spreadsheet/SIEM   Excel, Splunk, QRadar
  tsv             Log-pipeline friendly      Logstash, Elastic ingest
  jsonl           Streaming pipelines        Kafka, Python scripts
  zeek_intel      Zeek/Bro network sensor    Zeek Intel Framework
  misp_csv        MISP threat intel platform MISP bulk import
  blocklist       Firewall/proxy deny rules  iptables, pfSense, Squid

All formats are written to a directory (one file per format) or a single
file if a specific format is requested.

Usage:
    from output.ioc_csv import IOCExporter

    exporter = IOCExporter(iocs, case_ref="IR-2026-001", analyst="Jane")

    # Write all formats at once
    paths = exporter.write_all("./exports/")

    # Write one specific format
    exporter.write_csv("iocs.csv")
    exporter.write_zeek_intel("zeek_intel.txt")
    exporter.write_misp_csv("misp_import.csv")
    exporter.write_blocklist("blocklist_ips.txt", ioc_type="ipv4")

    # Get a format as string
    csv_text  = exporter.to_csv()
    zeek_text = exporter.to_zeek_intel()
"""

import csv
import json
import os
import sys
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

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
sys.path.insert(0, os.path.join(_ROOT, 'intelligence'))

# â”€â”€ Zeek Intel Framework type map â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# https://docs.zeek.org/en/master/frameworks/intel.html
_ZEEK_TYPE: dict[str, str] = {
    "ipv4":        "Intel::ADDR",
    "domain":      "Intel::DOMAIN",
    "url":         "Intel::URL",
    "hash_md5":    "Intel::FILE_HASH",
    "hash_sha1":   "Intel::FILE_HASH",
    "hash_sha256": "Intel::FILE_HASH",
    "file_path":   "Intel::FILE_NAME",
    "email":       "Intel::EMAIL",
    "user_agent":  "Intel::SOFTWARE",
    "hostname":    "Intel::DOMAIN",
    "process":     "Intel::SOFTWARE",
}

# â”€â”€ MISP CSV column order â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# https://www.circl.lu/doc/misp/MISP_Import_Export.pdf
_MISP_TYPE: dict[str, str] = {
    "ipv4":        "ip-src",
    "domain":      "domain",
    "url":         "url",
    "hash_md5":    "md5",
    "hash_sha1":   "sha1",
    "hash_sha256": "sha256",
    "file_path":   "filename",
    "email":       "email-src",
    "hostname":    "hostname",
    "user_agent":  "user-agent",
    "process":     "filename",
}

# IOC types that produce meaningful blocklist entries
_BLOCKLIST_TYPES = {"ipv4", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256"}


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe(val: str) -> str:
    """Strip characters unsafe in CSV/TSV values."""
    return val.replace("\n", " ").replace("\r", " ").replace("\t", " ")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# IOC EXPORTER
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class IOCExporter:
    """
    Multi-format IOC flat-file exporter.

    Args:
        iocs:       list[IOC] from IOCExtractor.extract()
        case_ref:   Case reference for metadata headers
        analyst:    Analyst name for attribution fields
        min_confidence: Filter IOCs below this confidence (0.0â€“1.0)
    """

    def __init__(
        self,
        iocs:            list,
        case_ref:        str   = "IR-UNKNOWN",
        analyst:         str   = "analyst",
        min_confidence:  float = 0.0,
    ):
        self._case_ref = case_ref
        self._analyst  = analyst
        self._ts       = _utcnow()
        self._iocs     = [
            i for i in iocs
            if i.confidence >= min_confidence
        ]

    # â”€â”€ Filter helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _by_type(self, ioc_type: str) -> list:
        return [i for i in self._iocs if i.ioc_type == ioc_type]

    def _of_types(self, *types) -> list:
        return [i for i in self._iocs if i.ioc_type in types]

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # FORMAT 1 â€” Standard CSV
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    def to_csv(self) -> str:
        """
        Full-detail CSV export. All IOC types, all fields.
        Compatible with Splunk, QRadar, Excel, Google Sheets.

        Columns: type, value, confidence, source_rule, source_ip,
                 timestamp, tags, case_ref, exported_at
        """
        buf    = StringIO()
        writer = csv.writer(buf, quoting=csv.QUOTE_ALL)

        # Header comment block
        buf.write("# NexLog IOC Export\n")
        buf.write(f"# Case: {self._case_ref}\n")
        buf.write(f"# Analyst: {self._analyst}\n")
        buf.write(f"# Generated: {self._ts}\n")
        buf.write(f"# Total IOCs: {len(self._iocs)}\n")

        writer.writerow([
            "type", "value", "confidence",
            "source_rule", "source_ip", "timestamp",
            "tags", "case_ref", "exported_at",
        ])

        for ioc in self._iocs:
            writer.writerow([
                ioc.ioc_type,
                _safe(ioc.value),
                f"{ioc.confidence:.3f}",
                ioc.source_rule,
                ioc.source_ip,
                ioc.timestamp,
                "|".join(ioc.tags),
                self._case_ref,
                self._ts,
            ])
        return buf.getvalue()

    def write_csv(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_csv(), encoding="utf-8")
        return path

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # FORMAT 2 â€” TSV (Tab-Separated Values)
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    def to_tsv(self) -> str:
        """
        Tab-separated export â€” ideal for Logstash, Elastic ingest pipelines,
        and shell tools (awk, cut, grep).
        No quoting â€” tabs are the delimiter, values are tab-stripped.
        """
        lines = [
            f"# NexLog IOC Export | Case: {self._case_ref} | "
            f"Generated: {self._ts}",
            "\t".join([
                "type", "value", "confidence",
                "source_rule", "source_ip", "timestamp", "tags",
            ]),
        ]
        for ioc in self._iocs:
            lines.append("\t".join([
                ioc.ioc_type,
                _safe(ioc.value),
                f"{ioc.confidence:.3f}",
                ioc.source_rule,
                ioc.source_ip or "",
                ioc.timestamp  or "",
                "|".join(ioc.tags),
            ]))
        return "\n".join(lines) + "\n"

    def write_tsv(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_tsv(), encoding="utf-8")
        return path

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # FORMAT 3 â€” JSON Lines (JSONL)
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    def to_jsonl(self) -> str:
        """
        One JSON object per line â€” natively consumed by Kafka, Python
        streaming scripts, Elastic bulk API, and jq.

        Each record includes all IOC fields plus case metadata.
        """
        lines = []
        for ioc in self._iocs:
            record = ioc.to_dict()
            record["case_ref"]    = self._case_ref
            record["exported_at"] = self._ts
            lines.append(json.dumps(record, ensure_ascii=False))
        return "\n".join(lines) + ("\n" if lines else "")

    def write_jsonl(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_jsonl(), encoding="utf-8")
        return path

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # FORMAT 4 â€” Zeek Intel Framework
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    def to_zeek_intel(self) -> str:
        """
        Zeek (formerly Bro) Intel Framework format.
        https://docs.zeek.org/en/master/frameworks/intel.html

        Columns (tab-separated, # header comments):
          indicator  indicator_type  meta.source  meta.desc
          meta.url   meta.do_notice  meta.if_in   meta.whitelist

        Only IOC types with a Zeek mapping are included.
        meta.do_notice = T causes Zeek to generate a notice log entry.
        """
        lines = [
            "# Zeek Intelligence Feed â€” NexLog",
            f"# Case: {self._case_ref}  Analyst: {self._analyst}",
            f"# Generated: {self._ts}",
            "#",
            "#fields\tindicator\tindicator_type\tmeta.source\t"
            "meta.desc\tmeta.url\tmeta.do_notice",
        ]

        for ioc in self._iocs:
            zeek_type = _ZEEK_TYPE.get(ioc.ioc_type)
            if not zeek_type:
                continue

            desc = (
                f"NexLog case {self._case_ref} | "
                f"rule:{ioc.source_rule} | "
                f"conf:{ioc.confidence:.0%}"
            )
            lines.append("\t".join([
                _safe(ioc.value),
                zeek_type,
                f"nexlog/{self._case_ref}",
                _safe(desc),
                "-",   # meta.url â€” no URL for offline cases
                "T",   # meta.do_notice â€” generate notice log
            ]))

        return "\n".join(lines) + "\n"

    def write_zeek_intel(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_zeek_intel(), encoding="utf-8")
        return path

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # FORMAT 5 â€” MISP CSV Import
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    def to_misp_csv(self) -> str:
        """
        MISP bulk import CSV format.
        https://www.circl.lu/doc/misp/MISP_Import_Export.pdf

        Columns: uuid, event_id, category, type, value,
                 comment, to_ids, distribution, timestamp

        event_id is left blank (filled by MISP on import).
        to_ids=1 means the attribute should be used for IDS matching.
        distribution=0 means your organisation only.
        category is inferred from IOC type.
        """
        import uuid as _uuid

        _CATEGORY: dict[str, str] = {
            "ipv4":        "Network activity",
            "domain":      "Network activity",
            "url":         "Network activity",
            "hash_md5":    "Payload delivery",
            "hash_sha1":   "Payload delivery",
            "hash_sha256": "Payload delivery",
            "file_path":   "Artifacts dropped",
            "email":       "Social network",
            "hostname":    "Network activity",
            "user_agent":  "Network activity",
            "process":     "Artifacts dropped",
        }

        buf    = StringIO()
        writer = csv.writer(buf, quoting=csv.QUOTE_ALL)
        writer.writerow([
            "uuid", "event_id", "category", "type",
            "value", "comment", "to_ids", "distribution", "timestamp",
        ])

        for ioc in self._iocs:
            misp_type = _MISP_TYPE.get(ioc.ioc_type)
            if not misp_type:
                continue

            comment = (
                f"NexLog | Case:{self._case_ref} | "
                f"Rule:{ioc.source_rule} | Conf:{ioc.confidence:.0%}"
            )
            writer.writerow([
                str(_uuid.uuid4()),    # uuid
                "",                    # event_id (MISP fills this)
                _CATEGORY.get(ioc.ioc_type, "External analysis"),
                misp_type,
                _safe(ioc.value),
                comment,
                "1",                   # to_ids
                "0",                   # distribution: your org only
                ioc.timestamp or self._ts,
            ])
        return buf.getvalue()

    def write_misp_csv(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_misp_csv(), encoding="utf-8")
        return path

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # FORMAT 6 â€” Plain Blocklist
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    def to_blocklist(
        self,
        ioc_type:      str   = "ipv4",
        min_confidence: float = 0.75,
        comment_char:  str   = "#",
    ) -> str:
        """
        Plain text blocklist â€” one value per line with comment header.
        Ready for direct use in:
          - iptables (ipv4 blocklist)
          - pfSense / OPNsense aliases
          - Squid proxy (domain/url blocklist)
          - BIND RPZ (domain blocklist)
          - Suricata/Snort IP reputation lists

        Args:
            ioc_type:       Which IOC type to export ("ipv4","domain","url",
                            "hash_sha256" etc.)
            min_confidence: Only include IOCs at or above this threshold.
            comment_char:   Comment prefix character (# for most tools).
        """
        filtered = [
            i for i in self._iocs
            if i.ioc_type == ioc_type
            and i.confidence >= min_confidence
        ]
        filtered.sort(key=lambda i: -i.confidence)

        lines = [
            f"{comment_char} NexLog Blocklist",
            f"{comment_char} Case: {self._case_ref}",
            f"{comment_char} Type: {ioc_type}",
            f"{comment_char} Min confidence: {min_confidence:.0%}",
            f"{comment_char} Count: {len(filtered)}",
            f"{comment_char} Generated: {self._ts}",
            f"{comment_char} Analyst: {self._analyst}",
            "",
        ]
        for ioc in filtered:
            rule  = ioc.source_rule
            conf  = f"{ioc.confidence:.0%}"
            lines.append(
                f"{ioc.value}"
                f"  {comment_char} {rule} conf={conf}"
            )
        return "\n".join(lines) + "\n"

    def write_blocklist(
        self,
        path:           str | Path,
        ioc_type:       str   = "ipv4",
        min_confidence: float = 0.75,
    ) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            self.to_blocklist(ioc_type, min_confidence),
            encoding="utf-8",
        )
        return path

    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
    # WRITE ALL
    # â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

    def write_all(self, output_dir: str | Path) -> dict[str, Path]:
        """
        Write every format to output_dir in one call.

        Returns a dict mapping format name â†’ written file path.
        Also writes per-type IP, domain, and hash blocklists.

        Directory layout produced:
            output_dir/
              iocs.csv
              iocs.tsv
              iocs.jsonl
              iocs_zeek_intel.txt
              iocs_misp.csv
              blocklist_ipv4.txt
              blocklist_domain.txt
              blocklist_sha256.txt
        """
        out  = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        stem = self._case_ref.lower().replace(" ", "_").replace("/", "-")

        written: dict[str, Path] = {}

        written["csv"]        = self.write_csv       (out / f"{stem}_iocs.csv")
        written["tsv"]        = self.write_tsv       (out / f"{stem}_iocs.tsv")
        written["jsonl"]      = self.write_jsonl     (out / f"{stem}_iocs.jsonl")
        written["zeek_intel"] = self.write_zeek_intel(out / f"{stem}_zeek_intel.txt")
        written["misp_csv"]   = self.write_misp_csv  (out / f"{stem}_misp.csv")

        # Per-type blocklists (only written if that type has IOCs)
        for ioc_type, filename in [
            ("ipv4",        f"{stem}_blocklist_ips.txt"),
            ("domain",      f"{stem}_blocklist_domains.txt"),
            ("hash_sha256", f"{stem}_blocklist_hashes_sha256.txt"),
            ("hash_md5",    f"{stem}_blocklist_hashes_md5.txt"),
            ("url",         f"{stem}_blocklist_urls.txt"),
        ]:
            count = sum(1 for i in self._iocs if i.ioc_type == ioc_type)
            if count > 0:
                written[f"blocklist_{ioc_type}"] = self.write_blocklist(
                    out / filename, ioc_type=ioc_type
                )

        return written

    # â”€â”€ Statistics â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def summary(self) -> dict:
        """Return counts by IOC type."""
        from collections import Counter
        by_type  = Counter(i.ioc_type   for i in self._iocs)
        by_rule  = Counter(i.source_rule for i in self._iocs)
        avg_conf = (sum(i.confidence for i in self._iocs) /
                    max(len(self._iocs), 1))
        return {
            "total":          len(self._iocs),
            "by_type":        dict(by_type),
            "top_rules":      dict(by_rule.most_common(5)),
            "avg_confidence": round(avg_conf, 3),
            "case_ref":       self._case_ref,
            "exported_at":    self._ts,
        }

    def __repr__(self) -> str:
        return (f"<IOCExporter iocs={len(self._iocs)} "
                f"case={self._case_ref}>")
