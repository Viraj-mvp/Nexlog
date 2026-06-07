"""
intelligence/ioc_extractor.py â€” NexLog Layer 3
Extracts structured IOCs from Finding objects produced by updated Layer 2.

Fixes vs draft version:
  - hostname extracted as IOC indicator (new Finding field)
  - process_name scanned for suspicious paths / tool names
  - event_id included in tags for Windows-origin IOCs
  - supporting_lines now scanned (was only trigger_line before)
  - Self-locating sys.path

IOC types:
  ipv4        â€” source/dest IPs from Finding fields + regex from text
  domain      â€” FQDNs from URIs, messages, supporting lines
  url         â€” full HTTP/S URLs
  hash_md5    â€” 32-char hex
  hash_sha1   â€” 40-char hex
  hash_sha256 â€” 64-char hex
  file_path   â€” Windows and Linux absolute paths
  email       â€” email addresses
  hostname    â€” server/workstation hostnames from Finding.hostname
  user_agent  â€” fingerprinted attack tool UA strings
  process     â€” suspicious process names from Finding.process_name
"""

import csv
import ipaddress
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from io import StringIO

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
sys.path.insert(0, os.path.join(_ROOT, 'detection'))

from finding import Finding   # noqa: E402

# â”€â”€ Compiled patterns â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

_RE_IPV4 = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
_RE_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+(?:com|net|org|io|gov|edu|mil|co|uk|de|fr|ru|cn|info|biz|'
    r'xyz|onion|bit|tk|ml|ga|cf|pw|top|club|site|online|live|tech)'
    r'\b',
    re.IGNORECASE
)
_RE_URL    = re.compile(r'https?://[^\s\'"<>]{4,200}', re.IGNORECASE)
_RE_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
_RE_SHA1   = re.compile(r'\b[a-fA-F0-9]{40}\b')
_RE_MD5    = re.compile(r'\b[a-fA-F0-9]{32}\b')
_RE_WINPATH = re.compile(
    r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*',
    re.IGNORECASE
)
_RE_LINUXPATH = re.compile(
    r'(?<!\w)/(?:etc|var|tmp|home|usr|bin|sbin|proc|dev)'
    r'(?:/[^\s\'"<>|;,]{1,100})+'
)
_RE_EMAIL = re.compile(
    r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'
)

# Known attack tool UA substrings
_ATTACK_UA = re.compile(
    r'(?i)(sqlmap|nikto|nessus|masscan|nmap|zgrab|nuclei|'
    r'dirbuster|gobuster|feroxbuster|ffuf|hydra|medusa|'
    r'burpsuite|metasploit|acunetix|w3af|arachni|appscan)',
    re.IGNORECASE
)

# Suspicious process names worth extracting as IOC
_SUSPICIOUS_PROCS = re.compile(
    r'(?i)(mimikatz|meterpreter|cobalt.*strike|beacon|'
    r'powersploit|empire|sliver|havoc|metasploit|'
    r'nc\.exe|ncat\.exe|netcat|xmrig|'
    r'psexec|wmiexec|dcomexec|atexec|smbexec)',
    re.IGNORECASE
)


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True


def _utcnow_str() -> str:
    """Return current UTC timestamp in STIX-compliant format (no microseconds)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# STIX indicator_types vocabulary per IOC type
_INDICATOR_TYPES: dict[str, list[str]] = {
    "ipv4":        ["malicious-activity"],
    "domain":      ["malicious-activity", "compromised"],
    "url":         ["malicious-activity"],
    "hash_md5":    ["malicious-activity"],
    "hash_sha1":   ["malicious-activity"],
    "hash_sha256": ["malicious-activity"],
    "file_path":   ["malicious-activity"],
    "email":       ["attribution"],
    "hostname":    ["compromised"],
    "process":     ["malicious-activity"],
    "user_agent":  ["malicious-activity", "attribution"],
}


class IOC:
    """A single extracted Indicator of Compromise."""
    __slots__ = ("ioc_type", "value", "confidence",
                 "source_rule", "source_ip", "timestamp", "tags")

    def __init__(self, ioc_type: str, value: str,
                 confidence:  float     = 0.7,
                 source_rule: str       = "",
                 source_ip:   str       = "",
                 timestamp:   str       = "",
                 tags:        list[str] = None):
        self.ioc_type    = ioc_type
        self.value       = value.strip()
        self.confidence  = round(confidence, 3)
        self.source_rule = source_rule
        self.source_ip   = source_ip
        self.timestamp   = timestamp
        self.tags        = tags or []

    def to_dict(self) -> dict:
        return {
            "type":        self.ioc_type,
            "value":       self.value,
            "confidence":  self.confidence,
            "source_rule": self.source_rule,
            "source_ip":   self.source_ip,
            "timestamp":   self.timestamp,
            "tags":        self.tags,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "IOC":
        """Deserialise an IOC from a dict produced by to_dict()."""
        return cls(
            ioc_type    = d.get("type", d.get("ioc_type", "")),
            value       = d.get("value", ""),
            confidence  = float(d.get("confidence", 0.7)),
            source_rule = d.get("source_rule", ""),
            source_ip   = d.get("source_ip", ""),
            timestamp   = d.get("timestamp", ""),
            tags        = list(d.get("tags", [])),
        )

    def to_stix_indicator(
        self,
        created_by_ref: str = "",
        tlp_id:         str = "",
    ) -> dict:
        """
        Produce a single STIX 2.1 indicator object for this IOC.
        Useful for incremental STIX export without building a full bundle.

        STIX patterns per IOC type:
          ipv4       â†’ [ipv4-addr:value = '<v>']
          domain     â†’ [domain-name:value = '<v>']
          url        â†’ [url:value = '<v>']
          hash_md5   â†’ [file:hashes.MD5 = '<v>']
          hash_sha1  â†’ [file:hashes.'SHA-1' = '<v>']
          hash_sha256â†’ [file:hashes.'SHA-256' = '<v>']
          file_path  â†’ [file:name = '<v>']
          email      â†’ [email-addr:value = '<v>']
          hostname   â†’ [domain-name:value = '<v>']
          process    â†’ [process:name = '<v>']
          user_agent â†’ [network-traffic:extensions.'http-request-ext'
                          .request_header.'User-Agent' = '<v>']

        Returns a dict â€” a complete STIX 2.1 indicator object ready to
        be placed in a bundle["objects"] list.
        Returns None if this IOC type has no STIX pattern mapping.
        """
        _PATTERNS = {
            "ipv4":       "[ipv4-addr:value = '{v}']",
            "domain":     "[domain-name:value = '{v}']",
            "url":        "[url:value = '{v}']",
            "hash_md5":   "[file:hashes.MD5 = '{v}']",
            "hash_sha1":  "[file:hashes.'SHA-1' = '{v}']",
            "hash_sha256":"[file:hashes.'SHA-256' = '{v}']",
            "file_path":  "[file:name = '{v}']",
            "email":      "[email-addr:value = '{v}']",
            "hostname":   "[domain-name:value = '{v}']",
            "process":    "[process:name = '{v}']",
            "user_agent": ("[network-traffic:extensions.'http-request-ext'"
                           ".request_header.'User-Agent' = '{v}']"),
        }
        tmpl = _PATTERNS.get(self.ioc_type)
        if not tmpl:
            return None
        try:
            pattern = tmpl.format(v=self.value.replace("'", "\\'"))
        except Exception:
            return None

        obj: dict = {
            "type":            "indicator",
            "spec_version":    "2.1",
            "id":              f"indicator--{uuid.uuid4()}",
            "created":         self.timestamp or _utcnow_str(),
            "modified":        self.timestamp or _utcnow_str(),
            "name":            f"{self.ioc_type}: {self.value[:80]}",
            "description":     (f"NexLog extraction. "
                                f"Rule: {self.source_rule}. "
                                f"Confidence: {self.confidence:.0%}."),
            "indicator_types": _INDICATOR_TYPES.get(self.ioc_type,
                                                    ["malicious-activity"]),
            "pattern":         pattern,
            "pattern_type":    "stix",
            "valid_from":      self.timestamp or _utcnow_str(),
            "confidence":      int(self.confidence * 100),
            "labels":          list({self.ioc_type} | set(self.tags)),
        }
        if created_by_ref:
            obj["created_by_ref"] = created_by_ref
        if tlp_id:
            obj["object_marking_refs"] = [tlp_id]
        return obj

    def __repr__(self) -> str:
        return f"<IOC [{self.ioc_type}] {self.value[:60]}>"


class IOCExtractor:
    """
    Extracts IOCs from Finding objects produced by Layer 2.
    Uses all fields added in the Layer 2 v2 update:
      hostname, process_name, event_id, supporting_lines.
    """

    def __init__(self, include_private_ips: bool = False):
        self.include_private_ips = include_private_ips

    # â”€â”€ Main entry point â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def extract(self, findings: list[Finding]) -> list[IOC]:
        """
        Extract and deduplicate IOCs from a list of findings.
        Deduplication key: (type, value.lower()) â€” highest confidence wins.
        """
        seen: dict[tuple, IOC] = {}
        for f in findings:
            ts  = f.timestamp.isoformat() if f.timestamp else ""
            sip = f.source_ip or ""
            for ioc in self._from_finding(f, ts, sip):
                key = (ioc.ioc_type, ioc.value.lower())
                if key not in seen or ioc.confidence > seen[key].confidence:
                    seen[key] = ioc
        return sorted(seen.values(),
                      key=lambda i: (-i.confidence, i.ioc_type, i.value))

    # â”€â”€ Per-finding extraction â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _from_finding(self, f: Finding, ts: str, sip: str) -> list[IOC]:
        iocs: list[IOC] = []
        conf = f.confidence
        rid  = f.rule_id

        # Base tags: category + MITRE technique IDs + event_id if present
        tags: list[str] = [f.category] + [t.full_id for t in f.mitre_tags]
        if f.event_id:
            tags.append(f"EventID:{f.event_id}")

        # â”€â”€ Network IPs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        for ip in filter(None, [f.source_ip, f.dest_ip]):
            if self.include_private_ips or not _is_private(ip):
                c = conf if ip == f.source_ip else conf * 0.9
                iocs.append(IOC("ipv4", ip, c, rid, sip, ts, tags))

        # â”€â”€ Hostname (new Layer 2 field) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if f.hostname and not self._looks_like_ip(f.hostname):
            iocs.append(IOC("hostname", f.hostname,
                            conf * 0.85, rid, sip, ts, tags))

        # â”€â”€ Process name (new Layer 2 field) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if f.process_name and _SUSPICIOUS_PROCS.search(f.process_name):
            iocs.append(IOC("process", f.process_name,
                            min(conf + 0.05, 1.0), rid, sip, ts, tags))

        # â”€â”€ HTTP User-Agent â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        ind = f.indicators
        ua  = ind.get("http_user_agent") or ""
        if ua and _ATTACK_UA.search(ua):
            iocs.append(IOC("user_agent", ua,
                            min(conf + 0.1, 1.0), rid, sip, ts, tags))

        # â”€â”€ URI â†’ URLs and domains â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        uri = ind.get("http_uri_decoded") or ""
        for m in _RE_URL.finditer(uri):
            iocs.append(IOC("url", m.group(0)[:500], conf, rid, sip, ts, tags))
        for m in _RE_DOMAIN.finditer(uri):
            d = m.group(0).lower()
            if len(d) > 4:
                iocs.append(IOC("domain", d, conf * 0.8, rid, sip, ts, tags))

        # â”€â”€ Full text scan: trigger_line + supporting_lines + matched_text â”€
        # supporting_lines is now populated from Layer 2 (was missing before)
        text_blob = " ".join(filter(None, [
            f.trigger_line,
            ind.get("matched_text", ""),
            ind.get("message", ""),
            " ".join(f.supporting_lines),   # all lines, not just last 3
        ]))
        iocs.extend(self._scan_text(text_blob, conf, rid, sip, ts, tags))

        return iocs

    def _scan_text(self, text: str, conf: float,
                   rule_id: str, source_ip: str,
                   ts: str, tags: list[str]) -> list[IOC]:
        iocs: list[IOC] = []

        # Hashes â€” longest first to avoid partial matches
        sha256s = set()
        for m in _RE_SHA256.finditer(text):
            h = m.group(0).lower()
            sha256s.add(h)
            iocs.append(IOC("hash_sha256", h, conf, rule_id, source_ip, ts, tags))

        for m in _RE_SHA1.finditer(text):
            h = m.group(0).lower()
            if not any(s.startswith(h) for s in sha256s):
                iocs.append(IOC("hash_sha1", h, conf, rule_id, source_ip, ts, tags))

        all_hashes = sha256s | {m.group(0).lower() for m in _RE_SHA1.finditer(text)}
        for m in _RE_MD5.finditer(text):
            h = m.group(0).lower()
            if not any(s.startswith(h) for s in all_hashes):
                iocs.append(IOC("hash_md5", h,
                                conf * 0.8, rule_id, source_ip, ts, tags))

        # File paths
        for m in _RE_WINPATH.finditer(text):
            iocs.append(IOC("file_path", m.group(0),
                            conf * 0.7, rule_id, source_ip, ts, tags))
        for m in _RE_LINUXPATH.finditer(text):
            iocs.append(IOC("file_path", m.group(0),
                            conf * 0.7, rule_id, source_ip, ts, tags))

        # Email addresses
        for m in _RE_EMAIL.finditer(text):
            iocs.append(IOC("email", m.group(0).lower(),
                            conf * 0.8, rule_id, source_ip, ts, tags))

        # IPs found in text (lower confidence than finding.source_ip)
        for m in _RE_IPV4.finditer(text):
            ip = m.group(0)
            if self.include_private_ips or not _is_private(ip):
                iocs.append(IOC("ipv4", ip,
                                conf * 0.75, rule_id, source_ip, ts, tags))

        # Domains found in text
        for m in _RE_DOMAIN.finditer(text):
            d = m.group(0).lower()
            if len(d) > 4:
                iocs.append(IOC("domain", d,
                                conf * 0.7, rule_id, source_ip, ts, tags))

        return iocs

    @staticmethod
    def _looks_like_ip(s: str) -> bool:
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    # â”€â”€ Exports â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def to_csv(self, iocs: list[IOC]) -> str:
        """Return IOCs as CSV string."""
        buf    = StringIO()
        writer = csv.DictWriter(buf, fieldnames=[
            "type", "value", "confidence",
            "source_rule", "source_ip", "timestamp", "tags"
        ])
        writer.writeheader()
        for ioc in iocs:
            d         = ioc.to_dict()
            d["tags"] = "|".join(d["tags"])
            writer.writerow(d)
        return buf.getvalue()

    def to_stix_bundle(
        self,
        iocs:      list[IOC],
        case_name: str = "NexLog Investigation",
        analyst:   str = "nexlog",
    ) -> str:
        """
        STIX 2.1 bundle as JSON string. Stdlib only â€” no stix2 package.
        Includes: identity object + one indicator per IOC.
        """
        now     = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        tool_id = f"identity--{uuid.uuid4()}"

        _PATTERNS = {
            "ipv4":        lambda v: f"[ipv4-addr:value = '{v}']",
            "domain":      lambda v: f"[domain-name:value = '{v}']",
            "url":         lambda v: f"[url:value = '{v}']",
            "hash_md5":    lambda v: f"[file:hashes.MD5 = '{v}']",
            "hash_sha1":   lambda v: f"[file:hashes.'SHA-1' = '{v}']",
            "hash_sha256": lambda v: f"[file:hashes.'SHA-256' = '{v}']",
            "file_path":   lambda v: f"[file:name = '{v}']",
            "email":       lambda v: f"[email-addr:value = '{v}']",
            "hostname":    lambda v: f"[domain-name:value = '{v}']",
            "process":     lambda v: f"[process:name = '{v}']",
            "user_agent":  lambda v: (
                f"[network-traffic:extensions.'http-request-ext'"
                f".request_header.'User-Agent' = '{v}']"
            ),
        }

        objects = [{
            "type": "identity", "spec_version": "2.1", "id": tool_id,
            "created": now, "modified": now, "name": "NexLog",
            "identity_class": "system",
            "description": f"Case: {case_name} | Analyst: {analyst}",
        }]

        for ioc in iocs:
            pattern_fn = _PATTERNS.get(ioc.ioc_type)
            if not pattern_fn:
                continue
            try:
                pattern = pattern_fn(ioc.value.replace("'", "\\'"))
            except Exception:
                continue

            objects.append({
                "type": "indicator", "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created":    ioc.timestamp or now,
                "modified":   ioc.timestamp or now,
                "name":       f"{ioc.ioc_type}: {ioc.value[:60]}",
                "description": f"Rule: {ioc.source_rule} | "
                               f"Confidence: {ioc.confidence:.0%}",
                "pattern":       pattern,
                "pattern_type":  "stix",
                "valid_from":    ioc.timestamp or now,
                "confidence":    int(ioc.confidence * 100),
                "labels":        list({ioc.ioc_type} | set(ioc.tags)),
            })

        return json.dumps({
            "type": "bundle",
            "id":   f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": objects,
        }, indent=2)

    # â”€â”€ Filter â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    @staticmethod
    def filter(
        iocs:           list[IOC],
        ioc_types:      list[str]    = None,
        min_confidence: float        = 0.0,
        source_rule:    str          = "",
        has_tag:        str          = "",
        exclude_private_ips: bool    = False,
    ) -> list[IOC]:
        """
        Filter a list of IOCs by multiple optional criteria.
        All criteria are ANDed â€” only IOCs matching every supplied
        criterion are returned.

        Args:
            iocs:              Source IOC list.
            ioc_types:         Keep only these types (e.g. ["ipv4","domain"]).
            min_confidence:    Minimum confidence threshold (0.0â€“1.0).
            source_rule:       Keep only IOCs from this rule ID (substring match).
            has_tag:           Keep only IOCs that have this tag (substring match).
            exclude_private_ips: Drop RFC-1918 / loopback IP addresses.

        Returns:
            Filtered list[IOC]. Original list is not modified.
        """
        result = []
        for ioc in iocs:
            if ioc_types and ioc.ioc_type not in ioc_types:
                continue
            if ioc.confidence < min_confidence:
                continue
            if source_rule and source_rule.lower() not in ioc.source_rule.lower():
                continue
            if has_tag and not any(has_tag.lower() in t.lower() for t in ioc.tags):
                continue
            if exclude_private_ips and ioc.ioc_type == "ipv4":
                try:
                    if ipaddress.ip_address(ioc.value).is_private:
                        continue
                except ValueError:
                    pass
            result.append(ioc)
        return result

    # â”€â”€ Deduplicate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    @staticmethod
    def deduplicate(iocs: list[IOC]) -> list[IOC]:
        """
        Deduplicate a list of IOCs by (type, value.lower()).
        When duplicates exist, the one with the highest confidence is kept.
        Tag lists from all duplicates are merged and deduplicated.

        This exposes as a public method the dedup logic previously
        only available as a dict inside extract().

        Returns:
            Deduplicated list[IOC], ordered by first-seen type+value.
        """
        seen:  dict[tuple, IOC] = {}
        order: list[tuple]      = []

        for ioc in iocs:
            key = (ioc.ioc_type, ioc.value.lower())
            if key not in seen:
                seen[key]  = ioc
                order.append(key)
            else:
                existing = seen[key]
                # Merge tags from both copies
                merged_tags = list(dict.fromkeys(existing.tags + ioc.tags))
                if ioc.confidence > existing.confidence:
                    # Replace with higher-confidence version, keep merged tags
                    seen[key] = IOC(
                        ioc_type    = ioc.ioc_type,
                        value       = ioc.value,
                        confidence  = ioc.confidence,
                        source_rule = ioc.source_rule,
                        source_ip   = ioc.source_ip or existing.source_ip,
                        timestamp   = ioc.timestamp or existing.timestamp,
                        tags        = merged_tags,
                    )
                else:
                    existing.tags = merged_tags

        return [seen[k] for k in order]

    # â”€â”€ Merge â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    @staticmethod
    def merge(*ioc_lists: list[IOC]) -> list[IOC]:
        """
        Merge two or more IOC lists into one deduplicated list.
        Equivalent to concatenating all lists then calling deduplicate().
        Useful when combining IOCs from multiple sessions or analysts.

        Example:
            combined = IOCExtractor.merge(session1_iocs, session2_iocs)
        """
        combined: list[IOC] = []
        for lst in ioc_lists:
            combined.extend(lst)
        return IOCExtractor.deduplicate(combined)

    # â”€â”€ Enrich â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def enrich(
        self,
        iocs:         list[IOC],
        geoip:        bool = True,
        abuseipdb:    bool = False,
        abuseipdb_key: str = "",
    ) -> list[IOC]:
        """
        Inline enrichment pass â€” adds GeoIP and AbuseIPDB data to IOC tags
        in a single pass, modifying each IOC in-place.

        Each IOC is enriched only if it is of type "ipv4" and not private.

        GeoIP enrichment (always free, no API key):
          Adds tags: country:<CC>, asn:<num>, city:<name>
          Uses ip-api.com REST if GEOIP_DB_PATH not set.

        AbuseIPDB enrichment (requires api key):
          Adds tags: abuse_score:<0-100>, known_bad_ip (if score > 25)
          Requires: ABUSEIPDB_API_KEY env var or abuseipdb_key param.

        Args:
            iocs:          IOC list to enrich (modified in-place).
            geoip:         Enable GeoIP enrichment.
            abuseipdb:     Enable AbuseIPDB enrichment.
            abuseipdb_key: AbuseIPDB API key (overrides env var).

        Returns:
            The same list[IOC] with tags mutated â€” also returns self
            for chaining.
        """
        ip_iocs = [i for i in iocs
                   if i.ioc_type == "ipv4" and not _is_private(i.value)]
        if not ip_iocs:
            return iocs

        # GeoIP enrichment
        if geoip:
            try:
                sys.path.insert(0, os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "intelligence"))
                from geoip import GeoIP
                geo = GeoIP()
                for ioc in ip_iocs:
                    info = geo.lookup(ioc.value)
                    if not info:
                        continue
                    new_tags = []
                    if info.get("country_code"):
                        new_tags.append(f"country:{info['country_code']}")
                    if info.get("asn"):
                        new_tags.append(f"asn:{info['asn']}")
                    if info.get("city") and info["city"] not in ("", "Unknown"):
                        new_tags.append(f"city:{info['city']}")
                    # Merge without duplicating
                    for tag in new_tags:
                        if tag not in ioc.tags:
                            ioc.tags.append(tag)
            except Exception:
                pass   # GeoIP unavailable â€” degrade gracefully

        # AbuseIPDB enrichment
        if abuseipdb:
            try:
                from abuseipdb import AbuseIPDB
                key = abuseipdb_key or os.environ.get("ABUSEIPDB_API_KEY", "")
                if key:
                    client = AbuseIPDB(api_key=key)
                    for ioc in ip_iocs:
                        result = client.check(ioc.value)
                        if not result:
                            continue
                        score = result.get("abuse_confidence_score", 0)
                        if score is not None:
                            tag = f"abuse_score:{score}"
                            if tag not in ioc.tags:
                                ioc.tags.append(tag)
                            if score >= 25 and "known_bad_ip" not in ioc.tags:
                                ioc.tags.append("known_bad_ip")
                            cc = result.get("country_code", "")
                            if cc:
                                tag_cc = f"country:{cc}"
                                if tag_cc not in ioc.tags:
                                    ioc.tags.append(tag_cc)
            except Exception:
                pass   # AbuseIPDB unavailable â€” degrade gracefully

        return iocs
