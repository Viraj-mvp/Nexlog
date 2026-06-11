"""
parsers.py â€” NexLog Layer 1
One parser per log format. 50+ formats covered.
Every parser: stateless, never raises, returns LogEntry.

Categories:
  Web/Proxy:     Apache, Nginx, IIS, HAProxy, Squid, Caddy, Traefik
  System/OS:     Syslog RFC3164/5424, Auditd, Journald, macOS, dmesg
  Windows:       EVTX, Sysmon, Windows Firewall, DNS, PowerShell
  Network/Sec:   Zeek (conn/dns/http/ssl/files), Suricata EVE, Snort,
                 Cisco ASA/IOS, Palo Alto, Fortinet, pfSense, iptables,
                 CEF, LEEF, GELF
  Cloud:         CloudTrail, VPC Flow, ALB, Azure, GCP
  Database:      MySQL, PostgreSQL, MSSQL, MongoDB, Redis
  Container:     Docker, Kubernetes, Falco
  Email:         Postfix, Exchange, Sendmail
  DNS:           BIND, Windows DNS
  Generic:       JSON, CSV, XML
  AI Fallback:   Unknown format â†’ LLM extraction
"""

import csv
import io
import json
import re
from abc import ABC, abstractmethod
from datetime import datetime, timezone, timedelta
from typing import Optional
from urllib.parse import unquote_plus

# XXE protection: use defusedxml if available, otherwise standard ET with precautions
from models import LogEntry, LogFormat

try:
    from defusedxml import ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET
    import warnings
    warnings.warn(
        "defusedxml not installed â€” XML parsing may be vulnerable to XXE. "
        "Install with: pip install defusedxml",
        RuntimeWarning,
        stacklevel=2
    )


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TIMESTAMP UTILITIES
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

_MONTHS = {
    "jan":1,"feb":2,"mar":3,"apr":4,"may":5,"jun":6,
    "jul":7,"aug":8,"sep":9,"oct":10,"nov":11,"dec":12,
}

def _parse_apache_ts(raw: str) -> Optional[datetime]:
    m = re.match(r'(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-]\d{4})', raw.strip())
    if not m:
        return None
    day, mon_s, year, hh, mm, ss, tz_s = m.groups()
    mon = _MONTHS.get(mon_s.lower())
    if not mon:
        return None
    sign = 1 if tz_s[0] == "+" else -1
    tz   = timezone(timedelta(hours=sign*int(tz_s[1:3]), minutes=sign*int(tz_s[3:5])))
    return datetime(int(year), mon, int(day), int(hh), int(mm), int(ss), tzinfo=tz).astimezone(timezone.utc)

def _parse_syslog_ts(raw: str, year: Optional[int] = None) -> Optional[datetime]:
    m = re.match(r'(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})', raw)
    if not m:
        return None
    mon_s, day, hh, mm, ss = m.groups()
    mon = _MONTHS.get(mon_s.lower())
    if not mon:
        return None
    y = year or datetime.now(timezone.utc).year
    try:
        return datetime(y, mon, int(day), int(hh), int(mm), int(ss), tzinfo=timezone.utc)
    except ValueError:
        return None

def _parse_apache_error_ts(raw: str) -> Optional[datetime]:
    # Format: "Sun Dec 04 04:47:44 2005"
    m = re.match(r'(\w{3})\s+(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})', raw.strip())
    if not m:
        return None
    _, mon_s, day, hh, mm, ss, year = m.groups()
    mon = _MONTHS.get(mon_s.lower())
    if not mon:
        return None
    try:
        return datetime(int(year), mon, int(day), int(hh), int(mm), int(ss), tzinfo=timezone.utc)
    except ValueError:
        return None

def _parse_iso8601(raw: str) -> Optional[datetime]:
    if not raw:
        return None
    raw = str(raw).strip().rstrip("Z")
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, AttributeError):
        pass
    # Try common variants
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S",
                "%d/%b/%Y:%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            return datetime.strptime(raw[:len(fmt)+2], fmt).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
    return None

def _parse_w3c_ts(date: str, time: str) -> Optional[datetime]:
    """Parse W3C date+time fields: 2026-01-04 10:00:22"""
    try:
        return datetime.strptime(f"{date} {time}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None

def _safe_int(val) -> Optional[int]:
    try:
        return int(val) if val not in (None, "-", "") else None
    except (ValueError, TypeError):
        return None

def _http_severity(status: Optional[int]) -> str:
    if status is None: return "INFO"
    if status >= 500:  return "ERROR"
    if status >= 400:  return "WARNING"
    return "INFO"


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# BASE PARSER
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class BaseParser(ABC):
    log_format: LogFormat = LogFormat.UNKNOWN

    @abstractmethod
    def parse_line(self, raw_line: str, line_number: int, source_file: str) -> LogEntry:
        ...

    def _minimal(self, raw_line: str, line_number: int, source_file: str) -> LogEntry:
        return LogEntry(raw_line=raw_line, line_number=line_number,
                        source_file=source_file, log_format=self.log_format)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# WEB / PROXY
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class ApacheCombinedParser(BaseParser):
    """Apache/Nginx Combined Log Format"""
    log_format = LogFormat.APACHE_COMBINED

    _PAT = re.compile(
        r'(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
        r'\[(?P<time>[^\]]+)\]\s+'
        r'"(?P<method>[A-Z]{2,10}|-)\s+(?P<uri>\S+)\s+(?P<proto>[^"]+)"\s+'
        r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)'
        r'(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?'
    )

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        m = self._PAT.match(raw_line)
        if not m:
            return e
        g = m.groupdict()
        e.source_ip       = g["ip"] if g["ip"] != "-" else None
        e.username        = g["user"] if g["user"] != "-" else None
        e.timestamp_raw   = g["time"]
        e.timestamp       = _parse_apache_ts(g["time"])
        e.http_method     = g["method"] if g["method"] != "-" else None
        e.http_uri        = g["uri"]
        e.http_uri_decoded = unquote_plus(g["uri"])
        e.http_version    = g["proto"]
        e.http_status     = _safe_int(g["status"])
        e.http_bytes      = _safe_int(g["bytes"])
        e.http_referrer   = g.get("ref") or None
        e.http_user_agent = g.get("ua") or None
        e.severity        = _http_severity(e.http_status)
        return e


class ApacheErrorParser(BaseParser):
    """Apache Error Log Format"""
    log_format = LogFormat.APACHE_ERROR

    _PAT = re.compile(
        r'\[(?P<time>[^\]]+)\]\s+'
        r'\[(?P<module>[^\]]*)\]\s+'
        r'(?:\[pid\s+(?P<pid>\d+)\]\s+)?'
        r'(?:\[client\s+(?P<client>[^\]]+)\]\s+)?'
        r'(?P<msg>.*)'
    )

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        m = self._PAT.match(raw_line)
        if not m:
            e.message = raw_line.strip()
            return e
        g = m.groupdict()
        e.timestamp_raw = g["time"]
        e.timestamp     = _parse_apache_error_ts(g["time"])
        e.process_id    = _safe_int(g.get("pid"))
        client = g.get("client", "") or ""
        if ":" in client:
            parts = client.rsplit(":", 1)
            e.source_ip   = parts[0]
            e.source_port = _safe_int(parts[1])
        elif client:
            e.source_ip = client
        e.message     = (g.get("msg") or "").strip()
        sev_map    = {"emerg": "CRITICAL", "alert": "CRITICAL", "crit": "CRITICAL",
                      "error": "ERROR", "warn": "WARNING", "notice": "INFO",
                      "info": "INFO", "debug": "INFO"}
        e.severity = sev_map.get((g.get("module") or "").lower().split(":")[-1], "INFO")
        return e


class NginxErrorParser(BaseParser):
    """Nginx Error Log"""
    log_format = LogFormat.NGINX_ERROR

    _PAT = re.compile(
        r'(?P<time>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'\[(?P<level>\w+)\]\s+(?P<pid>\d+)#\d+:\s+'
        r'(?:\*\d+\s+)?(?P<msg>.+)'
    )

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        m = self._PAT.match(raw_line)
        if not m:
            e.message = raw_line.strip()
            return e
        g = m.groupdict()
        e.timestamp_raw = g["time"]
        e.timestamp     = _parse_iso8601(g["time"].replace("/", "-"))
        e.process_id    = _safe_int(g["pid"])
        e.message     = (g.get("msg") or "").strip()
        level_map = {"emerg": "CRITICAL", "alert": "CRITICAL", "crit": "CRITICAL",
                     "error": "ERROR", "warn": "WARNING", "notice": "INFO",
                     "info": "INFO", "debug": "INFO"}
        e.severity = level_map.get(g["level"].lower(), "INFO")
        # Extract client IP if present
        ip_m = re.search(r'client:\s*([\d\.]+)', e.message)
        if ip_m:
            e.source_ip = ip_m.group(1)
        return e


class IISParser(BaseParser):
    """Microsoft IIS W3C Extended Log Format"""
    log_format = LogFormat.IIS_W3C

    def __init__(self):
        self._fields: list[str] = []

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        line = raw_line.strip()
        if line.startswith("#Fields:"):
            self._fields = line[8:].strip().split()
            return e
        if line.startswith("#"):
            return e
        if not self._fields:
            # Default IIS W3C fields
            self._fields = ["date","time","s-ip","cs-method","cs-uri-stem",
                            "cs-uri-query","s-port","cs-username","c-ip",
                            "cs(User-Agent)","cs(Referer)","sc-status",
                            "sc-substatus","sc-win32-status","time-taken"]
        parts = line.split()
        if len(parts) < 4:
            return e
        row = dict(zip(self._fields, parts))
        date_s = row.get("date", "")
        time_s = row.get("time", "")
        if date_s and time_s:
            e.timestamp_raw = f"{date_s} {time_s}"
            e.timestamp     = _parse_w3c_ts(date_s, time_s)
        e.source_ip       = row.get("c-ip") or row.get("client-ip")
        e.dest_ip         = row.get("s-ip")
        e.dest_port       = _safe_int(row.get("s-port"))
        e.http_method     = row.get("cs-method")
        stem              = row.get("cs-uri-stem", "")
        query             = row.get("cs-uri-query", "-")
        e.http_uri        = f"{stem}?{query}" if query != "-" else stem
        e.http_uri_decoded = unquote_plus(e.http_uri) if e.http_uri else None
        e.username        = row.get("cs-username", "-") or None
        e.http_user_agent = row.get("cs(User-Agent)", "").replace("+", " ") or None
        e.http_referrer   = row.get("cs(Referer)") or None
        e.http_status     = _safe_int(row.get("sc-status"))
        e.http_bytes      = _safe_int(row.get("sc-bytes") or row.get("cs-bytes"))
        e.severity        = _http_severity(e.http_status)
        e.extra["time_taken_ms"] = row.get("time-taken")
        return e


class HAProxyParser(BaseParser):
    """HAProxy access log"""
    log_format = LogFormat.HAPROXY

    _PAT = re.compile(
        r'(?P<client_ip>[\d\.]+):(?P<client_port>\d+)\s+'
        r'\[(?P<time>[^\]]+)\]\s+'
        r'(?P<frontend>\S+)\s+(?P<backend>\S+)\s+'
        r'(?P<tr>[-\d]+)/(?P<tw>[-\d]+)/(?P<tc>[-\d]+)/(?P<tr2>[-\d]+)/(?P<tt>[-\d]+)\s+'
        r'(?P<status>\d+)\s+(?P<bytes>\d+)'
    )

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        m = self._PAT.search(raw_line)
        if not m:
            e.message = raw_line.strip()
            return e
        g = m.groupdict()
        e.source_ip   = g["client_ip"]
        e.source_port = _safe_int(g["client_port"])
        e.timestamp_raw = g["time"]
        e.timestamp   = _parse_apache_ts(g["time"])
        e.http_status = _safe_int(g["status"])
        e.http_bytes  = _safe_int(g["bytes"])
        e.severity    = _http_severity(e.http_status)
        e.extra.update({k: g[k] for k in ["frontend", "backend", "tt"]})
        return e


class SquidParser(BaseParser):
    """Squid Proxy Native Log Format"""
    log_format = LogFormat.SQUID

    _PAT = re.compile(
        r'(?P<ts>[\d\.]+)\s+(?P<elapsed>\d+)\s+(?P<client>\S+)\s+'
        r'(?P<result_code>\S+)/(?P<status>\d+)\s+(?P<bytes>\d+)\s+'
        r'(?P<method>\S+)\s+(?P<url>\S+)\s+(?P<user>\S+)\s+'
        r'(?P<peer_code>\S+)/(?P<peer_host>\S+)\s+(?P<mime>\S+)'
    )

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        m = self._PAT.match(raw_line.strip())
        if not m:
            return e
        g = m.groupdict()
        ts = float(g["ts"])
        e.timestamp    = datetime.fromtimestamp(ts, tz=timezone.utc)
        e.timestamp_raw = g["ts"]
        e.source_ip    = g["client"]
        e.username     = g["user"] if g["user"] != "-" else None
        e.http_method  = g["method"]
        e.http_uri     = g["url"]
        e.http_status  = _safe_int(g["status"])
        e.http_bytes   = _safe_int(g["bytes"])
        e.severity     = _http_severity(e.http_status)
        e.extra["squid_result"] = g["result_code"]
        e.extra["elapsed_ms"]   = g["elapsed"]
        return e


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# SYSTEM / OS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class SyslogParser(BaseParser):
    """RFC 3164 syslog and Linux auth.log"""
    log_format = LogFormat.SYSLOG

    _PAT = re.compile(
        r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
        r'(?P<host>\S+)\s+(?P<proc>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)'
    )
    _SSH_FAIL   = re.compile(r'Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)')
    _SSH_OK     = re.compile(r'Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)')
    _SSH_INV    = re.compile(r'Invalid user (\S+) from (\S+)')
    _SUDO       = re.compile(r'(\S+)\s+:\s+TTY=\S+\s+;\s+USER=(\S+)\s+;\s+COMMAND=(.+)')

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        m = self._PAT.match(raw_line)
        if not m:
            return e
        g = m.groupdict()
        ts_raw = f"{g['month']} {g['day']} {g['time']}"
        e.timestamp_raw = ts_raw
        e.timestamp     = _parse_syslog_ts(ts_raw)
        e.hostname      = g["host"]
        e.process_name  = g["proc"].strip()
        e.process_id    = _safe_int(g["pid"])
        e.message       = g["msg"]
        msg = g["msg"]

        mf = self._SSH_FAIL.search(msg)
        if mf:
            e.username = mf.group(1); e.source_ip = mf.group(2)
            e.source_port = _safe_int(mf.group(3)); e.auth_result = "failure"
            e.severity = "WARNING"; return e

        ma = self._SSH_OK.search(msg)
        if ma:
            e.username = ma.group(1); e.source_ip = ma.group(2)
            e.source_port = _safe_int(ma.group(3)); e.auth_result = "success"
            e.severity = "INFO"; return e

        mi = self._SSH_INV.search(msg)
        if mi:
            e.username = mi.group(1); e.source_ip = mi.group(2)
            e.auth_result = "failure"; e.severity = "WARNING"; return e

        ms = self._SUDO.search(msg)
        if ms:
            e.username = ms.group(1); e.command_line = ms.group(3).strip()
            e.extra["sudo_as"] = ms.group(2); e.severity = "INFO"

        e.severity = e.severity or "INFO"
        return e


class SyslogRFC5424Parser(BaseParser):
    """RFC 5424 Structured Syslog"""
    log_format = LogFormat.SYSLOG_RFC5424

    _PAT = re.compile(
        r'<(?P<pri>\d+)>(?P<ver>\d+)\s+'
        r'(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+'
        r'(?P<pid>\S+)\s+(?P<msgid>\S+)\s+'
        r'(?P<sd>(?:-|\[.*?\])+)\s+(?P<msg>.*)'
    )
    _SYSLOG_SEV = ["CRITICAL","CRITICAL","CRITICAL","ERROR","WARNING","INFO","INFO","INFO"]

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        m = self._PAT.match(raw_line)
        if not m:
            return e
        g = m.groupdict()
        pri = _safe_int(g["pri"]) or 0
        e.timestamp_raw = g["ts"]
        # BIND format: 04-Jan-2026 10:00:00.123
        try:
            from datetime import datetime, timezone as _tz
            e.timestamp = datetime.strptime(g["ts"][:20], "%d-%b-%Y %H:%M:%S").replace(tzinfo=_tz.utc)
        except (ValueError, TypeError):
            e.timestamp = _parse_iso8601(g["ts"])
        e.source_ip = g["ip"]
        e.hostname      = g["host"] if g["host"] != "-" else None
        e.process_name  = g["app"]  if g["app"]  != "-" else None
        e.process_id    = _safe_int(g["pid"]) if g["pid"] != "-" else None
        e.message       = g["msg"]
        e.severity      = self._SYSLOG_SEV[pri % 8]
        # Parse structured data
        for kv in re.findall(r'(\w+)="([^"]*)"', g["sd"]):
            e.extra[kv[0]] = kv[1]
        return e


class AuditdParser(BaseParser):
    """Linux auditd audit.log â€” key=value format"""
    log_format = LogFormat.AUDITD

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        # audit(1704355292.123:456): key=val key=val ...
        kv = {}
        for m in re.finditer(r'(\w+)=(?:"([^"]*)"|([\S]+))', raw_line):
            kv[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)

        # Timestamp from audit(ts:serial)
        ts_m = re.search(r'audit\((\d+\.\d+):\d+\)', raw_line)
        if ts_m:
            e.timestamp = datetime.fromtimestamp(float(ts_m.group(1)), tz=timezone.utc)
            e.timestamp_raw = ts_m.group(1)

        e.process_name  = kv.get("comm") or kv.get("exe", "").rsplit("/", 1)[-1]
        e.process_id    = _safe_int(kv.get("pid"))
        e.parent_pid    = _safe_int(kv.get("ppid"))
        e.username      = kv.get("uid") or kv.get("auid")
        e.hostname      = kv.get("hostname") or kv.get("node")
        e.source_ip     = kv.get("addr") if kv.get("addr") not in (None, "?", "") else None
        e.command_line  = kv.get("cmd") or kv.get("cmdline")
        e.file_path     = kv.get("name") or kv.get("path")
        e.event_id      = kv.get("type")
        e.message       = f"auditd: type={kv.get('type','')} {raw_line[:200]}"
        e.extra         = kv
        # Auth events
        if kv.get("type") in ("USER_AUTH", "USER_LOGIN", "USER_ACCT"):
            e.auth_result = "success" if kv.get("res") == "success" else "failure"
            e.severity = "WARNING" if e.auth_result == "failure" else "INFO"
        else:
            e.severity = "INFO"
        return e


class JournaldParser(BaseParser):
    """systemd journald JSON export (journalctl -o json)"""
    log_format = LogFormat.JOURNALD

    _PRIORITIES = {0:"CRITICAL",1:"CRITICAL",2:"CRITICAL",3:"ERROR",
                   4:"WARNING",5:"INFO",6:"INFO",7:"INFO"}

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        try:
            obj = json.loads(raw_line)
        except json.JSONDecodeError:
            return e
        ts_us = obj.get("__REALTIME_TIMESTAMP")
        if ts_us:
            try:
                e.timestamp = datetime.fromtimestamp(int(ts_us)/1e6, tz=timezone.utc)
                e.timestamp_raw = ts_us
            except (ValueError, TypeError):
                pass
        e.hostname     = obj.get("_HOSTNAME")
        e.process_name = obj.get("_COMM") or obj.get("SYSLOG_IDENTIFIER")
        e.process_id   = _safe_int(obj.get("_PID"))
        e.message      = obj.get("MESSAGE", "")
        e.username     = obj.get("_UID")
        pri = _safe_int(obj.get("PRIORITY"))
        e.severity     = self._PRIORITIES.get(pri, "INFO")
        e.extra        = dict(obj)
        return e


class KernLogParser(BaseParser):
    """Linux kern.log / dmesg"""
    log_format = LogFormat.KERN_LOG

    _PAT = re.compile(r'(?:\[(?P<uptime>[\d\.]+)\])?\s*(?P<msg>.*)')

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        # Try syslog-prefixed kern.log first
        syslog_m = re.match(
            r'^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+kernel:\s*(.*)', raw_line)
        if syslog_m:
            e.timestamp_raw = syslog_m.group(1)
            e.timestamp     = _parse_syslog_ts(syslog_m.group(1))
            e.message       = syslog_m.group(2)
        else:
            m = self._PAT.match(raw_line)
            if m:
                e.extra["kernel_uptime"] = m.group("uptime")
                e.message = m.group("msg")
        e.process_name = "kernel"
        e.severity = ("CRITICAL" if re.search(r'\b(panic|oops|BUG|NULL pointer)\b', e.message or "", re.I)
                      else "WARNING" if re.search(r'\b(error|fail|warn)\b', e.message or "", re.I)
                      else "INFO")
        return e


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# WINDOWS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

_EVTX_SEV = {
    "4625": "WARNING", "4648": "WARNING", "4698": "WARNING",
    "4702": "WARNING", "4720": "WARNING", "4732": "WARNING",
    "4756": "WARNING", "7045": "WARNING", "4657": "WARNING",
    "4670": "WARNING", "4672": "WARNING", "4673": "WARNING",
    "4674": "WARNING", "4728": "WARNING", "4735": "WARNING",
    "4740": "WARNING", "4767": "WARNING", "1102": "CRITICAL",
    "4624": "INFO",    "4688": "INFO",    "4689": "INFO",
    "4776": "WARNING",
}
_LOGON_TYPES = {
    "2":"interactive","3":"network","4":"batch","5":"service",
    "7":"unlock","8":"network_cleartext","9":"new_credentials",
    "10":"remote_interactive","11":"cached_interactive",
}
_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


class EvtxParser(BaseParser):
    """Windows EVTX XML events"""
    log_format = LogFormat.WINDOWS_EVTX

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        if raw_line.startswith("[EVTX-"):
            e.message = raw_line; return e
        try:
            root = ET.fromstring(raw_line)
        except ET.ParseError:
            e.message = f"[XML parse error] {raw_line[:120]}"; return e

        sys  = root.find("e:System", _NS)
        data = root.find("e:EventData", _NS)
        if sys is None:
            return e

        eid_el = sys.find("e:EventID", _NS)
        if eid_el is not None:
            e.event_id = eid_el.text

        tc_el = sys.find("e:TimeCreated", _NS)
        if tc_el is not None:
            ts_raw = tc_el.get("SystemTime", "")
            e.timestamp_raw = ts_raw
            e.timestamp     = _parse_iso8601(ts_raw)

        comp_el = sys.find("e:Computer", _NS)
        if comp_el is not None:
            e.hostname = comp_el.text

        ev_data: dict = {}
        if data is not None:
            for item in data:
                name = item.get("Name", "")
                ev_data[name] = item.text or ""

        e.username    = ev_data.get("TargetUserName") or ev_data.get("SubjectUserName")
        ip_raw        = ev_data.get("IpAddress") or ev_data.get("WorkstationName")
        e.source_ip   = ip_raw if ip_raw and ip_raw not in ("::1","127.0.0.1","-") else None
        e.source_port = _safe_int(ev_data.get("IpPort"))
        lt = ev_data.get("LogonType", "")
        if lt:
            e.extra["logon_type"]      = lt
            e.extra["logon_type_name"] = _LOGON_TYPES.get(lt, lt)
        if e.event_id == "4624":
            e.auth_result = "success"
        elif e.event_id in ("4625", "4648", "4776"):
            e.auth_result = "failure"
        if e.event_id == "4688":
            e.command_line = ev_data.get("CommandLine")
            e.process_name = ev_data.get("NewProcessName", "").rsplit("\\", 1)[-1]
        e.severity = _EVTX_SEV.get(e.event_id or "", "INFO")
        e.extra["event_data"] = ev_data
        e.message = f"EventID {e.event_id} on {e.hostname}"
        return e


class SysmonParser(BaseParser):
    """Sysmon XML events (superset of EVTX)"""
    log_format = LogFormat.WINDOWS_SYSMON

    _EVTX = EvtxParser()

    def parse_line(self, raw_line, line_number, source_file):
        e = self._EVTX.parse_line(raw_line, line_number, source_file)
        e.log_format = LogFormat.WINDOWS_SYSMON
        ev = e.extra.get("event_data", {})
        # Sysmon enriches process, network, file, registry events
        e.command_line = ev.get("CommandLine") or e.command_line
        e.file_hash_md5  = ev.get("Hashes", "").split(",")[0].replace("MD5=","") or None
        e.file_hash_sha256 = None
        for h in ev.get("Hashes", "").split(","):
            if "SHA256=" in h:
                e.file_hash_sha256 = h.replace("SHA256=","")
        e.dest_ip   = ev.get("DestinationIp") or e.dest_ip
        e.dest_port = _safe_int(ev.get("DestinationPort")) or e.dest_port
        e.protocol  = (ev.get("Protocol") or "").lower() or None
        e.file_path = ev.get("TargetFilename") or ev.get("ImageLoaded")
        return e


class WindowsFirewallParser(BaseParser):
    """Windows Firewall WFAS log (W3C format)"""
    log_format = LogFormat.WINDOWS_FIREWALL

    _FIELDS = ["date","time","action","protocol","src-ip","dst-ip",
               "src-port","dst-port","size","tcpflags","tcpsyn",
               "tcpack","tcpwin","icmptype","icmpcode","info","path"]

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        line = raw_line.strip()
        if line.startswith("#"): return e
        parts = line.split()
        if len(parts) < 8: return e
        row = dict(zip(self._FIELDS, parts))
        e.timestamp_raw = f"{row.get('date','')} {row.get('time','')}"
        e.timestamp     = _parse_w3c_ts(row.get("date",""), row.get("time",""))
        e.action        = row.get("action","").lower()
        e.protocol      = row.get("protocol","").lower()
        e.source_ip     = row.get("src-ip")
        e.dest_ip       = row.get("dst-ip")
        e.source_port   = _safe_int(row.get("src-port"))
        e.dest_port     = _safe_int(row.get("dst-port"))
        e.direction     = row.get("path","").lower()
        e.severity      = "WARNING" if e.action == "drop" else "INFO"
        e.message       = f"Firewall {e.action}: {e.protocol} {e.source_ip}:{e.source_port} â†’ {e.dest_ip}:{e.dest_port}"
        return e


class PowerShellParser(BaseParser):
    """PowerShell ScriptBlock log (from EVTX EventID 4104)"""
    log_format = LogFormat.POWERSHELL_SCRIPT

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        e.process_name = "powershell"
        # Try XML first
        if "<Event" in raw_line:
            evtx = EvtxParser()
            base = evtx.parse_line(raw_line, line_number, source_file)
            base.log_format = LogFormat.POWERSHELL_SCRIPT
            ev = base.extra.get("event_data", {})
            base.command_line = ev.get("ScriptBlockText")
            base.severity = ("CRITICAL" if ev.get("MessageNumber","0") == "1"
                             and any(x in (base.command_line or "").lower()
                                     for x in ["invoke-mimikatz","bypass","downloadstring",
                                               "encodedcommand","iex","invoke-expression"])
                             else "WARNING")
            return base
        e.command_line = raw_line.strip()
        e.severity = "INFO"
        return e


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# NETWORK / SECURITY TOOLS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class ZeekConnParser(BaseParser):
    """Zeek conn.log TSV"""
    log_format = LogFormat.ZEEK_CONN

    # Header: ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto
    #         service duration orig_bytes resp_bytes conn_state ...
    _FIELDS: list[str] = []

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        if raw_line.startswith("#fields"):
            self._FIELDS = raw_line.split("\t")[1:]
            return e
        if raw_line.startswith("#"): return e
        parts = raw_line.rstrip("\n").split("\t")
        fields = self._FIELDS or ["ts","uid","id.orig_h","id.orig_p","id.resp_h",
                                   "id.resp_p","proto","service","duration",
                                   "orig_bytes","resp_bytes","conn_state",
                                   "local_orig","local_resp","missed_bytes",
                                   "history","orig_pkts","orig_ip_bytes",
                                   "resp_pkts","resp_ip_bytes","tunnel_parents"]
        row = dict(zip(fields, parts))
        ts_raw = row.get("ts","")
        try:
            e.timestamp = datetime.fromtimestamp(float(ts_raw), tz=timezone.utc)
        except (ValueError, TypeError):
            pass
        e.timestamp_raw = ts_raw
        e.source_ip   = row.get("id.orig_h")
        e.source_port = _safe_int(row.get("id.orig_p"))
        e.dest_ip     = row.get("id.resp_h")
        e.dest_port   = _safe_int(row.get("id.resp_p"))
        e.protocol    = row.get("proto","").lower()
        state = row.get("conn_state","")
        e.action = "allow" if state in ("SF","S1","S2","S3","RSTO","RSTR") else "drop"
        e.severity = "WARNING" if row.get("orig_bytes","0") not in ("","0","-") and \
                                   _safe_int(row.get("orig_bytes")) and \
                                   _safe_int(row.get("orig_bytes","0") or "0") > 1_000_000 else "INFO"
        e.message = f"Zeek conn: {e.source_ip}:{e.source_port} â†’ {e.dest_ip}:{e.dest_port} [{state}]"
        e.extra = row
        return e


class ZeekDNSParser(BaseParser):
    """Zeek dns.log TSV"""
    log_format = LogFormat.ZEEK_DNS

    _FIELDS: list[str] = []

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        if raw_line.startswith("#fields"):
            self._FIELDS = raw_line.split("\t")[1:]
            return e
        if raw_line.startswith("#"): return e
        parts = raw_line.rstrip("\n").split("\t")
        fields = self._FIELDS or ["ts","uid","id.orig_h","id.orig_p","id.resp_h",
                                   "id.resp_p","proto","trans_id","rtt","query",
                                   "qclass","qclass_name","qtype","qtype_name",
                                   "rcode","rcode_name","AA","TC","RD","RA",
                                   "Z","answers","TTLs","rejected"]
        row = dict(zip(fields, parts))
        try:
            e.timestamp = datetime.fromtimestamp(float(row.get("ts","0")), tz=timezone.utc)
        except (ValueError, TypeError):
            pass
        e.source_ip  = row.get("id.orig_h")
        e.source_port = _safe_int(row.get("id.orig_p"))
        e.dest_ip    = row.get("id.resp_h")
        e.dns_query  = row.get("query")
        e.dns_type   = row.get("qtype_name")
        e.dns_answer = row.get("answers","").split(",")[0] if row.get("answers") else None
        e.dns_rcode  = row.get("rcode_name")
        e.protocol   = "dns"
        # Flag suspicious: NXDOMAIN, long queries, rare types
        if e.dns_rcode == "NXDOMAIN":
            e.severity = "WARNING"
        elif e.dns_type in ("TXT","NULL","ANY") and len(e.dns_query or "") > 50:
            e.severity = "WARNING"  # possible DNS tunneling
        else:
            e.severity = "INFO"
        e.message = f"DNS {e.dns_type} {e.dns_query} â†’ {e.dns_rcode}"
        e.extra = row
        return e


class ZeekHTTPParser(BaseParser):
    """Zeek http.log TSV"""
    log_format = LogFormat.ZEEK_HTTP

    _FIELDS: list[str] = []

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        if raw_line.startswith("#fields"):
            self._FIELDS = raw_line.split("\t")[1:]
            return e
        if raw_line.startswith("#"): return e
        parts = raw_line.rstrip("\n").split("\t")
        fields = self._FIELDS or ["ts","uid","id.orig_h","id.orig_p","id.resp_h",
                                   "id.resp_p","trans_depth","method","host","uri",
                                   "referrer","version","user_agent","origin",
                                   "request_body_len","response_body_len",
                                   "status_code","status_msg","info_code",
                                   "info_msg","tags","username","password",
                                   "proxied","orig_fuids","orig_filenames",
                                   "orig_mime_types","resp_fuids","resp_filenames",
                                   "resp_mime_types"]
        row = dict(zip(fields, parts))
        try:
            e.timestamp = datetime.fromtimestamp(float(row.get("ts","0")), tz=timezone.utc)
        except (ValueError, TypeError):
            pass
        e.source_ip       = row.get("id.orig_h")
        e.dest_ip         = row.get("id.resp_h")
        e.dest_port       = _safe_int(row.get("id.resp_p"))
        e.http_method     = row.get("method")
        e.http_uri        = row.get("uri")
        e.http_uri_decoded = unquote_plus(e.http_uri) if e.http_uri else None
        e.http_status     = _safe_int(row.get("status_code"))
        e.http_user_agent = row.get("user_agent")
        e.hostname        = row.get("host")
        e.username        = row.get("username") if row.get("username") != "-" else None
        e.severity        = _http_severity(e.http_status)
        e.message = f"HTTP {e.http_method} {e.hostname}{e.http_uri} â†’ {e.http_status}"
        e.extra = row
        return e


class ZeekSSLParser(BaseParser):
    """Zeek ssl.log TSV"""
    log_format = LogFormat.ZEEK_SSL

    _FIELDS: list[str] = []

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        if raw_line.startswith("#fields"):
            self._FIELDS = raw_line.split("\t")[1:]
            return e
        if raw_line.startswith("#"): return e
        parts = raw_line.rstrip("\n").split("\t")
        fields = self._FIELDS or ["ts","uid","id.orig_h","id.orig_p","id.resp_h",
                                   "id.resp_p","version","cipher","curve","server_name",
                                   "resumed","last_alert","next_protocol","established",
                                   "ssl_history","cert_chain_fuids","client_cert_chain_fuids",
                                   "subject","issuer","client_subject","client_issuer",
                                   "validation_status","ja3","ja3s"]
        row = dict(zip(fields, parts))
        try:
            e.timestamp = datetime.fromtimestamp(float(row.get("ts","0")), tz=timezone.utc)
        except (ValueError, TypeError):
            pass
        e.source_ip      = row.get("id.orig_h")
        e.dest_ip        = row.get("id.resp_h")
        e.dest_port      = _safe_int(row.get("id.resp_p"))
        e.tls_version    = row.get("version")
        e.tls_cipher     = row.get("cipher")
        e.tls_server_name = row.get("server_name") if row.get("server_name") != "-" else None
        e.tls_ja3        = row.get("ja3")
        e.protocol       = "tls"
        alert = row.get("last_alert","")
        e.severity = "WARNING" if alert and alert != "-" else "INFO"
        e.message = f"TLS {e.tls_version} {e.tls_server_name or e.dest_ip} cipher={e.tls_cipher}"
        e.extra = row
        return e


class ZeekJSONParser(BaseParser):
    """Zeek JSON log output (any type)"""
    log_format = LogFormat.ZEEK_JSON

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        try:
            obj = json.loads(raw_line)
        except json.JSONDecodeError:
            return e
        ts = obj.get("ts")
        try:
            e.timestamp = datetime.fromtimestamp(float(ts), tz=timezone.utc) if ts else None
        except (ValueError, TypeError):
            pass
        e.source_ip   = obj.get("id.orig_h") or obj.get("src_ip")
        e.source_port = _safe_int(obj.get("id.orig_p"))
        e.dest_ip     = obj.get("id.resp_h") or obj.get("dst_ip")
        e.dest_port   = _safe_int(obj.get("id.resp_p"))
        e.dns_query   = obj.get("query")
        e.dns_type    = obj.get("qtype_name")
        e.http_method = obj.get("method")
        e.http_uri    = obj.get("uri")
        e.http_status = _safe_int(obj.get("status_code"))
        e.tls_version = obj.get("version")
        e.tls_ja3     = obj.get("ja3")
        e.tls_server_name = obj.get("server_name")
        e.severity    = "INFO"
        e.extra       = obj
        return e


class SuricataEVEParser(BaseParser):
    """Suricata EVE JSON log"""
    log_format = LogFormat.SURICATA_EVE

    _SEV_MAP = {1:"CRITICAL",2:"HIGH",3:"MEDIUM",4:"LOW",5:"INFO"}

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        try:
            obj = json.loads(raw_line)
        except json.JSONDecodeError:
            return e
        e.timestamp_raw = obj.get("timestamp","")
        e.timestamp     = _parse_iso8601(e.timestamp_raw)
        e.source_ip     = obj.get("src_ip")
        e.source_port   = _safe_int(obj.get("src_port"))
        e.dest_ip       = obj.get("dest_ip")
        e.dest_port     = _safe_int(obj.get("dest_port"))
        e.protocol      = obj.get("proto","").lower()
        e.hostname      = obj.get("hostname")

        event_type = obj.get("event_type","")
        if event_type == "alert":
            alert = obj.get("alert", {})
            e.message   = alert.get("signature","")
            e.event_id  = str(alert.get("signature_id",""))
            e.severity  = self._SEV_MAP.get(alert.get("severity",5), "INFO")
            e.rule_name = alert.get("signature")
            e.tags      = [alert.get("category","")]
            e.action    = alert.get("action","")
            e.extra["mitre"] = alert.get("metadata", {}).get("mitre_attack", [])
        elif event_type == "dns":
            dns = obj.get("dns", {})
            e.dns_query = dns.get("rrname")
            e.dns_type  = dns.get("rrtype")
            e.dns_rcode = dns.get("rcode")
            e.severity  = "INFO"
        elif event_type == "http":
            http = obj.get("http", {})
            e.http_method = http.get("http_method")
            e.http_uri    = http.get("url")
            e.http_status = _safe_int(http.get("status"))
            e.http_user_agent = http.get("http_user_agent")
            e.severity    = _http_severity(e.http_status)
        elif event_type == "tls":
            tls = obj.get("tls", {})
            e.tls_version    = tls.get("version")
            e.tls_server_name = tls.get("sni")
            e.tls_ja3        = tls.get("ja3", {}).get("hash")
            e.severity       = "INFO"
        else:
            e.message  = obj.get("message","") or event_type
            e.severity = "INFO"
        e.extra = obj
        return e


class SnortFastParser(BaseParser):
    """Snort fast alert format: MM/DD-HH:MM:SS ... [sid:xxx] msg {proto} ip->ip"""
    log_format = LogFormat.SNORT_FAST

    _PAT = re.compile(
        r'(?P<ts>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+\[\*\*\]\s+'
        r'\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+'
        r'(?P<msg>[^\[]+)\s+\[\*\*\]\s+'
        r'(?:\[Classification:\s*(?P<cls>[^\]]+)\]\s+)?'
        r'(?:\[Priority:\s*(?P<pri>\d+)\]\s+)?'
        r'\{(?P<proto>\w+)\}\s+'
        r'(?P<src>[\d\.:]+)\s*->\s*(?P<dst>[\d\.:]+)'
    )

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        m = self._PAT.search(raw_line)
        if not m:
            return e
        g = m.groupdict()
        # Parse MM/DD-HH:MM:SS using current year
        ts_str = f"{datetime.now(timezone.utc).year}/{g['ts']}"
        try:
            e.timestamp = datetime.strptime(ts_str, "%Y/%m/%d-%H:%M:%S.%f")\
                          .replace(tzinfo=timezone.utc)
        except ValueError:
            pass
        e.timestamp_raw = g["ts"]
        src = (g.get("src") or "0.0.0.0:0").rsplit(":", 1)
        dst = (g.get("dst") or "0.0.0.0:0").rsplit(":", 1)
        e.source_ip   = src[0]
        e.source_port = _safe_int(src[1]) if len(src) > 1 else None
        e.dest_ip     = dst[0]
        e.dest_port   = _safe_int(dst[1]) if len(dst) > 1 else None
        e.protocol    = g["proto"].lower()
        e.message     = (g.get("msg") or "").strip()
        e.event_id    = f"{g.get('gid','?')}:{g.get('sid','?')}:{g.get('rev','?')}"
        pri_map = {"1":"CRITICAL","2":"HIGH","3":"MEDIUM","4":"LOW"}
        e.severity    = pri_map.get(g.get("pri",""), "WARNING")
        e.tags        = [g.get("cls","").strip()]
        return e


class CiscoASAParser(BaseParser):
    """Cisco ASA syslog messages"""
    log_format = LogFormat.CISCO_ASA

    _PAT = re.compile(
        r'%ASA-(?P<level>\d)-(?P<msgid>\d{6}):\s+(?P<msg>.*)'
    )
    _CONN = re.compile(
        r'(?P<action>\w+)\s+(?P<proto>\w+)\s+(?:connection|inbound|outbound)\s+'
        r'(?:from|for)?\s*(?P<src>[\d\.]+)/(?P<sport>\d+)\s+'
        r'(?:to|on)\s+(?P<dst>[\d\.]+)/(?P<dport>\d+)'
    )
    _DENIED = re.compile(
        r'(?P<action>Deny|Permit)\s+(?P<proto>\w+)\s+(?:src|from)\s+'
        r'(?P<src_iface>\w+):(?P<src>[\d\.]+)/(?P<sport>\d+)\s+'
        r'(?:dst|to)\s+(?P<dst_iface>\w+):(?P<dst>[\d\.]+)/(?P<dport>\d+)'
    )

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        # Extract syslog timestamp prefix first
        syslog_m = re.match(r'(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+(.*)', raw_line)
        rest = raw_line
        if syslog_m:
            e.timestamp_raw = syslog_m.group(1)
            e.timestamp     = _parse_syslog_ts(syslog_m.group(1))
            rest = syslog_m.group(2)

        m = self._PAT.search(rest)
        if not m:
            e.message = raw_line.strip(); return e
        g = m.groupdict()
        level_map = {"1":"CRITICAL","2":"CRITICAL","3":"ERROR","4":"WARNING","5":"INFO","6":"INFO","7":"INFO"}
        e.severity  = level_map.get(g["level"], "INFO")
        e.event_id  = g["msgid"]
        e.message   = g["msg"]
        e.process_name = "cisco-asa"

        conn = self._CONN.search(g["msg"])
        if conn:
            c = conn.groupdict()
            e.action    = c["action"].lower()
            e.protocol  = c["proto"].lower()
            e.source_ip = c["src"]; e.source_port = _safe_int(c["sport"])
            e.dest_ip   = c["dst"]; e.dest_port   = _safe_int(c["dport"])
        else:
            denied = self._DENIED.search(g["msg"])
            if denied:
                d = denied.groupdict()
                e.action    = d["action"].lower()
                e.protocol  = d["proto"].lower()
                e.source_ip = d["src"]; e.source_port = _safe_int(d["sport"])
                e.dest_ip   = d["dst"]; e.dest_port   = _safe_int(d["dport"])
        return e


class CEFParser(BaseParser):
    """Common Event Format (ArcSight CEF)"""
    log_format = LogFormat.CEF

    _HEADER = re.compile(
        r'CEF:(?P<ver>\d+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|'
        r'(?P<version>[^|]*)\|(?P<sig_id>[^|]*)\|(?P<name>[^|]*)\|'
        r'(?P<severity>[^|]*)\|(?P<ext>.*)'
    )
    _KV = re.compile(r'(\w+)=((?:[^=\\]|\\.)*?)(?=\s+\w+=|$)')

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        # CEF may be prefixed by syslog
        cef_idx = raw_line.find("CEF:")
        if cef_idx < 0: return e
        # Parse syslog prefix
        prefix = raw_line[:cef_idx].strip()
        if prefix:
            ts_m = re.search(r'(\w{3}\s+\d+\s+\d+:\d+:\d+)', prefix)
            if ts_m:
                e.timestamp = _parse_syslog_ts(ts_m.group(1))
                e.timestamp_raw = ts_m.group(1)

        m = self._HEADER.match(raw_line[cef_idx:])
        if not m: return e
        g = m.groupdict()
        e.event_id   = g["sig_id"]
        e.message    = g["name"]
        sev = g["severity"]
        sev_map = {"10":"CRITICAL","9":"CRITICAL","8":"CRITICAL",
                   "7":"HIGH","6":"HIGH","5":"MEDIUM","4":"MEDIUM",
                   "3":"LOW","2":"LOW","1":"INFO","0":"INFO",
                   "Very-High":"CRITICAL","High":"HIGH","Medium":"MEDIUM",
                   "Low":"LOW","Unknown":"INFO"}
        e.severity = sev_map.get(sev, "WARNING")

        ext = {}
        for kv in self._KV.finditer(g["ext"]):
            ext[kv.group(1)] = kv.group(2).strip()

        e.source_ip   = ext.get("src") or ext.get("sourceAddress")
        e.source_port = _safe_int(ext.get("spt") or ext.get("sourcePort"))
        e.dest_ip     = ext.get("dst") or ext.get("destinationAddress")
        e.dest_port   = _safe_int(ext.get("dpt") or ext.get("destinationPort"))
        e.username    = ext.get("suser") or ext.get("duser")
        e.hostname    = ext.get("dhost") or ext.get("shost")
        e.file_path   = ext.get("filePath") or ext.get("fname")
        e.file_hash_sha256 = ext.get("fileHash")
        # CEF timestamp: rt = epoch ms
        rt = ext.get("rt") or ext.get("end") or ext.get("start")
        if rt:
            try:
                ts = float(rt)
                e.timestamp = datetime.fromtimestamp(ts/1000 if ts > 1e10 else ts, tz=timezone.utc)
            except (ValueError, TypeError):
                pass
        e.extra = ext
        return e


class LEEFParser(BaseParser):
    """LEEF (Log Event Extended Format) â€” IBM QRadar"""
    log_format = LogFormat.LEEF

    _HEADER = re.compile(
        r'LEEF:(?P<ver>[^|]+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|'
        r'(?P<version>[^|]*)\|(?P<id>[^|]*)\|'
    )

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        leef_idx = raw_line.find("LEEF:")
        if leef_idx < 0: return e
        m = self._HEADER.match(raw_line[leef_idx:])
        if not m: return e
        ext_str = raw_line[leef_idx + m.end():]
        g = m.groupdict()
        e.event_id   = g["id"]
        e.process_name = g["product"]
        # LEEF uses tab or custom delimiter for ext
        delim = "\t"
        ext = {}
        for kv in ext_str.split(delim):
            if "=" in kv:
                k, _, v = kv.partition("=")
                ext[k.strip()] = v.strip()
        e.source_ip   = ext.get("src") or ext.get("srcIP")
        e.dest_ip     = ext.get("dst") or ext.get("dstIP")
        e.source_port = _safe_int(ext.get("srcPort"))
        e.dest_port   = _safe_int(ext.get("dstPort"))
        e.username    = ext.get("usrName") or ext.get("accountName")
        e.protocol    = (ext.get("proto") or "").lower() or None
        sev = ext.get("severity","").lower()
        e.severity = ("CRITICAL" if sev in ("critical","very-high")
                      else "HIGH" if sev == "high"
                      else "MEDIUM" if sev in ("medium","moderate")
                      else "LOW" if sev == "low" else "INFO")
        ts = ext.get("devTime") or ext.get("startTime")
        if ts:
            e.timestamp = _parse_iso8601(ts)
        e.message = f"LEEF {g['product']} {g['id']}"
        e.extra = ext
        return e


class IPTablesParser(BaseParser):
    """Linux iptables/nftables kernel log via syslog"""
    log_format = LogFormat.IPTABLES

    _PREFIX = re.compile(r'kernel:\s+(?:\[\s*[\d\.]+\]\s+)?(?P<prefix>[^:]+?):\s+(?P<kv>.*)')

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        # First extract syslog header
        syslog_m = re.match(
            r'(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+kernel:\s+(.*)', raw_line)
        kv_str = raw_line
        if syslog_m:
            e.timestamp_raw = syslog_m.group(1)
            e.timestamp     = _parse_syslog_ts(syslog_m.group(1))
            e.hostname      = syslog_m.group(2)
            kv_str          = syslog_m.group(3)
        # Extract key=value pairs
        kv: dict = {}
        for m in re.finditer(r'(\w+)=(\S+)', kv_str):
            kv[m.group(1)] = m.group(2)
        e.source_ip   = kv.get("SRC")
        e.dest_ip     = kv.get("DST")
        e.source_port = _safe_int(kv.get("SPT"))
        e.dest_port   = _safe_int(kv.get("DPT"))
        e.protocol    = kv.get("PROTO","").lower() or None
        e.direction   = "inbound" if kv.get("IN") else "outbound" if kv.get("OUT") else None
        # Determine action from prefix (before first colon in kv_str)
        prefix_m = re.match(r'([\w\-\s]+):\s+', kv_str)
        prefix = prefix_m.group(1).strip() if prefix_m else ""
        e.action   = "drop" if re.search(r'\b(DROP|REJECT|DENY)\b', prefix, re.I) else "allow"
        e.severity = "WARNING" if e.action == "drop" else "INFO"
        e.message  = f"iptables {e.action}: {e.protocol} {e.source_ip}:{e.source_port} â†’ {e.dest_ip}:{e.dest_port}"
        e.extra    = kv
        return e


class PaloAltoParser(BaseParser):
    """Palo Alto Networks CSV syslog (TRAFFIC/THREAT logs)"""
    log_format = LogFormat.PALOALTO

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        # Strip syslog prefix
        csv_start = raw_line.find(",")
        if csv_start < 0: return e
        # Back up to find a proper CSV start
        try:
            reader = csv.reader(io.StringIO(raw_line))
            parts  = next(reader)
        except (StopIteration, csv.Error):
            return e
        if len(parts) < 20: return e
        # PAN-OS field positions vary by log type
        # TRAFFIC: [0]=domain [1]=recv_time [2]=serial [3]=type [4]=subtype
        # Common fields: type=parts[3]
        log_type = parts[3] if len(parts) > 3 else ""
        if log_type.upper() == "TRAFFIC":
            e.timestamp_raw = parts[1]
            e.timestamp     = _parse_iso8601(parts[1])
            e.source_ip     = parts[7]  if len(parts)>7  else None
            e.dest_ip       = parts[8]  if len(parts)>8  else None
            e.source_port   = _safe_int(parts[24]) if len(parts)>24 else None
            e.dest_port     = _safe_int(parts[25]) if len(parts)>25 else None
            e.protocol      = parts[29].lower() if len(parts)>29 else None
            e.action        = parts[30].lower() if len(parts)>30 else None
            e.username      = parts[6]  if len(parts)>6  and parts[6] else None
            e.http_bytes    = _safe_int(parts[33]) if len(parts)>33 else None
            e.severity      = "WARNING" if e.action in ("deny","drop","drop-icmp") else "INFO"
            e.message = f"PAN-OS {log_type}: {e.action} {e.protocol} {e.source_ip} â†’ {e.dest_ip}"
        elif log_type.upper() == "THREAT":
            e.timestamp_raw = parts[1]
            e.timestamp     = _parse_iso8601(parts[1])
            e.source_ip     = parts[7]  if len(parts)>7  else None
            e.dest_ip       = parts[8]  if len(parts)>8  else None
            e.message       = parts[31] if len(parts)>31 else ""
            threat_sev      = parts[16] if len(parts)>16 else ""
            sev_map = {"critical":"CRITICAL","high":"HIGH","medium":"MEDIUM",
                       "low":"LOW","informational":"INFO"}
            e.severity = sev_map.get(threat_sev.lower(), "WARNING")
        else:
            e.message  = raw_line.strip()
            e.severity = "INFO"
        e.extra["pan_type"] = log_type
        return e


class FortinetParser(BaseParser):
    """Fortinet FortiGate key=value log"""
    log_format = LogFormat.FORTINET

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        kv: dict = {}
        for m in re.finditer(r'(\w+)=(?:"([^"]*)"|([\S]+))', raw_line):
            kv[m.group(1)] = m.group(2) if m.group(2) is not None else m.group(3)
        date = kv.get("date",""); time = kv.get("time","")
        if date and time:
            e.timestamp_raw = f"{date} {time}"
            e.timestamp     = _parse_w3c_ts(date, time)
        e.source_ip   = kv.get("srcip")
        e.dest_ip     = kv.get("dstip")
        e.source_port = _safe_int(kv.get("srcport"))
        e.dest_port   = _safe_int(kv.get("dstport"))
        e.protocol    = kv.get("proto","").lower() or None
        e.action      = kv.get("action","").lower() or None
        e.username    = kv.get("user") or kv.get("srcuser")
        e.message     = kv.get("msg") or kv.get("devname")
        sev_map = {"emergency":"CRITICAL","alert":"CRITICAL","critical":"CRITICAL",
                   "error":"ERROR","warning":"WARNING","notice":"INFO",
                   "information":"INFO","debug":"INFO"}
        e.severity = sev_map.get((kv.get("level","")).lower(), "INFO")
        e.extra = kv
        return e


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# CLOUD
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class CloudTrailParser(BaseParser):
    """AWS CloudTrail JSON"""
    log_format = LogFormat.AWS_CLOUDTRAIL

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        try:
            obj = json.loads(raw_line) if isinstance(raw_line, str) else raw_line
        except json.JSONDecodeError:
            return e
        e.timestamp_raw = obj.get("eventTime","")
        e.timestamp     = _parse_iso8601(e.timestamp_raw)
        e.source_ip     = obj.get("sourceIPAddress")
        e.http_user_agent = obj.get("userAgent")
        uid = obj.get("userIdentity", {})
        e.username      = uid.get("userName") or uid.get("principalId") or uid.get("type")
        e.http_method   = obj.get("eventName")
        e.cloud_provider = "aws"
        e.cloud_region   = obj.get("awsRegion")
        e.cloud_service  = obj.get("eventSource","").replace(".amazonaws.com","")
        e.cloud_resource = str(obj.get("requestParameters","") or "")[:200]
        error = obj.get("errorCode")
        if error:
            e.auth_result = "failure"; e.severity = "WARNING"
            e.extra["error_code"]    = error
            e.extra["error_message"] = obj.get("errorMessage","")
        else:
            e.severity = "INFO"
        e.message = f"CloudTrail {e.http_method} on {e.cloud_service}"
        e.extra   = dict(obj)
        return e


class VPCFlowParser(BaseParser):
    """AWS VPC Flow Logs"""
    log_format = LogFormat.AWS_VPC_FLOW

    _FIELDS = ["version","account_id","interface_id","srcaddr","dstaddr",
               "srcport","dstport","protocol","packets","bytes",
               "start","end","action","log_status"]

    def __init__(self):
        self._fields = self._FIELDS[:]

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        line = raw_line.strip()
        if line.startswith("version") or line.startswith("#"):
            if not line.startswith("#"):
                self._fields = line.split()
            return e
        parts = line.split()
        if len(parts) < 8: return e
        row = dict(zip(self._fields, parts))
        start_ts = row.get("start","0")
        try:
            e.timestamp = datetime.fromtimestamp(float(start_ts), tz=timezone.utc)
        except (ValueError, TypeError):
            pass
        e.source_ip   = row.get("srcaddr")
        e.dest_ip     = row.get("dstaddr")
        e.source_port = _safe_int(row.get("srcport"))
        e.dest_port   = _safe_int(row.get("dstport"))
        proto_map = {"6":"tcp","17":"udp","1":"icmp"}
        e.protocol    = proto_map.get(row.get("protocol",""), row.get("protocol","").lower())
        e.action      = row.get("action","").lower()
        e.cloud_provider = "aws"
        e.cloud_resource = row.get("interface_id")
        e.cloud_account  = row.get("account_id")
        e.severity    = "WARNING" if e.action == "reject" else "INFO"
        e.http_bytes  = _safe_int(row.get("bytes"))
        e.message     = f"VPC Flow {e.action}: {e.protocol} {e.source_ip}:{e.source_port} â†’ {e.dest_ip}:{e.dest_port}"
        e.extra = row
        return e


class AzureActivityParser(BaseParser):
    """Azure Activity Log JSON"""
    log_format = LogFormat.AZURE_ACTIVITY

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        try:
            obj = json.loads(raw_line)
        except json.JSONDecodeError:
            return e
        e.timestamp_raw = obj.get("time","") or obj.get("eventTimestamp","")
        e.timestamp     = _parse_iso8601(e.timestamp_raw)
        caller = obj.get("caller","") or obj.get("claims",{}).get("upn","")
        e.username      = caller
        e.source_ip     = obj.get("httpRequest",{}).get("clientIpAddress") or obj.get("callerIpAddress")
        e.cloud_provider = "azure"
        e.cloud_resource = obj.get("resourceId","")
        e.cloud_service  = obj.get("resourceProvider","")
        e.http_method    = obj.get("operationName","")
        status = obj.get("status",{})
        e.action = (status.get("value","") if isinstance(status, dict) else str(status)).lower()
        e.severity = ("WARNING" if e.action in ("failed","canceled")
                      else "CRITICAL" if e.action == "critical" else "INFO")
        e.message = f"Azure {e.http_method}: {e.action}"
        e.extra = dict(obj)
        return e


class GCPAuditParser(BaseParser):
    """GCP Cloud Audit Log JSON"""
    log_format = LogFormat.GCP_AUDIT

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        try:
            obj = json.loads(raw_line)
        except json.JSONDecodeError:
            return e
        e.timestamp_raw = obj.get("timestamp","") or obj.get("receiveTimestamp","")
        e.timestamp     = _parse_iso8601(e.timestamp_raw)
        payload         = obj.get("protoPayload", obj.get("jsonPayload", obj))
        auth_info       = payload.get("authorizationInfo",[{}])[0] if isinstance(payload.get("authorizationInfo"), list) else {}
        e.username      = payload.get("authenticationInfo",{}).get("principalEmail")
        e.source_ip     = payload.get("requestMetadata",{}).get("callerIp")
        e.http_method   = payload.get("methodName") or payload.get("requestMethod")
        e.cloud_provider = "gcp"
        e.cloud_resource = obj.get("resource",{}).get("type","")
        status = payload.get("status",{})
        code = status.get("code",0) if isinstance(status, dict) else 0
        e.severity  = ("CRITICAL" if code >= 500
                       else "WARNING" if code >= 400 or code in (1,2,3,7,13,14,16)
                       else "INFO")
        e.action    = "allow" if auth_info.get("granted") else "deny"
        e.message   = f"GCP {e.http_method}: {e.cloud_resource}"
        e.extra     = dict(obj)
        return e


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# DATABASE
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class MySQLParser(BaseParser):
    """MySQL error / general / slow query log"""
    log_format = LogFormat.MYSQL_ERROR

    _DATE = re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})')
    _GENERAL = re.compile(r'(\d+)\s+(\w+)\s+(.*)')

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        e.process_name = "mysqld"
        # ISO timestamp
        ts_m = self._DATE.search(raw_line)
        if ts_m:
            e.timestamp_raw = ts_m.group(1)
            e.timestamp     = _parse_iso8601(ts_m.group(1))
        # Severity words
        sev_m = re.search(r'\b(ERROR|Warning|Note|System)\b', raw_line)
        sev_map = {"ERROR":"ERROR","Warning":"WARNING","Note":"INFO","System":"INFO"}
        e.severity = sev_map.get(sev_m.group(1),"INFO") if sev_m else "INFO"
        # Extract host/user from access events
        conn_m = re.search(r"Access denied for user '([^']+)'@'([^']+)'", raw_line)
        if conn_m:
            e.username    = conn_m.group(1)
            e.source_ip   = conn_m.group(2)
            e.auth_result = "failure"
            e.severity    = "WARNING"
        e.message = raw_line.strip()
        return e


class PostgreSQLParser(BaseParser):
    """PostgreSQL log"""
    log_format = LogFormat.POSTGRESQL

    _PAT = re.compile(
        r'(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:\s+\w+)?)\s+'
        r'\[(?P<pid>\d+)\]\s+(?:(?P<user>\S+)@(?P<db>\S+)\s+)?(?P<level>\w+):\s+(?P<msg>.*)'
    )

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        m = self._PAT.match(raw_line)
        if not m:
            e.message = raw_line.strip(); return e
        g = m.groupdict()
        e.timestamp_raw = g["ts"]
        # BIND format: 04-Jan-2026 10:00:00.123
        try:
            from datetime import datetime, timezone as _tz
            e.timestamp = datetime.strptime(g["ts"][:20], "%d-%b-%Y %H:%M:%S").replace(tzinfo=_tz.utc)
        except (ValueError, TypeError):
            e.timestamp = _parse_iso8601(g["ts"])
        e.source_ip = g["ip"]
        e.process_id    = _safe_int(g["pid"])
        e.username      = g.get("user")
        e.message       = g["msg"]
        e.process_name  = "postgres"
        lev = g["level"].upper()
        sev_map = {"PANIC":"CRITICAL","FATAL":"CRITICAL","ERROR":"ERROR",
                   "WARNING":"WARNING","INFO":"INFO","LOG":"INFO","DEBUG":"INFO"}
        e.severity = sev_map.get(lev, "INFO")
        # Auth failures
        if "password authentication failed" in g["msg"].lower():
            e.auth_result = "failure"; e.severity = "WARNING"
        ip_m = re.search(r'host="([^"]+)"', g["msg"])
        if ip_m:
            e.source_ip = ip_m.group(1)
        return e


class MongoDBParser(BaseParser):
    """MongoDB log (4.4+ JSON format)"""
    log_format = LogFormat.MONGODB

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        try:
            obj = json.loads(raw_line)
            e.timestamp_raw = str(obj.get("t",""))
            e.timestamp     = _parse_iso8601(str(obj.get("t",{}).get("$date","")))
            e.process_id    = _safe_int(obj.get("ctx","").split("-")[-1] if "-" in str(obj.get("ctx","")) else None)
            e.message       = obj.get("msg","")
            sev_map = {"F":"CRITICAL","E":"ERROR","W":"WARNING","I":"INFO","D":"INFO"}
            e.severity = sev_map.get(obj.get("s","I"), "INFO")
            attr = obj.get("attr",{})
            if isinstance(attr, dict):
                e.source_ip = attr.get("remote","").split(":")[0] or None
                e.username  = attr.get("user") or attr.get("principalName")
            e.extra = obj
        except (json.JSONDecodeError, AttributeError):
            # Older text format: YYYY-MM-DDTHH:MM:SS.mmm+0000 severity component [context] message
            old_m = re.match(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\S+)\s+(\w)\s+\S+\s+\[([^\]]+)\]\s+(.*)', raw_line)
            if old_m:
                e.timestamp_raw = old_m.group(1)
                e.timestamp     = _parse_iso8601(old_m.group(1))
                sev_map = {"F":"CRITICAL","E":"ERROR","W":"WARNING","I":"INFO","D":"INFO"}
                e.severity = sev_map.get(old_m.group(2),"INFO")
                e.message  = old_m.group(4)
        return e


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# CONTAINER / KUBERNETES
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class DockerJSONParser(BaseParser):
    """Docker container log (--log-driver json-file)"""
    log_format = LogFormat.DOCKER_JSON

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        try:
            obj = json.loads(raw_line)
        except json.JSONDecodeError:
            return e
        e.timestamp_raw = obj.get("time","")
        e.timestamp     = _parse_iso8601(e.timestamp_raw)
        e.message       = obj.get("log","").strip()
        stream          = obj.get("stream","stdout")
        e.severity      = "ERROR" if stream == "stderr" else "INFO"
        e.extra["stream"] = stream
        # Try to parse inner log message
        if e.message and e.message.startswith("{"):
            try:
                inner = json.loads(e.message)
                e.extra["inner"] = inner
                e.severity = inner.get("level","INFO").upper() if "level" in inner else e.severity
            except json.JSONDecodeError:
                pass
        return e


class KubernetesAuditParser(BaseParser):
    """Kubernetes API Server Audit Log JSON"""
    log_format = LogFormat.KUBERNETES_AUDIT

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        try:
            obj = json.loads(raw_line)
        except json.JSONDecodeError:
            return e
        e.timestamp_raw = obj.get("stageTimestamp","") or obj.get("requestReceivedTimestamp","")
        e.timestamp     = _parse_iso8601(e.timestamp_raw)
        e.http_method   = obj.get("verb","")
        e.http_uri      = obj.get("requestURI","")
        e.source_ip     = obj.get("sourceIPs",[None])[0] if obj.get("sourceIPs") else None
        user            = obj.get("user",{})
        e.username      = user.get("username")
        res             = obj.get("objectRef",{})
        e.cloud_resource = f"{res.get('resource','')}/{res.get('name','')}"
        code            = obj.get("responseStatus",{}).get("code",0)
        e.http_status   = code
        e.severity      = ("CRITICAL" if code >= 500
                           else "WARNING" if code >= 400
                           else "INFO")
        e.action        = "allow" if code < 400 else "deny"
        e.message = f"K8s audit: {e.http_method} {e.http_uri} â†’ {code}"
        e.extra   = dict(obj)
        return e


class FalcoParser(BaseParser):
    """Falco runtime security JSON alerts"""
    log_format = LogFormat.FALCO

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        try:
            obj = json.loads(raw_line)
        except json.JSONDecodeError:
            # Text format: 11:30:02.450022704: Warning Sensitive file opened for reading...
            text_m = re.match(r'(\S+):\s+(\w+)\s+(.*)', raw_line)
            if text_m:
                e.message  = text_m.group(3)
                sev_m = {"Emergency":"CRITICAL","Alert":"CRITICAL","Critical":"CRITICAL",
                         "Error":"ERROR","Warning":"WARNING","Notice":"INFO","Informational":"INFO"}
                e.severity = sev_m.get(text_m.group(2),"WARNING")
            return e
        e.timestamp_raw = obj.get("time","")
        e.timestamp     = _parse_iso8601(e.timestamp_raw)
        e.message       = obj.get("output","")
        sev_map = {"EMERGENCY":"CRITICAL","ALERT":"CRITICAL","CRITICAL":"CRITICAL",
                   "ERROR":"ERROR","WARNING":"WARNING","NOTICE":"INFO","INFORMATIONAL":"INFO"}
        e.severity = sev_map.get(obj.get("priority","WARNING").upper(), "WARNING")
        fields = obj.get("output_fields",{})
        e.process_name = fields.get("proc.name")
        e.process_id   = _safe_int(fields.get("proc.pid"))
        e.command_line = fields.get("proc.cmdline")
        e.username     = fields.get("user.name")
        e.hostname     = fields.get("container.id") or fields.get("k8s.pod.name")
        e.file_path    = fields.get("fd.name")
        e.extra        = obj
        return e


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# EMAIL
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class PostfixParser(BaseParser):
    """Postfix mail log"""
    log_format = LogFormat.POSTFIX

    _BASE = re.compile(
        r'^(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+postfix/(\w+)\[(\d+)\]:\s+(.*)'
    )
    _SMTP = re.compile(r'status=(\w+)')
    _SASL = re.compile(r'SASL (\w+) authentication failed.*client=(\S+)')
    _FROM = re.compile(r'from=<([^>]*)>')
    _TO   = re.compile(r'to=<([^>]*)>')
    _RELAY = re.compile(r'relay=(\S+)')

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        m = self._BASE.match(raw_line)
        if not m:
            return e
        ts_raw, host, service, pid, msg = m.groups()
        e.timestamp_raw = ts_raw
        e.timestamp     = _parse_syslog_ts(ts_raw)
        e.hostname      = host
        e.process_name  = f"postfix/{service}"
        e.process_id    = _safe_int(pid)
        e.message       = msg
        # SASL auth failure
        sa = self._SASL.search(msg)
        if sa:
            e.auth_result = "failure"
            e.severity    = "WARNING"
            e.source_ip   = sa.group(2).split("[")[-1].rstrip("]") if "[" in sa.group(2) else None
            return e
        # Delivery status
        status_m = self._SMTP.search(msg)
        if status_m:
            status = status_m.group(1).lower()
            e.severity = ("ERROR" if status in ("bounced","deferred","undeliverable")
                          else "INFO")
        from_m = self._FROM.search(msg)
        if from_m:
            e.username = from_m.group(1) or None
        # Extract relay IP
        relay_m = self._RELAY.search(msg)
        if relay_m:
            relay = relay_m.group(1)
            ip_m = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', relay)
            if ip_m:
                e.source_ip = ip_m.group(1)
        e.severity = e.severity or "INFO"
        return e


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# DNS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class BINDQueryParser(BaseParser):
    """BIND9 query log"""
    log_format = LogFormat.BIND_QUERY

    _PAT = re.compile(
        r'(?P<ts>\d{2}-\w{3}-\d{4}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+'
        r'(?:client\s+@[^\s]+\s+)?(?P<ip>[\d\.]+)#(?P<port>\d+)\s+'
        r'(?:\([^)]+\)\s+)?query:\s+(?P<query>\S+)\s+(?P<cls>\w+)\s+(?P<type>\w+)'
        r'(?:\s+(?P<flags>[+-?]\w*))?'
    )

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        m = self._PAT.search(raw_line)
        if not m:
            e.message = raw_line.strip(); return e
        g = m.groupdict()
        e.timestamp_raw = g["ts"]
        # BIND format: 04-Jan-2026 10:00:00.123
        try:
            from datetime import datetime, timezone as _tz
            e.timestamp = datetime.strptime(g["ts"][:20], "%d-%b-%Y %H:%M:%S").replace(tzinfo=_tz.utc)
        except (ValueError, TypeError):
            e.timestamp = _parse_iso8601(g["ts"])
        e.source_ip = g["ip"]
        e.source_ip     = g["ip"]
        e.source_port   = _safe_int(g["port"])
        e.dns_query     = g["query"]
        e.dns_type      = g["type"]
        e.protocol      = "dns"
        # Flag DGA-like: very long random-looking domains
        if len(g["query"]) > 50 or re.search(r'[a-z0-9]{20,}', g["query"]):
            e.severity = "WARNING"
        else:
            e.severity = "INFO"
        e.message = f"DNS query {e.dns_type} {e.dns_query} from {e.source_ip}"
        return e


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# GENERIC JSON / CSV / XML
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class JsonParser(BaseParser):
    """Generic JSONL â€” one JSON object per line"""
    log_format = LogFormat.JSON_GENERIC

    _IP_KEYS   = ["ip","src_ip","source_ip","remote_addr","clientip","sourceIPAddress",
                  "ipAddress","client_ip","origin","remote_ip"]
    _TIME_KEYS = ["timestamp","time","eventTime","@timestamp","created","datetime","ts",
                  "date","log_time","event_time","record_time"]
    _MSG_KEYS  = ["message","msg","log","text","event","description","detail","content"]
    _USER_KEYS = ["user","username","userName","user_name","targetUserName","actor",
                  "account","login","principal","email"]

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        try:
            obj = json.loads(raw_line)
        except json.JSONDecodeError:
            e.message = f"[JSON error] {raw_line[:80]}"; return e
        if not isinstance(obj, dict):
            return e

        for key in self._IP_KEYS:
            if key in obj:
                e.source_ip = str(obj[key]); break
        for key in self._TIME_KEYS:
            if key in obj:
                raw_ts = str(obj[key]); e.timestamp_raw = raw_ts
                e.timestamp = _parse_iso8601(raw_ts); break
        for key in self._MSG_KEYS:
            if key in obj:
                e.message = str(obj[key]); break
        for key in self._USER_KEYS:
            if key in obj:
                e.username = str(obj[key]); break

        e.http_method     = obj.get("method") or obj.get("request_method") or obj.get("verb")
        e.http_uri        = obj.get("uri") or obj.get("path") or obj.get("request_uri") or obj.get("url")
        e.http_status     = _safe_int(obj.get("status") or obj.get("response_code") or obj.get("status_code"))
        e.http_bytes      = _safe_int(obj.get("bytes") or obj.get("response_bytes") or obj.get("size"))
        e.http_user_agent = obj.get("user_agent") or obj.get("agent") or obj.get("useragent")
        e.hostname        = obj.get("hostname") or obj.get("host") or obj.get("server") or e.hostname
        e.dest_ip         = obj.get("dest_ip") or obj.get("dst_ip") or obj.get("destination_ip")
        e.source_port     = _safe_int(obj.get("src_port") or obj.get("sport") or obj.get("source_port"))
        e.dest_port       = _safe_int(obj.get("dst_port") or obj.get("dport") or obj.get("dest_port") or obj.get("port"))
        e.protocol        = (obj.get("proto") or obj.get("protocol") or "").lower() or None
        e.severity        = (obj.get("level") or obj.get("severity") or obj.get("log_level") or
                             obj.get("loglevel") or "INFO").upper()
        if e.severity not in ("CRITICAL","HIGH","ERROR","WARNING","WARN","INFO","DEBUG"):
            e.severity = _http_severity(e.http_status)
        e.severity = e.severity.replace("WARN","WARNING")

        if e.http_uri:
            e.http_uri_decoded = unquote_plus(e.http_uri)
        e.extra = dict(obj)
        return e


class GELFParser(BaseParser):
    """Graylog Extended Log Format JSON"""
    log_format = LogFormat.GELF

    _SEV = {0:"CRITICAL",1:"CRITICAL",2:"CRITICAL",3:"ERROR",
            4:"WARNING",5:"INFO",6:"INFO",7:"INFO"}

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        try:
            obj = json.loads(raw_line)
        except json.JSONDecodeError:
            return e
        e.timestamp_raw = str(obj.get("timestamp",""))
        try:
            e.timestamp = datetime.fromtimestamp(float(obj.get("timestamp",0)), tz=timezone.utc)
        except (ValueError, TypeError):
            pass
        e.hostname     = obj.get("host")
        e.message      = obj.get("short_message","") or obj.get("full_message","")
        e.severity     = self._SEV.get(obj.get("level",6), "INFO")
        e.source_ip    = obj.get("_src_ip") or obj.get("_source_ip")
        e.username     = obj.get("_username") or obj.get("_user")
        e.http_status  = _safe_int(obj.get("_http_status") or obj.get("_status"))
        e.extra        = {k: v for k, v in obj.items() if k.startswith("_")}
        return e


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# AI FALLBACK PARSER
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class AIParser(BaseParser):
    """
    AI-assisted parser for completely unknown log formats.

    Uses the LLM client to extract structured fields from an unrecognised
    log line. Caches the format schema after the first 5 lines to avoid
    calling the LLM on every single line.

    Fields extracted by LLM:
        timestamp, source_ip, dest_ip, source_port, dest_port,
        username, message, severity, http_method, http_uri,
        http_status, process_name, event_id, action, protocol

    The parser never raises â€” if LLM is unavailable, returns a minimal
    entry with the raw line stored in message.
    """
    log_format = LogFormat.AI_PARSED

    def __init__(self):
        self._llm       = None
        self._schema    = None      # cached field extraction instructions
        self._sample_lines: list = []
        self._sample_max = 5
        self._init_llm()

    def _init_llm(self):
        try:
            import os, sys
            root = os.path.dirname(os.path.abspath(__file__))
            for _ in range(8):
                if os.path.isfile(os.path.join(root, "pathconfig.py")):
                    break
                root = os.path.dirname(root)
            if root not in sys.path:
                sys.path.insert(0, root)
            from ai.llm_client import LLMClient
            self._llm = LLMClient()
        except Exception:
            self._llm = None

    def _ask_llm(self, prompt: str) -> str:
        if self._llm is None:
            return ""
        try:
            return self._llm.generate(prompt, context="", max_tokens=300)
        except Exception:
            return ""

    def _build_schema(self, sample_lines: list[str]) -> dict:
        """Ask LLM to identify the log format and field positions."""
        samples = "\n".join(sample_lines[:5])
        prompt  = (
            "You are a log format expert. Analyse these log lines and return ONLY "
            "a JSON object with keys: format_name, field_map (mapping field name â†’ "
            "regex or position), timestamp_format, confidence (0-1).\n\n"
            f"Log samples:\n{samples}\n\n"
            "Respond ONLY with a valid JSON object, no prose."
        )
        raw = self._ask_llm(prompt)
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return {}

    def _extract_fields(self, raw_line: str) -> dict:
        """Ask LLM to extract structured fields from a single line."""
        prompt = (
            "Extract fields from this log line. "
            "Return ONLY a JSON object with any of these keys that apply: "
            "timestamp, source_ip, dest_ip, source_port, dest_port, "
            "username, message, severity, http_method, http_uri, http_status, "
            "process_name, event_id, action, protocol, hostname, "
            "file_path, command_line, dns_query, dns_type.\n\n"
            f"Log line: {raw_line[:500]}\n\n"
            "Respond ONLY with a valid JSON object."
        )
        raw = self._ask_llm(prompt)
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            # Template fallback: try basic regex extraction
            return self._template_extract(raw_line)

    def _template_extract(self, raw_line: str) -> dict:
        """Regex-based extraction when LLM is unavailable."""
        fields: dict = {}
        # IP addresses
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw_line)
        if ips:
            fields["source_ip"] = ips[0]
            if len(ips) > 1:
                fields["dest_ip"] = ips[1]
        # Timestamps (various)
        ts_m = re.search(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', raw_line)
        if ts_m:
            fields["timestamp"] = ts_m.group(0)
        # Port numbers
        ports = re.findall(r'(?:port|:)(\d{2,5})\b', raw_line, re.IGNORECASE)
        if ports:
            fields["dest_port"] = ports[0]
        # Severity words
        sev_m = re.search(r'\b(CRITICAL|ERROR|WARNING|WARN|INFO|DEBUG|NOTICE|ALERT)\b',
                          raw_line, re.IGNORECASE)
        if sev_m:
            fields["severity"] = sev_m.group(1).upper().replace("WARN","WARNING")
        # HTTP method
        http_m = re.search(r'\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b', raw_line)
        if http_m:
            fields["http_method"] = http_m.group(1)
        # HTTP status
        status_m = re.search(r'\b([1-5]\d{2})\b', raw_line)
        if status_m:
            fields["http_status"] = status_m.group(1)
        # Username hints
        user_m = re.search(r'(?:user|username|login)[=:\s]+(\S+)', raw_line, re.IGNORECASE)
        if user_m:
            fields["username"] = user_m.group(1).strip("\"'")
        fields["message"] = raw_line.strip()
        return fields

    def parse_line(self, raw_line: str, line_number: int, source_file: str) -> LogEntry:
        e = self._minimal(raw_line, line_number, source_file)
        e.log_format = LogFormat.AI_PARSED

        # Collect sample lines to build schema
        if len(self._sample_lines) < self._sample_max:
            self._sample_lines.append(raw_line)

        # Use LLM to extract fields
        fields = self._extract_fields(raw_line)
        if not fields:
            e.message = raw_line.strip()
            e.severity = "INFO"
            return e

        # Map extracted fields onto LogEntry
        ts_raw = fields.get("timestamp")
        if ts_raw:
            e.timestamp_raw = str(ts_raw)
            e.timestamp     = _parse_iso8601(str(ts_raw))

        e.source_ip     = str(fields.get("source_ip","")) or None
        e.dest_ip       = str(fields.get("dest_ip","")) or None
        e.source_port   = _safe_int(fields.get("source_port"))
        e.dest_port     = _safe_int(fields.get("dest_port"))
        e.username      = str(fields.get("username","")) or None
        e.hostname      = str(fields.get("hostname","")) or None
        e.message       = str(fields.get("message", raw_line.strip()))
        e.http_method   = str(fields.get("http_method","")) or None
        e.http_uri      = str(fields.get("http_uri","")) or None
        e.http_status   = _safe_int(fields.get("http_status"))
        e.process_name  = str(fields.get("process_name","")) or None
        e.event_id      = str(fields.get("event_id","")) or None
        e.action        = str(fields.get("action","")) or None
        e.protocol      = str(fields.get("protocol","")).lower() or None
        e.command_line  = str(fields.get("command_line","")) or None
        e.file_path     = str(fields.get("file_path","")) or None
        e.dns_query     = str(fields.get("dns_query","")) or None
        e.dns_type      = str(fields.get("dns_type","")) or None

        sev = str(fields.get("severity","INFO")).upper().replace("WARN","WARNING")
        e.severity = sev if sev in ("CRITICAL","ERROR","WARNING","INFO") else \
                     _http_severity(e.http_status)
        e.ai_confidence = 0.8 if self._llm else 0.4
        e.extra["ai_parsed"] = True
        e.extra["ai_fields"] = fields
        return e


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# PARSER REGISTRY
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

# Singleton instances (stateless parsers can be shared)
_REGISTRY: dict[LogFormat, BaseParser] = {
    # Web / Proxy
    LogFormat.APACHE_COMBINED:  ApacheCombinedParser(),
    LogFormat.APACHE_ERROR:     ApacheErrorParser(),
    LogFormat.NGINX_ACCESS:     ApacheCombinedParser(),   # same format
    LogFormat.NGINX_ERROR:      NginxErrorParser(),
    LogFormat.IIS_W3C:          IISParser(),
    LogFormat.HAPROXY:          HAProxyParser(),
    LogFormat.SQUID:            SquidParser(),
    LogFormat.CADDY:            JsonParser(),              # Caddy uses JSON
    LogFormat.TRAEFIK:          JsonParser(),              # Traefik uses JSON
    # System / OS
    LogFormat.SYSLOG:           SyslogParser(),
    LogFormat.SYSLOG_RFC5424:   SyslogRFC5424Parser(),
    LogFormat.AUTH_LOG:         SyslogParser(),
    LogFormat.AUDITD:           AuditdParser(),
    LogFormat.JOURNALD:         JournaldParser(),
    LogFormat.KERN_LOG:         KernLogParser(),
    LogFormat.DMESG:            KernLogParser(),
    LogFormat.MACOS_UNIFIED:    JsonParser(),              # JSON output
    # Windows
    LogFormat.WINDOWS_EVTX:     EvtxParser(),
    LogFormat.WINDOWS_SYSMON:   SysmonParser(),
    LogFormat.WINDOWS_FIREWALL: WindowsFirewallParser(),
    LogFormat.WINDOWS_DNS:      SyslogParser(),            # syslog-wrapped
    LogFormat.POWERSHELL_SCRIPT: PowerShellParser(),
    # Network / Security
    LogFormat.ZEEK_CONN:        ZeekConnParser(),
    LogFormat.ZEEK_DNS:         ZeekDNSParser(),
    LogFormat.ZEEK_HTTP:        ZeekHTTPParser(),
    LogFormat.ZEEK_SSL:         ZeekSSLParser(),
    LogFormat.ZEEK_FILES:       ZeekJSONParser(),
    LogFormat.ZEEK_JSON:        ZeekJSONParser(),
    LogFormat.SURICATA_EVE:     SuricataEVEParser(),
    LogFormat.SNORT_FAST:       SnortFastParser(),
    LogFormat.CISCO_ASA:        CiscoASAParser(),
    LogFormat.CISCO_IOS:        SyslogParser(),            # standard syslog
    LogFormat.PALOALTO:         PaloAltoParser(),
    LogFormat.FORTINET:         FortinetParser(),
    LogFormat.CHECKPOINT:       CEFParser(),               # Checkpoint sends CEF
    LogFormat.PFSENSE:          SyslogParser(),            # syslog-wrapped
    LogFormat.IPTABLES:         IPTablesParser(),
    LogFormat.CEF:              CEFParser(),
    LogFormat.LEEF:             LEEFParser(),
    LogFormat.GELF:             GELFParser(),
    # Cloud
    LogFormat.AWS_CLOUDTRAIL:   CloudTrailParser(),
    LogFormat.AWS_VPC_FLOW:     VPCFlowParser(),
    LogFormat.AWS_ALB:          ApacheCombinedParser(),    # ALB is Apache-like
    LogFormat.AWS_WAF:          JsonParser(),
    LogFormat.AWS_S3_ACCESS:    ApacheCombinedParser(),
    LogFormat.AZURE_ACTIVITY:   AzureActivityParser(),
    LogFormat.AZURE_SIGNIN:     AzureActivityParser(),
    LogFormat.AZURE_NSG_FLOW:   JsonParser(),
    LogFormat.GCP_AUDIT:        GCPAuditParser(),
    LogFormat.GCP_VPC_FLOW:     JsonParser(),
    # Database
    LogFormat.MYSQL_ERROR:      MySQLParser(),
    LogFormat.MYSQL_GENERAL:    MySQLParser(),
    LogFormat.MYSQL_SLOW:       MySQLParser(),
    LogFormat.POSTGRESQL:       PostgreSQLParser(),
    LogFormat.MSSQL:            SyslogParser(),
    LogFormat.MONGODB:          MongoDBParser(),
    LogFormat.REDIS:            SyslogParser(),
    # Container / Kubernetes
    LogFormat.DOCKER_JSON:      DockerJSONParser(),
    LogFormat.KUBERNETES_AUDIT: KubernetesAuditParser(),
    LogFormat.KUBERNETES_POD:   DockerJSONParser(),
    LogFormat.FALCO:            FalcoParser(),
    # Email
    LogFormat.POSTFIX:          PostfixParser(),
    LogFormat.EXCHANGE:         JsonParser(),
    LogFormat.SENDMAIL:         SyslogParser(),
    # DNS
    LogFormat.BIND_QUERY:       BINDQueryParser(),
    LogFormat.WINDOWS_DNS_QUERY: SyslogParser(),
    # Generic
    LogFormat.JSON_GENERIC:     JsonParser(),
    LogFormat.JSON_LINES:       JsonParser(),
    LogFormat.GELF:             GELFParser(),
    # AI / Unknown
    LogFormat.AI_PARSED:        AIParser(),
    LogFormat.UNKNOWN:          AIParser(),   # unknown â†’ AI parser
}


def get_parser(fmt: LogFormat) -> BaseParser:
    """Return the parser for a given format. Falls back to AIParser for UNKNOWN."""
    return _REGISTRY.get(fmt, AIParser())


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# ANDROID LOGCAT
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class AndroidLogcatParser(BaseParser):
    """
    Android Logcat format.
    Pattern: MM-DD HH:MM:SS.mmm  PID  TID LEVEL TAG: message
    Example: 03-17 16:13:38.811  1702  2395 D WindowManager: printFreezing...
    """
    log_format = LogFormat.ANDROID_LOGCAT

    _PAT = re.compile(
        r'^(?P<date>\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2}\.\d+)'
        r'\s+(?P<pid>\d+)\s+(?P<tid>\d+)'
        r'\s+(?P<level>[VDIWEF])\s+'
        r'(?P<tag>[^:]+):\s*(?P<msg>.*)'
    )
    _LEVELS = {
        'V': 'INFO', 'D': 'INFO', 'I': 'INFO',
        'W': 'WARNING', 'E': 'ERROR', 'F': 'CRITICAL'
    }

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        line = raw_line.rstrip('\r\n')
        m = self._PAT.match(line)
        if not m:
            e.message = line.strip()
            return e
        g = m.groupdict()
        # Android has no year â€” use current year
        year = datetime.now(timezone.utc).year
        try:
            e.timestamp = datetime.strptime(
                f"{year}-{g['date']} {g['time'][:8]}", "%Y-%m-%d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
        e.timestamp_raw = f"{g['date']} {g['time']}"
        e.process_id    = _safe_int(g['pid'])
        e.extra['tid']  = g['tid']
        e.process_name  = g['tag'].strip()
        e.message       = g['msg'].strip()
        e.severity      = self._LEVELS.get(g['level'], 'INFO')
        # Extract package names as hostname equivalent
        pkg = re.search(r'([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){2,})', g['tag'])
        if pkg:
            e.hostname = pkg.group(1)
        # Security flags
        if g['level'] in ('E', 'F'):
            if any(w in g['msg'].lower() for w in
                   ['permission denied', 'security', 'exploit', 'violation',
                    'crash', 'fatal', 'exception']):
                e.severity = 'ERROR' if g['level'] == 'E' else 'CRITICAL'
        return e


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# HADOOP / LOG4J FAMILY (Hadoop, Spark, Kafka, ZooKeeper, Spring Boot, etc.)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class Log4jParser(BaseParser):
    """
    Apache Log4j / Log4j2 pattern layout parser.
    Covers: Hadoop, Spark, Kafka, ZooKeeper, HBase, Hive, Spring Boot, Log4net.

    Common patterns:
      YYYY-MM-DD HH:MM:SS,mmm LEVEL ClassName (ThreadName): message
      YYYY-MM-DD HH:MM:SS.mmm [Thread] LEVEL Class - message
      INFO [main] o.a.h.c.NameNode: Starting server...
    """
    log_format = LogFormat.LOG4J

    # Pattern 1: Standard log4j - timestamp LEVEL class thread: msg
    _PAT1 = re.compile(
        r'^(?P<ts>\d{4}-\d{2}-\d{2}[T ,]\d{2}:\d{2}:\d{2}[,\.]\d+)'
        r'\s+(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)'
        r'\s+(?P<class>\S+)'
        r'(?:\s+\((?P<thread>[^)]+)\))?'
        r'(?::?\s+(?P<msg>.*))?'
    )
    # Pattern 2: [timestamp] [thread] LEVEL class - msg (Spark/Spring style)
    _PAT2 = re.compile(
        r'^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[,\.]\d+)?)'
        r'\s+\[(?P<thread>[^\]]+)\]'
        r'\s+(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)'
        r'\s+(?P<class>\S+)'
        r'\s+-\s+(?P<msg>.*)'
    )
    # Pattern 3: LEVEL [thread] class: msg (short log4j)
    _PAT3 = re.compile(
        r'^(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)'
        r'\s+\[(?P<thread>[^\]]+)\]'
        r'\s+(?P<class>\S+):\s+(?P<msg>.*)'
    )
    # Pattern 4: YY/MM/DD HH:MM:SS LEVEL class@host: msg (ZooKeeper)
    _PAT4 = re.compile(
        r'^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d+)'
        r'\s+\[(?P<thread>[^\]]+)\]'
        r'\s+(?P<level>DEBUG|INFO|WARN|ERROR|FATAL)'
        r'\s+(?P<class>[^:]+):\s*(?P<msg>.*)'
    )

    _SEV = {
        'TRACE': 'INFO', 'DEBUG': 'INFO', 'INFO': 'INFO',
        'WARN': 'WARNING', 'WARNING': 'WARNING',
        'ERROR': 'ERROR', 'FATAL': 'CRITICAL', 'CRITICAL': 'CRITICAL',
    }

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        line = raw_line.rstrip('\r\n').strip()

        for pat in (self._PAT4, self._PAT1, self._PAT2, self._PAT3):
            m = pat.match(line)
            if not m:
                continue
            g = m.groupdict()
            ts = g.get('ts', '')
            if ts:
                e.timestamp_raw = ts
                e.timestamp = _parse_iso8601(ts.replace(',', '.'))
            level = g.get('level', 'INFO').upper().replace('WARN', 'WARNING')
            e.severity     = self._SEV.get(level, 'INFO')
            e.process_name = g.get('class', '').strip()
            e.message      = (g.get('msg') or '').strip()
            e.extra['thread'] = g.get('thread', '')
            # Extract IPs
            ip_m = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', e.message)
            if ip_m:
                e.source_ip = ip_m.group(0)
            # Extract hostname from class (e.g. org.apache.hadoop.hdfs.server.namenode.NameNode)
            cls = g.get('class', '')
            if cls and len(cls) > 4:
                e.hostname = cls.split('.')[-1] if '.' in cls else cls
            return e

        # Generic: just grab level and message
        lev_m = re.search(r'\b(TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL)\b', line)
        e.severity = self._SEV.get((lev_m.group(1) if lev_m else 'INFO').upper(), 'INFO')
        e.message  = line
        # Timestamp anywhere in line
        ts_m = re.search(r'\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}', line)
        if ts_m:
            e.timestamp_raw = ts_m.group(0)
            e.timestamp = _parse_iso8601(ts_m.group(0))
        return e


class HadoopParser(Log4jParser):
    """Apache Hadoop â€” uses Log4j format with Hadoop-specific enrichment."""
    log_format = LogFormat.HADOOP

    _HADOOP_COMPONENTS = {
        'NameNode': 'hdfs', 'DataNode': 'hdfs', 'SecondaryNameNode': 'hdfs',
        'ResourceManager': 'yarn', 'NodeManager': 'yarn', 'ApplicationMaster': 'yarn',
        'JobTracker': 'mapreduce', 'TaskTracker': 'mapreduce',
        'HMaster': 'hbase', 'HRegionServer': 'hbase',
    }

    def parse_line(self, raw_line, line_number, source_file):
        e = super().parse_line(raw_line, line_number, source_file)
        e.log_format = LogFormat.HADOOP
        # Map component name
        for comp, svc in self._HADOOP_COMPONENTS.items():
            if comp in (e.process_name or '') or comp in (e.message or ''):
                e.extra['hadoop_service'] = svc
                break
        # Security: failed operations, exceptions
        msg_lower = (e.message or '').lower()
        if any(w in msg_lower for w in ['exception', 'error', 'failed', 'permission denied']):
            if e.severity == 'INFO':
                e.severity = 'WARNING'
        return e


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# WINDOWS CBS / SERVICING LOG
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class WindowsCBSParser(BaseParser):
    """
    Windows Component-Based Servicing (CBS) log.
    Format: YYYY-MM-DD HH:MM:SS, Level      Component  message

    Example:
    2016-09-28 04:30:30, Info                  CBS    Loaded Servicing Stack
    2016-09-28 04:30:31, Info                  CSI    00000001@2016/9/27:...
    """
    log_format = LogFormat.WINDOWS_CBS

    _PAT = re.compile(
        r'^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})'
        r',\s+(?P<level>\w+)'
        r'\s+(?P<component>\w+)\s+'
        r'(?P<msg>.*)'
    )
    _SEV = {
        'Info': 'INFO', 'Warning': 'WARNING', 'Error': 'ERROR',
        'Debug': 'INFO', 'Verbose': 'INFO',
    }

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        line = raw_line.rstrip('\r\n')
        m = self._PAT.match(line)
        if not m:
            e.message = line.strip()
            return e
        g = m.groupdict()
        e.timestamp_raw = g['ts']
        e.timestamp     = _parse_iso8601(g['ts'])
        e.severity      = self._SEV.get(g['level'], 'INFO')
        e.process_name  = g['component']
        e.message       = g['msg'].strip()
        # Flag failures
        msg = e.message.lower()
        if any(w in msg for w in ['failed', 'error', 'hresult = 0x8', 'corrupt']):
            if e.severity == 'INFO':
                e.severity = 'WARNING'
        if 'E_FAIL' in e.message or 'HRESULT = 0x80' in e.message:
            e.severity = 'ERROR'
        e.extra['cbs_component'] = g['component']
        return e


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# OPENSTACK (Nova, Keystone, Neutron, Cinder, Swift)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class OpenStackParser(BaseParser):
    """
    OpenStack service logs (Nova, Keystone, Neutron, Cinder, Swift, Glance).

    Format:
    YYYY-MM-DD HH:MM:SS.mmm PID LEVEL nova.compute.manager [-] Starting instance...
    YYYY-MM-DD HH:MM:SS.mmm HOSTNAME nova.api [-] GET /v2/servers -> 200 OK

    Detects auth failures, API errors, VM operations, tenant/project context.
    """
    log_format = LogFormat.OPENSTACK

    _PAT = re.compile(
        r'^(?:\S+\s+)?'  # Optional filename prefix
        r'(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)'
        r'(?:\s+(?P<pid>\d+))?'
        r'\s+(?P<level>DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL|AUDIT|TRACE)'
        r'\s+(?P<module>\S+)'
        r'(?:\s+\[(?P<req>[^\]]*)\])?'
        r'\s+(?P<msg>.*)'
    )
    _SEV = {
        'DEBUG': 'INFO', 'TRACE': 'INFO', 'INFO': 'INFO', 'AUDIT': 'INFO',
        'WARNING': 'WARNING', 'WARN': 'WARNING',
        'ERROR': 'ERROR', 'CRITICAL': 'CRITICAL',
    }
    # OpenStack services
    _SVC_MAP = {
        'nova': 'compute', 'keystone': 'identity', 'neutron': 'network',
        'cinder': 'storage', 'swift': 'objectstore', 'glance': 'image',
        'heat': 'orchestration', 'horizon': 'dashboard', 'manila': 'share',
        'octavia': 'loadbalancer', 'barbican': 'key-manager',
    }

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        line = raw_line.rstrip('\r\n')
        m = self._PAT.match(line)
        if not m:
            e.message = line.strip()
            return e
        g = m.groupdict()
        e.timestamp_raw = g['ts']
        e.timestamp     = _parse_iso8601(g['ts'])
        e.process_id    = _safe_int(g.get('pid'))
        level = (g['level'] or 'INFO').upper().replace('WARN', 'WARNING')
        e.severity      = self._SEV.get(level, 'INFO')
        e.process_name  = g['module']
        e.message       = g['msg'].strip()
        e.cloud_provider = 'openstack'

        # Identify service
        module = g['module'].lower()
        for svc, svc_type in self._SVC_MAP.items():
            if svc in module:
                e.cloud_service = svc_type
                break

        # Extract request context [req-xxx tenant-xxx user-xxx]
        req_ctx = g.get('req', '') or ''
        req_m = re.search(r'req-([0-9a-f-]+)', req_ctx)
        if req_m:
            e.extra['request_id'] = req_m.group(1)
        tenant_m = re.search(r'([0-9a-f]{32})', req_ctx)
        if tenant_m:
            e.cloud_account = tenant_m.group(1)

        # HTTP API calls
        http_m = re.search(
            r'"?(GET|POST|PUT|DELETE|PATCH|HEAD)\s+(\S+)\s+HTTP[^"]*"\s+(\d{3})',
            e.message)
        if http_m:
            e.http_method = http_m.group(1)
            e.http_uri    = http_m.group(2)
            e.http_status = _safe_int(http_m.group(3))
            e.severity    = _http_severity(e.http_status)

        # Auth events
        msg_l = e.message.lower()
        if 'authenticated' in msg_l or 'token created' in msg_l:
            e.auth_result = 'success'
        elif 'unauthorized' in msg_l or 'authentication failed' in msg_l or 'forbidden' in msg_l:
            e.auth_result = 'failure'
            e.severity = 'WARNING'

        # Extract IP
        ip_m = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', e.message)
        if ip_m:
            e.source_ip = ip_m.group(0)

        # Username
        user_m = re.search(r'user[_\s]+(?:id[:\s]+)?([a-f0-9]{32}|\w+@\S+|\w{3,})', e.message, re.I)
        if user_m:
            e.username = user_m.group(1)

        return e


class OpenStackNovaParser(OpenStackParser):
    log_format = LogFormat.OPENSTACK_NOVA
    def parse_line(self, r, ln, sf):
        e = super().parse_line(r, ln, sf)
        e.log_format = LogFormat.OPENSTACK_NOVA
        e.cloud_service = 'compute'
        return e

class OpenStackKeystoneParser(OpenStackParser):
    log_format = LogFormat.OPENSTACK_KEYSTONE
    def parse_line(self, r, ln, sf):
        e = super().parse_line(r, ln, sf)
        e.log_format = LogFormat.OPENSTACK_KEYSTONE
        e.cloud_service = 'identity'
        return e

class OpenStackNeutronParser(OpenStackParser):
    log_format = LogFormat.OPENSTACK_NEUTRON
    def parse_line(self, r, ln, sf):
        e = super().parse_line(r, ln, sf)
        e.log_format = LogFormat.OPENSTACK_NEUTRON
        e.cloud_service = 'network'
        return e


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# MACOS INSTALL / SYSTEM LOG
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class MacOSInstallParser(BaseParser):
    """
    macOS installer and system log.
    Formats:
      YYYY-MM-DD HH:MM:SS+ZZ  component  pid  level  message
      Mar 17 10:00:00 hostname process[pid]: message (standard syslog)
      Jan  1 00:00:00.000 process[pid] <Level>: message
    """
    log_format = LogFormat.MACOS_INSTALL

    _PAT1 = re.compile(
        r'^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[+-]\d{2}(?::\d{2})?)'
        r'\s+(?P<component>\S+)\s+(?P<pid>\d+)\s+(?P<level>\w+)\s+(?P<msg>.*)'
    )
    _PAT2 = re.compile(
        r'^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+'
        r'(?P<host>\S+)\s+(?P<proc>[^\[]+)\[(?P<pid>\d+)\]'
        r'(?:\s+<(?P<level>\w+)>)?:\s*(?P<msg>.*)'
    )
    _SEV = {
        'Default': 'INFO', 'Info': 'INFO', 'Debug': 'INFO',
        'Notice': 'INFO', 'Warning': 'WARNING', 'Error': 'ERROR',
        'Critical': 'CRITICAL', 'Alert': 'CRITICAL', 'Emergency': 'CRITICAL',
    }

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        line = raw_line.rstrip('\r\n')

        m = self._PAT1.match(line)
        if m:
            g = m.groupdict()
            e.timestamp_raw = g['ts']
            e.timestamp = _parse_iso8601(g['ts'])
            e.process_name = g['component']
            e.process_id = _safe_int(g['pid'])
            e.severity = self._SEV.get(g['level'], 'INFO')
            e.message = g['msg'].strip()
            return e

        m = self._PAT2.match(line)
        if m:
            g = m.groupdict()
            e.timestamp_raw = g['ts']
            e.timestamp = _parse_syslog_ts(g['ts'])
            e.hostname = g['host']
            e.process_name = g['proc'].strip()
            e.process_id = _safe_int(g['pid'])
            e.severity = self._SEV.get(g.get('level') or 'Default', 'INFO')
            e.message = g['msg'].strip()
            return e

        # Generic fallback
        e.message = line.strip()
        ts_m = re.search(r'\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}', line)
        if ts_m:
            e.timestamp = _parse_iso8601(ts_m.group(0))
        return e


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# HEALTH APP LOG
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class HealthAppParser(BaseParser):
    """
    Healthcare/fitness application log.
    Format: YYYY-MM-DD HH:MM:SS:mmm module|funcname|linenumber|message

    Example:
    2017-08-15 00:13:03:575|Step_LSC|getSupportiveapp|3|step count:370 appId:Step_LSC

    These logs track step counts, heart rate, sensor events, user activity.
    Security-relevant: unauthorized data access, anomalous health readings.
    """
    log_format = LogFormat.HEALTH_APP

    _PAT = re.compile(
        r'^(?P<ts>\d{4}(?:-\d{2}-|\d{2})\d{2}[- ]\d{2}:\d{2}:\d{2}(?::\d+)?)'
        r'\|(?P<module>[^|]+)'
        r'(?:\|(?P<func>[^|]+))?'
        r'\|(?P<line>\d+)'
        r'\|(?P<msg>.*)'
    )
    # Alternate: just timestamp + pipe-separated fields
    _PAT2 = re.compile(
        r'^(?P<ts>\d{4}(?:-\d{2}-|\d{2})\d{2}[- ]\d{2}:\d{2}:\d{2})'
        r'(?::\d+)?\s+(?P<msg>.*)'
    )

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        line = raw_line.rstrip('\r\n').strip()
        m = self._PAT.match(line)
        if m:
            g = m.groupdict()
            e.timestamp_raw = g['ts']
            try:
                # Try both formats: "YYYY-MM-DD HH:MM:SS:mmm" and "YYYYMMDD-HH:MM:SS:mmm"
                if g['ts'][4] == '-':  # Has hyphens in date part (YYYY-MM-DD)
                    if g['ts'][10] == ' ':  # Space between date and time
                        e.timestamp = datetime.strptime(g['ts'][:19], '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
                    else:  # Hyphen between date and time
                        e.timestamp = datetime.strptime(g['ts'][:19], '%Y-%m-%d-%H:%M:%S').replace(tzinfo=timezone.utc)
                else:  # No hyphens in date part (YYYYMMDD)
                    # Hyphen between date and time: "YYYYMMDD-HH:MM:SS"
                    e.timestamp = datetime.strptime(g['ts'][:17], '%Y%m%d-%H:%M:%S').replace(tzinfo=timezone.utc)
            except ValueError:
                pass
            e.process_name = g['module'].strip()
            if g.get('func') is not None:
                e.extra['func'] = g['func'].strip()
            e.extra['line'] = g['line']
            e.message = g['msg'].strip()
            e.severity = 'INFO'
            # Flag anomalies
            msg_l = e.message.lower()
            if any(w in msg_l for w in ['error', 'exception', 'fail', 'denied', 'invalid']):
                e.severity = 'WARNING'
            return e

        m2 = self._PAT2.match(line)
        if m2:
            g = m2.groupdict()
            e.timestamp_raw = g['ts']
            e.timestamp = _parse_iso8601(g['ts'])
            e.message = g['msg'].strip()
            e.severity = 'INFO'
            return e

        e.message = line
        e.severity = 'INFO'
        return e


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# GENERIC LINUX SYSTEM LOG (covers many distros)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class LinuxSyslogParser(BaseParser):
    """
    Generic Linux system log â€” covers auth.log, kern.log, daemon.log,
    messages, secure, cron, dpkg.log, apt/history.log etc.
    Wraps the base SyslogParser with additional Linux-specific enrichment.
    """
    log_format = LogFormat.SYSLOG

    _SYSLOG = SyslogParser()

    # Additional Linux service patterns
    _CRON    = re.compile(r'CRON\[\d+\].*CMD\s+\((.+)\)')
    _DPKG    = re.compile(r'(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?P<action>install|upgrade|remove|purge)\s+(?P<pkg>\S+)')
    _KERN_OOM = re.compile(r'Out of memory|oom-killer|killed process', re.I)
    _FAIL2BAN = re.compile(r'fail2ban\.\w+\s+(?:WARNING|NOTICE)\s+\[([^\]]+)\]\s+(Ban|Unban)\s+([\d\.]+)')

    def parse_line(self, raw_line, line_number, source_file):
        e = self._SYSLOG.parse_line(raw_line, line_number, source_file)
        e.log_format = LogFormat.SYSLOG
        msg = e.message or ''

        # Cron command extraction
        cron_m = self._CRON.search(msg)
        if cron_m:
            e.command_line = cron_m.group(1)

        # DPKG log
        dpkg_m = self._DPKG.match(raw_line)
        if dpkg_m:
            e.timestamp = _parse_iso8601(dpkg_m.group('ts'))
            e.extra['dpkg_action'] = dpkg_m.group('action')
            e.extra['dpkg_package'] = dpkg_m.group('pkg')
            e.message = raw_line.strip()

        # OOM killer â€” always critical
        if self._KERN_OOM.search(msg):
            e.severity = 'CRITICAL'

        # Fail2ban
        f2b_m = self._FAIL2BAN.search(raw_line)
        if f2b_m:
            e.extra['fail2ban_jail'] = f2b_m.group(1)
            e.extra['fail2ban_action'] = f2b_m.group(2)
            e.source_ip = f2b_m.group(3)
            e.severity = 'WARNING'

        return e


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# PYTHON LOGGING / DJANGO / FLASK
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class PythonLoggingParser(BaseParser):
    """
    Python logging module default format.
    Covers: Django, Flask, FastAPI, Gunicorn, Celery, etc.

    Formats:
    YYYY-MM-DD HH:MM:SS,mmm levelname logger message
    [YYYY-MM-DD HH:MM:SS] levelname in module: message
    timestamp levelname pid module.function:line - message
    """
    log_format = LogFormat.PYTHON_LOGGING

    _PAT1 = re.compile(
        r'^(?P<ts>\d{4}-\d{2}-\d{2}[\s,T]\d{2}:\d{2}:\d{2}(?:[,\.]\d+)?)'
        r'\s+(?P<level>DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL|EXCEPTION)'
        r'\s+(?P<logger>\S+)'
        r'(?:\s+(?P<func>\S+))?'
        r'(?:\s*:\s*|\s+)(?P<msg>.*)'
    )
    _PAT2 = re.compile(
        r'^\[(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\]'
        r'\s+(?P<level>DEBUG|INFO|WARNING|ERROR|CRITICAL)'
        r'\s+in\s+(?P<module>\S+):\s*(?P<msg>.*)'
    )
    # Gunicorn access log
    _GUNICORN = re.compile(
        r'(?P<ip>[\d\.]+) - - \[(?P<ts>[^\]]+)\] '
        r'"(?P<method>\w+) (?P<uri>\S+)[^"]*" (?P<status>\d+)'
    )
    _SEV = {'DEBUG': 'INFO', 'INFO': 'INFO', 'WARNING': 'WARNING',
            'WARN': 'WARNING', 'ERROR': 'ERROR', 'CRITICAL': 'CRITICAL',
            'EXCEPTION': 'ERROR'}

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        line = raw_line.rstrip('\r\n').strip()

        # Gunicorn access log
        gu = self._GUNICORN.search(line)
        if gu:
            g = gu.groupdict()
            e.source_ip   = g['ip']
            e.http_method = g['method']
            e.http_uri    = g['uri']
            e.http_status = _safe_int(g['status'])
            e.timestamp   = _parse_apache_ts(g['ts'])
            e.severity    = _http_severity(e.http_status)
            return e

        for pat in (self._PAT1, self._PAT2):
            m = pat.match(line)
            if m:
                g = m.groupdict()
                e.timestamp_raw = g['ts']
                e.timestamp = _parse_iso8601(g['ts'].replace(',', '.'))
                level = g['level'].upper()
                e.severity = self._SEV.get(level, 'INFO')
                e.process_name = g.get('logger') or g.get('module') or ''
                e.message = g['msg'].strip()
                # Django request info
                req_m = re.search(r'"(GET|POST|PUT|DELETE|PATCH)\s+(\S+)[^"]*"\s+(\d{3})', e.message)
                if req_m:
                    e.http_method = req_m.group(1)
                    e.http_uri = req_m.group(2)
                    e.http_status = _safe_int(req_m.group(3))
                # IP
                ip_m = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', e.message)
                if ip_m:
                    e.source_ip = ip_m.group(0)
                return e

        e.message = line
        # Last resort level detection
        lev_m = re.search(r'\b(DEBUG|INFO|WARNING|ERROR|CRITICAL)\b', line)
        e.severity = self._SEV.get(lev_m.group(1) if lev_m else 'INFO', 'INFO')
        ts_m = re.search(r'\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}', line)
        if ts_m:
            e.timestamp = _parse_iso8601(ts_m.group(0))
        return e


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# OPENSSH ENHANCED (covers more SSH patterns than SyslogParser)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class OpenSSHParser(SyslogParser):
    """Enhanced SSH log parser with brute force and key-based auth detection."""
    log_format = LogFormat.AUTH_LOG

    _KEY_AUTH   = re.compile(r'Accepted publickey for (\S+) from (\S+) port (\d+)')
    _CERT_AUTH  = re.compile(r'Accepted certificate ID "([^"]+)" .+ from (\S+) port (\d+)')
    _DISCONN    = re.compile(r'Disconnected from (?:authenticating )?user (\S+) (\S+) port (\d+)')
    _MAX_AUTH   = re.compile(r'error: maximum authentication attempts exceeded for .+ from (\S+)')
    _SCAN       = re.compile(r'Invalid user (\S+) from (\S+)|Did not receive identification string from (\S+)')
    _BREAK      = re.compile(r'Connection closed by (?:invalid user )?(\S+) (\S+)')
    _TUNNEL     = re.compile(r'Accepted direct-tcpip channel .+ to (\S+):(\d+) .+ from (\S+)')

    def parse_line(self, raw_line, line_number, source_file):
        e = super().parse_line(raw_line, line_number, source_file)
        msg = e.message or ''

        m = self._KEY_AUTH.search(msg)
        if m:
            e.username = m.group(1); e.source_ip = m.group(2)
            e.source_port = _safe_int(m.group(3))
            e.auth_result = 'success'; e.severity = 'INFO'
            e.extra['auth_method'] = 'publickey'
            return e

        m = self._MAX_AUTH.search(msg)
        if m:
            e.source_ip = m.group(1)
            e.severity = 'CRITICAL'  # brute force
            e.auth_result = 'failure'
            e.tags.append('brute_force')
            return e

        m = self._TUNNEL.search(msg)
        if m:
            e.dest_ip = m.group(1); e.dest_port = _safe_int(m.group(2))
            e.source_ip = m.group(3)
            e.severity = 'WARNING'
            e.tags.append('ssh_tunnel')
            return e

        return e


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# FAIL2BAN
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class Fail2BanParser(BaseParser):
    """Fail2ban action log."""
    log_format = LogFormat.FAIL2BAN

    _PAT = re.compile(
        r'^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d+)'
        r'\s+fail2ban\.(?P<module>\w+)\s+\[(?P<pid>\d+)\]'
        r'\s+(?P<level>\w+)\s+(?P<msg>.*)'
    )
    _BAN   = re.compile(r'\[([^\]]+)\]\s+Ban\s+([\d\.]+)')
    _UNBAN = re.compile(r'\[([^\]]+)\]\s+Unban\s+([\d\.]+)')
    _FOUND = re.compile(r'\[([^\]]+)\]\s+Found\s+([\d\.]+)')

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        line = raw_line.rstrip('\r\n')
        m = self._PAT.match(line)
        if not m:
            e.message = line.strip(); return e
        g = m.groupdict()
        e.timestamp_raw = g['ts']
        e.timestamp = _parse_iso8601(g['ts'].replace(',', '.'))
        e.process_name = f"fail2ban.{g['module']}"
        e.process_id = _safe_int(g['pid'])
        e.message = g['msg'].strip()
        sev_map = {'DEBUG':'INFO','INFO':'INFO','NOTICE':'INFO',
                   'WARNING':'WARNING','ERROR':'ERROR','CRITICAL':'CRITICAL'}
        e.severity = sev_map.get(g['level'].upper(), 'INFO')

        ban = self._BAN.search(e.message)
        if ban:
            e.extra['jail'] = ban.group(1)
            e.source_ip = ban.group(2)
            e.action = 'block'
            e.severity = 'WARNING'
            e.auth_result = 'failure'

        unban = self._UNBAN.search(e.message)
        if unban:
            e.extra['jail'] = unban.group(1)
            e.source_ip = unban.group(2)
            e.action = 'unblock'
            e.severity = 'INFO'

        found = self._FOUND.search(e.message)
        if found:
            e.extra['jail'] = found.group(1)
            e.source_ip = found.group(2)
            e.tags.append('brute_force_attempt')

        return e


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# OSSEC / WAZUH AGENT LOG
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class OSSECParser(BaseParser):
    """OSSEC / Wazuh HIDS alert log."""
    log_format = LogFormat.OSSEC

    _PAT = re.compile(
        r'\*\* Alert (?P<ts>\d+\.\d+):(?P<offset>\d+)?'
        r' - (?P<groups>[^;]+);(?P<agent>[^\n]*)\n'
        r'(?P<ts_human>\d{4} \w+ \d{2} \d{2}:\d{2}:\d{2})[^\n]*\n'
        r'Rule: (?P<rule>\d+)\s+\(level (?P<level>\d+)\) -> \'(?P<desc>[^\']+)\'\n'
        r'(?:Src IP: (?P<src_ip>\S+)\n)?'
        r'(?:Src Port: (?P<src_port>\d+)\n)?'
        r'(?:User: (?P<user>\S+)\n)?'
        r'(?P<msg>.*)', re.DOTALL)

    _SINGLE = re.compile(
        r'(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2})'
        r'\s+ossec:\s+(?P<msg>.*)'
    )

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        m = self._SINGLE.match(raw_line)
        if m:
            e.timestamp = _parse_iso8601(m.group('ts'))
            e.message = m.group('msg')
            e.severity = 'WARNING'
            ip_m = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', e.message)
            if ip_m:
                e.source_ip = ip_m.group(0)
            return e
        # Multi-line OSSEC alert
        e.message = raw_line.strip()
        ts_m = re.search(r'\d{10}\.\d+', raw_line)
        if ts_m:
            try:
                e.timestamp = datetime.fromtimestamp(float(ts_m.group(0)), tz=timezone.utc)
            except ValueError:
                pass
        level_m = re.search(r'level (\d+)', raw_line)
        if level_m:
            lev = int(level_m.group(1))
            e.severity = ('CRITICAL' if lev >= 13 else 'ERROR' if lev >= 10
                          else 'WARNING' if lev >= 7 else 'INFO')
        ip_m = re.search(r'Src IP: (\S+)', raw_line)
        if ip_m:
            e.source_ip = ip_m.group(1)
        user_m = re.search(r'User: (\S+)', raw_line)
        if user_m:
            e.username = user_m.group(1)
        return e


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# OPENVPN
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class OpenVPNParser(BaseParser):
    """OpenVPN server log."""
    log_format = LogFormat.OPENVPN

    _PAT = re.compile(
        r'^(?P<ts>\w{3}\s+\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})'
        r'\s+(?P<msg>.*)'
    )
    _PAT2 = re.compile(
        r'^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})'
        r'\s+(?P<msg>.*)'
    )

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        line = raw_line.rstrip('\r\n')
        for pat in (self._PAT2, self._PAT):
            m = pat.match(line)
            if m:
                e.timestamp_raw = m.group('ts')
                e.timestamp = _parse_iso8601(m.group('ts'))
                e.message = m.group('msg').strip()
                break
        else:
            e.message = line.strip()
        msg = e.message
        # Client connections
        conn_m = re.search(r'([\d\.]+):(\d+) \[(\S+)\] Peer Connection Initiated', msg)
        if conn_m:
            e.source_ip = conn_m.group(1)
            e.source_port = _safe_int(conn_m.group(2))
            e.username = conn_m.group(3)
            e.auth_result = 'success'
            e.severity = 'INFO'
        # Auth failures
        elif re.search(r'AUTH_FAILED|TLS Error|Certificate verification failed', msg, re.I):
            e.auth_result = 'failure'
            e.severity = 'WARNING'
            ip_m = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', msg)
            if ip_m:
                e.source_ip = ip_m.group(0)
        else:
            e.severity = 'INFO'
        return e


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# ELASTICSEARCH
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class ElasticsearchParser(Log4jParser):
    """Elasticsearch uses Log4j2 with extra JSON context blocks."""
    log_format = LogFormat.ELASTICSEARCH

    def parse_line(self, raw_line, line_number, source_file):
        e = super().parse_line(raw_line, line_number, source_file)
        e.log_format = LogFormat.ELASTICSEARCH
        # ES often logs cluster/node info
        node_m = re.search(r'\[([^\]]+)\]\[([^\]]+)\]', raw_line)
        if node_m:
            e.hostname = node_m.group(1)
            e.extra['es_index'] = node_m.group(2)
        # Security events
        msg = e.message or ''
        if 'authentication failed' in msg.lower() or 'forbidden' in msg.lower():
            e.auth_result = 'failure'
            e.severity = 'WARNING'
        if 'authentication success' in msg.lower():
            e.auth_result = 'success'
        return e


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# CROWDSTRIKE FALCON
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class CrowdStrikeParser(BaseParser):
    """CrowdStrike Falcon EDR JSON events."""
    log_format = LogFormat.CROWDSTRIKE

    _SEV_MAP = {
        'Critical': 'CRITICAL', 'High': 'HIGH', 'Medium': 'MEDIUM',
        'Low': 'LOW', 'Informational': 'INFO',
        1: 'INFO', 2: 'LOW', 3: 'MEDIUM', 4: 'HIGH', 5: 'CRITICAL',
    }

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        try:
            obj = json.loads(raw_line)
        except json.JSONDecodeError:
            e.message = raw_line.strip()
            return e

        ts = obj.get('timestamp') or obj.get('EventCreationTime') or obj.get('time')
        if ts:
            e.timestamp = _parse_iso8601(str(ts))
            e.timestamp_raw = str(ts)

        e.hostname = obj.get('ComputerName') or obj.get('hostname')
        e.username = obj.get('UserName') or obj.get('user')
        e.process_name = obj.get('FileName') or obj.get('ImageFileName', '').rsplit('\\', 1)[-1]
        e.process_id = _safe_int(obj.get('TargetProcessId') or obj.get('pid'))
        e.command_line = obj.get('CommandLine')
        e.source_ip = obj.get('RemoteAddress') or obj.get('src_ip')
        e.dest_ip = obj.get('LocalAddress') or obj.get('dst_ip')
        e.file_path = obj.get('TargetFilePath') or obj.get('FilePath')
        e.file_hash_sha256 = obj.get('SHA256HashData') or obj.get('sha256')

        sev_raw = obj.get('Severity') or obj.get('severity') or obj.get('SeverityName')
        e.severity = self._SEV_MAP.get(sev_raw, 'WARNING') if sev_raw else 'WARNING'

        detect = obj.get('DetectName') or obj.get('Technique') or obj.get('name', '')
        e.message = detect or obj.get('description', raw_line[:200])
        e.extra = obj
        return e


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# SPRING BOOT / JAVA APPLICATION LOG
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class SpringBootParser(Log4jParser):
    """Spring Boot uses Logback with a fixed pattern layout."""
    log_format = LogFormat.SPRING_BOOT

    _SPRING = re.compile(
        r'^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[,\.]\d+)'
        r'\s+(?P<level>TRACE|DEBUG|INFO|WARN|ERROR)'
        r'\s+(?P<pid>\d+)'
        r'\s+---\s+\[(?P<thread>[^\]]+)\]'
        r'\s+(?P<logger>\S+)'
        r'\s+:\s+(?P<msg>.*)'
    )

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        line = raw_line.rstrip('\r\n')
        m = self._SPRING.match(line)
        if m:
            g = m.groupdict()
            e.timestamp_raw = g['ts']
            e.timestamp = _parse_iso8601(g['ts'].replace(',', '.'))
            e.process_id = _safe_int(g['pid'])
            e.process_name = g['logger']
            e.extra['thread'] = g['thread']
            level = g['level'].upper()
            e.severity = {'DEBUG':'INFO','INFO':'INFO','WARN':'WARNING','ERROR':'ERROR'}.get(level, 'INFO')
            e.message = g['msg'].strip()
            ip_m = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', e.message)
            if ip_m:
                e.source_ip = ip_m.group(0)
            return e
        return super().parse_line(raw_line, line_number, source_file)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# VMware ESXi
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class VMwareESXParser(BaseParser):
    """VMware ESXi / vCenter log."""
    log_format = LogFormat.VMWARE_ESX

    _PAT = re.compile(
        r'^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?[Z+-]\S*)'
        r'\s+(?P<host>\S+)'
        r'\s+(?P<proc>[^\[]+)\[(?P<pid>\d+)\]:\s+'
        r'(?P<msg>.*)'
    )
    _PAT2 = re.compile(
        r'^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[Z+-]\S*)'
        r'\s+(?P<msg>.*)'
    )

    def parse_line(self, raw_line, line_number, source_file):
        e = self._minimal(raw_line, line_number, source_file)
        line = raw_line.rstrip('\r\n')
        for pat in (self._PAT, self._PAT2):
            m = pat.match(line)
            if m:
                g = m.groupdict()
                e.timestamp_raw = g['ts']
                e.timestamp = _parse_iso8601(g['ts'])
                e.hostname = g.get('host')
                e.process_name = (g.get('proc') or '').strip()
                e.process_id = _safe_int(g.get('pid'))
                e.message = g['msg'].strip()
                break
        else:
            e.message = line.strip()

        msg = e.message.lower()
        e.severity = ('ERROR' if re.search(r'\berror\b|\bfailed?\b|\bfailure\b', msg)
                      else 'WARNING' if re.search(r'\bwarn\b|\bcritical\b', msg)
                      else 'INFO')
        # Auth
        if 'login successful' in msg or 'authenticated' in msg:
            e.auth_result = 'success'
        elif 'login failed' in msg or 'authentication failure' in msg:
            e.auth_result = 'failure'; e.severity = 'WARNING'
        ip_m = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', e.message)
        if ip_m:
            e.source_ip = ip_m.group(0)
        return e

# â”€â”€ Registry extension: new format parsers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Appended after class definitions to avoid forward-reference errors.
def _extend_registry() -> None:
    _REGISTRY.update({
        # Mobile / Embedded
        LogFormat.ANDROID_LOGCAT:      AndroidLogcatParser(),
        LogFormat.IOS_SYSLOG:          SyslogParser(),
        # Big Data / Distributed Systems
        LogFormat.HADOOP:              HadoopParser(),
        LogFormat.SPARK:               Log4jParser(),
        LogFormat.KAFKA:               Log4jParser(),
        LogFormat.ZOOKEEPER:           Log4jParser(),
        LogFormat.ELASTICSEARCH:       ElasticsearchParser(),
        # Windows Application Logs
        LogFormat.WINDOWS_CBS:         WindowsCBSParser(),
        LogFormat.WINDOWS_SETUP:       WindowsCBSParser(),
        LogFormat.WINDOWS_UPDATE:      WindowsCBSParser(),
        LogFormat.IIS_HTTPAPI:         ApacheCombinedParser(),
        # macOS
        LogFormat.MACOS_INSTALL:       MacOSInstallParser(),
        LogFormat.MACOS_CRASHREPORTER: MacOSInstallParser(),
        # OpenStack
        LogFormat.OPENSTACK:           OpenStackParser(),
        LogFormat.OPENSTACK_NOVA:      OpenStackNovaParser(),
        LogFormat.OPENSTACK_KEYSTONE:  OpenStackKeystoneParser(),
        LogFormat.OPENSTACK_NEUTRON:   OpenStackNeutronParser(),
        LogFormat.VMWARE_ESX:          VMwareESXParser(),
        # Healthcare / Domain-specific
        LogFormat.HEALTH_APP:          HealthAppParser(),
        LogFormat.LOG4J:               Log4jParser(),
        LogFormat.PYTHON_LOGGING:      PythonLoggingParser(),
        LogFormat.DJANGO:              PythonLoggingParser(),
        LogFormat.RAILS:               PythonLoggingParser(),
        LogFormat.NODEJS:              JsonParser(),
        LogFormat.SPRING_BOOT:         SpringBootParser(),
        # Security Tools
        LogFormat.OSSEC:               OSSECParser(),
        LogFormat.FAIL2BAN:            Fail2BanParser(),
        LogFormat.CROWDSTRIKE:         CrowdStrikeParser(),
        LogFormat.CARBONBLACK:         JsonParser(),
        # Network / VPN
        LogFormat.JUNIPER:             SyslogParser(),
        LogFormat.F5_BIG_IP:           SyslogParser(),
        LogFormat.OPENVPN:             OpenVPNParser(),
        LogFormat.WIREGUARD:           KernLogParser(),
    })

_extend_registry()
