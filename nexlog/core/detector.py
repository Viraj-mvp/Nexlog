"""
detector.py â€” NexLog Layer 1
Format detection for 50+ log formats.

Priority order:
  1. Magic bytes   â€” binary signatures (EVTX, gzip, SQLite)
  2. Extension     â€” unambiguous extensions (.evtx, .jsonl, .pcap)
  3. Content probe â€” first 15 lines scored against all format patterns
  4. AI probe      â€” sample sent to LLM if confidence < threshold
  5. Fallback      â€” AI_PARSED (parser extracts what it can)
"""

import json
import re
from pathlib import Path
from typing import Optional

from models import LogFormat


# â”€â”€ Magic byte signatures â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

_MAGIC: list[tuple[bytes, LogFormat]] = [
    (b"ElfFile\x00",   LogFormat.WINDOWS_EVTX),
    (b"\x1f\x8b",      LogFormat.UNKNOWN),       # gzip â€” probe after decompress
    (b"SQLite format", LogFormat.UNKNOWN),        # SQLite DB
    (b"MZ",            LogFormat.UNKNOWN),        # PE binary
    (b"\xd4\xc3\xb2\xa1", LogFormat.UNKNOWN),    # PCAP little-endian
    (b"\xa1\xb2\xc3\xd4", LogFormat.UNKNOWN),    # PCAP big-endian
    (b"\x0a\x0d\x0d\x0a", LogFormat.UNKNOWN),    # PCAPNG
]

# â”€â”€ Extension map â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

_EXT_MAP: dict[str, Optional[LogFormat]] = {
    ".evtx":    LogFormat.WINDOWS_EVTX,
    ".jsonl":   LogFormat.JSON_LINES,
    ".ndjson":  LogFormat.JSON_LINES,
    ".json":    LogFormat.JSON_GENERIC,
    ".log":     None,   # probe content
    ".txt":     None,
    ".csv":     LogFormat.CSV_GENERIC,
    ".pcap":    LogFormat.UNKNOWN,
    ".pcapng":  LogFormat.UNKNOWN,
    ".gz":      None,
    ".bz2":     None,
    ".xz":      None,
}

# â”€â”€ Filename hints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

_FILENAME_HINTS: list[tuple[re.Pattern, LogFormat]] = [
    (re.compile(r'auth\.log',            re.I), LogFormat.AUTH_LOG),
    (re.compile(r'syslog',               re.I), LogFormat.SYSLOG),
    (re.compile(r'kern\.log',            re.I), LogFormat.KERN_LOG),
    (re.compile(r'dmesg',                re.I), LogFormat.DMESG),
    (re.compile(r'audit\.log',           re.I), LogFormat.AUDITD),
    (re.compile(r'access\.log',          re.I), LogFormat.APACHE_COMBINED),
    (re.compile(r'error\.log',           re.I), LogFormat.APACHE_ERROR),
    (re.compile(r'nginx.*access',        re.I), LogFormat.NGINX_ACCESS),
    (re.compile(r'nginx.*error',         re.I), LogFormat.NGINX_ERROR),
    (re.compile(r'iis.*\.log',           re.I), LogFormat.IIS_W3C),
    (re.compile(r'u_ex\d{6}',           re.I), LogFormat.IIS_W3C),    # IIS default name
    (re.compile(r'haproxy',              re.I), LogFormat.HAPROXY),
    (re.compile(r'squid|access\.log',    re.I), LogFormat.SQUID),
    (re.compile(r'conn\.log',            re.I), LogFormat.ZEEK_CONN),
    (re.compile(r'dns\.log',             re.I), LogFormat.ZEEK_DNS),
    (re.compile(r'http\.log',            re.I), LogFormat.ZEEK_HTTP),
    (re.compile(r'ssl\.log',             re.I), LogFormat.ZEEK_SSL),
    (re.compile(r'suricata.*eve',        re.I), LogFormat.SURICATA_EVE),
    (re.compile(r'suricata.*fast',       re.I), LogFormat.SNORT_FAST),
    (re.compile(r'snort',                re.I), LogFormat.SNORT_FAST),
    (re.compile(r'cloudtrail',           re.I), LogFormat.AWS_CLOUDTRAIL),
    (re.compile(r'vpc.*flow|flow.*logs', re.I), LogFormat.AWS_VPC_FLOW),
    (re.compile(r'mysql.*error',         re.I), LogFormat.MYSQL_ERROR),
    (re.compile(r'mysql.*slow',          re.I), LogFormat.MYSQL_SLOW),
    (re.compile(r'postgresql|postgres',  re.I), LogFormat.POSTGRESQL),
    (re.compile(r'mongodb|mongod',       re.I), LogFormat.MONGODB),
    (re.compile(r'postfix|mail\.log',    re.I), LogFormat.POSTFIX),
    (re.compile(r'named.*query|bind',    re.I), LogFormat.BIND_QUERY),
    (re.compile(r'falco',                re.I), LogFormat.FALCO),
    (re.compile(r'k8s.*audit|kube.*audit',re.I),LogFormat.KUBERNETES_AUDIT),
    (re.compile(r'journal',              re.I), LogFormat.JOURNALD),
    (re.compile(r'windows.*firewall|wfas',re.I),LogFormat.WINDOWS_FIREWALL),
    (re.compile(r'powershell.*script',   re.I), LogFormat.POWERSHELL_SCRIPT),
    (re.compile(r'cbs\.log|cbs_',        re.I), LogFormat.WINDOWS_CBS),
    (re.compile(r'windowsupdate',         re.I), LogFormat.WINDOWS_UPDATE),
    (re.compile(r'setupact|setup\.log',  re.I), LogFormat.WINDOWS_SETUP),
    (re.compile(r'android|logcat',        re.I), LogFormat.ANDROID_LOGCAT),
    (re.compile(r'nova\.log|nova-',      re.I), LogFormat.OPENSTACK_NOVA),
    (re.compile(r'keystone',              re.I), LogFormat.OPENSTACK_KEYSTONE),
    (re.compile(r'neutron',               re.I), LogFormat.OPENSTACK_NEUTRON),
    (re.compile(r'openstack|cinder|swift|glance|heat', re.I), LogFormat.OPENSTACK),
    (re.compile(r'hadoop|namenode|datanode|yarn|mapred', re.I), LogFormat.HADOOP),
    (re.compile(r'elasticsearch|elastic', re.I), LogFormat.ELASTICSEARCH),
    (re.compile(r'spark',                 re.I), LogFormat.SPARK),
    (re.compile(r'kafka',                 re.I), LogFormat.KAFKA),
    (re.compile(r'zookeeper',             re.I), LogFormat.ZOOKEEPER),
    (re.compile(r'healthapp|health_app|step_lsc', re.I), LogFormat.HEALTH_APP),
    (re.compile(r'spring.*boot',          re.I), LogFormat.SPRING_BOOT),
    (re.compile(r'django',                re.I), LogFormat.DJANGO),
    (re.compile(r'fail2ban',              re.I), LogFormat.FAIL2BAN),
    (re.compile(r'crowdstrike|falcon',    re.I), LogFormat.CROWDSTRIKE),
    (re.compile(r'openvpn',              re.I), LogFormat.OPENVPN),
    (re.compile(r'vmware|esxi|vcenter',   re.I), LogFormat.VMWARE_ESX),
    (re.compile(r'macos.*install|system\.log', re.I), LogFormat.MACOS_INSTALL),
]

# â”€â”€ Content probe patterns â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# (LogFormat, compiled_pattern, minimum_confidence_weight)
# Higher weight = stronger signal. Probe score = sum of weights for matching lines.

_PROBES: list[tuple[LogFormat, re.Pattern, float]] = [
    # Must-match strong signals first
    (LogFormat.WINDOWS_EVTX,
     re.compile(r'<Event\s+xmlns='), 2.0),

    (LogFormat.SURICATA_EVE,
     re.compile(r'"event_type"\s*:\s*"(?:alert|dns|http|tls|flow)"'), 2.0),

    (LogFormat.AWS_CLOUDTRAIL,
     re.compile(r'"eventSource"\s*:\s*"[^"]+\.amazonaws\.com"'), 2.0),

    (LogFormat.AWS_VPC_FLOW,
     re.compile(r'^(?:\d+\s+){3}[\d\.]+\s+[\d\.]+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(?:ACCEPT|REJECT|NODATA)\b'), 2.0),

    (LogFormat.ZEEK_CONN,
     re.compile(r'^#(?:fields|types)\tts\tuid\tid\.orig_h'), 2.0),

    (LogFormat.ZEEK_DNS,
     re.compile(r'^#(?:fields|types)\tts\tuid.*query\tqclass'), 2.0),

    (LogFormat.ZEEK_HTTP,
     re.compile(r'^#(?:fields|types)\tts\tuid.*method\thost\turi'), 2.0),

    (LogFormat.ZEEK_SSL,
     re.compile(r'^#(?:fields|types)\tts\tuid.*version\tcipher'), 2.0),

    (LogFormat.CEF,
     re.compile(r'CEF:\d+\|'), 2.0),

    (LogFormat.LEEF,
     re.compile(r'LEEF:\d+\|'), 2.0),

    (LogFormat.GELF,
     re.compile(r'"version"\s*:\s*"1\.\d+".*"short_message"'), 2.0),

    (LogFormat.SNORT_FAST,
     re.compile(r'\[\*\*\]\s+\[\d+:\d+:\d+\]'), 2.0),

    (LogFormat.CISCO_ASA,
     re.compile(r'%ASA-\d-\d{6}:'), 2.0),

    (LogFormat.PALOALTO,
     re.compile(r'TRAFFIC|THREAT|URL|WILDFIRE|SYSTEM,\d+,\d+,'), 1.5),

    (LogFormat.FORTINET,
     re.compile(r'devname=\S+.*logid=\S+|type=\S+.*subtype=\S+.*level=\S+'), 1.5),

    (LogFormat.AUDITD,
     re.compile(r'audit\(\d+\.\d+:\d+\):'), 2.0),

    (LogFormat.JOURNALD,
     re.compile(r'"__REALTIME_TIMESTAMP"\s*:\s*"\d+"'), 2.0),

    (LogFormat.KUBERNETES_AUDIT,
     re.compile(r'"apiVersion"\s*:\s*"audit\.k8s\.io/'), 2.0),

    (LogFormat.DOCKER_JSON,
     re.compile(r'"log"\s*:.*"stream"\s*:\s*"(?:stdout|stderr)"'), 2.0),

    (LogFormat.FALCO,
     re.compile(r'"output"\s*:.*"priority"\s*:\s*"(?:Emergency|Alert|Critical|Error|Warning|Notice)"'), 1.5),

    (LogFormat.IIS_W3C,
     re.compile(r'^#Fields:.*c-ip|^#Software: Microsoft IIS'), 2.0),

    (LogFormat.WINDOWS_FIREWALL,
     re.compile(r'^#Fields: date time action protocol src-ip dst-ip'), 2.0),

    (LogFormat.POSTGRESQL,
     re.compile(r'\[\d+\]\s+\w+@\w+\s+(?:LOG|ERROR|FATAL|PANIC|WARNING):'), 1.5),

    (LogFormat.MYSQL_ERROR,
     re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z\s+\d+\s+\[(?:Note|Warning|Error|System)\]'), 1.5),

    (LogFormat.MONGODB,
     re.compile(r'"msg"\s*:.*"attr"\s*:|NETWORK\s+\[conn\d+\]'), 1.5),

    (LogFormat.POSTFIX,
     re.compile(r'postfix/(?:smtp|smtpd|qmgr|cleanup)\[\d+\]'), 1.5),

    (LogFormat.BIND_QUERY,
     re.compile(r'client\s+@\S+\s+\d+\.\d+\.\d+\.\d+#\d+\s+query:'), 1.5),

    (LogFormat.SYSLOG_RFC5424,
     re.compile(r'^<\d+>\d+\s+\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'), 1.5),

    (LogFormat.IPTABLES,
     re.compile(r'(?:IN=\S*|OUT=\S*)\s+.*SRC=\d+\.\d+\.\d+\.\d+\s+DST=\d+'), 1.5),

    (LogFormat.HAPROXY,
     re.compile(r'\d+\.\d+\.\d+\.\d+:\d+\s+\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\.\d+\].*\d+/\d+/\d+/\d+/\d+\s+\d{3}'), 1.5),

    (LogFormat.SQUID,
     re.compile(r'^\d+\.\d{3}\s+\d+\s+\d+\.\d+\.\d+\.\d+\s+(?:TCP|UDP)_'), 1.5),

    # Apache Combined â€” high priority
    (LogFormat.APACHE_COMBINED,
     re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}\s+\S+\s+\S+\s+\[\d{2}/\w{3}/\d{4}:'), 1.5),

    # Apache Error
    (LogFormat.APACHE_ERROR,
     re.compile(r'^\[(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\w+\s+\d+\s+\d{2}:\d{2}:\d{2}'), 1.0),

    # Nginx Error
    (LogFormat.NGINX_ERROR,
     re.compile(r'^\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}\s+\[(?:emerg|alert|crit|error|warn|notice|info|debug)\]'), 1.5),

    # Syslog RFC 3164 â€” broad, check last
    (LogFormat.AUTH_LOG,
     re.compile(r'(?:sshd|sudo|pam_unix|su|login)\[\d+\]:'), 1.0),

    (LogFormat.SYSLOG,
     re.compile(r'^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+:'), 1.0),

    (LogFormat.JSON_GENERIC,
     re.compile(r'^\s*\{'), 0.8),

    (LogFormat.ANDROID_LOGCAT,
     re.compile(r'^\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}'), 2.0),

    (LogFormat.WINDOWS_CBS,
     re.compile(r'^\d{4}-\d{2}-\d{2}.*,\s+(?:Info|Warning|Error)\s+(?:CBS|CSI)\s'), 2.0),

    (LogFormat.OPENSTACK,
     re.compile(r'(?:nova|keystone|neutron|cinder|swift)\.\w+\s+\[-\]'), 2.0),

    (LogFormat.HADOOP,
     re.compile(r'org\.apache\.hadoop'), 2.0),

    (LogFormat.LOG4J,
     re.compile(r'\d{4}-\d{2}-\d{2}.*(?:DEBUG|INFO|WARN|ERROR|FATAL).*org\.apache'), 1.5),

    (LogFormat.HEALTH_APP,
     re.compile(r'^\d{4}-\d{2}-\d{2}.*\|\w+\|\w+\|\d+\|'), 2.0),

    (LogFormat.SPRING_BOOT,
     re.compile(r'\d+\s+---\s+\[.*\].*\s+:\s+'), 2.0),

    (LogFormat.FAIL2BAN,
     re.compile(r'fail2ban\.\w+.*\[(?:Ban|Found|Unban)'), 2.0),

    (LogFormat.AWS_CLOUDTRAIL,
     re.compile(r'"eventName"\s*:\s*"\w+".*"eventSource"'), 1.0),

    (LogFormat.AZURE_ACTIVITY,
     re.compile(r'"operationName"\s*:.*"resourceProvider"\s*:\s*"Microsoft\.'), 1.0),

    (LogFormat.GCP_AUDIT,
     re.compile(r'"logName"\s*:.*"projects/.*cloudaudit.googleapis'), 1.0),
]


def detect_format(path: str | Path) -> LogFormat:
    """
    Detect the log format of a file.

    Strategy:
    1. Magic bytes
    2. Extension
    3. Filename hints
    4. Content probe (first 15 non-empty lines)
    5. Fallback â†’ AI_PARSED
    """
    path = Path(path)

    # â”€â”€ Step 1: magic bytes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    try:
        with open(path, "rb") as f:
            magic = f.read(16)
        for sig, fmt in _MAGIC:
            if magic.startswith(sig):
                if fmt != LogFormat.UNKNOWN:
                    return fmt
                break
    except (IOError, OSError):
        pass

    # â”€â”€ Step 2: extension â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    ext = path.suffix.lower()
    if ext in _EXT_MAP and _EXT_MAP[ext] is not None:
        return _EXT_MAP[ext]

    # â”€â”€ Step 3: filename hints â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    name = path.name.lower()
    for pattern, fmt in _FILENAME_HINTS:
        if pattern.search(name):
            return fmt

    # â”€â”€ Step 4: content probe â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    result = _probe_content(path)
    if result != LogFormat.UNKNOWN:
        return result

    # â”€â”€ Step 5: AI fallback â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    return LogFormat.AI_PARSED


def _probe_content(path: Path, sample_lines: int = 15) -> LogFormat:
    """
    Score first N non-empty lines against all format patterns.
    Returns the best match or UNKNOWN if confidence is low.
    """
    try:
        from reader import stream_lines
    except ImportError:
        return LogFormat.UNKNOWN

    scores: dict[LogFormat, float] = {}
    lines_read = 0

    for _, line in stream_lines(path):
        if not line.strip():
            continue
        for fmt, pattern, weight in _PROBES:
            if pattern.search(line):
                scores[fmt] = scores.get(fmt, 0.0) + weight
        lines_read += 1
        if lines_read >= sample_lines:
            break

    if not lines_read:
        return LogFormat.UNKNOWN

    if not scores:
        # Try JSON detection directly
        try:
            with open(path, "r", errors="replace") as f:
                first_line = f.readline().strip()
            if first_line.startswith("{") or first_line.startswith("["):
                return LogFormat.JSON_GENERIC
        except (IOError, OSError):
            pass
        return LogFormat.UNKNOWN

    best     = max(scores, key=lambda k: scores[k])
    best_scr = scores[best]

    # Require a minimum absolute score based on weight
    if best_scr < 0.8:
        return LogFormat.UNKNOWN

    # If Apache Combined and AUTH_LOG both score â€” prefer AUTH_LOG
    # when sshd/sudo keywords are present
    if (best == LogFormat.APACHE_COMBINED
            and scores.get(LogFormat.AUTH_LOG, 0) > 0):
        return LogFormat.AUTH_LOG

    return best


def detect_format_from_line(line: str) -> LogFormat:
    """
    Single-line format detection used for per-line fallback when
    file-level detection returns UNKNOWN.
    """
    for fmt, pattern, _ in _PROBES:
        if pattern.search(line):
            return fmt
    return LogFormat.AI_PARSED


def is_binary(path: str | Path) -> bool:
    """True if the file is binary (not a text-based log)."""
    try:
        with open(Path(path), "rb") as f:
            chunk = f.read(1024)
        non_print = sum(1 for b in chunk if b < 9 or (13 < b < 32))
        return (non_print / max(len(chunk), 1)) > 0.30
    except (IOError, OSError):
        return False


def supported_formats() -> list[str]:
    """Return a list of all supported log format names (for UI display)."""
    return sorted(f.value for f in LogFormat if f != LogFormat.UNKNOWN)
