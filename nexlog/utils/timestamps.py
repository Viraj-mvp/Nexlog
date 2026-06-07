"""
utils/timestamps.py â€” NexLog shared utilities
Centralised timestamp parsing extracted from core/parsers.py.
All timestamp parsing should go through these functions so
normalisation logic lives in exactly one place.

All output datetimes are timezone-aware UTC.
"""

import re
from datetime import datetime, timezone, timedelta
from typing import Optional

_MONTHS = {
    "jan":1,"feb":2,"mar":3,"apr":4,"may":5,"jun":6,
    "jul":7,"aug":8,"sep":9,"oct":10,"nov":11,"dec":12,
}


def parse_apache(raw: str) -> Optional[datetime]:
    """
    Parse Apache Combined Log timestamp.
    Format: 04/Jan/2026:10:00:22 +0000
    Returns UTC datetime.
    """
    m = re.match(
        r'(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-]\d{4})',
        raw.strip()
    )
    if not m:
        return None
    day, mon_s, year, hh, mm, ss, tz_s = m.groups()
    mon = _MONTHS.get(mon_s.lower())
    if not mon:
        return None
    sign    = 1 if tz_s[0] == "+" else -1
    tz_off  = timezone(timedelta(hours=sign * int(tz_s[1:3]),
                                  minutes=sign * int(tz_s[3:5])))
    dt = datetime(int(year), mon, int(day),
                  int(hh), int(mm), int(ss), tzinfo=tz_off)
    return dt.astimezone(timezone.utc)


def parse_syslog(raw: str, year: Optional[int] = None) -> Optional[datetime]:
    """
    Parse syslog RFC 3164 timestamp (no year!).
    Format: Jan  4 10:01:32
    year defaults to current year if None.
    """
    m = re.match(r'(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})', raw)
    if not m:
        return None
    mon_s, day, hh, mm, ss = m.groups()
    mon = _MONTHS.get(mon_s.lower())
    if not mon:
        return None
    if year is None:
        year = datetime.now(timezone.utc).year
    try:
        return datetime(year, mon, int(day),
                        int(hh), int(mm), int(ss), tzinfo=timezone.utc)
    except ValueError:
        return None


def parse_iso8601(raw: str) -> Optional[datetime]:
    """
    Parse ISO 8601 / RFC 3339 timestamp.
    Handles: 2026-01-04T10:00:00Z, 2026-01-04T10:00:00+05:30,
             2026-01-04T10:00:00.123456Z
    Returns UTC datetime.
    """
    if not raw:
        return None
    try:
        normalised = raw.strip().replace(" ", "T")
        if normalised.endswith("Z"):
            normalised = normalised[:-1] + "+00:00"
        dt = datetime.fromisoformat(normalised)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (ValueError, AttributeError):
        return None


def parse_windows_evtx(raw: str) -> Optional[datetime]:
    """
    Parse Windows EVTX SystemTime attribute.
    Format: 2026-01-04T10:02:00.000000000Z
    """
    return parse_iso8601(raw)


def to_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """Ensure a datetime is UTC. If naive, assume UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def format_for_report(dt: Optional[datetime]) -> str:
    """Return a human-readable UTC timestamp string for reports."""
    if dt is None:
        return "unknown"
    utc = to_utc(dt)
    return utc.strftime("%Y-%m-%d %H:%M:%S UTC")
