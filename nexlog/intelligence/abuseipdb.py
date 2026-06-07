"""
intelligence/abuseipdb.py â€” NexLog Layer 3
AbuseIPDB v2 API integration for optional threat intelligence enrichment.

AbuseIPDB is a public database of IP addresses reported for malicious
activity. The free tier allows 1,000 checks/day.

Features:
  - Single IP check with full report data
  - Batch checking against a list of IPs (rate-limited automatically)
  - SQLite-backed local cache: never re-query the same IP within TTL
  - Automatic confidence score boost on findings from known-bad IPs
  - Graceful degradation: works with no API key (returns empty results)

Setup:
    1. Get a free API key at https://www.abuseipdb.com/api
    2. Set env var: ABUSEIPDB_API_KEY=<your-key>
       OR pass api_key= to the constructor

Usage:
    from intelligence.abuseipdb import AbuseIPDB

    adb = AbuseIPDB()                    # reads key from ABUSEIPDB_API_KEY
    result = adb.check("185.220.100.5")

    print(result["abuse_confidence"])    # 0-100 score
    print(result["total_reports"])       # total report count
    print(result["country_code"])        # "DE"
    print(result["is_whitelisted"])      # False

    # Enrich a list of IOCs in-place
    adb.enrich_iocs(iocs)

    # Enrich findings â€” boosts confidence on known-bad source IPs
    adb.enrich_findings(findings)

    # Check many IPs (cached â€” no re-query within TTL)
    results = adb.check_many(["1.2.3.4", "5.6.7.8"])
"""

import json
import os
import sqlite3
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from typing import Optional


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

# â”€â”€ Configuration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_API_KEY      = os.environ.get("ABUSEIPDB_API_KEY", "")
if not _API_KEY:
    import warnings
    warnings.warn("ABUSEIPDB_API_KEY not set â€” threat intelligence enrichment disabled", stacklevel=2)
_API_BASE     = "https://api.abuseipdb.com/api/v2"
_TIMEOUT      = 10         # seconds per request
_RATE_DELAY   = 1.2        # seconds between requests (free: 1 req/sec safe)
_DEFAULT_TTL  = 86400      # cache TTL: 24 hours in seconds
_DEFAULT_DAYS = 90         # lookback window for abuse reports
_DEFAULT_CACHE = os.path.join(_ROOT, ".abuseipdb_cache.db")

_CACHE_DDL = """
CREATE TABLE IF NOT EXISTS ip_cache (
    ip           TEXT PRIMARY KEY,
    checked_at   TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
"""

# â”€â”€ Null result template â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def _null_result(ip: str, reason: str = "no_key") -> dict:
    return {
        "ip":               ip,
        "abuse_confidence": 0,
        "total_reports":    0,
        "num_distinct_users": 0,
        "last_reported_at": None,
        "country_code":     "",
        "isp":              "",
        "domain":           "",
        "is_public":        True,
        "is_whitelisted":   False,
        "usage_type":       "",
        "source":           "none",
        "reason":           reason,
        "checked_at":       _utcnow(),
    }


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# AbuseIPDB CLIENT
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class AbuseIPDB:
    """
    AbuseIPDB v2 API client with SQLite-backed caching.

    Operates gracefully without an API key â€” returns empty results
    so callers never need to handle missing-key exceptions.

    Args:
        api_key:    AbuseIPDB API key. Falls back to ABUSEIPDB_API_KEY env var.
        cache_path: Path to SQLite cache file. Default: .abuseipdb_cache.db
                    in project root. Pass ":memory:" for ephemeral cache.
        cache_ttl:  Seconds before a cached result expires. Default: 86400 (24h).
        max_age_days: Lookback window for abuse reports. Default: 90.
    """

    def __init__(
        self,
        api_key:      str = "",
        cache_path:   str = "",
        cache_ttl:    int = _DEFAULT_TTL,
        max_age_days: int = _DEFAULT_DAYS,
    ):
        self._key         = api_key or _API_KEY
        self._ttl         = cache_ttl
        self._max_age     = max_age_days
        self._last_call   = 0.0    # timestamp of last API call (rate limiting)
        self._call_count  = 0
        self._cache_hits  = 0
        self._conn        = None

        if not self._key:
            return

        # Open SQLite cache. Cache failures should not stop log analysis.
        db_path = cache_path or _DEFAULT_CACHE
        try:
            self._conn = sqlite3.connect(db_path)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute(_CACHE_DDL)
            self._conn.commit()
        except sqlite3.Error:
            self._conn = None

    # â”€â”€ Single IP check â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def check(self, ip: str, max_age_days: int = 0) -> dict:
        """
        Check one IP address against AbuseIPDB.

        Returns from cache if fresh; queries API if stale or absent.
        Returns a null result dict if no API key is configured.

        Args:
            ip:          IPv4 or IPv6 address to check.
            max_age_days: Override the instance default lookback window.

        Returns dict with:
            abuse_confidence  int     0â€“100 score
            total_reports     int     total report count
            num_distinct_users int    number of distinct reporters
            last_reported_at  str|None ISO timestamp of most recent report
            country_code      str     2-letter ISO country code
            isp               str     ISP name
            domain            str     associated domain
            is_public         bool
            is_whitelisted    bool
            usage_type        str     e.g. "Data Center/Web Hosting/Transit"
            source            str     "abuseipdb" | "cache" | "none"
            reason            str     why it's "none" if so
            checked_at        str     ISO timestamp
        """
        ip = ip.strip()
        if not self._key:
            return _null_result(ip, "no_api_key")

        # Cache lookup
        cached = self._get_cache(ip)
        if cached:
            cached["source"] = "cache"
            self._cache_hits += 1
            return cached

        # No API key â€” return empty result
        if not self._key:
            return _null_result(ip, "no_api_key")

        # Rate limit: respect 1 req/sec for free tier
        elapsed = time.monotonic() - self._last_call
        if elapsed < _RATE_DELAY:
            time.sleep(_RATE_DELAY - elapsed)

        result = self._query_api(ip, max_age_days or self._max_age)
        self._last_call = time.monotonic()
        self._call_count += 1

        # Cache the result
        if result.get("source") == "abuseipdb":
            self._set_cache(ip, result)

        return result

    def check_many(self, ips: list[str]) -> dict[str, dict]:
        """
        Check multiple IPs. Cached results are returned without API calls.
        API calls are made one at a time with rate limiting.

        Returns: {ip: result_dict, ...}
        """
        results = {}
        for ip in ips:
            results[ip] = self.check(ip)
        return results

    # â”€â”€ API query â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _query_api(self, ip: str, max_age_days: int) -> dict:
        """
        Make a single API request to AbuseIPDB.
        Returns null result on any error.
        """
        url = f"{_API_BASE}/check?ipAddress={ip}&maxAgeInDays={max_age_days}&verbose"
        try:
            req = urllib.request.Request(
                url,
                headers={
                    "Key":    self._key,
                    "Accept": "application/json",
                    "User-Agent": "nexlog/2.0 (DFIR research)",
                },
            )
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                body = json.loads(resp.read().decode("utf-8"))

            data = body.get("data", {})
            return {
                "ip":                 ip,
                "abuse_confidence":   data.get("abuseConfidenceScore", 0),
                "total_reports":      data.get("totalReports", 0),
                "num_distinct_users": data.get("numDistinctUsers", 0),
                "last_reported_at":   data.get("lastReportedAt"),
                "country_code":       data.get("countryCode", ""),
                "isp":                data.get("isp", ""),
                "domain":             data.get("domain", ""),
                "is_public":          data.get("isPublic", True),
                "is_whitelisted":     data.get("isWhitelisted", False),
                "usage_type":         data.get("usageType", ""),
                "source":             "abuseipdb",
                "reason":             "",
                "checked_at":         _utcnow(),
            }

        except urllib.error.HTTPError as e:
            if e.code == 401:
                return _null_result(ip, "invalid_api_key")
            if e.code == 429:
                return _null_result(ip, "rate_limit_exceeded")
            return _null_result(ip, f"http_error_{e.code}")
        except urllib.error.URLError:
            return _null_result(ip, "network_unavailable")
        except Exception as e:
            return _null_result(ip, f"error:{e}")

    # â”€â”€ Cache â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _get_cache(self, ip: str) -> Optional[dict]:
        """Return cached result if not expired, else None."""
        if self._conn is None:
            return None
        now = _utcnow()
        row = self._conn.execute(
            "SELECT payload_json, expires_at FROM ip_cache WHERE ip=?", (ip,)
        ).fetchone()
        if row and row["expires_at"] > now:
            try:
                return json.loads(row["payload_json"])
            except json.JSONDecodeError:
                return None
        return None

    def _set_cache(self, ip: str, result: dict) -> None:
        """Store a result in the SQLite cache with expiry."""
        if self._conn is None:
            return
        expires = (
            datetime.now(timezone.utc) + timedelta(seconds=self._ttl)
        ).isoformat()
        self._conn.execute(
            """INSERT OR REPLACE INTO ip_cache(ip, checked_at, expires_at, payload_json)
               VALUES (?, ?, ?, ?)""",
            (ip, _utcnow(), expires, json.dumps(result))
        )
        self._conn.commit()

    def purge_cache(self) -> int:
        """Delete all expired cache entries. Returns count deleted."""
        if self._conn is None:
            return 0
        cur = self._conn.execute(
            "DELETE FROM ip_cache WHERE expires_at <= ?", (_utcnow(),)
        )
        self._conn.commit()
        return cur.rowcount

    def clear_cache(self) -> None:
        """Wipe the entire cache."""
        if self._conn is None:
            return
        self._conn.execute("DELETE FROM ip_cache")
        self._conn.commit()

    @property
    def cache_count(self) -> int:
        """Number of cached entries (including expired)."""
        if self._conn is None:
            return 0
        return self._conn.execute(
            "SELECT COUNT(*) FROM ip_cache"
        ).fetchone()[0]

    # â”€â”€ Enrichment helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def enrich_finding(self, finding, threshold: int = 25) -> dict:
        """
        Check finding.source_ip against AbuseIPDB.
        If abuse_confidence >= threshold, boost finding.confidence
        and write results into finding.extra["abuseipdb"].

        Args:
            finding:   Finding object with source_ip field.
            threshold: Minimum abuse score to trigger confidence boost (0â€“100).

        Returns the AbuseIPDB result dict.
        """
        if not finding.source_ip:
            return {}

        info = self.check(finding.source_ip)
        finding.extra["abuseipdb"] = info

        score = info.get("abuse_confidence", 0)
        if score >= threshold:
            # Boost confidence proportionally (max +0.15)
            boost = min(score / 100 * 0.15, 0.15)
            finding.confidence = min(finding.confidence + boost, 1.0)
            if "known_malicious_ip" not in finding.extra.get("rule_tags", []):
                finding.extra.setdefault("rule_tags", []).append("known_malicious_ip")

        return info

    def enrich_ioc(self, ioc, threshold: int = 25) -> dict:
        """
        Enrich an IOC whose type is 'ipv4' with AbuseIPDB data.
        Boosts IOC confidence and adds country/malicious tags.

        Returns the AbuseIPDB result dict.
        """
        if ioc.ioc_type != "ipv4":
            return {}

        info  = self.check(ioc.value)
        score = info.get("abuse_confidence", 0)

        # Adjust IOC confidence based on abuse score
        if score >= threshold:
            ioc.confidence = min(ioc.confidence + (score / 100 * 0.2), 1.0)
            if "known_bad_ip" not in ioc.tags:
                ioc.tags.append("known_bad_ip")
            if f"abuse_score:{score}" not in ioc.tags:
                ioc.tags.append(f"abuse_score:{score}")

        cc = info.get("country_code", "")
        if cc and f"country:{cc}" not in ioc.tags:
            ioc.tags.append(f"country:{cc}")

        return info

    def enrich_iocs(self, iocs: list, threshold: int = 25) -> None:
        """Enrich all ipv4-type IOCs in-place (in-place, no return value)."""
        unique_ips = {i.value for i in iocs if i.ioc_type == "ipv4"}
        _ = self.check_many(list(unique_ips))   # warm cache
        for ioc in iocs:
            if ioc.ioc_type == "ipv4":
                self.enrich_ioc(ioc, threshold)

    def enrich_findings(self, findings: list, threshold: int = 25) -> None:
        """Enrich all findings with AbuseIPDB data (in-place)."""
        unique_ips = {f.source_ip for f in findings if f.source_ip}
        _ = self.check_many(list(unique_ips))   # warm cache
        for f in findings:
            self.enrich_finding(f, threshold)

    # â”€â”€ Statistics â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def stats(self) -> dict:
        """Return usage statistics for this session."""
        return {
            "api_calls":     self._call_count,
            "cache_hits":    self._cache_hits,
            "cache_entries": self.cache_count,
            "has_api_key":   bool(self._key),
            "cache_ttl_sec": self._ttl,
        }

    def __repr__(self) -> str:
        return (
            f"<AbuseIPDB key={'set' if self._key else 'unset'} "
            f"calls={self._call_count} "
            f"cache_hits={self._cache_hits}>"
        )

    def __del__(self):
        try:
            if hasattr(self, "_conn") and self._conn:
                self._conn.close()
        except Exception:
            pass


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()
