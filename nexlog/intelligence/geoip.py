"""
intelligence/geoip.py â€” NexLog Layer 3
IP geolocation enrichment for findings and IOCs.

Two-tier lookup strategy â€” no hard dependency on any external package:

  Tier 1 â€” MaxMind GeoLite2 (offline, accurate, requires mmdb file)
    Requires: pip install maxminddb
    Database: GeoLite2-City.mmdb (free from maxmind.com with account)
    Set env var: GEOIP_DB_PATH=/path/to/GeoLite2-City.mmdb

  Tier 2 â€” ip-api.com REST (online, no key, 45 req/min free)
    Used automatically when MaxMind db is not available.
    Set env var: GEOIP_USE_API=1 to force REST even if mmdb present.
    Set env var: GEOIP_USE_API=0 to disable REST fallback entirely.

  Private/reserved IPs are never queried â€” instantly classified locally.

Results are cached in memory for the lifetime of the GeoIP instance
to avoid redundant lookups across many findings with the same source_ip.

Usage:
    from intelligence.geoip import GeoIP

    geo = GeoIP()                      # auto-configure
    info = geo.lookup("185.220.100.5")

    print(info["country"])   # "Germany"
    print(info["city"])      # "Frankfurt am Main"
    print(info["asn"])       # "AS4134"
    print(info["is_tor"])    # True

    # Enrich a Finding in-place
    geo.enrich_finding(finding)
    print(finding.extra["geoip"])

    # Enrich an IOC
    geo.enrich_ioc(ioc)
"""

import ipaddress
import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone
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
sys.path.insert(0, os.path.join(_ROOT, 'utils'))

# â”€â”€ Constants â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_DEFAULT_DB_PATH   = os.environ.get("GEOIP_DB_PATH", "")
_USE_API           = os.environ.get("GEOIP_USE_API", "1").strip() not in ("0", "false", "no")
_API_TIMEOUT       = 5        # seconds
_API_BASE_URL      = "http://ip-api.com/json"
_API_FIELDS        = "status,country,countryCode,region,regionName,city,zip,lat,lon,isp,org,as,query"
_CACHE_SENTINEL    = object()  # marks "already looked up, result is None"

# â”€â”€ Private IP ranges (never geo-lookup) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

# Known Tor exit node ranges (static list â€” supplement with live list if needed)
_TOR_RANGES = [
    ipaddress.ip_network("185.220.100.0/22"),
    ipaddress.ip_network("185.220.104.0/22"),
    ipaddress.ip_network("199.249.224.0/21"),
    ipaddress.ip_network("204.8.156.0/22"),
    ipaddress.ip_network("176.10.99.0/24"),
    ipaddress.ip_network("77.247.181.0/24"),
]


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _PRIVATE_NETS)
    except ValueError:
        return True


def _is_tor(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in _TOR_RANGES)
    except ValueError:
        return False


# â”€â”€ Null result â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def _null_result(ip: str, reason: str = "") -> dict:
    return {
        "ip":          ip,
        "country":     "",
        "country_code": "",
        "region":      "",
        "city":        "",
        "postal":      "",
        "latitude":    None,
        "longitude":   None,
        "isp":         "",
        "org":         "",
        "asn":         "",
        "is_private":  _is_private(ip),
        "is_tor":      _is_tor(ip),
        "source":      "none",
        "reason":      reason,
        "looked_up_at": _utcnow(),
    }


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# GeoIP CLASS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class GeoIP:
    """
    IP geolocation enrichment with automatic tier selection.

    Tier 1: MaxMind GeoLite2 mmdb (offline, accurate)
    Tier 2: ip-api.com REST API   (online, rate-limited)

    Results cached in memory for the session lifetime.
    Private IPs are answered instantly without any lookup.

    Args:
        db_path:   Path to GeoLite2-City.mmdb. If empty, reads
                   GEOIP_DB_PATH env var, then falls back to REST.
        use_api:   Whether to use REST fallback when mmdb unavailable.
        cache_size: Max number of IPs to cache (LRU eviction).
    """

    def __init__(
        self,
        db_path:    str  = "",
        use_api:    bool = _USE_API,
        cache_size: int  = 5000,
    ):
        self._use_api    = use_api
        self._cache_size = cache_size
        self._cache:     dict[str, dict] = {}
        self._mmdb       = None

        # Try to load MaxMind mmdb
        resolved_path = db_path or _DEFAULT_DB_PATH
        if resolved_path:
            self._mmdb = self._load_mmdb(resolved_path)

    # â”€â”€ Configuration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _load_mmdb(self, path: str):
        """
        Load MaxMind database. Returns reader object or None.
        Fails silently â€” falls back to REST automatically.
        """
        try:
            import maxminddb
            reader = maxminddb.open_database(path)
            return reader
        except ImportError:
            # maxminddb package not installed
            return None
        except Exception:
            # File not found, corrupted, etc.
            return None

    @property
    def has_mmdb(self) -> bool:
        """True if a MaxMind database is loaded and ready."""
        return self._mmdb is not None

    @property
    def source(self) -> str:
        """Active lookup source: 'maxmind', 'ip-api', or 'none'."""
        if self._mmdb:
            return "maxmind"
        if self._use_api:
            return "ip-api"
        return "none"

    # â”€â”€ Lookup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def lookup(self, ip: str) -> dict:
        """
        Look up geolocation for an IP address.

        Returns a dict with: country, country_code, region, city,
        latitude, longitude, isp, org, asn, is_private, is_tor, source.

        Private IPs are returned immediately with is_private=True
        without any external query.
        """
        ip = ip.strip()

        # Cache hit
        if ip in self._cache:
            return self._cache[ip]

        # Private IP â€” never query external services
        if _is_private(ip):
            result = _null_result(ip, "private/reserved IP")
            result["is_private"] = True
            self._cache_put(ip, result)
            return result

        # Validate IP
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            result = _null_result(ip, "invalid IP address")
            self._cache_put(ip, result)
            return result

        # Tier 1: MaxMind
        if self._mmdb:
            result = self._lookup_maxmind(ip)
            if result:
                self._cache_put(ip, result)
                return result

        # Tier 2: ip-api.com REST
        if self._use_api:
            result = self._lookup_rest(ip)
            if result:
                self._cache_put(ip, result)
                return result

        # No result available
        result = _null_result(ip, "no lookup source available")
        self._cache_put(ip, result)
        return result

    def lookup_many(self, ips: list[str]) -> dict[str, dict]:
        """
        Look up multiple IPs. Cached IPs are returned immediately.
        REST lookups are performed one at a time (ip-api.com has no
        free batch endpoint without an API key).

        Returns: {ip: geoinfo_dict, ...}
        """
        return {ip: self.lookup(ip) for ip in ips}

    # â”€â”€ MaxMind lookup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _lookup_maxmind(self, ip: str) -> Optional[dict]:
        try:
            record = self._mmdb.get(ip)
            if not record:
                return None

            country = record.get("country", {})
            city    = record.get("city", {})
            subdiv  = record.get("subdivisions", [{}])[0] if record.get("subdivisions") else {}
            loc     = record.get("location", {})
            postal  = record.get("postal", {})
            traits  = record.get("traits", {})

            return {
                "ip":           ip,
                "country":      (country.get("names") or {}).get("en", ""),
                "country_code": country.get("iso_code", ""),
                "region":       (subdiv.get("names") or {}).get("en", ""),
                "city":         (city.get("names") or {}).get("en", ""),
                "postal":       postal.get("code", ""),
                "latitude":     loc.get("latitude"),
                "longitude":    loc.get("longitude"),
                "isp":          traits.get("isp", ""),
                "org":          traits.get("organization", ""),
                "asn":          f"AS{traits['autonomous_system_number']}" if traits.get("autonomous_system_number") else "",
                "is_private":   False,
                "is_tor":       _is_tor(ip),
                "source":       "maxmind",
                "reason":       "",
                "looked_up_at": _utcnow(),
            }
        except Exception:
            return None

    # â”€â”€ REST API lookup â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _lookup_rest(self, ip: str) -> Optional[dict]:
        """
        Query ip-api.com (free, no key, 45 req/min).
        Returns None on any error â€” falls through to null result.
        """
        url = f"{_API_BASE_URL}/{ip}?fields={_API_FIELDS}"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "nexlog/2.0 (DFIR research)"},
            )
            with urllib.request.urlopen(req, timeout=_API_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            if data.get("status") != "success":
                return None

            return {
                "ip":           ip,
                "country":      data.get("country", ""),
                "country_code": data.get("countryCode", ""),
                "region":       data.get("regionName", ""),
                "city":         data.get("city", ""),
                "postal":       data.get("zip", ""),
                "latitude":     data.get("lat"),
                "longitude":    data.get("lon"),
                "isp":          data.get("isp", ""),
                "org":          data.get("org", ""),
                "asn":          data.get("as", "").split(" ")[0],  # "AS12345 Name" â†’ "AS12345"
                "is_private":   False,
                "is_tor":       _is_tor(ip),
                "source":       "ip-api",
                "reason":       "",
                "looked_up_at": _utcnow(),
            }
        except urllib.error.URLError:
            return None  # network unavailable
        except Exception:
            return None

    # â”€â”€ Enrichment helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def enrich_finding(self, finding) -> dict:
        """
        Look up geolocation for finding.source_ip and write
        the result into finding.extra["geoip"].

        Returns the geoip dict.
        """
        if not finding.source_ip:
            return {}
        info = self.lookup(finding.source_ip)
        finding.extra["geoip"] = info
        return info

    def enrich_ioc(self, ioc) -> dict:
        """
        Look up geolocation for an IOC whose type is 'ipv4'.
        Writes result into ioc.tags as a country tag.

        Returns the geoip dict (empty if ioc is not an IP type).
        """
        if ioc.ioc_type != "ipv4":
            return {}
        info = self.lookup(ioc.value)
        cc   = info.get("country_code", "")
        if cc and f"country:{cc}" not in ioc.tags:
            ioc.tags.append(f"country:{cc}")
        if info.get("is_tor") and "tor" not in ioc.tags:
            ioc.tags.append("tor_exit")
        return info

    def enrich_findings(self, findings: list) -> None:
        """Enrich all findings with geolocation data (in-place)."""
        unique_ips = {f.source_ip for f in findings if f.source_ip}
        _ = self.lookup_many(list(unique_ips))   # warm cache
        for f in findings:
            self.enrich_finding(f)

    # â”€â”€ Cache management â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _cache_put(self, ip: str, result: dict) -> None:
        if len(self._cache) >= self._cache_size:
            # Simple eviction: remove oldest key
            oldest = next(iter(self._cache))
            del self._cache[oldest]
        self._cache[ip] = result

    def clear_cache(self) -> None:
        """Clear the in-memory IP cache."""
        self._cache.clear()

    @property
    def cache_size(self) -> int:
        return len(self._cache)

    def __repr__(self) -> str:
        return (
            f"<GeoIP source={self.source} "
            f"cached={self.cache_size} "
            f"has_mmdb={self.has_mmdb}>"
        )


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()
