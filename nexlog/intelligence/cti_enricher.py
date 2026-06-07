"""
intelligence/cti_enricher.py â€” NexLog v2
==============================================
Live Cyber Threat Intelligence enrichment using FREE public APIs.

Five free CTI sources â€” no credit card, no billing:
  1. VirusTotal     â€” IP/domain/hash reputation (1000 req/day free)
                      Sign up: https://www.virustotal.com/gui/join-us
                      Env: VIRUSTOTAL_API_KEY
  2. AlienVault OTX â€” Threat indicators (unlimited free)
                      Sign up: https://otx.alienvault.com
                      Env: OTX_API_KEY
  3. URLhaus        â€” Malicious URL/domain database (unlimited, no key)
                      API: https://urlhaus-api.abuse.ch/v1/
  4. MalwareBazaar  â€” Malware hash lookups (unlimited, no key)
                      API: https://bazaar.abuse.ch/api/
  5. AbuseIPDB      â€” IP abuse score (already in project, 1000 req/day)

Threat score: 0 (clean) â†’ 10 (confirmed malicious)
Color mapping: 0â€“3 green, 4â€“6 amber, 7â€“10 red

Usage:
    from intelligence.cti_enricher import CTIEnricher

    enricher = CTIEnricher()
    result = enricher.enrich_ip("203.0.113.5")
    print(result)  # {"score": 8.5, "sources": {...}, "tags": [...]}

    # Enrich all findings in a session
    enricher.enrich_findings(findings)
"""

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

_root = os.path.dirname(os.path.abspath(__file__))
for _ in range(8):
    if os.path.isfile(os.path.join(_root, "pathconfig.py")):
        break
    _root = os.path.dirname(_root)
if _root not in sys.path:
    sys.path.insert(0, _root)
from pathconfig import ROOT, add_root
add_root()

# â”€â”€ API keys from env â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_VT_KEY   = os.environ.get("VIRUSTOTAL_API_KEY", "")
_OTX_KEY  = os.environ.get("OTX_API_KEY", "")
_TIMEOUT  = 8

# â”€â”€ Simple in-memory cache to respect rate limits â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_CACHE: dict = {}
_CACHE_TTL  = 3600  # 1 hour


def _fetch(url: str, headers: dict = None, timeout: int = _TIMEOUT) -> Optional[dict]:
    """Make a GET request and return parsed JSON or None."""
    try:
        req = urllib.request.Request(url, headers=headers or {}, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def _fetch_post(url: str, data: dict, headers: dict = None,
                timeout: int = _TIMEOUT) -> Optional[dict]:
    """Make a POST request and return parsed JSON or None."""
    try:
        payload = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(
            url, data=payload, headers=headers or {}, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def _cached(key: str):
    """Return cached result if fresh, else None."""
    if key in _CACHE:
        result, ts = _CACHE[key]
        if time.monotonic() - ts < _CACHE_TTL:
            return result
    return None


def _cache(key: str, value: dict):
    _CACHE[key] = (value, time.monotonic())


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# INDIVIDUAL SOURCE LOOKUPS
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def _vt_ip(ip: str) -> dict:
    """VirusTotal IP lookup. Returns malicious count / total engines."""
    if not _VT_KEY:
        return {}
    key = f"vt_ip_{ip}"
    cached = _cached(key)
    if cached is not None:
        return cached

    url  = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    data = _fetch(url, headers={"x-apikey": _VT_KEY})
    if not data:
        return _cache(key, {}) or {}

    attrs    = data.get("data", {}).get("attributes", {})
    analysis = attrs.get("last_analysis_stats", {})
    result   = {
        "malicious":   analysis.get("malicious", 0),
        "suspicious":  analysis.get("suspicious", 0),
        "total":       sum(analysis.values()) or 1,
        "country":     attrs.get("country", ""),
        "as_owner":    attrs.get("as_owner", ""),
        "reputation":  attrs.get("reputation", 0),
        "tags":        attrs.get("tags", []),
    }
    _cache(key, result)
    return result


def _vt_domain(domain: str) -> dict:
    """VirusTotal domain lookup."""
    if not _VT_KEY:
        return {}
    key  = f"vt_domain_{domain}"
    cached = _cached(key)
    if cached is not None:
        return cached

    url  = f"https://www.virustotal.com/api/v3/domains/{domain}"
    data = _fetch(url, headers={"x-apikey": _VT_KEY})
    if not data:
        return _cache(key, {}) or {}

    attrs    = data.get("data", {}).get("attributes", {})
    analysis = attrs.get("last_analysis_stats", {})
    result   = {
        "malicious":  analysis.get("malicious", 0),
        "suspicious": analysis.get("suspicious", 0),
        "total":      sum(analysis.values()) or 1,
        "categories": attrs.get("categories", {}),
        "reputation": attrs.get("reputation", 0),
    }
    _cache(key, result)
    return result


def _vt_hash(sha256: str) -> dict:
    """VirusTotal file hash lookup."""
    if not _VT_KEY:
        return {}
    key  = f"vt_hash_{sha256}"
    cached = _cached(key)
    if cached is not None:
        return cached

    url  = f"https://www.virustotal.com/api/v3/files/{sha256}"
    data = _fetch(url, headers={"x-apikey": _VT_KEY})
    if not data:
        return _cache(key, {}) or {}

    attrs    = data.get("data", {}).get("attributes", {})
    analysis = attrs.get("last_analysis_stats", {})
    result   = {
        "malicious":   analysis.get("malicious", 0),
        "suspicious":  analysis.get("suspicious", 0),
        "total":       sum(analysis.values()) or 1,
        "type":        attrs.get("type_description", ""),
        "name":        attrs.get("meaningful_name", ""),
        "family":      list(attrs.get("popular_threat_classification", {})
                            .get("popular_threat_name", [{"value":""}]))[0] if
                       attrs.get("popular_threat_classification") else "",
    }
    _cache(key, result)
    return result


def _otx_ip(ip: str) -> dict:
    """AlienVault OTX IP pulse lookup (free, no key required for basic)."""
    key = f"otx_ip_{ip}"
    cached = _cached(key)
    if cached is not None:
        return cached

    headers = {}
    if _OTX_KEY:
        headers["X-OTX-API-KEY"] = _OTX_KEY

    url  = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    data = _fetch(url, headers=headers)
    if not data:
        return _cache(key, {}) or {}

    result = {
        "pulse_count": data.get("pulse_info", {}).get("count", 0),
        "reputation":  data.get("reputation", 0),
        "country":     data.get("country_name", ""),
        "tags":        [t for p in data.get("pulse_info", {}).get("pulses", [])
                        for t in p.get("tags", [])],
    }
    _cache(key, result)
    return result


def _urlhaus_domain(domain: str) -> dict:
    """URLhaus domain check â€” free, no key required."""
    key = f"urlhaus_domain_{domain}"
    cached = _cached(key)
    if cached is not None:
        return cached

    data = _fetch_post(
        "https://urlhaus-api.abuse.ch/v1/host/",
        {"host": domain}
    )
    if not data or data.get("query_status") == "no_results":
        return _cache(key, {"malicious": False}) or {}

    urls_count = len(data.get("urls", []))
    result = {
        "malicious":   urls_count > 0,
        "url_count":   urls_count,
        "blacklists":  data.get("blacklists", {}),
    }
    _cache(key, result)
    return result


def _malwarebazaar_hash(sha256: str) -> dict:
    """MalwareBazaar hash lookup â€” free, no key required."""
    key = f"mb_{sha256}"
    cached = _cached(key)
    if cached is not None:
        return cached

    data = _fetch_post(
        "https://bazaar.abuse.ch/api/",
        {"query": "get_info", "hash": sha256}
    )
    if not data or data.get("query_status") != "ok":
        return _cache(key, {"found": False}) or {}

    info = data.get("data", [{}])[0]
    result = {
        "found":     True,
        "file_type": info.get("file_type", ""),
        "file_name": info.get("file_name", ""),
        "tags":      info.get("tags", []),
        "signature": info.get("signature", ""),
    }
    _cache(key, result)
    return result


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# THREAT SCORE CALCULATOR
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def _compute_score(vt: dict, otx: dict = None, urlhaus: dict = None) -> float:
    """Aggregate a 0â€“10 threat score from multiple source results."""
    score = 0.0

    # VirusTotal â€” primary signal
    if vt:
        total = vt.get("total", 1)
        mal   = vt.get("malicious", 0)
        sus   = vt.get("suspicious", 0)
        ratio = (mal + sus * 0.5) / max(total, 1)
        score = max(score, ratio * 10)
        if vt.get("reputation", 0) < -50:
            score = max(score, 7.0)

    # OTX pulse count
    if otx:
        pulses = otx.get("pulse_count", 0)
        if pulses > 5:
            score = max(score, min(pulses / 2, 8.0))
        elif pulses > 0:
            score = max(score, 4.0)

    # URLhaus
    if urlhaus and urlhaus.get("malicious"):
        score = max(score, 7.0)

    return round(min(score, 10.0), 1)


def _color_for_score(score: float) -> str:
    """Return hex color for threat score."""
    if score >= 7:
        return "#FF3B5C"    # red â€” malicious
    if score >= 4:
        return "#FFB700"    # amber â€” suspicious
    return "#00FF9D"        # green â€” clean


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# PUBLIC API
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class CTIEnricher:
    """
    Enriches NexLog findings with live CTI data from free APIs.
    All API calls are cached for 1 hour to respect rate limits.
    """

    def enrich_ip(self, ip: str) -> dict:
        """
        Look up an IP across all available CTI sources.

        Returns:
            {
                "score":   float (0-10),
                "color":   str hex,
                "sources": {"vt": {...}, "otx": {...}},
                "tags":    list[str],
                "summary": str,
            }
        """
        vt  = _vt_ip(ip)
        otx = _otx_ip(ip)

        score  = _compute_score(vt, otx)
        tags   = list(set(vt.get("tags", []) + otx.get("tags", [])))
        source = "clean" if score < 4 else "suspicious" if score < 7 else "malicious"

        country = vt.get("country") or otx.get("country") or "?"
        as_own  = vt.get("as_owner", "")

        summary = (
            f"IP {ip} ({country}) â€” threat score {score:.1f}/10 ({source}). "
            + (f"VT: {vt.get('malicious',0)}/{vt.get('total',0)} engines flagged. " if vt else "")
            + (f"OTX: {otx.get('pulse_count',0)} threat pulses. " if otx else "")
            + (f"AS: {as_own}." if as_own else "")
        )

        return {
            "score":   score,
            "color":   _color_for_score(score),
            "sources": {"vt": vt, "otx": otx},
            "tags":    tags[:10],
            "summary": summary.strip(),
        }

    def enrich_domain(self, domain: str) -> dict:
        """Look up a domain across VT and URLhaus."""
        vt      = _vt_domain(domain)
        urlhaus = _urlhaus_domain(domain)

        score   = _compute_score(vt, urlhaus=urlhaus)
        source  = "clean" if score < 4 else "suspicious" if score < 7 else "malicious"
        summary = (
            f"Domain {domain} â€” threat score {score:.1f}/10 ({source}). "
            + (f"VT: {vt.get('malicious',0)}/{vt.get('total',0)} engines flagged. " if vt else "")
            + ("URLhaus: known malicious URL host. " if urlhaus.get("malicious") else "")
        )
        return {
            "score":   score,
            "color":   _color_for_score(score),
            "sources": {"vt": vt, "urlhaus": urlhaus},
            "tags":    list(vt.get("categories", {}).values())[:5],
            "summary": summary.strip(),
        }

    def enrich_hash(self, sha256: str) -> dict:
        """Look up a file hash across VT and MalwareBazaar."""
        vt = _vt_hash(sha256)
        mb = _malwarebazaar_hash(sha256)

        score   = _compute_score(vt)
        if mb.get("found"):
            score = max(score, 8.0)  # if it's in bazaar it's malware

        source  = "clean" if score < 4 else "suspicious" if score < 7 else "malware"
        tags    = mb.get("tags", [])
        sig     = mb.get("signature", vt.get("family", ""))

        summary = (
            f"Hash {sha256[:16]}â€¦ â€” threat score {score:.1f}/10 ({source}). "
            + (f"VT: {vt.get('malicious',0)}/{vt.get('total',0)} engines flagged. " if vt else "")
            + (f"MalwareBazaar: known malware ({sig}). " if mb.get("found") else "Not in MalwareBazaar. ")
        )
        return {
            "score":   score,
            "color":   _color_for_score(score),
            "sources": {"vt": vt, "malwarebazaar": mb},
            "tags":    tags[:10],
            "summary": summary.strip(),
            "family":  sig,
        }

    def enrich_findings(self, findings: list) -> None:
        """
        Enrich a list of finding objects in-place.
        Adds a .cti_enrichment dict to each finding that has an IP/domain/hash.
        Respects rate limits with a 0.2s delay between unique lookups.
        """
        seen_ips:     set = set()
        ip_cache:     dict = {}

        for f in findings:
            if isinstance(f, dict):
                ip = f.get("source_ip")
            else:
                ip = getattr(f, "source_ip", None)

            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                result = self.enrich_ip(ip)
                ip_cache[ip] = result
                time.sleep(0.2)  # gentle rate limiting

            if ip and ip in ip_cache:
                if isinstance(f, dict):
                    f["cti_enrichment"] = ip_cache[ip]
                else:
                    try:
                        f.cti_enrichment = ip_cache[ip]
                    except AttributeError:
                        pass

    def quick_score(self, ip: str) -> tuple[float, str]:
        """
        Fastest path: return (score, color) for an IP.
        Uses cache if warm, otherwise makes API call.
        Used for real-time GUI badge coloring.
        """
        result = self.enrich_ip(ip)
        return result["score"], result["color"]
