"""
utils/ip_utils.py â€” NexLog shared utilities
IP address helpers: private range detection, simple geolocation
hint from IP range, ASN-range based ISP classification.
No external API calls â€” purely local logic.
"""

import ipaddress
import re
from typing import Optional


# â”€â”€ Classification â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def is_private(ip: str) -> bool:
    """True if ip is RFC1918, loopback, link-local, or documentation range."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def is_public(ip: str) -> bool:
    return not is_private(ip)


def ip_version(ip: str) -> Optional[int]:
    """Return 4 or 6, or None if not a valid IP."""
    try:
        return ipaddress.ip_address(ip).version
    except ValueError:
        return None


def classify_ip(ip: str) -> str:
    """
    Return a classification string for an IP address.
    Used in confidence adjustment and report generation.

    Returns one of:
      "private"      â€” RFC1918, loopback, link-local
      "loopback"     â€” 127.x.x.x
      "documentation"â€” 192.0.2.x / 198.51.100.x / 203.0.113.x (TEST-NET)
      "multicast"    â€” 224.x - 239.x
      "public"       â€” everything else (real internet IP)
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid"

    if addr.is_loopback:
        return "loopback"
    if addr.is_multicast:
        return "multicast"
    if str(addr).startswith(("192.0.2.", "198.51.100.", "203.0.113.")):
        return "documentation"
    if addr.is_private:
        return "private"
    return "public"


# â”€â”€ Network helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def ips_same_subnet(ip1: str, ip2: str, prefix_len: int = 24) -> bool:
    """True if both IPs are in the same /{prefix_len} subnet."""
    try:
        n1 = ipaddress.ip_network(f"{ip1}/{prefix_len}", strict=False)
        return ipaddress.ip_address(ip2) in n1
    except ValueError:
        return False


def extract_ips(text: str) -> list[str]:
    """Extract all IPv4 addresses from a text string. Deduplicated, ordered."""
    pattern = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}'
        r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    )
    seen, result = set(), []
    for m in pattern.finditer(text):
        ip = m.group(0)
        if ip not in seen:
            seen.add(ip)
            result.append(ip)
    return result


def is_tor_exit_range(ip: str) -> bool:
    """
    Heuristic: IPs in ranges commonly associated with Tor exit nodes.
    This is NOT a live lookup â€” it's a static subnet check against
    well-known Tor infrastructure ranges as of 2024.
    For production use, integrate with a live Tor exit node list.
    """
    _TOR_RANGES = [
        "185.220.100.0/22",  # Tor Project infrastructure
        "185.220.104.0/22",
        "199.249.224.0/21",
        "204.8.156.0/22",
        "176.10.99.0/24",
        "77.247.181.0/24",
    ]
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(r) for r in _TOR_RANGES)
    except ValueError:
        return False
