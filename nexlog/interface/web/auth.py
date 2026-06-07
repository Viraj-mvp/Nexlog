"""
NexLog web authentication and response hardening.

API routes fail closed when no API key is configured. Static UI assets remain
public so the browser can show a clear "configure your key" state instead of a
blank page.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import threading
import time
from collections import defaultdict, deque
from ipaddress import ip_address, ip_network
from typing import Optional
from urllib.parse import urlparse

_API_KEY: Optional[str] = os.environ.get("NEXLOG_API_KEY")
_TRUSTED_PROXIES = [
    value.strip()
    for value in os.environ.get(
        "NEXLOG_TRUSTED_PROXIES",
        "127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
    ).split(",")
    if value.strip()
]

_RATE_WINDOW_SECS = int(os.environ.get("NEXLOG_RATE_WINDOW_SECS", "60"))
_RATE_MAX_REQUESTS = int(os.environ.get("NEXLOG_RATE_MAX_REQUESTS", "120"))
_rate_buckets: dict[str, deque] = defaultdict(deque)
_rate_lock = threading.Lock()

_PUBLIC_PATHS = {"/", "/index.html", "/api/health", "/api/v1/health", "/api/auth/status"}
_PUBLIC_PREFIXES = ("/static/", "/app/", "/assets/")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "0",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "object-src 'none'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self' ws: wss:;"
    ),
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cache-Control": "no-store",
}


def is_public_path(path: str) -> bool:
    """Return True when the path can be served before API auth."""
    parsed_path = urlparse(path).path
    return parsed_path in _PUBLIC_PATHS or parsed_path.startswith(_PUBLIC_PREFIXES)


def _effective_api_key(api_key: str = "") -> str:
    return api_key or _API_KEY or ""


def check_auth(path: str, headers: dict) -> tuple[bool, int, str]:
    """
    Return (allowed, status_code, message).

    Uses hash + constant-time compare to avoid length/timing leaks and fails
    closed for API routes when no key is configured.
    """
    if is_public_path(path):
        return True, 200, ""

    expected = _effective_api_key()
    if not expected:
        return (
            False,
            503,
            "API authentication not configured. Set NEXLOG_API_KEY.",
        )

    provided = (
        headers.get("X-API-Key", "")
        or headers.get("Authorization", "").removeprefix("Bearer ").strip()
    )
    if not provided:
        return False, 401, "Missing X-API-Key header"

    expected_hash = hashlib.sha256(expected.encode()).digest()
    provided_hash = hashlib.sha256(provided.encode()).digest()
    if not hmac.compare_digest(expected_hash, provided_hash):
        return False, 401, "Invalid API key"

    return True, 200, ""


def check_rate_limit(client_ip: str, scope: str = "global") -> tuple[bool, str]:
    """Sliding-window in-memory rate limiter."""
    key = f"{scope}:{client_ip or 'unknown'}"
    with _rate_lock:
        now = time.monotonic()
        bucket = _rate_buckets[key]
        while bucket and now - bucket[0] > _RATE_WINDOW_SECS:
            bucket.popleft()
        if len(bucket) >= _RATE_MAX_REQUESTS:
            return False, f"Rate limit exceeded: {_RATE_MAX_REQUESTS} req/{_RATE_WINDOW_SECS}s"
        bucket.append(now)
        return True, ""


def _is_trusted_proxy(remote_addr: str) -> bool:
    """Trust forwarded headers only from configured proxies."""
    try:
        remote = ip_address(remote_addr)
        return any(remote in ip_network(net, strict=False) for net in _TRUSTED_PROXIES)
    except ValueError:
        return False


def get_client_ip(headers: dict, remote_addr: str) -> str:
    """Extract the client IP without blindly trusting X-Forwarded-For."""
    xff = headers.get("X-Forwarded-For", "")
    if xff and _is_trusted_proxy(remote_addr or ""):
        candidate = xff.split(",")[0].strip()
        if candidate:
            return candidate
    return remote_addr or "unknown"


def auth_status(api_key: str = "") -> dict:
    """Return a small status object used by startup messages and health views."""
    return {
        "auth_enabled": bool(_effective_api_key(api_key)),
        "primary_env": "NEXLOG_API_KEY",
    }


def create_auth_middleware(api_key: str = ""):
    """Create Starlette middleware compatible with interface.web.serve."""
    global _API_KEY
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import JSONResponse

    effective_key = _effective_api_key(api_key)
    if api_key:
        _API_KEY = api_key

    class AuthMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            if is_public_path(request.url.path):
                return await call_next(request)

            headers = request.headers
            remote_addr = request.client.host if request.client else ""
            client_ip = get_client_ip(headers, remote_addr)
            rate_allowed, rate_msg = check_rate_limit(client_ip, request.url.path)
            if not rate_allowed:
                return JSONResponse({"error": rate_msg}, status_code=429)

            if not effective_key:
                return JSONResponse(
                    {"error": "API authentication not configured."},
                    status_code=503,
                )

            provided = (
                headers.get("X-API-Key", "")
                or headers.get("Authorization", "").removeprefix("Bearer ").strip()
            )
            expected_hash = hashlib.sha256(effective_key.encode()).digest()
            provided_hash = hashlib.sha256(provided.encode()).digest()
            if not provided or not hmac.compare_digest(expected_hash, provided_hash):
                return JSONResponse({"error": "Invalid API key"}, status_code=401)

            return await call_next(request)

    return AuthMiddleware


def guard_stdlib_request(handler, method: str, path: str, api_key: str = ""):
    """
    Return a stdlib server response tuple when a request should be blocked.
    Returning None means the request is allowed.
    """
    del method
    effective_key = _effective_api_key(api_key)
    parsed_path = urlparse(path).path
    if is_public_path(parsed_path):
        return None
    if not effective_key:
        return 503, {"error": "API authentication not configured."}

    headers = dict(handler.headers)
    provided = (
        headers.get("X-API-Key", "")
        or headers.get("Authorization", "").removeprefix("Bearer ").strip()
    )
    expected_hash = hashlib.sha256(effective_key.encode()).digest()
    provided_hash = hashlib.sha256(provided.encode()).digest()
    if not provided or not hmac.compare_digest(expected_hash, provided_hash):
        return 401, {"error": "Invalid API key"}
    return None
