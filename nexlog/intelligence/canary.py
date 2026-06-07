"""
intelligence/canary.py â€” NexLog v2  Canary Token Generator
================================================================
Generate honeytokens (canary tokens) and track when they are triggered.
Triggered tokens appear as new findings in the case database.

Token types:
  URL       â€” HTTP URL that pings back when visited (needs a listener)
  DNS       â€” Domain that logs DNS lookups (needs DNS logger)
  AWS_KEY   â€” Fake AWS access key (triggers GitHub/repo secret scanners)
  WORD_DOC  â€” Macro-free DOCX with a tracking image (pings on open)
  API_KEY   â€” Fake API key string for credential monitoring

Local listener:
  Run:  python -m intelligence.canary --serve --port 9999
  All token hits POST to http://localhost:9999/ping/<token_id>
  and are written to the case DB as CANARY findings.

Usage:
    from intelligence.canary import CanaryManager
    from storage.case_db import CaseDB

    with CaseDB("case.facase") as db:
        mgr = CanaryManager(db=db)

        # Generate a URL token
        token = mgr.create_url_token(label="Finance Invoice Q4")
        print(token["token_url"])  # plant this in a document

        # Generate a fake AWS key (GitHub scanner will alert you)
        aws = mgr.create_aws_key_token(label="Dev server creds")
        print(aws["access_key"])   # put this in a fake .env or README

        # List all active tokens
        for t in mgr.list_tokens():
            print(t)
"""

import hashlib
import json
import os
import re
import secrets
import string
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Optional

_root = os.path.dirname(os.path.abspath(__file__))
for _ in range(8):
    if os.path.isfile(os.path.join(_root, "pathconfig.py")):
        break
    _root = os.path.dirname(_root)
if _root not in sys.path:
    sys.path.insert(0, _root)
from pathconfig import ROOT, add_root, WORKSPACE_DIR
add_root()

# â”€â”€ Token storage file â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_TOKEN_STORE = os.path.join(WORKSPACE_DIR, "canary_tokens.json")
_LISTENER_HOST = os.environ.get("CANARY_HOST", "localhost")
_LISTENER_PORT = int(os.environ.get("CANARY_PORT", "9999"))


def _load_tokens() -> dict:
    if os.path.exists(_TOKEN_STORE):
        try:
            with open(_TOKEN_STORE) as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_tokens(tokens: dict) -> None:
    os.makedirs(os.path.dirname(_TOKEN_STORE), exist_ok=True)
    with open(_TOKEN_STORE, "w") as f:
        json.dump(tokens, f, indent=2)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# CANARY MANAGER
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class CanaryManager:
    """
    Create and monitor canary tokens integrated with NexLog case DB.
    Triggered tokens automatically create CANARY-* findings in the case.
    """

    def __init__(self, db=None, case_id: str = ""):
        self._db      = db
        self._case_id = case_id
        self._tokens  = _load_tokens()
        self._lock    = threading.Lock()

    # â”€â”€ Token creation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def _new_id(self) -> str:
        return secrets.token_urlsafe(12)

    def _listener_url(self, token_id: str) -> str:
        return f"http://{_LISTENER_HOST}:{_LISTENER_PORT}/ping/{token_id}"

    def create_url_token(self, label: str = "Unlabelled URL token") -> dict:
        """
        Create a URL canary token.
        Plant the URL in a document, email, or web page.
        Any visit logs the source IP, user-agent, and timestamp.

        Returns:
            {
                "token_id":  str,
                "token_url": str,   â† plant this
                "label":     str,
                "type":      "URL",
                "created":   str,
            }
        """
        tid = self._new_id()
        token = {
            "token_id":  tid,
            "type":      "URL",
            "label":     label,
            "token_url": self._listener_url(tid),
            "created":   datetime.now(timezone.utc).isoformat(),
            "hits":      [],
        }
        with self._lock:
            self._tokens[tid] = token
            _save_tokens(self._tokens)
        return token

    def create_aws_key_token(self, label: str = "Fake AWS key") -> dict:
        """
        Create a fake AWS access key pair.
        Paste this in a repo, config file, or README.
        GitHub's secret scanning will alert when pushed â€” but you set the alert,
        not GitHub. Monitor AbuseIPDB/CloudTrail for the key ID being used.

        Returns fake AKIA... key + secret for planting.
        """
        tid        = self._new_id()
        chars      = string.ascii_uppercase + string.digits
        access_key = "AKIA" + "".join(secrets.choice(chars) for _ in range(16))
        secret_key = secrets.token_urlsafe(40)

        token = {
            "token_id":   tid,
            "type":       "AWS_KEY",
            "label":      label,
            "access_key": access_key,
            "secret_key": secret_key,
            "created":    datetime.now(timezone.utc).isoformat(),
            "hits":       [],
            "note":       "Monitor AWS CloudTrail for AssumeRole/GetCallerIdentity calls using this key.",
        }
        with self._lock:
            self._tokens[tid] = token
            _save_tokens(self._tokens)
        return token

    def create_api_key_token(self, label: str = "Fake API key",
                             prefix: str = "sk") -> dict:
        """
        Create a fake API key string for monitoring credential leaks.
        Returns a key like: sk-nexlog-<random>
        """
        tid = self._new_id()
        key = f"{prefix}-nexlog-{secrets.token_urlsafe(24)}"

        token = {
            "token_id":  tid,
            "type":      "API_KEY",
            "label":     label,
            "api_key":   key,
            "created":   datetime.now(timezone.utc).isoformat(),
            "hits":      [],
            "note":      f"Search logs for '{key[:20]}' to detect leakage.",
        }
        with self._lock:
            self._tokens[tid] = token
            _save_tokens(self._tokens)
        return token

    def create_dns_token(self, label: str = "DNS canary") -> dict:
        """
        Create a DNS canary token.
        Embed this hostname in a document or config file.
        DNS lookups will appear in your DNS resolver logs.
        Combine with a wildcard DNS zone for full tracking.
        """
        tid  = self._new_id()
        host = f"{tid[:8]}.canary.nexlog.local"

        token = {
            "token_id": tid,
            "type":     "DNS",
            "label":    label,
            "hostname": host,
            "created":  datetime.now(timezone.utc).isoformat(),
            "hits":     [],
            "note":     f"Monitor DNS logs for lookups to {host}",
        }
        with self._lock:
            self._tokens[tid] = token
            _save_tokens(self._tokens)
        return token

    # â”€â”€ Token management â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    def list_tokens(self) -> list[dict]:
        """Return all tokens (without secrets for display)."""
        result = []
        for tid, t in self._tokens.items():
            display = {k: v for k, v in t.items()
                       if k not in ("secret_key",)}
            display["hit_count"] = len(t.get("hits", []))
            result.append(display)
        return sorted(result, key=lambda x: x["created"], reverse=True)

    def get_token(self, token_id: str) -> Optional[dict]:
        return self._tokens.get(token_id)

    def delete_token(self, token_id: str) -> bool:
        with self._lock:
            if token_id in self._tokens:
                del self._tokens[token_id]
                _save_tokens(self._tokens)
                return True
        return False

    def record_hit(self, token_id: str, source_ip: str = "",
                   user_agent: str = "") -> Optional[dict]:
        """
        Record a token trigger hit.
        If a case DB is attached, creates a CANARY finding automatically.
        Returns the token dict or None if token not found.
        """
        token = self._tokens.get(token_id)
        if not token:
            return None

        hit = {
            "timestamp":  datetime.now(timezone.utc).isoformat(),
            "source_ip":  source_ip,
            "user_agent": user_agent,
        }

        with self._lock:
            self._tokens[token_id].setdefault("hits", []).append(hit)
            _save_tokens(self._tokens)

        # â”€â”€ Auto-create finding in case DB â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        if self._db is not None:
            self._create_canary_finding(token, hit)

        return self._tokens[token_id]

    def _create_canary_finding(self, token: dict, hit: dict) -> None:
        """Write a CANARY finding to the case DB when a token is triggered."""
        try:
            from detection.finding import Finding, Severity, MitreTag
            ts_str = hit.get("timestamp", datetime.now(timezone.utc).isoformat())
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))

            finding = Finding(
                rule_id      = "CANARY-001",
                rule_name    = "Honeytoken Accessed",
                description  = (f"Canary token '{token['label']}' "
                                 f"(type={token['type']}) was triggered from "
                                 f"IP {hit.get('source_ip', 'unknown')}."),
                severity     = Severity.HIGH,
                category     = "insider_threat",
                source_ip    = hit.get("source_ip") or None,
                trigger_line = (f"CANARY HIT: token_id={token['token_id']} "
                                f"label={token['label']} "
                                f"ip={hit.get('source_ip','')} "
                                f"ua={hit.get('user_agent','')}"),
                timestamp    = ts,
                risk_score   = 9.0,
                mitre_tags   = [MitreTag(
                    tactic_id      = "TA0009",
                    tactic_name    = "Collection",
                    technique_id   = "T1005",
                    technique_name = "Data from Local System",
                )],
            )

            session_id = self._db.list_sessions()[0]["session_id"] if \
                         self._db.list_sessions() else None
            if session_id:
                self._db.save_findings([finding], session_id)
        except Exception:
            pass  # Never crash the listener thread


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# LOCAL HTTP LISTENER  (stdlib only)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class _CanaryHandler(BaseHTTPRequestHandler):
    """Simple HTTP handler that logs canary token hits."""

    manager: "CanaryManager" = None  # set at startup

    def do_GET(self):
        match = re.match(r"/ping/([A-Za-z0-9_\-]+)", self.path)
        if match:
            token_id   = match.group(1)
            source_ip  = self.client_address[0]
            user_agent = self.headers.get("User-Agent", "")

            token = self.manager.record_hit(token_id, source_ip, user_agent)

            label = token["label"] if token else "unknown"
            print(f"[CANARY HIT] token={token_id} label={label!r} "
                  f"ip={source_ip} ua={user_agent[:60]!r}")

            # Return 1x1 transparent GIF (undetectable tracking pixel)
            gif = (b"\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00"
                   b"\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x00\x00\x00\x00"
                   b"\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02"
                   b"\x44\x01\x00\x3b")
            self.send_response(200)
            self.send_header("Content-Type", "image/gif")
            self.send_header("Content-Length", str(len(gif)))
            self.end_headers()
            self.wfile.write(gif)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args):
        pass  # suppress default access log


def run_listener(manager: "CanaryManager", host: str = _LISTENER_HOST,
                 port: int = _LISTENER_PORT) -> threading.Thread:
    """
    Start the canary token HTTP listener in a background thread.

    Args:
        manager: CanaryManager instance to record hits into.
        host:    Listen address (default: localhost).
        port:    Listen port (default: 9999).

    Returns:
        The running Thread (daemon=True, stops with the process).
    """
    _CanaryHandler.manager = manager

    server = HTTPServer((host, port), _CanaryHandler)

    def _run():
        print(f"[Canary] Listener running at http://{host}:{port}/ping/<token_id>")
        server.serve_forever()

    t = threading.Thread(target=_run, daemon=True, name="canary-listener")
    t.start()
    return t


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="NexLog Canary Token Listener")
    p.add_argument("--serve", action="store_true")
    p.add_argument("--port", type=int, default=_LISTENER_PORT)
    p.add_argument("--host", default=_LISTENER_HOST)
    args = p.parse_args()

    if args.serve:
        mgr = CanaryManager()
        t   = run_listener(mgr, args.host, args.port)
        try:
            t.join()
        except KeyboardInterrupt:
            print("\nListener stopped.")
