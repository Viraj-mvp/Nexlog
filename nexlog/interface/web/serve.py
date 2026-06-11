"""
interface/web/serve.py - NexLog full-stack web server
Integrated server: FastAPI backend + React SPA static files + auth + upload.

This module extends api.py with:
  1. Static file serving  â€” /static/* â†’ interface/web/static/
  2. SPA routing          â€” unknown GET paths â†’ index.html (React router)
  3. File upload endpoint â€” POST /api/upload (secure, sandboxed)
  4. Auth middleware      â€” optional API key protection
  5. WebSocket endpoint   â€” /ws/analysis â€” streams live findings during analysis

Usage:
    # Recommended: FastAPI + uvicorn
    python serve.py --port 8000 --key mysecretkey

    # As a module
    from interface.web.serve import create_full_app
    app = create_full_app(api_key=os.environ.get("NEXLOG_API_KEY", ""), case_db="case.facase")
    # uvicorn.run(app, host="0.0.0.0", port=8000)

    # Stdlib mode (no FastAPI â€” serves static files via http.server)
    from interface.web.serve import run_stdlib_fullstack
    run_stdlib_fullstack(port=8000)

Security notes:
  - Uploaded files are written to a sandboxed temp directory, never the
    project tree. Filenames are sanitised and made unpredictable.
  - API key auth is optional but strongly recommended for team deployments.
  - Static files are served from interface/web/static/ only â€” no directory
    traversal is possible because paths are resolved against the static root.
  - File upload size is capped at 512 MB by default.
"""

import json
import os
import sys
from pathlib import Path

# â”€â”€ Self-locating path â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

_root = os.path.dirname(os.path.abspath(__file__))
for _ in range(8):
    if os.path.isfile(os.path.join(_root, 'pathconfig.py')):
        break
    _root = os.path.dirname(_root)
if _root not in sys.path:
    sys.path.insert(0, _root)
from pathconfig import ROOT, add_root, load_env_profile
add_root()
load_env_profile("web")
_ROOT = ROOT
_STATIC_DIR = Path(__file__).parent / "static"
_REACT_STATIC_DIR = _STATIC_DIR / "react"
_SPA_INDEX = _REACT_STATIC_DIR / "index.html"

for _p in ['core','detection','storage','intelligence','output','interface/web']:
    sys.path.insert(0, os.path.join(_ROOT, _p))

from interface.web.auth import guard_stdlib_request, auth_status
from file_upload import FileUploadHandler

_MIME_MAP = {
    ".html":  "text/html; charset=utf-8",
    ".css":   "text/css",
    ".js":    "application/javascript",
    ".jsx":   "application/javascript",
    ".json":  "application/json",
    ".ico":   "image/x-icon",
    ".png":   "image/png",
    ".svg":   "image/svg+xml",
    ".woff2": "font/woff2",
    ".map":   "application/json",
}

_upload_handler = FileUploadHandler()


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# FASTAPI FULL STACK APP
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def create_full_app(
    case_db_path:   str  = "nexlog.facase",
    rules_dir:      str  = "",
    api_key:        str  = "",
    cors_origins:   list = None,
    upload_dir:     str  = "",
    max_upload_mb:  int  = 512,
):
    """
    Create a fully-integrated FastAPI app:
      - All 14 REST API endpoints from api.py
      - POST /api/upload  â€” secure file upload
      - GET  /ws/analysis â€” WebSocket for live finding stream
      - GET  /            â€” React SPA index.html
      - GET  /static/*    â€” static assets

    Args:
        case_db_path:  Path to SQLite case database.
        rules_dir:     Path to YAML rules directory.
        api_key:       API key for optional authentication.
        cors_origins:  CORS allowed origins. Default: ["*"]
        upload_dir:    Directory for uploaded files.
        max_upload_mb: Maximum upload size in MB.
    """
    try:
        from fastapi import FastAPI, File, UploadFile, WebSocket, HTTPException
        from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
        from fastapi.staticfiles import StaticFiles
        from fastapi.middleware.cors import CORSMiddleware
    except ImportError:
        raise ImportError(
            "FastAPI not installed.\n"
            "Run: pip install fastapi uvicorn python-multipart\n"
            "Or use stdlib mode: python serve.py --stdlib"
        )

    # Build the base API app (all 14 endpoints)
    from api import create_app
    app = create_app(
        case_db_path = case_db_path,
        rules_dir    = rules_dir,
        cors_origins = cors_origins,
        api_key      = api_key,
    )

    if not _SPA_INDEX.exists():
        raise RuntimeError(
            f"React bundle entry not found: {_SPA_INDEX}. "
            "Build frontend first: cd website && npm run build"
        )

    @app.middleware("http")
    async def _no_cache_react_assets(request, call_next):
        response = await call_next(request)
        path = request.url.path
        if path == "/" or path == "/index.html" or path.startswith("/static/react/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response

    # Upload handler
    uploader = FileUploadHandler(
        upload_dir = upload_dir or str(_upload_handler._upload_dir),
        max_size   = max_upload_mb * 1024 * 1024,
    )

    # â”€â”€ Upload endpoint â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    @app.post("/api/upload", tags=["Analysis"])
    async def upload_log(file: UploadFile = File(...)):
        """
        Upload a log file for analysis.

        Security controls:
          - Extension whitelist (.log .txt .json .jsonl .csv .evtx .xml)
          - File size limit (default 512 MB)
          - Magic byte validation for binary formats
          - Filename sanitisation (path traversal prevention)
          - Sandboxed storage (temp directory, not project tree)

        Returns: { ok, path, sha256, size, filename, error }
        The returned path can be passed directly to POST /api/analyse.
        """
        result = await uploader.save_fastapi(file)
        if not result.ok:
            raise HTTPException(400, result.error)
        return result.to_dict()

    @app.delete("/api/upload", tags=["Analysis"])
    def delete_upload(path: str):
        """Delete a previously uploaded file (cleanup after analysis)."""
        deleted = uploader.cleanup(Path(path))
        return {"deleted": deleted, "path": path}

    # â”€â”€ WebSocket â€” live analysis stream â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    @app.websocket("/ws/analysis")
    async def ws_analysis(websocket: WebSocket):
        """
        WebSocket endpoint that streams finding events live during analysis.
        Client sends: { "log_path": "...", "analyst": "...", "min_severity": "..." }
        Server sends: { "type": "finding"|"progress"|"done"|"error", ...data }
        """
        await websocket.accept()
        try:
            msg = await websocket.receive_json()
            log_path     = msg.get("log_path", "")
            analyst      = msg.get("analyst", "analyst")
            min_severity = msg.get("min_severity", "LOW")

            if not log_path or not Path(log_path).exists():
                await websocket.send_json({
                    "type": "error",
                    "message": f"file not found: {log_path}"
                })
                return

            # Run analysis in a thread, stream events via queue
            import asyncio
            import queue as _queue
            event_q: _queue.Queue = _queue.Queue()

            def _run():
                try:
                    sys.path.insert(0, _ROOT)
                    from rule_engine import RuleEngine
                    from engine import Engine
                    from storage.case_db import CaseDB
                    from attck_tagger import detect_attack_chain

                    rules_path = Path(rules_dir or os.path.join(
                        _ROOT, "detection", "rules"))
                    detect = RuleEngine(str(rules_path))
                    parse  = Engine()
                    findings = []

                    event_q.put({"type":"progress","pct":10,
                                 "message":"Rules loaded"})

                    for entry in parse.parse(Path(log_path)):
                        for f in detect.evaluate(entry):
                            findings.append(f)
                            event_q.put({
                                "type":       "finding",
                                "rule_id":    f.rule_id,
                                "severity":   f.severity.value,
                                "risk_score": f.risk_score,
                                "source_ip":  f.source_ip or "",
                                "category":   f.category,
                            })

                    event_q.put({"type":"progress","pct":85,
                                 "message":f"{len(findings)} findings detected"})

                    findings = RuleEngine.deduplicate_findings(findings)
                    with CaseDB(case_db_path) as db:
                        meta = parse.file_meta or {}
                        sid  = db.create_session(
                            source_file=log_path,
                            sha256=meta.get("sha256",""),
                            file_size=meta.get("size",0),
                            rules_loaded=detect._rules_loaded,
                        )
                        db.save_findings(findings, sid)
                        db.record_evidence(log_path,
                            meta.get("sha256",""),meta.get("size",0),sid,
                            lines_parsed=parse.stats.total_lines if parse.stats else 0,
                            findings_count=len(findings))
                        chains = detect_attack_chain(findings)
                        if chains:
                            db.save_attack_chains(chains, sid)

                    event_q.put({
                        "type":       "done",
                        "session_id": sid,
                        "total":      len(findings),
                        "chains":     len(chains) if chains else 0,
                    })
                except Exception as e:
                    event_q.put({"type":"error","message":str(e)})

            loop   = asyncio.get_event_loop()
            thread = loop.run_in_executor(None, _run)

            while True:
                try:
                    event = event_q.get(timeout=0.1)
                    await websocket.send_json(event)
                    if event["type"] in ("done","error"):
                        break
                except _queue.Empty:
                    # Check if thread finished with no more events
                    if thread.done():
                        break
                    await asyncio.sleep(0.1)

        except Exception as e:
            try:
                await websocket.send_json({"type":"error","message":str(e)})
            except Exception:
                pass
        finally:
            try:
                await websocket.close()
            except Exception:
                pass

    # â”€â”€ Static file serving â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    if _STATIC_DIR.exists():
        # Mount /static for assets
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)),
                  name="static")

        # SPA fallback: all unknown GET paths return the React/Vite app.
        index = _SPA_INDEX

        @app.get("/{full_path:path}", include_in_schema=False)
        async def spa_fallback(full_path: str):
            # Never serve index.html for API paths
            if full_path.startswith("api/") or full_path.startswith("ws/"):
                raise HTTPException(404)
            return FileResponse(
                str(index),
                headers={
                    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                    "Pragma": "no-cache",
                    "Expires": "0",
                },
            )

    return app


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# STDLIB FULL-STACK SERVER
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def run_stdlib_fullstack(
    port:           int  = 8000,
    host:           str  = "127.0.0.1",
    case_db_path:   str  = "nexlog.facase",
    rules_dir:      str  = "",
    api_key:        str  = "",
) -> None:
    """
    Run the full stack (API + static files) using Python's stdlib http.server.
    No FastAPI required. Authentication enforced if api_key is set.
    """
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from urllib.parse import urlparse, parse_qs

    if not _SPA_INDEX.exists():
        raise RuntimeError(
            f"React bundle entry not found: {_SPA_INDEX}. "
            "Build frontend first: cd website && npm run build"
        )

    # Import API handler
    from api import _AppState, _Handler
    state       = _AppState(case_db_path, rules_dir)
    api_handler = _Handler(state)

    class _FullStackHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            print(f"  [{self.address_string()}] {fmt % args}")

        def _respond(self, code: int, body, content_type: str = "application/json", extra_headers: dict | None = None) -> None:
            if isinstance(body, dict):
                payload = json.dumps(body, default=str).encode("utf-8")
            elif isinstance(body, str):
                payload = body.encode("utf-8")
            else:
                payload = body
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers",
                             "Content-Type, X-API-Key")
            if extra_headers:
                for hk, hv in extra_headers.items():
                    self.send_header(hk, hv)
            self.end_headers()
            self.wfile.write(payload)

        def _read_body(self) -> dict:
            length = int(self.headers.get("Content-Length", 0))
            if length:
                try:
                    return json.loads(self.rfile.read(length).decode("utf-8"))
                except Exception:
                    return {}
            return {}

        def _auth_check(self) -> bool:
            """Returns True if request is allowed. Responds 401 if not."""
            result = guard_stdlib_request(self, self.command, self.path, api_key)
            if result:
                self._respond(*result)
                return False
            return True

        def do_OPTIONS(self):
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods",
                             "GET, POST, DELETE, OPTIONS")
            self.send_header("Access-Control-Allow-Headers",
                             "Content-Type, X-API-Key")
            self.end_headers()

        def do_GET(self):
            if not self._auth_check():
                return
            parsed  = urlparse(self.path)
            path    = parsed.path
            query   = parse_qs(parsed.query)

            # API routes
            if path.startswith("/api/"):
                code, resp = api_handler._route("GET", path, query, {})
                self._respond(code, resp)
                return

            # Static files
            if path.startswith("/static/"):
                self._serve_static(path[8:])
                return

            # SPA fallback: serve the React/Vite app.
            index = _SPA_INDEX
            self._respond(
                200,
                index.read_bytes(),
                "text/html; charset=utf-8",
                {
                    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                    "Pragma": "no-cache",
                    "Expires": "0",
                },
            )

        def do_POST(self):
            if not self._auth_check():
                return
            parsed = urlparse(self.path)
            path   = parsed.path
            query  = parse_qs(parsed.query)

            # File upload endpoint
            if path == "/api/upload":
                self._handle_upload()
                return

            body  = self._read_body()
            code, resp = api_handler._route("POST", path, query, body)
            self._respond(code, resp)

        def do_DELETE(self):
            if not self._auth_check():
                return
            parsed = urlparse(self.path)
            query  = parse_qs(parsed.query)
            body   = {}
            code, resp = api_handler._route("DELETE", parsed.path, query, body)
            self._respond(code, resp)

        def _serve_static(self, rel_path: str) -> None:
            """Serve a file from the static directory safely."""
            # Resolve and check it stays inside static dir
            try:
                target = (_STATIC_DIR / rel_path).resolve()
                target.relative_to(_STATIC_DIR.resolve())
            except (ValueError, RuntimeError):
                self._respond(403, {"error": "forbidden"})
                return
            if not target.exists() or not target.is_file():
                self._respond(404, {"error": "not found"})
                return
            ext      = target.suffix.lower()
            ctype    = _MIME_MAP.get(ext, "application/octet-stream")
            content  = target.read_bytes()
            headers = {}
            if rel_path.startswith("react/"):
                headers = {
                    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                    "Pragma": "no-cache",
                    "Expires": "0",
                }
            self._respond(200, content, ctype, headers if headers else None)

        def _handle_upload(self) -> None:
            """Handle multipart file upload in stdlib mode."""
            content_type = self.headers.get("Content-Type", "")
            length       = int(self.headers.get("Content-Length", 0))
            if not length:
                self._respond(400, {"error": "empty upload"})
                return
            if length > 512 * 1024 * 1024:
                self._respond(413, {"error": "file too large (max 512 MB)"})
                return

            if "multipart/form-data" not in content_type.lower():
                self._respond(400, {"error": "multipart/form-data is required"})
                return

            raw = self.rfile.read(length)
            filename = "upload.log"
            file_bytes = b""
            try:
                from email.parser import BytesParser
                from email.policy import default

                header_block = (
                    f"Content-Type: {content_type}\r\n"
                    "MIME-Version: 1.0\r\n\r\n"
                ).encode("utf-8")
                msg = BytesParser(policy=default).parsebytes(header_block + raw)
                if not msg.is_multipart():
                    self._respond(400, {"error": "invalid multipart payload"})
                    return

                for part in msg.iter_parts():
                    if part.get_content_disposition() != "form-data":
                        continue
                    if part.get_param("name", header="content-disposition") != "file":
                        continue
                    filename = part.get_filename() or filename
                    file_bytes = part.get_payload(decode=True) or b""
                    break
            except Exception:
                self._respond(400, {"error": "failed to parse multipart upload"})
                return

            if not file_bytes:
                self._respond(400, {"error": "no file field found"})
                return

            result = _upload_handler.save_raw(filename, file_bytes, content_type)
            if not result.ok:
                self._respond(400, {"error": result.error})
                return
            self._respond(200, result.to_dict())

    server = HTTPServer((host, port), _FullStackHandler)
    print("\n  NexLog Full Stack (stdlib mode)")
    print(f"  API:     http://{host}:{port}/api/")
    print(f"  UI:      http://{host}:{port}/")
    print(f"  Auth:    {auth_status(api_key)['auth_enabled']}")
    print(f"  Case DB: {case_db_path}")
    print(f"  Static:  {_STATIC_DIR}")
    print("  Press Ctrl+C to stop\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Server stopped.")
    finally:
        try:
            server.server_close()
        finally:
            state.close()


# ═══════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def _cli_main() -> None:
    """Entry point for the ``nexlog-serve`` console script."""
    import argparse
    import atexit
    import signal
    import subprocess
    import time
    from pathlib import Path

    parser = argparse.ArgumentParser(
        prog="nexlog-serve",
        description="NexLog Full Stack Server (API + React UI)",
    )
    parser.add_argument("--port",   type=int, default=8000)
    parser.add_argument("--host",   default="127.0.0.1")
    parser.add_argument("--case",   default="nexlog.facase", metavar="FILE")
    parser.add_argument("--rules",  default="", metavar="DIR")
    parser.add_argument("--key",    default="", metavar="KEY",
                        help="API key (or set NEXLOG_API_KEY env var)")
    parser.add_argument("--stdlib", action="store_true",
                        help="Use stdlib http.server instead of FastAPI")
    parser.add_argument("--upload-dir", default="", metavar="DIR")
    parser.add_argument("--no-browser", action="store_true",
                        help="Don't open the web UI automatically")
    parser.add_argument("--daemon", action="store_true",
                        help="Run the server in the background (daemon mode)")
    parser.add_argument("--stop", action="store_true",
                        help="Stop a running daemon server")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug logging")
    args = parser.parse_args()

    # Get PID file path
    pid_file = Path.home() / ".nexlog.pid"

    # Handle --stop flag
    if args.stop:
        if not pid_file.exists():
            print("Error: No PID file found. Server not running?")
            return
        try:
            pid = int(pid_file.read_text())
            print(f"Stopping server with PID {pid}...")
            # Try to terminate the process
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/F", "/PID", str(pid)], check=True)
            else:
                os.kill(pid, signal.SIGTERM)
            # Wait a bit and clean up
            time.sleep(1)
            if pid_file.exists():
                pid_file.unlink()
            print("Server stopped.")
        except Exception as e:
            print(f"Error stopping server: {e}")
        return

    # Check if PID file already exists (server might be running)
    if pid_file.exists():
        try:
            pid = int(pid_file.read_text())
            # Check if process is still running
            if sys.platform == "win32":
                result = subprocess.run(
                    ["tasklist", "/FI", f"PID eq {pid}"], capture_output=True, text=True
                )
                if str(pid) not in result.stdout:
                    print("Warning: PID file exists but process not found. Cleaning up...")
                    pid_file.unlink()
            else:
                try:
                    os.kill(pid, 0)  # Check if process is running
                    print(f"Error: Server already running with PID {pid}")
                    print(f"Use --stop to stop it or remove {pid_file}")
                    return
                except OSError:
                    print("Warning: PID file exists but process not found. Cleaning up...")
                    pid_file.unlink()
        except Exception as e:
            print(f"Warning: Could not check PID file: {e}")

    def cleanup():
        if pid_file.exists():
            try:
                pid_file.unlink()
            except Exception:
                pass

    # Function to open browser
    def open_browser():
        if not args.no_browser:
            try:
                import webbrowser
                url = f"http://{args.host}:{args.port}/"
                print(f"Opening browser: {url}")
                # Wait a bit for server to start
                time.sleep(1)
                webbrowser.open(url)
            except Exception as e:
                if args.debug:
                    print(f"Could not open browser: {e}")

    # Handle daemon mode
    if args.daemon:
        if sys.platform == "win32":
            print("Daemon mode not supported on Windows.")
            return
        try:
            # Daemonize process
            pid = os.fork()
            if pid > 0:
                print(f"Server started in daemon mode with PID {pid}")
                return
            os.setsid()
            pid = os.fork()
            if pid > 0:
                return
            # Redirect file descriptors
            devnull = os.open(os.devnull, os.O_RDWR)
            os.dup2(devnull, 0)
            os.dup2(devnull, 1)
            os.dup2(devnull, 2)
            # Write PID file
            pid_file.write_text(str(os.getpid()))
            atexit.register(cleanup)
        except Exception as e:
            print(f"Error starting daemon: {e}")
            return

    # Write PID file for non-daemon mode as well
    if not args.daemon:
        pid_file.write_text(str(os.getpid()))
        atexit.register(cleanup)

        # Set up signal handlers for clean shutdown
        def signal_handler(sig, frame):
            print("\n  Shutting down...")
            cleanup()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

    if args.stdlib:
        print("\n  NexLog Full Stack (stdlib mode)")
        print(f"  API:     http://{args.host}:{args.port}/api/")
        print(f"  UI:      http://{args.host}:{args.port}/")
        print(f"  Auth:    {auth_status(args.key)['auth_enabled']}")
        print(f"  Case DB: {args.case}")
        print(f"  Static:  {_STATIC_DIR}")
        print("  Press Ctrl+C to stop\n")
        if not args.daemon:
            open_browser()
        run_stdlib_fullstack(
            port         = args.port,
            host         = args.host,
            case_db_path = args.case,
            rules_dir    = args.rules,
            api_key      = args.key,
        )
    else:
        try:
            import uvicorn
            app = create_full_app(
                case_db_path  = args.case,
                rules_dir     = args.rules,
                api_key       = args.key,
                upload_dir    = args.upload_dir,
            )
            print("\n  NexLog Full Stack (FastAPI)")
            print(f"  UI:     http://{args.host}:{args.port}/")
            print(f"  Docs:   http://{args.host}:{args.port}/docs")
            print(f"  Auth:   {auth_status(args.key)['auth_enabled']}\n")
            if not args.daemon:
                open_browser()
            uvicorn.run(app, host=args.host, port=args.port, log_level="debug" if args.debug else "info")
        except ImportError:
            print("FastAPI/uvicorn not installed â€” falling back to stdlib mode.")
            print("\n  NexLog Full Stack (stdlib mode)")
            print(f"  API:     http://{args.host}:{args.port}/api/")
            print(f"  UI:      http://{args.host}:{args.port}/")
            print(f"  Auth:    {auth_status(args.key)['auth_enabled']}")
            print(f"  Case DB: {args.case}")
            print(f"  Static:  {_STATIC_DIR}")
            print("  Press Ctrl+C to stop\n")
            if not args.daemon:
                open_browser()
            run_stdlib_fullstack(
                port=args.port, host=args.host,
                case_db_path=args.case,
                rules_dir=args.rules,
                api_key=args.key,
            )


if __name__ == "__main__":
    _cli_main()
