"""
NexLog hardened upload handling.

Uploads are treated as untrusted evidence: validate first, store in a quarantine
sandbox with unpredictable names, never extract archives automatically, and
return only metadata needed by analysis jobs.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import pathlib
import sys
import tempfile
import uuid
import zipfile
from dataclasses import dataclass
from typing import Optional

_root = os.path.dirname(os.path.abspath(__file__))
for _ in range(8):
    if os.path.isfile(os.path.join(_root, "pathconfig.py")):
        break
    _root = os.path.dirname(_root)
if _root not in sys.path:
    sys.path.insert(0, _root)
from pathconfig import ROOT, WORKSPACE_DIR, add_root

add_root()
_ROOT = ROOT

MAX_UPLOAD_BYTES = int(os.environ.get("NEXLOG_MAX_UPLOAD_BYTES", str(500 * 1024 * 1024)))
MAX_DECOMPRESSED_BYTES = int(os.environ.get("NEXLOG_MAX_DECOMPRESSED_BYTES", str(1024 * 1024 * 1024)))
MAX_ARCHIVE_FILES = int(os.environ.get("NEXLOG_MAX_ARCHIVE_FILES", "2000"))
MAX_ARCHIVE_DEPTH = 1
DEFAULT_UPLOAD_DIR = pathlib.Path(WORKSPACE_DIR) / "uploads" / "quarantine"

ALLOWED_EXTENSIONS = {
    ".log",
    ".txt",
    ".json",
    ".jsonl",
    ".xml",
    ".evtx",
    ".csv",
    ".gz",
    ".zip",
}

MAGIC_SIGNATURES = {
    b"MSLO": "evtx",
    b"\x1f\x8b": "gz",
    b"PK\x03\x04": "zip",
    b'{"Records"': "cloudtrail",
    b"<Events": "xml",
    b"<?xml": "xml",
}

FORMAT_EXTENSIONS = {
    "evtx": {".evtx"},
    "gz": {".gz"},
    "zip": {".zip"},
    "cloudtrail": {".json"},
    "xml": {".xml"},
    "unknown": {".log", ".txt", ".json", ".jsonl", ".csv"},
}

BLOCKED_PATHS = [
    "/etc/",
    "/proc/",
    "/sys/",
    "/dev/",
    "/root/",
    "/boot/",
    "/bin/",
    "/sbin/",
    "/usr/bin/",
]

ALLOWED_BASE_DIRS: list[pathlib.Path] = [
    pathlib.Path("/var/log").resolve(),
    pathlib.Path("/tmp").resolve(),
    pathlib.Path(tempfile.gettempdir()).resolve(),
    pathlib.Path(WORKSPACE_DIR).resolve(),
    pathlib.Path(_ROOT).resolve(),
]

_seen_digests: set[str] = set()


def _is_relative_to(path: pathlib.Path, base: pathlib.Path) -> bool:
    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False


def _safe_display_path(path: pathlib.Path) -> str:
    """Return a non-sensitive path string for errors/logging."""
    try:
        return path.name
    except Exception:
        return "evidence"


def validate_log_path(log_path: str) -> pathlib.Path:
    """Validate a server-side log path before analysis."""
    resolved = pathlib.Path(log_path).resolve()
    path_str = str(resolved)

    for blocked in BLOCKED_PATHS:
        if path_str.startswith(blocked):
            raise PermissionError("Access denied")

    if not any(_is_relative_to(resolved, base) for base in ALLOWED_BASE_DIRS):
        raise PermissionError("Path is outside approved evidence directories")

    if not resolved.is_file():
        raise FileNotFoundError(f"Log file not found: {_safe_display_path(resolved)}")

    if resolved.stat().st_size > MAX_UPLOAD_BYTES:
        raise ValueError(f"File too large: {resolved.stat().st_size} bytes")
    return resolved


def _detect_format(data: bytes) -> str:
    for magic, fmt in MAGIC_SIGNATURES.items():
        if data[: len(magic)] == magic:
            return fmt
    stripped = data[:256].lstrip()
    if stripped.startswith(b"{") or stripped.startswith(b"["):
        return "json"
    return "unknown"


def _validate_zip(data: bytes) -> None:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_ARCHIVE_FILES:
                raise ValueError("Archive contains too many files")
            total = 0
            for info in infos:
                name = info.filename.replace("\\", "/")
                parts = [p for p in name.split("/") if p]
                if len(parts) > MAX_ARCHIVE_DEPTH + 1:
                    raise ValueError("Archive nesting is too deep")
                if name.startswith("/") or ".." in parts:
                    raise ValueError("Archive contains unsafe paths")
                if pathlib.Path(name).suffix.lower() in {".exe", ".dll", ".ps1", ".bat", ".cmd", ".scr"}:
                    raise ValueError("Archive contains executable content")
                total += int(info.file_size)
                if total > MAX_DECOMPRESSED_BYTES:
                    raise ValueError("Archive decompressed size is too large")
    except zipfile.BadZipFile as exc:
        raise ValueError("Corrupted ZIP archive") from exc


def _validate_gzip(data: bytes) -> None:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz:
            total = 0
            while True:
                chunk = gz.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_DECOMPRESSED_BYTES:
                    raise ValueError("Gzip decompressed size is too large")
    except OSError as exc:
        raise ValueError("Corrupted gzip archive") from exc


def validate_upload(data: bytes, filename: str) -> tuple[str, str]:
    """
    Validate raw upload bytes.

    Returns (safe_filename, detected_format).
    Raises ValueError on validation failure.
    """
    if len(data) == 0:
        raise ValueError("Empty upload")
    if len(data) > MAX_UPLOAD_BYTES:
        raise ValueError(f"Upload exceeds {MAX_UPLOAD_BYTES} bytes")

    safe_name = pathlib.Path(filename).name
    if not safe_name or safe_name.startswith("."):
        raise ValueError("Invalid filename")
    if any(part in filename for part in ("..", "/", "\\")):
        raise ValueError("Path traversal in filename")
    if any(ord(ch) < 32 for ch in safe_name):
        raise ValueError("Filename contains control characters")

    suffix = pathlib.Path(safe_name).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Extension not allowed: {suffix!r}")

    detected = _detect_format(data)
    allowed_for_format = FORMAT_EXTENSIONS.get(detected)
    if allowed_for_format and suffix not in allowed_for_format:
        # Allow plain JSON/JSONL/CSV/logs to remain "unknown"; block binary mismatch.
        if detected not in {"unknown", "json"}:
            raise ValueError(f"File extension does not match detected {detected} content")

    if b"\x00" in data[:1024] and detected == "unknown":
        raise ValueError("Binary content in non-binary upload")

    return safe_name, detected


def _inspect_upload(data: bytes, filename: str) -> tuple[str, str, str]:
    """Validate upload and perform persistence-only archive safety checks."""
    safe_name, detected = validate_upload(data, filename)
    if detected == "zip":
        _validate_zip(data)
    elif detected == "gz":
        _validate_gzip(data)
    digest = hashlib.sha256(data).hexdigest()
    return safe_name, detected, digest


def save_upload(data: bytes, filename: str) -> pathlib.Path:
    """Save validated upload to the quarantine directory and return its path."""
    safe_name, _, digest = _inspect_upload(data, filename)
    upload_dir = DEFAULT_UPLOAD_DIR
    upload_dir.mkdir(parents=True, exist_ok=True)
    dest = upload_dir / f"{digest[:16]}_{safe_name}"
    dest.write_bytes(data)
    return dest


@dataclass
class UploadResult:
    ok: bool
    path: str = ""
    sha256: str = ""
    size: int = 0
    filename: str = ""
    stored_name: str = ""
    detected_format: str = "unknown"
    duplicate: bool = False
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "filename": self.filename,
            "stored_name": self.stored_name,
            "detected_format": self.detected_format,
            "duplicate": self.duplicate,
            "error": self.error,
        }


class FileUploadHandler:
    """Secure upload manager used by FastAPI and stdlib web servers."""

    def __init__(self, upload_dir: Optional[str] = None, max_size: int = MAX_UPLOAD_BYTES) -> None:
        self.max_size = max_size
        self._upload_dir = pathlib.Path(upload_dir or DEFAULT_UPLOAD_DIR).resolve()
        self._upload_dir.mkdir(parents=True, exist_ok=True)

    async def save_fastapi(self, upload_file) -> UploadResult:
        filename = getattr(upload_file, "filename", "") or "upload.log"
        data = await upload_file.read()
        return self.save_raw(filename, data, getattr(upload_file, "content_type", ""))

    def save_raw(self, filename: str, data: bytes, content_type: str = "") -> UploadResult:
        del content_type
        if len(data) > self.max_size:
            return UploadResult(
                ok=False,
                size=len(data),
                filename=pathlib.Path(filename).name,
                error=f"Upload exceeds {self.max_size} bytes",
            )

        try:
            safe_name, detected, digest = _inspect_upload(data, filename)
            duplicate = digest in _seen_digests
            _seen_digests.add(digest)
            dest_name = f"{uuid.uuid4().hex}_{digest[:16]}_{safe_name}"
            dest = (self._upload_dir / dest_name).resolve()
            if not _is_relative_to(dest, self._upload_dir):
                raise ValueError("Resolved upload path escaped upload directory")
            dest.write_bytes(data)
            return UploadResult(
                ok=True,
                path=str(dest),
                sha256=digest,
                size=len(data),
                filename=safe_name,
                stored_name=dest_name,
                detected_format=detected,
                duplicate=duplicate,
            )
        except Exception as exc:
            return UploadResult(
                ok=False,
                size=len(data),
                filename=pathlib.Path(filename).name,
                error=str(exc),
            )

    def cleanup(self, path: pathlib.Path) -> bool:
        """Delete a prior upload only if it is inside the quarantine sandbox."""
        try:
            target = pathlib.Path(path).resolve()
            if not _is_relative_to(target, self._upload_dir):
                return False
            if target.is_file():
                target.unlink()
                return True
        except OSError:
            return False
        return False
