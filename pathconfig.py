"""
Canonical NexLog path anchors.

The repository keeps thin launchers at the root while source packages live
under ``nexlog/``. Frozen PyInstaller builds load bundled assets from
``sys._MEIPASS`` and write runtime case data to a user-writable workspace.
"""

from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile
from typing import Iterable

APP_NAME = "NexLog"
APP_PACKAGE = "nexlog"


def _is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def _repo_root() -> Path:
    return Path(__file__).resolve().parent


def _bundle_root() -> Path:
    if hasattr(sys, "_MEIPASS"):
        return Path(getattr(sys, "_MEIPASS")).resolve()
    return _repo_root()


def _app_root() -> Path:
    bundle = _bundle_root()
    packaged = bundle / APP_PACKAGE
    if packaged.exists():
        return packaged
    source = _repo_root() / APP_PACKAGE
    return source if source.exists() else bundle


def _runtime_workspace() -> Path:
    override = os.environ.get("NEXLOG_WORKSPACE_DIR")
    if override:
        return Path(override).expanduser().resolve()
    if not _is_frozen():
        repo_workspace = _repo_root() / "workspace"
        if _is_writable_workspace(repo_workspace):
            return repo_workspace
        fallback = _fallback_workspace()
        if _is_writable_workspace(fallback):
            return fallback
        return repo_workspace
    if sys.platform.startswith("win"):
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if base:
            return Path(base) / APP_NAME / "workspace"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME / "workspace"
    data_home = os.environ.get("XDG_DATA_HOME")
    if data_home:
        return Path(data_home).expanduser() / APP_NAME / "workspace"
    return Path.home() / ".local" / "share" / APP_NAME / "workspace"


def _is_writable_workspace(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / f".nexlog_write_check_{os.getpid()}"
        probe.write_text("ok", encoding="utf-8")
        try:
            probe.unlink(missing_ok=True)
        except OSError:
            pass
        return True
    except OSError:
        return False


def _fallback_workspace() -> Path:
    override = os.environ.get("NEXLOG_FALLBACK_WORKSPACE_DIR")
    if override:
        return Path(override).expanduser().resolve()
    if sys.platform.startswith("win") and Path("C:/tmp").exists():
        return Path("C:/tmp") / "nexlog-workspace"
    return Path(tempfile.gettempdir()) / "nexlog-workspace"


REPO_ROOT_PATH: Path = _repo_root()
BUNDLE_ROOT_PATH: Path = _bundle_root()
ROOT_PATH: Path = _app_root()
SOURCE_ROOT_PATH: Path = REPO_ROOT_PATH
WORKSPACE_PATH: Path = _runtime_workspace()

ROOT: str = str(ROOT_PATH)
SOURCE_ROOT: str = str(SOURCE_ROOT_PATH)
WORKSPACE_DIR: str = str(WORKSPACE_PATH)


def _init_workspace() -> None:
    WORKSPACE_PATH.mkdir(parents=True, exist_ok=True)


def ensure_workspace() -> str:
    """Create and return the writable NexLog workspace directory."""
    _init_workspace()
    return WORKSPACE_DIR


def add_paths(*package_names: str) -> None:
    """Add app subdirectories to sys.path. Idempotent."""
    for name in package_names:
        for base in (ROOT_PATH, REPO_ROOT_PATH, BUNDLE_ROOT_PATH):
            p = str(base / name)
            if os.path.isdir(p) and p not in sys.path:
                sys.path.insert(0, p)


def add_root() -> None:
    """Add repository, app, and bundle roots to sys.path."""
    for p in (str(REPO_ROOT_PATH), str(ROOT_PATH), str(BUNDLE_ROOT_PATH)):
        if p not in sys.path:
            sys.path.insert(0, p)


def _load_env_file(path: Path, *, override: bool) -> bool:
    """Load one dotenv file if python-dotenv is installed and the file exists."""
    if not path.exists():
        return False
    try:
        from dotenv import load_dotenv
    except ImportError:
        return False
    load_dotenv(str(path), override=override)
    return True


def _profile_files(profile: str | None) -> Iterable[tuple[str, bool]]:
    """Return env files in deterministic low-to-high precedence order."""
    yield ".env", False
    yield ".env.shared", True
    if profile:
        yield f".env.{profile}", True
    yield ".env.local", True


def _apply_profile_aliases(profile: str | None) -> None:
    """Map profile-scoped NexLog variables onto the generic runtime names."""
    if not profile:
        return
    prefix = f"NEXLOG_{profile.upper()}_"
    aliases = {
        f"{prefix}API_KEY": "NEXLOG_API_KEY",
        f"{prefix}GROQ_API_KEY": "GROQ_API_KEY",
        f"{prefix}GROQ_MODEL": "GROQ_MODEL",
        f"{prefix}GEMINI_API_KEY": "GEMINI_API_KEY",
        f"{prefix}GEMINI_MODEL": "GEMINI_MODEL",
        f"{prefix}ANTHROPIC_API_KEY": "ANTHROPIC_API_KEY",
        f"{prefix}ANTHROPIC_MODEL": "ANTHROPIC_MODEL",
        f"{prefix}OLLAMA_HOST": "OLLAMA_HOST",
        f"{prefix}MODEL": "NEXLOG_MODEL",
        f"{prefix}AI_PROVIDER_1": "NEXLOG_AI_PROVIDER_1",
        f"{prefix}AI_KEY_1": "NEXLOG_AI_KEY_1",
        f"{prefix}AI_ENDPOINT_1": "NEXLOG_AI_ENDPOINT_1",
        f"{prefix}AI_MODEL_1": "NEXLOG_AI_MODEL_1",
        f"{prefix}AI_PROVIDER_2": "NEXLOG_AI_PROVIDER_2",
        f"{prefix}AI_KEY_2": "NEXLOG_AI_KEY_2",
        f"{prefix}AI_ENDPOINT_2": "NEXLOG_AI_ENDPOINT_2",
        f"{prefix}AI_MODEL_2": "NEXLOG_AI_MODEL_2",
        f"{prefix}HARDWARE_MODE": "NEXLOG_HARDWARE_MODE",
    }
    for source, target in aliases.items():
        value = os.environ.get(source)
        if value:
            os.environ[target] = value


def load_env_profile(profile: str | None = None) -> dict[str, object]:
    """
    Load NexLog environment files for cli/gui/web without leaking secrets.

    Precedence: .env, .env.shared, .env.<profile>, .env.local. Profile-specific
    variables such as NEXLOG_WEB_GROQ_API_KEY are mapped to the generic names
    consumed by the existing runtime clients.
    """
    loaded: list[str] = []
    normalized = (profile or os.environ.get("NEXLOG_ENV_PROFILE", "")).strip().lower()
    if normalized not in {"", "cli", "gui", "web"}:
        normalized = ""
    for filename, override in _profile_files(normalized or None):
        if _load_env_file(REPO_ROOT_PATH / filename, override=override):
            loaded.append(filename)
    _apply_profile_aliases(normalized or None)
    return {"profile": normalized or "default", "loaded": loaded}


_PACKAGES = [
    "core",
    "detection",
    "storage",
    "intelligence",
    "output",
    "utils",
    "ai",
    os.path.join("interface", "web"),
    os.path.join("interface", "gui"),
]

add_root()
for _pkg in _PACKAGES:
    add_paths(_pkg)

load_env_profile(os.environ.get("NEXLOG_ENV_PROFILE", ""))
