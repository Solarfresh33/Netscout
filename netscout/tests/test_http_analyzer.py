"""Tests for HTTP header audit logic (no real network calls)."""

from unittest.mock import MagicMock, patch

from netscout.core.models import HTTPResult, Severity
from netscout.modules.http_analyzer import (
    _audit_security_headers,
    _audit_information_disclosure,
    _ensure_scheme,
    _extract_max_age,
)


def _result_with_headers(headers: dict) -> HTTPResult:
    r = HTTPResult(url="https://example.com", status_code=200)
    r.headers = headers
    return r


class TestEnsureScheme:
    def test_adds_https_when_missing(self):
        assert _ensure_scheme("example.com") == "https://example.com"

    def test_preserves_http(self):
        assert _ensure_scheme("http://example.com") == "http://example.com"

    def test_preserves_https(self):
        assert _ensure_scheme("https://example.com") == "https://example.com"


class TestExtractMaxAge:
    def test_parses_max_age(self):
        assert _extract_max_age("max-age=31536000; includeSubDomains") == 31536000

    def test_missing_max_age(self):
        assert _extract_max_age("includeSubDomains") is None

    def test_invalid_value(self):
        assert _extract_max_age("max-age=abc") is None


class TestAuditSecurityHeaders:
    def test_missing_all_headers_reduces_score(self):
        result = _result_with_headers({})
        _audit_security_headers(result)
        assert result.score < 100
        assert len(result.issues) > 0

    def test_all_headers_present_no_issues(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
            "X-XSS-Protection": "1; mode=block",
        }
        result = _result_with_headers(headers)
        _audit_security_headers(result)
        assert result.score == 100
        assert len(result.issues) == 0

    def test_low_hsts_max_age_flagged(self):
        headers = {
            "Strict-Transport-Security": "max-age=3600",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
            "X-XSS-Protection": "1; mode=block",
        }
        result = _result_with_headers(headers)
        _audit_security_headers(result)
        hsts_issues = [i for i in result.issues if i.header == "Strict-Transport-Security"]
        assert len(hsts_issues) > 0


class TestAuditInfoDisclosure:
    def test_server_header_flagged(self):
        result = _result_with_headers({"Server": "Apache/2.4.51"})
        result.server = "Apache/2.4.51"
        _audit_information_disclosure(result)
        server_issues = [i for i in result.issues if i.header == "Server"]
        assert len(server_issues) == 1
        assert server_issues[0].severity == Severity.INFO

    def test_cookie_without_secure_flagged(self):
        result = _result_with_headers({"Set-Cookie": "session=abc123; HttpOnly; Path=/"})
        _audit_information_disclosure(result)
        cookie_issues = [i for i in result.issues if i.header == "Set-Cookie"]
        assert any("Secure" in i.description for i in cookie_issues)

    def test_no_sensitive_headers_no_issues(self):
        result = _result_with_headers({"Content-Type": "text/html"})
        _audit_information_disclosure(result)
        assert len(result.issues) == 0
