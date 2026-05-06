"""Tests for SSL analyzer (audit logic, no real network calls)."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from netscout.core.models import SSLResult, Severity
from netscout.modules.ssl_analyzer import _audit, _flatten_rdn, _extract_san


def _make_result(**kwargs) -> SSLResult:
    defaults = dict(host="example.com", port=443, version="TLSv1.3",
                    cipher="TLS_AES_256_GCM_SHA384", bits=256, score=100)
    defaults.update(kwargs)
    return SSLResult(**defaults)


class TestAuditExpiry:
    def test_expired_cert_is_critical(self):
        past = datetime.now(timezone.utc) - timedelta(days=1)
        result = _make_result(not_after=past)
        _audit(result)
        severities = [i.severity for i in result.issues]
        assert Severity.CRITICAL in severities
        assert result.score < 100

    def test_expiring_soon_is_high(self):
        soon = datetime.now(timezone.utc) + timedelta(days=10)
        result = _make_result(not_after=soon)
        _audit(result)
        severities = [i.severity for i in result.issues]
        assert Severity.HIGH in severities

    def test_valid_cert_no_expiry_issue(self):
        future = datetime.now(timezone.utc) + timedelta(days=365)
        result = _make_result(not_after=future)
        _audit(result)
        expiry_issues = [i for i in result.issues if "expir" in i.title.lower()]
        assert len(expiry_issues) == 0


class TestAuditProtocol:
    def test_weak_protocol_critical(self):
        result = _make_result(version="TLSv1")
        _audit(result)
        severities = [i.severity for i in result.issues]
        assert Severity.CRITICAL in severities

    def test_strong_protocol_no_issue(self):
        result = _make_result(version="TLSv1.3")
        _audit(result)
        proto_issues = [i for i in result.issues if "protocol" in i.title.lower()]
        assert len(proto_issues) == 0


class TestAuditCipher:
    def test_rc4_cipher_flagged(self):
        result = _make_result(cipher="RC4-SHA")
        _audit(result)
        cipher_issues = [i for i in result.issues if "cipher" in i.title.lower()]
        assert len(cipher_issues) > 0

    def test_strong_cipher_ok(self):
        result = _make_result(cipher="TLS_AES_256_GCM_SHA384")
        _audit(result)
        cipher_issues = [i for i in result.issues if "cipher" in i.title.lower()]
        assert len(cipher_issues) == 0


class TestAuditSelfSigned:
    def test_self_signed_detected(self):
        rdn = {"commonName": "example.com", "organizationName": "Acme"}
        result = _make_result(subject=rdn, issuer=rdn)
        _audit(result)
        ss_issues = [i for i in result.issues if "self-signed" in i.title.lower()]
        assert len(ss_issues) == 1


class TestHelpers:
    def test_flatten_rdn(self):
        rdn = ((("commonName", "example.com"),), (("organizationName", "Acme"),))
        out = _flatten_rdn(rdn)
        assert out["commonName"] == "example.com"
        assert out["organizationName"] == "Acme"

    def test_extract_san(self):
        cert = {"subjectAltName": [("DNS", "example.com"), ("DNS", "www.example.com")]}
        sans = _extract_san(cert)
        assert "DNS:example.com" in sans
        assert "DNS:www.example.com" in sans
