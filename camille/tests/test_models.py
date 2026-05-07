"""Tests for data models."""

from datetime import datetime, timezone
from camille.core.models import (
    PortResult, PortState, SSLResult, SSLIssue, Severity,
    DNSRecord, DNSResult, HTTPResult, HeaderIssue, ScanResult,
)


class TestPortResult:
    def test_defaults(self):
        p = PortResult(port=80, state=PortState.OPEN)
        assert p.service == ""
        assert p.banner == ""

    def test_open_state(self):
        p = PortResult(port=443, state=PortState.OPEN, service="https")
        assert p.state == PortState.OPEN
        assert p.port == 443


class TestSSLResult:
    def test_initial_score(self):
        ssl = SSLResult(host="example.com", port=443)
        assert ssl.score == 100

    def test_add_issue_does_not_crash(self):
        ssl = SSLResult(host="example.com", port=443)
        ssl.issues.append(SSLIssue(
            severity=Severity.HIGH,
            title="Test",
            description="Test description",
        ))
        assert len(ssl.issues) == 1


class TestDNSRecord:
    def test_record_fields(self):
        r = DNSRecord(record_type="A", value="93.184.216.34", ttl=3600)
        assert r.record_type == "A"
        assert r.ttl == 3600


class TestHTTPResult:
    def test_default_score(self):
        h = HTTPResult(url="https://example.com")
        assert h.score == 100
        assert h.issues == []

    def test_add_issue(self):
        h = HTTPResult(url="https://example.com")
        h.issues.append(HeaderIssue(
            severity=Severity.MEDIUM,
            header="X-Frame-Options",
            description="Missing",
            recommendation="Add DENY",
        ))
        assert len(h.issues) == 1


class TestScanResult:
    def test_defaults(self):
        r = ScanResult(target="example.com")
        assert r.ports == []
        assert r.ssl is None
        assert r.dns is None
        assert r.http is None
        assert isinstance(r.timestamp, datetime)

    def test_duration_default(self):
        r = ScanResult(target="example.com")
        assert r.duration == 0.0
