"""Tests for report generation."""

import json
import tempfile
from pathlib import Path
from datetime import datetime, timezone

from camille.core.models import (
    ScanResult, PortResult, PortState,
    SSLResult, DNSResult, DNSRecord, HTTPResult,
)
from camille.reports.generator import to_json, save_json, save_html


def _make_full_result() -> ScanResult:
    result = ScanResult(target="example.com", duration=1.23)
    result.ports = [
        PortResult(port=80, state=PortState.OPEN, service="http"),
        PortResult(port=443, state=PortState.OPEN, service="https", banner="nginx/1.24"),
    ]
    result.dns = DNSResult(
        target="example.com",
        records=[DNSRecord(record_type="A", value="93.184.216.34", ttl=3600)],
    )
    result.http = HTTPResult(url="https://example.com", status_code=200, score=60)
    return result


class TestJSONReport:
    def test_to_json_is_valid_json(self):
        result = _make_full_result()
        output = to_json(result)
        data = json.loads(output)
        assert data["target"] == "example.com"

    def test_json_contains_ports(self):
        result = _make_full_result()
        data = json.loads(to_json(result))
        assert len(data["ports"]) == 2
        assert data["ports"][0]["port"] == 80

    def test_save_json_creates_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = _make_full_result()
            path = save_json(result, Path(tmpdir) / "report.json")
            assert path.exists()
            data = json.loads(path.read_text())
            assert data["target"] == "example.com"


class TestHTMLReport:
    def test_save_html_creates_file(self):
        try:
            import jinja2  # noqa: F401
        except ImportError:
            import pytest
            pytest.skip("jinja2 not installed")

        with tempfile.TemporaryDirectory() as tmpdir:
            result = _make_full_result()
            path = save_html(result, Path(tmpdir) / "report.html")
            assert path.exists()
            content = path.read_text()
            assert "example.com" in content
            assert "CAMILLE" in content

    def test_html_contains_port_table(self):
        try:
            import jinja2  # noqa: F401
        except ImportError:
            import pytest
            pytest.skip("jinja2 not installed")

        result = _make_full_result()
        from camille.reports.generator import to_html
        html = to_html(result)
        assert "Port Scan" in html
        assert "80" in html
