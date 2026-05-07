"""Tests for core utility functions."""

import pytest
from camille.core.utils import is_valid_target, strip_scheme, get_service_name


class TestIsValidTarget:
    def test_valid_ipv4(self):
        assert is_valid_target("192.168.1.1")

    def test_valid_domain(self):
        assert is_valid_target("example.com")

    def test_valid_subdomain(self):
        assert is_valid_target("mail.example.org")

    def test_url_with_scheme(self):
        assert is_valid_target("https://example.com")

    def test_invalid_target(self):
        assert not is_valid_target("not_a_domain")

    def test_empty_string(self):
        assert not is_valid_target("")


class TestStripScheme:
    def test_strips_https(self):
        assert strip_scheme("https://example.com/path") == "example.com"

    def test_strips_http(self):
        assert strip_scheme("http://example.com") == "example.com"

    def test_no_scheme_passthrough(self):
        assert strip_scheme("example.com") == "example.com"

    def test_strips_path(self):
        assert strip_scheme("example.com/path/to/page") == "example.com"


class TestGetServiceName:
    def test_known_ports(self):
        assert get_service_name(80) == "http"
        assert get_service_name(443) == "https"
        assert get_service_name(22) == "ssh"
        assert get_service_name(3306) == "mysql"

    def test_unknown_port(self):
        assert get_service_name(12345) == "unknown"
