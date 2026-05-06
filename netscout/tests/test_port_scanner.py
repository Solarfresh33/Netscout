"""Tests for port scanner (mocked socket calls)."""

import socket
from unittest.mock import patch, MagicMock

from netscout.modules.port_scanner import _probe_port, scan_ports
from netscout.core.models import PortState


class TestProbePort:
    def test_open_port_returns_result(self):
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"

        with patch("netscout.modules.port_scanner.socket.create_connection", return_value=mock_sock):
            result = _probe_port("example.com", 22)

        assert result is not None
        assert result.port == 22
        assert result.state == PortState.OPEN

    def test_closed_port_returns_none(self):
        with patch(
            "netscout.modules.port_scanner.socket.create_connection",
            side_effect=ConnectionRefusedError,
        ):
            result = _probe_port("example.com", 9999)

        assert result is None

    def test_timeout_returns_none(self):
        with patch(
            "netscout.modules.port_scanner.socket.create_connection",
            side_effect=socket.timeout,
        ):
            result = _probe_port("example.com", 80)

        assert result is None


class TestScanPorts:
    def test_scan_returns_only_open(self):
        def fake_probe(host, port):
            if port in (80, 443):
                from netscout.core.models import PortResult
                return PortResult(port=port, state=PortState.OPEN, service="http")
            return None

        with patch("netscout.modules.port_scanner._probe_port", side_effect=fake_probe):
            results = scan_ports("example.com", [80, 443, 8080])

        assert len(results) == 2
        ports = [r.port for r in results]
        assert 80 in ports
        assert 443 in ports
        assert 8080 not in ports

    def test_scan_sorted_by_port(self):
        def fake_probe(host, port):
            from netscout.core.models import PortResult
            return PortResult(port=port, state=PortState.OPEN)

        with patch("netscout.modules.port_scanner._probe_port", side_effect=fake_probe):
            results = scan_ports("example.com", [8080, 22, 443, 80])

        port_order = [r.port for r in results]
        assert port_order == sorted(port_order)
