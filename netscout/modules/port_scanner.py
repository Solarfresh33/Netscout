"""TCP port scanner with banner grabbing."""

import socket
import concurrent.futures
from typing import Optional

from netscout.core.models import PortResult, PortState
from netscout.core.utils import get_service_name, TOP_PORTS


BANNER_PROBES = {
    21:  b"",
    22:  b"",
    25:  b"EHLO netscout\r\n",
    80:  b"HEAD / HTTP/1.0\r\n\r\n",
    110: b"",
    143: b"",
    443: b"",
}

TIMEOUT = 1.5
BANNER_TIMEOUT = 2.0


def _probe_port(host: str, port: int) -> Optional[PortResult]:
    """Attempt TCP connection; grab banner if port is open."""
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            banner = _grab_banner(sock, port)
            service = get_service_name(port)
            return PortResult(
                port=port,
                state=PortState.OPEN,
                service=service,
                banner=banner,
            )
    except (ConnectionRefusedError, socket.timeout):
        return None
    except OSError:
        return None


def _grab_banner(sock: socket.socket, port: int) -> str:
    sock.settimeout(BANNER_TIMEOUT)
    try:
        probe = BANNER_PROBES.get(port)
        if probe is not None and probe:
            sock.sendall(probe)
        raw = sock.recv(1024)
        return raw.decode(errors="replace").strip()[:200]
    except (socket.timeout, OSError):
        return ""


def scan_ports(
    host: str,
    ports: Optional[list[int]] = None,
    max_workers: int = 100,
) -> list[PortResult]:
    """
    Scan TCP ports on host concurrently.

    Args:
        host: Target hostname or IP.
        ports: List of ports to scan (defaults to TOP_PORTS).
        max_workers: Thread pool size.

    Returns:
        Sorted list of open PortResult objects.
    """
    target_ports = ports or TOP_PORTS
    results: list[PortResult] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_probe_port, host, p): p for p in target_ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result is not None:
                results.append(result)

    return sorted(results, key=lambda r: r.port)
