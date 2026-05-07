"""Shared utility functions."""

import re
import socket
import ipaddress
from urllib.parse import urlparse


COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 119: "nntp", 123: "ntp",
    135: "msrpc", 139: "netbios-ssn", 143: "imap", 194: "irc",
    389: "ldap", 443: "https", 445: "smb", 465: "smtps", 514: "syslog",
    587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
    27017: "mongodb",
}

TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 194,
    389, 443, 445, 465, 587, 636, 993, 995, 1433, 1521, 2049,
    3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017,
]

# Hostnames that always resolve to a private/internal address.
_PRIVATE_HOSTNAMES = {"localhost", "localhost.localdomain", "ip6-localhost"}


def resolve_target(target: str) -> str:
    """Resolve hostname to IP, return as-is if already an IP."""
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve host: {target}") from exc


def is_valid_target(target: str) -> bool:
    """Validate target as IP, hostname, or URL."""
    cleaned = strip_scheme(target)
    try:
        ipaddress.ip_address(cleaned)
        return True
    except ValueError:
        pass
    if cleaned.lower() in _PRIVATE_HOSTNAMES:
        return True
    hostname_re = re.compile(
        r"^(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )
    return bool(hostname_re.match(cleaned))


def is_private_target(target: str) -> bool:
    """
    Return True if the target resolves to a loopback, link-local, private
    (RFC 1918), or otherwise non-routable address. Used to gate scans of
    internal infrastructure behind an explicit opt-in flag.
    """
    cleaned = strip_scheme(target).lower()
    if cleaned in _PRIVATE_HOSTNAMES:
        return True
    try:
        ip = ipaddress.ip_address(resolve_target(cleaned))
    except (ValueError, OSError):
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def strip_scheme(target: str) -> str:
    """Remove http(s):// prefix and path from target."""
    if "://" in target:
        parsed = urlparse(target)
        return parsed.hostname or target
    return target.split("/")[0]


def safe_filename(name: str) -> str:
    """
    Build a safe filename component from a target. Whitelists alphanumerics,
    dot, dash and underscore; everything else is replaced. Defends against
    accidental path traversal if validation upstream is ever loosened.
    """
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    # Collapse any '..' sequences into a single underscore (path traversal).
    cleaned = re.sub(r"\.{2,}", "_", cleaned)
    # Strip leading dots so the file is never hidden / never resembles "..".
    cleaned = cleaned.lstrip(".")
    return cleaned[:128] or "scan"


def get_service_name(port: int) -> str:
    return COMMON_SERVICES.get(port, "unknown")


def severity_color(severity: str) -> str:
    colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "cyan",
        "INFO": "blue",
    }
    return colors.get(severity, "white")
