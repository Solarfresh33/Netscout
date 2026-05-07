"""SSL/TLS certificate and configuration analyzer."""

import ssl
import socket
from datetime import datetime, timezone
from typing import Optional

from netscout.core.models import SSLResult, SSLIssue, Severity


WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHERS = {"RC4", "DES", "3DES", "NULL", "EXPORT", "anon"}

TIMEOUT = 5.0


def analyze_ssl(host: str, port: int = 443) -> Optional[SSLResult]:
    """
    Connect to host:port via TLS and analyze the certificate + config.

    Returns SSLResult or None if SSL is not available on that port.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                return _extract_result(host, port, tls_sock)
    except (ssl.SSLError, ConnectionRefusedError, socket.timeout, OSError):
        return None


def _extract_result(host: str, port: int, tls_sock: ssl.SSLSocket) -> SSLResult:
    cert = tls_sock.getpeercert()

    # tls_sock.cipher() can return None if the handshake hasn't fully
    # completed or the peer closed the connection abruptly.
    cipher_info = tls_sock.cipher()
    if cipher_info is None:
        cipher_name, proto, bits = "unknown", "unknown", 0
    else:
        cipher_name = cipher_info[0] or "unknown"
        proto = cipher_info[1] or "unknown"
        bits = cipher_info[2] or 0

    result = SSLResult(
        host=host,
        port=port,
        version=proto,
        cipher=cipher_name,
        bits=bits or 0,
        subject=_flatten_rdn(cert.get("subject", ())) if cert else {},
        issuer=_flatten_rdn(cert.get("issuer", ())) if cert else {},
        san=_extract_san(cert) if cert else [],
    )

    if cert:
        not_before_str = cert.get("notBefore", "")
        not_after_str = cert.get("notAfter", "")
        if not_before_str:
            result.not_before = _parse_cert_date(not_before_str)
        if not_after_str:
            result.not_after = _parse_cert_date(not_after_str)

    _audit(result)
    return result


def _audit(result: SSLResult) -> None:
    now = datetime.now(timezone.utc)

    # Expired certificate
    if result.not_after and result.not_after < now:
        result.issues.append(SSLIssue(
            severity=Severity.CRITICAL,
            title="Certificate expired",
            description=f"Certificate expired on {result.not_after.date()}",
        ))
        result.score -= 40

    # Certificate expiring soon (< 30 days)
    elif result.not_after:
        days_left = (result.not_after - now).days
        if days_left < 30:
            result.issues.append(SSLIssue(
                severity=Severity.HIGH,
                title="Certificate expiring soon",
                description=f"Certificate expires in {days_left} day(s)",
            ))
            result.score -= 15

    # Weak protocol
    if result.version in WEAK_PROTOCOLS:
        result.issues.append(SSLIssue(
            severity=Severity.CRITICAL,
            title=f"Weak protocol: {result.version}",
            description=f"{result.version} is deprecated and insecure. Upgrade to TLS 1.2+.",
        ))
        result.score -= 30

    # Weak cipher
    for weak in WEAK_CIPHERS:
        if weak in result.cipher.upper():
            result.issues.append(SSLIssue(
                severity=Severity.HIGH,
                title=f"Weak cipher suite: {result.cipher}",
                description=f"The cipher contains '{weak}' which is considered insecure.",
            ))
            result.score -= 20
            break

    # Short key
    if 0 < result.bits < 2048:
        result.issues.append(SSLIssue(
            severity=Severity.HIGH,
            title=f"Short key length: {result.bits} bits",
            description="Key length below 2048 bits is considered weak.",
        ))
        result.score -= 20

    # Self-signed
    if result.subject == result.issuer:
        result.issues.append(SSLIssue(
            severity=Severity.MEDIUM,
            title="Self-signed certificate",
            description="Certificate is not issued by a trusted CA.",
        ))
        result.score -= 10

    result.score = max(result.score, 0)


def _flatten_rdn(rdn_seq: tuple) -> dict:
    out: dict = {}
    for rdn in rdn_seq:
        for key, value in rdn:
            out[key] = value
    return out


def _extract_san(cert: dict) -> list[str]:
    sans = []
    for san_type, san_value in cert.get("subjectAltName", ()):
        sans.append(f"{san_type}:{san_value}")
    return sans


def _parse_cert_date(date_str: str) -> datetime:
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
        try:
            dt = datetime.strptime(date_str, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise ValueError(f"Unrecognized cert date format: {date_str!r}")
