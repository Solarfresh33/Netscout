"""HTTP security headers analyzer."""

from __future__ import annotations

from typing import Optional
from urllib.parse import urlparse

try:
    import requests
    from requests.exceptions import RequestException
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from netscout.core.models import HTTPResult, HeaderIssue, Severity


TIMEOUT = 10

SECURITY_HEADERS: dict[str, dict] = {
    "Strict-Transport-Security": {
        "severity": Severity.HIGH,
        "description": "HSTS is missing. Browsers may connect over plain HTTP.",
        "recommendation": (
            "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        ),
    },
    "Content-Security-Policy": {
        "severity": Severity.HIGH,
        "description": "No CSP header found. XSS and injection attacks are easier.",
        "recommendation": "Define a Content-Security-Policy that restricts script sources.",
    },
    "X-Frame-Options": {
        "severity": Severity.MEDIUM,
        "description": "X-Frame-Options is missing. Clickjacking may be possible.",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "severity": Severity.MEDIUM,
        "description": "X-Content-Type-Options is missing. MIME sniffing attacks possible.",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "description": "Referrer-Policy is missing. Full URLs may leak via Referer header.",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": Severity.LOW,
        "description": "Permissions-Policy is absent. Browser features are unrestricted.",
        "recommendation": "Define a Permissions-Policy to restrict camera, microphone, geolocation, etc.",
    },
    "X-XSS-Protection": {
        "severity": Severity.LOW,
        "description": "X-XSS-Protection is absent (legacy header, but still useful for older browsers).",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block",
    },
}

SCORE_DEDUCTIONS: dict[Severity, int] = {
    Severity.CRITICAL: 30,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 5,
    Severity.INFO: 0,
}

SENSITIVE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


def analyze_http(url: str) -> Optional[HTTPResult]:
    """
    Fetch HTTP(S) headers and evaluate security posture.

    Args:
        url: Target URL (scheme included or assumed https).

    Returns:
        HTTPResult or None if request fails.
    """
    if not HAS_REQUESTS:
        return None

    url = _ensure_scheme(url)
    result = HTTPResult(url=url)

    try:
        response = requests.get(
            url,
            timeout=TIMEOUT,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": "NetScout/1.0 (security-scanner)"},
        )
    except RequestException:
        return None

    result.status_code = response.status_code
    result.headers = dict(response.headers)
    result.redirects = [r.url for r in response.history]
    result.server = response.headers.get("Server", "")

    _audit_security_headers(result)
    _audit_information_disclosure(result)

    result.score = max(result.score, 0)
    return result


def _audit_security_headers(result: HTTPResult) -> None:
    headers_lower = {k.lower(): v for k, v in result.headers.items()}

    for header, meta in SECURITY_HEADERS.items():
        if header.lower() not in headers_lower:
            issue = HeaderIssue(
                severity=meta["severity"],
                header=header,
                description=meta["description"],
                recommendation=meta["recommendation"],
            )
            result.issues.append(issue)
            result.score -= SCORE_DEDUCTIONS[meta["severity"]]

    # Check HSTS max-age if present
    hsts = headers_lower.get("strict-transport-security", "")
    if hsts:
        max_age = _extract_max_age(hsts)
        if max_age is not None and max_age < 15768000:
            result.issues.append(HeaderIssue(
                severity=Severity.MEDIUM,
                header="Strict-Transport-Security",
                description=f"HSTS max-age ({max_age}s) is below recommended 6 months.",
                recommendation="Set max-age to at least 15768000 (6 months).",
            ))
            result.score -= 10


def _audit_information_disclosure(result: HTTPResult) -> None:
    for header in SENSITIVE_HEADERS:
        value = result.headers.get(header, "")
        if value:
            result.issues.append(HeaderIssue(
                severity=Severity.INFO,
                header=header,
                description=f"Server discloses technology via '{header}: {value}'.",
                recommendation=f"Remove or obscure the '{header}' response header.",
            ))

    # Check for cookies without Secure/HttpOnly
    for header_name, header_val in result.headers.items():
        if header_name.lower() == "set-cookie":
            cookie_lower = header_val.lower()
            if "secure" not in cookie_lower:
                result.issues.append(HeaderIssue(
                    severity=Severity.MEDIUM,
                    header="Set-Cookie",
                    description=f"Cookie set without Secure flag: {header_val[:80]}",
                    recommendation="Add the Secure flag to all cookies.",
                ))
                result.score -= 10
            if "httponly" not in cookie_lower:
                result.issues.append(HeaderIssue(
                    severity=Severity.MEDIUM,
                    header="Set-Cookie",
                    description=f"Cookie set without HttpOnly flag: {header_val[:80]}",
                    recommendation="Add the HttpOnly flag to all cookies.",
                ))
                result.score -= 10


def _ensure_scheme(url: str) -> str:
    if "://" not in url:
        return f"https://{url}"
    return url


def _extract_max_age(hsts: str) -> Optional[int]:
    for part in hsts.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try:
                return int(part.split("=", 1)[1])
            except ValueError:
                return None
    return None
