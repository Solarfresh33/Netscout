"""Data models for scan results."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class PortResult:
    port: int
    state: PortState
    service: str = ""
    version: str = ""
    banner: str = ""


@dataclass
class SSLIssue:
    severity: Severity
    title: str
    description: str


@dataclass
class SSLResult:
    host: str
    port: int
    version: str = ""
    cipher: str = ""
    bits: int = 0
    subject: dict = field(default_factory=dict)
    issuer: dict = field(default_factory=dict)
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    san: list[str] = field(default_factory=list)
    issues: list[SSLIssue] = field(default_factory=list)
    score: int = 100


@dataclass
class DNSRecord:
    record_type: str
    value: str
    ttl: int = 0


@dataclass
class DNSResult:
    target: str
    records: list[DNSRecord] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    zone_transfer: bool = False
    mx_records: list[str] = field(default_factory=list)
    nameservers: list[str] = field(default_factory=list)


@dataclass
class HeaderIssue:
    severity: Severity
    header: str
    description: str
    recommendation: str


@dataclass
class HTTPResult:
    url: str
    status_code: int = 0
    server: str = ""
    headers: dict = field(default_factory=dict)
    issues: list[HeaderIssue] = field(default_factory=list)
    score: int = 100
    redirects: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    target: str
    timestamp: datetime = field(default_factory=datetime.now)
    ports: list[PortResult] = field(default_factory=list)
    ssl: Optional[SSLResult] = None
    dns: Optional[DNSResult] = None
    http: Optional[HTTPResult] = None
    duration: float = 0.0
