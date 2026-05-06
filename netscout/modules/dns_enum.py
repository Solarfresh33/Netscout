"""DNS enumeration: records, zone transfer attempt, subdomain bruteforce."""

import concurrent.futures
import socket
from typing import Optional

try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

from netscout.core.models import DNSRecord, DNSResult


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR"]

COMMON_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "api", "dev", "staging",
    "portal", "admin", "test", "cdn", "media", "docs", "support", "app",
    "help", "status", "monitor", "git", "gitlab", "jenkins", "jira",
    "confluence", "wiki", "intranet", "internal", "corp",
]


def enumerate_dns(target: str, bruteforce: bool = True) -> DNSResult:
    """
    Enumerate DNS records for target domain.

    Args:
        target: Domain name to enumerate.
        bruteforce: Whether to attempt subdomain bruteforcing.

    Returns:
        DNSResult with all discovered information.
    """
    result = DNSResult(target=target)

    if HAS_DNSPYTHON:
        _collect_records_dnspython(target, result)
        _attempt_zone_transfer(target, result)
    else:
        _collect_records_stdlib(target, result)

    if bruteforce:
        result.subdomains = _bruteforce_subdomains(target)

    return result


def _collect_records_dnspython(target: str, result: DNSResult) -> None:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(target, rtype)
            for rdata in answers:
                value = rdata.to_text()
                record = DNSRecord(
                    record_type=rtype,
                    value=value,
                    ttl=int(answers.rrset.ttl),
                )
                result.records.append(record)

                if rtype == "MX":
                    result.mx_records.append(value)
                elif rtype == "NS":
                    result.nameservers.append(value)
        except (dns.exception.DNSException, Exception):
            continue


def _collect_records_stdlib(target: str, result: DNSResult) -> None:
    try:
        ip = socket.gethostbyname(target)
        result.records.append(DNSRecord(record_type="A", value=ip))
    except socket.gaierror:
        pass


def _attempt_zone_transfer(target: str, result: DNSResult) -> None:
    """Try AXFR zone transfer on each known nameserver."""
    for ns_raw in result.nameservers:
        ns = ns_raw.rstrip(".")
        try:
            ns_ip = socket.gethostbyname(ns)
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, target, timeout=5))
            if zone:
                result.zone_transfer = True
                for name in zone.nodes:
                    fqdn = f"{name}.{target}"
                    result.subdomains.append(fqdn)
                return
        except Exception:
            continue


def _check_subdomain(subdomain: str, domain: str) -> Optional[str]:
    fqdn = f"{subdomain}.{domain}"
    try:
        socket.gethostbyname(fqdn)
        return fqdn
    except socket.gaierror:
        return None


def _bruteforce_subdomains(target: str, max_workers: int = 30) -> list[str]:
    found: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_check_subdomain, sub, target): sub
            for sub in COMMON_SUBDOMAINS
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
    return sorted(found)
