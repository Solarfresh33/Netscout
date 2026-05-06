# NetScout

Network Security Reconnaissance & Analysis Tool — scan ports, analyze SSL/TLS, enumerate DNS, and audit HTTP security headers from a single command.

> **For authorized use only.** Only scan systems you own or have explicit permission to test.

---

## Features

| Module | What it does |
|--------|-------------|
| **Port Scanner** | Concurrent TCP scan with service detection and banner grabbing |
| **SSL/TLS Analyzer** | Certificate inspection, weak protocol/cipher detection, expiry check |
| **DNS Enumerator** | A/AAAA/MX/NS/TXT/SOA records, AXFR zone transfer attempt, subdomain bruteforce |
| **HTTP Analyzer** | Security header audit (HSTS, CSP, X-Frame-Options…), cookie flags, server disclosure |
| **Report Generator** | JSON export and dark-themed HTML report |

---

## Installation

**Requirements:** Python 3.9+

```bash
# Clone the repo
git clone <repo-url>
cd Projet-Cyber

# Install dependencies
pip install -r requirements.txt
```

---

## Quick Start

```bash
# Full scan of a domain
python -m netscout.cli scan example.com

# Save reports (JSON + HTML) to a directory
python -m netscout.cli scan example.com --output ./reports
```

---

## Commands

### `scan` — Run a security scan

```
python -m netscout.cli scan TARGET [OPTIONS]
```

`TARGET` can be a hostname (`example.com`), an IP address (`192.168.1.1`), or a URL (`https://example.com`).

#### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-p`, `--ports` | top 33 ports | Ports to scan: `80,443` or a range `1-1024` |
| `--no-ports` | — | Skip port scan |
| `--no-ssl` | — | Skip SSL/TLS analysis |
| `--no-dns` | — | Skip DNS enumeration |
| `--no-http` | — | Skip HTTP header analysis |
| `--no-bruteforce` | — | Skip subdomain bruteforce |
| `--ssl-port` | `443` | Port used for SSL/TLS connection |
| `-o`, `--output` | — | Directory to save reports |
| `-f`, `--format` | `both` | Report format: `json`, `html`, or `both` |
| `--threads` | `100` | Number of scanner threads |
| `-q`, `--quiet` | — | Suppress banner and progress spinners |

#### Examples

```bash
# Scan top ports only (no DNS, no HTTP)
python -m netscout.cli scan 10.0.0.1 --no-dns --no-http

# Scan a custom port range and save a JSON report
python -m netscout.cli scan example.com --ports 1-1024 --output ./reports --format json

# HTTPS-only scan on a non-standard port
python -m netscout.cli scan example.com --no-ports --no-dns --ssl-port 8443

# Fast scan — skip subdomain bruteforce, use more threads
python -m netscout.cli scan example.com --no-bruteforce --threads 200

# Quiet mode, save HTML report
python -m netscout.cli scan example.com -q --output ./reports --format html
```

---

### `info` — Show module status

```bash
python -m netscout.cli info
```

Displays which optional dependencies are available (requests, dnspython, jinja2).

---

## Reports

When `--output` is set, NetScout writes reports to the specified directory.

```
reports/
├── example_com.json   # Machine-readable full scan result
└── example_com.html   # Human-readable dark-themed report
```

The HTML report includes:
- Open ports table with banners
- SSL/TLS score (0–100) with certificate details and issues
- DNS records and discovered subdomains
- HTTP security header score with per-issue fix recommendations

---

## SSL/TLS Scoring

The SSL score starts at 100 and is reduced for each finding:

| Finding | Deduction |
|---------|-----------|
| Expired certificate | −40 |
| Weak protocol (TLS < 1.2, SSLv3…) | −30 |
| Weak cipher (RC4, DES, NULL…) | −20 |
| Short key (< 2048 bits) | −20 |
| Certificate expiring in < 30 days | −15 |
| Self-signed certificate | −10 |

---

## HTTP Security Header Scoring

The HTTP score starts at 100 and is reduced for each missing or misconfigured header:

| Header | Severity | Deduction |
|--------|----------|-----------|
| `Strict-Transport-Security` | HIGH | −20 |
| `Content-Security-Policy` | HIGH | −20 |
| `X-Frame-Options` | MEDIUM | −10 |
| `X-Content-Type-Options` | MEDIUM | −10 |
| `Referrer-Policy` | LOW | −5 |
| `Permissions-Policy` | LOW | −5 |
| `X-XSS-Protection` | LOW | −5 |
| HSTS `max-age` < 6 months | MEDIUM | −10 |
| Cookie without `Secure`/`HttpOnly` | MEDIUM | −10 each |

---

## Running Tests

```bash
PYTHONPATH=. python -m pytest netscout/tests/ -v
```

53 unit tests covering all modules. No network calls are made during tests (socket/requests are mocked).

---

## Project Structure

```
Projet-Cyber/
├── netscout/
│   ├── cli.py                  # Click CLI entry point
│   ├── core/
│   │   ├── models.py           # Data classes (ScanResult, PortResult, …)
│   │   └── utils.py            # Target validation, service name lookup
│   ├── modules/
│   │   ├── port_scanner.py     # TCP port scanner
│   │   ├── ssl_analyzer.py     # SSL/TLS analyzer
│   │   ├── dns_enum.py         # DNS enumerator
│   │   └── http_analyzer.py    # HTTP header analyzer
│   ├── reports/
│   │   └── generator.py        # JSON + HTML report generator
│   └── tests/                  # Unit tests
├── requirements.txt
└── pyproject.toml
```

### By Solar