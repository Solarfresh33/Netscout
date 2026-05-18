"""CAMILLE – Network Security Reconnaissance & Analysis Tool CLI."""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box

from camille.core.models import ScanResult
from camille.core.utils import (
    is_valid_target,
    is_private_target,
    safe_filename,
    strip_scheme,
    severity_color,
)
from camille.modules.port_scanner import scan_ports, TOP_PORTS
from camille.modules.ssl_analyzer import analyze_ssl
from camille.modules.dns_enum import enumerate_dns
from camille.modules.http_analyzer import analyze_http
from camille.reports.generator import save_json, save_html


console = Console()

BANNER = r"""
   ██████╗ █████╗ ███╗   ███╗██╗██╗     ██╗     ███████╗
  ██╔════╝██╔══██╗████╗ ████║██║██║     ██║     ██╔════╝
  ██║     ███████║██╔████╔██║██║██║     ██║     █████╗
  ██║     ██╔══██║██║╚██╔╝██║██║██║     ██║     ██╔══╝
  ╚██████╗██║  ██║██║ ╚═╝ ██║██║███████╗███████╗███████╗
   ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝╚══════╝╚══════╝╚══════╝

  Cyber Audit & Monitoring Intelligence for Local and Large Environments
  For authorized use only — v2.1.0
"""


def _print_banner() -> None:
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")


def _parse_ports(ports_str: Optional[str]) -> Optional[list[int]]:
    if not ports_str:
        return None
    result: list[int] = []
    for part in ports_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            result.extend(range(int(start), int(end) + 1))
        else:
            result.append(int(part))
    return result


@click.group()
def main() -> None:
    """CAMILLE — Network Security Reconnaissance & Analysis Tool."""
    pass


# --------------------------------------------------------------------------- #
# scan command                                                                  #
# --------------------------------------------------------------------------- #

@main.command()
@click.argument("target")
@click.option("--ports", "-p", default=None, help="Ports to scan: 80,443 or 1-1024 (default: top ports)")
@click.option("--no-ports", is_flag=True, help="Skip port scan")
@click.option("--no-ssl", is_flag=True, help="Skip SSL/TLS analysis")
@click.option("--no-dns", is_flag=True, help="Skip DNS enumeration")
@click.option("--no-http", is_flag=True, help="Skip HTTP header analysis")
@click.option("--no-bruteforce", is_flag=True, help="Skip subdomain bruteforce")
@click.option("--ssl-port", default=443, show_default=True, help="Port for SSL analysis")
@click.option("--output", "-o", default=None, help="Output directory for reports")
@click.option("--format", "-f", "fmt", default="both", type=click.Choice(["json", "html", "both"]), show_default=True)
@click.option("--threads", default=100, show_default=True, help="Scanner thread count")
@click.option("--allow-private", is_flag=True, help="Allow scanning of private/internal addresses (RFC 1918, loopback, etc.)")
@click.option("--quiet", "-q", is_flag=True, help="Suppress banner and progress output")
def scan(
    target: str,
    ports: Optional[str],
    no_ports: bool,
    no_ssl: bool,
    no_dns: bool,
    no_http: bool,
    no_bruteforce: bool,
    ssl_port: int,
    output: Optional[str],
    fmt: str,
    threads: int,
    allow_private: bool,
    quiet: bool,
) -> None:
    """Run a full security scan against TARGET (hostname, IP, or URL)."""
    if not quiet:
        _print_banner()

    clean_target = strip_scheme(target)

    if not is_valid_target(clean_target):
        console.print(f"[red]Invalid target:[/red] {target}")
        sys.exit(1)

    if is_private_target(clean_target) and not allow_private:
        console.print(
            f"[red]Refusing to scan private/internal target:[/red] {clean_target}\n"
            f"[yellow]Re-run with --allow-private if you really intend to scan internal "
            f"infrastructure (and have authorisation to do so).[/yellow]"
        )
        sys.exit(1)

    console.print(f"[bold]Target:[/bold] {clean_target}\n")
    result = ScanResult(target=clean_target)
    start = time.monotonic()

    # ── Port scan ─────────────────────────────────────────────────────────── #
    if not no_ports:
        port_list = _parse_ports(ports)
        label = f"{len(port_list)} ports" if port_list else f"{len(TOP_PORTS)} top ports"
        with Progress(SpinnerColumn(), TextColumn(f"[cyan]Scanning {label}..."), transient=True) as prog:
            prog.add_task("scan", total=None)
            result.ports = scan_ports(clean_target, port_list, threads)

        _display_ports(result)

    # ── SSL/TLS ───────────────────────────────────────────────────────────── #
    if not no_ssl:
        with Progress(SpinnerColumn(), TextColumn("[cyan]Analyzing SSL/TLS..."), transient=True) as prog:
            prog.add_task("ssl", total=None)
            result.ssl = analyze_ssl(clean_target, ssl_port)

        _display_ssl(result)

    # ── DNS ───────────────────────────────────────────────────────────────── #
    if not no_dns:
        with Progress(SpinnerColumn(), TextColumn("[cyan]Enumerating DNS..."), transient=True) as prog:
            prog.add_task("dns", total=None)
            result.dns = enumerate_dns(clean_target, bruteforce=not no_bruteforce)

        _display_dns(result)

    # ── HTTP ──────────────────────────────────────────────────────────────── #
    if not no_http:
        http_url = target if "://" in target else f"https://{clean_target}"
        with Progress(SpinnerColumn(), TextColumn("[cyan]Analyzing HTTP headers..."), transient=True) as prog:
            prog.add_task("http", total=None)
            result.http = analyze_http(http_url)

        _display_http(result)

    result.duration = time.monotonic() - start
    console.print(f"\n[dim]Scan completed in {result.duration:.2f}s[/dim]")

    # ── Save reports ──────────────────────────────────────────────────────── #
    if output:
        out_dir = Path(output)
        safe_name = safe_filename(clean_target.replace(".", "_"))
        if fmt in ("json", "both"):
            json_path = save_json(result, out_dir / f"{safe_name}.json")
            console.print(f"[green]JSON report:[/green] {json_path}")
        if fmt in ("html", "both"):
            html_path = save_html(result, out_dir / f"{safe_name}.html")
            console.print(f"[green]HTML report:[/green] {html_path}")


# --------------------------------------------------------------------------- #
# Display helpers                                                               #
# --------------------------------------------------------------------------- #

def _display_ports(result: ScanResult) -> None:
    if not result.ports:
        console.print(Panel("[yellow]No open ports found[/yellow]", title="Port Scan"))
        return

    table = Table(title=f"Open Ports ({len(result.ports)} found)", box=box.ROUNDED, border_style="cyan")
    table.add_column("Port", style="bold white", width=8)
    table.add_column("Service", style="cyan", width=14)
    table.add_column("Banner", style="dim")

    for p in result.ports:
        table.add_row(str(p.port), p.service, p.banner[:80] if p.banner else "—")

    console.print(table)
    console.print()


def _display_ssl(result: ScanResult) -> None:
    ssl = result.ssl
    if not ssl:
        console.print(Panel("[yellow]SSL/TLS not available on this target[/yellow]", title="SSL/TLS"))
        return

    score_style = "green" if ssl.score >= 75 else ("yellow" if ssl.score >= 40 else "red")
    panel_content = (
        f"Score: [{score_style}]{ssl.score}/100[/{score_style}]  "
        f"Protocol: [cyan]{ssl.version}[/cyan]  "
        f"Cipher: [cyan]{ssl.cipher}[/cyan] ({ssl.bits} bits)\n"
        f"Subject: {ssl.subject.get('commonName', '—')}  "
        f"Issuer: {ssl.issuer.get('organizationName', '—')}\n"
        f"Valid: {ssl.not_before.date() if ssl.not_before else '—'} → "
        f"{ssl.not_after.date() if ssl.not_after else '—'}"
    )

    if ssl.issues:
        panel_content += "\n\n[bold]Issues:[/bold]"
        for issue in ssl.issues:
            color = severity_color(issue.severity.value)
            panel_content += f"\n  [{color}][{issue.severity.value}][/{color}] {issue.title}"

    console.print(Panel(panel_content, title="SSL/TLS Analysis", border_style="cyan"))
    console.print()


def _display_dns(result: ScanResult) -> None:
    dns = result.dns
    if not dns:
        return

    lines: list[str] = []

    if dns.zone_transfer:
        lines.append("[bold red]CRITICAL: Zone transfer (AXFR) succeeded![/bold red]")

    if dns.records:
        table = Table(box=box.SIMPLE, show_header=True)
        table.add_column("Type", style="cyan", width=8)
        table.add_column("Value")
        table.add_column("TTL", width=8)
        for r in dns.records:
            table.add_row(r.record_type, r.value, str(r.ttl))
        console.print(Panel(table, title=f"DNS Records ({len(dns.records)})", border_style="cyan"))

    if dns.subdomains:
        subs = "  ".join(f"[cyan]{s}[/cyan]" for s in dns.subdomains)
        console.print(Panel(subs, title=f"Subdomains Found ({len(dns.subdomains)})", border_style="cyan"))

    console.print()


def _display_http(result: ScanResult) -> None:
    http = result.http
    if not http:
        console.print(Panel("[yellow]HTTP analysis failed[/yellow]", title="HTTP Headers"))
        return

    score_style = "green" if http.score >= 75 else ("yellow" if http.score >= 40 else "red")
    header_line = (
        f"Score: [{score_style}]{http.score}/100[/{score_style}]  "
        f"Status: [bold]{http.status_code}[/bold]  "
        f"Server: [cyan]{http.server or '—'}[/cyan]"
    )

    if http.issues:
        table = Table(box=box.SIMPLE, show_header=True)
        table.add_column("Severity", width=10)
        table.add_column("Header", style="cyan")
        table.add_column("Description")
        for issue in sorted(http.issues, key=lambda i: i.severity.value):
            color = severity_color(issue.severity.value)
            table.add_row(
                f"[{color}]{issue.severity.value}[/{color}]",
                issue.header,
                issue.description[:80],
            )
        console.print(Panel(
            header_line + "\n",
            title="HTTP Security Headers",
            border_style="cyan",
        ))
        console.print(table)
    else:
        console.print(Panel(
            header_line + "\n[green]All security headers are present.[/green]",
            title="HTTP Security Headers",
            border_style="cyan",
        ))

    console.print()


# --------------------------------------------------------------------------- #
# info command                                                                  #
# --------------------------------------------------------------------------- #

@main.command()
def info() -> None:
    """Display tool information and module status."""
    _print_banner()
    console.print("[bold]Modules:[/bold]")
    try:
        import requests as _req
        console.print("  [green]✓[/green] HTTP analyzer (requests available)")
    except ImportError:
        console.print("  [red]✗[/red] HTTP analyzer (install requests)")
    try:
        import dns as _dns  # noqa: F401
        console.print("  [green]✓[/green] DNS enumerator (dnspython available)")
    except ImportError:
        console.print("  [yellow]~[/yellow] DNS enumerator (stdlib only, install dnspython for full features)")
    try:
        from jinja2 import Environment  # noqa: F401
        console.print("  [green]✓[/green] HTML reports (jinja2 available)")
    except ImportError:
        console.print("  [red]✗[/red] HTML reports (install jinja2)")
    console.print("  [green]✓[/green] Port scanner (stdlib)")
    console.print("  [green]✓[/green] SSL/TLS analyzer (stdlib)")


# --------------------------------------------------------------------------- #
# serve command — launch the web interface                                      #
# --------------------------------------------------------------------------- #

@main.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind address")
@click.option("--port", default=8787, show_default=True, help="Listen port")
@click.option("--debug", is_flag=True, help="Enable Flask debug mode")
def serve(host: str, port: int, debug: bool) -> None:
    """Launch the CAMILLE web interface in a local browser."""
    _print_banner()
    try:
        from camille.web.server import run as run_web
    except ImportError:
        console.print(
            "[red]Flask is required for the web interface.[/red]\n"
            "Install it with: [cyan]pip install flask[/cyan]"
        )
        sys.exit(1)
    run_web(host=host, port=port, debug=debug)


@main.command()
def desktop() -> None:
    """Launch CAMILLE as a native desktop application window."""
    try:
        from camille.desktop import main as run_desktop
    except ImportError as exc:
        console.print(f"[red]Could not start desktop app:[/red] {exc}")
        sys.exit(1)
    run_desktop()


if __name__ == "__main__":
    main()
