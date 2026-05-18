"""
CAMILLE Web — local Flask interface around the existing scan modules.

Exposes:
  GET  /                  → the single-page UI
  GET  /api/scan          → Server-Sent Events stream of scan progress
  GET  /api/report.json   → last scan result as JSON download

Nothing here re-implements scanning logic: it orchestrates the exact same
functions the CLI uses (scan_ports, analyze_ssl, enumerate_dns, analyze_http)
and streams each module's result back to the browser as it completes.
"""

from __future__ import annotations

import json
import sys
import time
import queue
import threading
from pathlib import Path
from typing import Optional

from flask import Flask, Response, request, send_from_directory, jsonify

from camille.core.models import ScanResult
from camille.core.utils import is_valid_target, is_private_target, strip_scheme
from camille.modules.port_scanner import scan_ports, TOP_PORTS
from camille.modules.ssl_analyzer import analyze_ssl
from camille.modules.dns_enum import enumerate_dns
from camille.modules.http_analyzer import analyze_http
from camille.reports.generator import _DataclassEncoder, to_json


def _resource_dir() -> Path:
    """
    Locate the static folder both in development and inside a PyInstaller
    bundle. When frozen, PyInstaller unpacks data files into sys._MEIPASS.
    """
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS) / "camille" / "web" / "static"
    return Path(__file__).parent / "static"


_STATIC_DIR = _resource_dir()

app = Flask(__name__, static_folder=str(_STATIC_DIR))

# Keep the most recent result in memory so the UI can offer a JSON download.
_LAST_RESULT: dict = {"json": None}


def _parse_ports(ports_str: Optional[str]) -> Optional[list[int]]:
    if not ports_str:
        return None
    result: list[int] = []
    for part in ports_str.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            result.extend(range(int(start), int(end) + 1))
        else:
            result.append(int(part))
    return result


def _sse(event: str, data: dict) -> str:
    """Format a Server-Sent Event frame."""
    payload = json.dumps(data, cls=_DataclassEncoder)
    return f"event: {event}\ndata: {payload}\n\n"


@app.route("/")
def index() -> Response:
    return send_from_directory(_STATIC_DIR, "index.html")


@app.route("/api/report.json")
def report_json() -> Response:
    if not _LAST_RESULT["json"]:
        return jsonify({"error": "No scan has been run yet."}), 404
    return Response(
        _LAST_RESULT["json"],
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=camille-report.json"},
    )


@app.route("/api/scan")
def api_scan() -> Response:
    target_raw = (request.args.get("target") or "").strip()
    allow_private = request.args.get("allow_private") == "true"
    modules = request.args.get("modules", "ports,ssl,dns,http").split(",")
    ports_arg = request.args.get("ports") or None
    threads = int(request.args.get("threads", 100))
    no_bruteforce = request.args.get("no_bruteforce") == "true"

    clean_target = strip_scheme(target_raw)

    def generate():
        # ── Validation ───────────────────────────────────────────────── #
        if not target_raw:
            yield _sse("error", {"message": "No target provided."})
            return
        if not is_valid_target(clean_target):
            yield _sse("error", {"message": f"Invalid target: {target_raw}"})
            return
        if is_private_target(clean_target) and not allow_private:
            yield _sse("error", {
                "message": (
                    f"Refusing to scan private/internal target: {clean_target}. "
                    f"Enable 'Allow private targets' if you have authorisation."
                ),
                "kind": "private",
            })
            return

        result = ScanResult(target=clean_target)
        start = time.monotonic()
        yield _sse("start", {"target": clean_target})

        # ── Port scan ────────────────────────────────────────────────── #
        if "ports" in modules:
            yield _sse("progress", {"module": "ports", "state": "running"})
            try:
                port_list = _parse_ports(ports_arg)
                result.ports = scan_ports(clean_target, port_list, threads)
                yield _sse("module", {"module": "ports", "data": result.ports})
            except Exception as exc:  # noqa: BLE001 — surface, don't crash stream
                yield _sse("module", {"module": "ports", "error": str(exc)})

        # ── SSL/TLS ──────────────────────────────────────────────────── #
        if "ssl" in modules:
            yield _sse("progress", {"module": "ssl", "state": "running"})
            try:
                result.ssl = analyze_ssl(clean_target, 443)
                yield _sse("module", {"module": "ssl", "data": result.ssl})
            except Exception as exc:  # noqa: BLE001
                yield _sse("module", {"module": "ssl", "error": str(exc)})

        # ── DNS ──────────────────────────────────────────────────────── #
        if "dns" in modules:
            yield _sse("progress", {"module": "dns", "state": "running"})
            try:
                result.dns = enumerate_dns(clean_target, bruteforce=not no_bruteforce)
                yield _sse("module", {"module": "dns", "data": result.dns})
            except Exception as exc:  # noqa: BLE001
                yield _sse("module", {"module": "dns", "error": str(exc)})

        # ── HTTP ─────────────────────────────────────────────────────── #
        if "http" in modules:
            yield _sse("progress", {"module": "http", "state": "running"})
            try:
                http_url = (
                    target_raw if "://" in target_raw else f"https://{clean_target}"
                )
                result.http = analyze_http(http_url)
                yield _sse("module", {"module": "http", "data": result.http})
            except Exception as exc:  # noqa: BLE001
                yield _sse("module", {"module": "http", "error": str(exc)})

        result.duration = time.monotonic() - start
        _LAST_RESULT["json"] = to_json(result)
        yield _sse("done", {"duration": round(result.duration, 2)})

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


def run(host: str = "127.0.0.1", port: int = 8787, debug: bool = False) -> None:
    """Entry point used by the `camille serve` CLI command."""
    url = f"http://{host}:{port}"
    print(f"\n  CAMILLE web interface running at  \033[1;32m{url}\033[0m")
    print("  Press CTRL+C to stop.\n")
    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == "__main__":
    run()
