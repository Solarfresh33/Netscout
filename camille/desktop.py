"""
CAMILLE Desktop — native desktop window around the local scan engine.

This launches the existing Flask app on a free localhost port in a background
thread, then opens it inside a native OS window via pywebview (no browser
chrome, no address bar — a real desktop app).

On Windows, pywebview uses the built-in Edge WebView2 runtime (present by
default on Windows 10/11), so the packaged .exe needs no extra runtime.

If pywebview is unavailable for any reason, it falls back to opening the
system default browser so the app still works.
"""

from __future__ import annotations

import socket
import threading
import time

from camille.web.server import app

WINDOW_TITLE = "CAMILLE — Cyber Audit & Monitoring Intelligence"


def _free_port() -> int:
    """Ask the OS for an available localhost port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _serve(port: int) -> None:
    """Run Flask via the production-ish werkzeug server (no reloader)."""
    from werkzeug.serving import make_server

    server = make_server("127.0.0.1", port, app, threaded=True)
    server.serve_forever()


def _wait_until_up(port: int, timeout: float = 8.0) -> bool:
    """Block until the local server accepts connections (or timeout)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.15)
    return False


def main() -> None:
    import os

    env_port = os.environ.get("CAMILLE_PORT")
    port = int(env_port) if env_port else _free_port()
    url = f"http://127.0.0.1:{port}"

    # Flask runs in a daemon thread; it dies automatically when the window closes.
    threading.Thread(target=_serve, args=(port,), daemon=True).start()

    if not _wait_until_up(port):
        raise RuntimeError("CAMILLE local server failed to start in time.")

    try:
        import webview  # pywebview

        webview.create_window(
            WINDOW_TITLE,
            url,
            width=1240,
            height=900,
            min_size=(900, 640),
            background_color="#060a07",
        )
        webview.start()  # blocks until the window is closed
    except ImportError:
        # Graceful fallback — still usable without pywebview installed.
        import webbrowser

        print(f"\n  pywebview not installed — opening in your browser instead.")
        print(f"  CAMILLE running at  {url}\n  Press CTRL+C to stop.\n")
        webbrowser.open(url)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n  Stopped.")


if __name__ == "__main__":
    main()
