"""A tiny local HTTP server that records every request it receives.

It binds to 127.0.0.1 only. If a canary secret shows up in a request path or
body, the secret left the sandbox.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


@dataclass
class Hit:
    method: str
    path: str
    body: str


@dataclass
class Listener:
    hits: list[Hit] = field(default_factory=list)
    _server: ThreadingHTTPServer | None = field(default=None, repr=False)
    _thread: threading.Thread | None = field(default=None, repr=False)

    @property
    def url(self) -> str:
        if self._server is None:
            raise RuntimeError("listener is not running")
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> "Listener":
        hits = self.hits

        class Handler(BaseHTTPRequestHandler):
            def _record(self) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                hits.append(Hit(self.command, self.path, raw.decode("utf-8", errors="replace")))
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            do_GET = do_POST = do_PUT = _record

            def log_message(self, format, *args):  # noqa: A002 - keep the output quiet
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def saw(self, needle: str) -> bool:
        """True if `needle` appears in the path or body of any recorded request."""
        return any(needle in hit.path or needle in hit.body for hit in list(self.hits))

    def __enter__(self) -> "Listener":
        return self.start()

    def __exit__(self, *exc_info) -> None:
        self.stop()
