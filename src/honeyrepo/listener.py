"""A tiny local TCP listener that records every byte it receives.

It binds to 127.0.0.1 only. Whatever arrives is kept as raw bytes, so the
canary can be found in the request line, the headers or the body, however the
client chose to send it. It answers like a minimal HTTP server so clients
finish normally, and it signs the answer with a per-run nonce so the attacker
can tell the listener's reply from anyone else's.
"""

from __future__ import annotations

import secrets
import socket
import socketserver
import sys
import threading
import time
from dataclasses import dataclass

MAX_BYTES = 1 << 20  # per connection; anything beyond this is not kept
IDLE_SECONDS = 1.0  # how long to wait for more bytes before answering anyway
HEADER_END = b"\r\n\r\n"
SENTINEL_PREFIX = b"HONEYREPO-SENTINEL "


@dataclass(frozen=True)
class Connection:
    raw: bytes  # everything the client sent, possibly nothing
    truncated: bool = False  # True if more than MAX_BYTES arrived


def ack_text(nonce: str) -> str:
    return f"HONEYREPO-ACK {nonce}"


def _headers(head: bytes) -> dict[bytes, bytes]:
    found: dict[bytes, bytes] = {}
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        found[name.strip().lower()] = value.strip().lower()
    return found


def _chunked_complete(body: bytes) -> bool:
    position = 0
    while True:
        end = body.find(b"\r\n", position)
        if end == -1:
            return False
        try:
            size = int(body[position:end].split(b";")[0].strip() or b"0", 16)
        except ValueError:
            return True  # malformed: stop waiting, keep what we have
        if size == 0:  # the last chunk is followed by optional trailers and a blank line
            rest = body[end + 2 :]
            return rest.startswith(b"\r\n") or HEADER_END in rest
        position = end + 2 + size + 2
        if position > len(body):
            return False


def http_message_complete(buffer: bytes) -> bool:
    """True once `buffer` holds a whole HTTP request (headers plus the body it announced)."""
    head, separator, body = buffer.partition(HEADER_END)
    if not separator:
        return False
    headers = _headers(head)
    if b"chunked" in headers.get(b"transfer-encoding", b""):
        return _chunked_complete(body)
    length = headers.get(b"content-length", b"")
    if length.isdigit():
        return len(body) >= int(length)
    return True


def _wants_continue(buffer: bytes) -> bool:
    head, separator, body = buffer.partition(HEADER_END)
    return bool(separator) and not body and _headers(head).get(b"expect") == b"100-continue"


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    request_queue_size = 128  # a burst of connections must not be dropped

    def __init__(self, listener: "Listener") -> None:
        self.listener = listener
        super().__init__(("127.0.0.1", 0), _Handler)

    def process_request(self, request, client_address):  # runs right after accept()
        self.listener._begin()
        super().process_request(request, client_address)

    def handle_error(self, request, client_address):  # an exception inside a handler
        self.listener._fail(f"handler error: {sys.exc_info()[1]!r}")


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            self.server.listener._serve(self.request)
        finally:
            self.server.listener._end()


class Listener:
    """Collects connections. Use as a context manager."""

    def __init__(self, nonce: str | None = None) -> None:
        self.nonce = nonce or secrets.token_hex(8)
        self.errors: list[str] = []
        self._connections: list[Connection] = []
        self._server: _Server | None = None
        self._thread: threading.Thread | None = None
        self._cond = threading.Condition()
        self._active = 0
        self._sentinel = secrets.token_hex(8).encode()
        self._sentinel_seen = threading.Event()

    # -- lifecycle -----------------------------------------------------
    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("listener is not running")
        return self._server.server_address[1]

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> "Listener":
        server = _Server(self)
        if server.server_address[0] != "127.0.0.1":  # never expose the listener beyond this machine
            server.server_close()
            raise OSError(f"listener bound to {server.server_address[0]}, expected 127.0.0.1")
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        try:
            thread.start()
        except RuntimeError as err:  # e.g. "can't start new thread"
            server.server_close()
            raise OSError(f"could not start the listener thread: {err}") from err
        self._server, self._thread = server, thread
        return self

    def stop(self) -> None:
        if self._thread is not None:
            self._server.shutdown()  # only safe once serve_forever is running, or it waits forever
            self._thread.join(timeout=5)
            self._thread = None
        if self._server is not None:
            self._server.server_close()
            self._server = None

    def __enter__(self) -> "Listener":
        return self.start()

    def __exit__(self, *exc_info) -> None:
        self.stop()

    # -- results -------------------------------------------------------
    def connections(self) -> list[Connection]:
        with self._cond:
            return list(self._connections)

    def settle(self, timeout: float = 2.0) -> bool:
        """Wait until every connection made before this call has been read and recorded.

        A connection that is complete in the kernel but not yet accepted could otherwise
        be missed. We open one more connection ourselves: connections are accepted in
        order, so once that one has been seen, everything before it has been picked up.
        Returns False if that could not be confirmed.
        """
        deadline = time.monotonic() + timeout
        self._sentinel_seen.clear()
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=timeout) as probe:
                probe.sendall(SENTINEL_PREFIX + self._sentinel)
                probe.settimeout(timeout)
                try:
                    probe.recv(64)
                except OSError:
                    pass
        except OSError:
            return False
        if not self._sentinel_seen.wait(max(0.0, deadline - time.monotonic())):
            return False
        with self._cond:
            while self._active and (remaining := deadline - time.monotonic()) > 0:
                self._cond.wait(remaining)
            return self._active == 0

    # -- internals -----------------------------------------------------
    def _begin(self) -> None:
        with self._cond:
            self._active += 1

    def _end(self) -> None:
        with self._cond:
            self._active -= 1
            self._cond.notify_all()

    def _fail(self, message: str) -> None:
        with self._cond:
            self.errors.append(message)

    def _serve(self, conn: socket.socket) -> None:
        raw = b""
        recorded = False
        try:
            conn.settimeout(IDLE_SECONDS)
            continued = False
            while len(raw) < MAX_BYTES:
                try:
                    chunk = conn.recv(65536)
                except OSError:  # includes timeouts and resets: keep what we have
                    break
                if not chunk:
                    break
                raw += chunk
                if not continued and _wants_continue(raw):
                    continued = True
                    try:
                        conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
                    except OSError:
                        break
                if http_message_complete(raw) or raw == SENTINEL_PREFIX + self._sentinel:
                    break
            if raw == SENTINEL_PREFIX + self._sentinel:  # our own probe from settle(); not the attacker
                self._sentinel_seen.set()
                recorded = True
            else:
                with self._cond:
                    self._connections.append(Connection(raw[:MAX_BYTES], len(raw) >= MAX_BYTES))
                recorded = True
            body = ack_text(self.nonce).encode()
            reply = (
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode()
                + body
            )
            try:
                conn.sendall(reply)
            except OSError:
                pass
        except Exception as err:  # noqa: BLE001 - a listener bug must never look like "nothing happened"
            self._fail(f"listener error: {err!r}")
        finally:
            if not recorded:
                with self._cond:
                    self._connections.append(Connection(raw[:MAX_BYTES], len(raw) >= MAX_BYTES))
