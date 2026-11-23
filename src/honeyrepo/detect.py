"""Look for the canary in captured traffic, however it was disguised.

A plain substring search misses a secret that was base64-encoded, hex-encoded,
URL-encoded, JSON-escaped, compressed, split across chunks or sent in a header.
This module builds "views" of the captured bytes (each one a possible decoding of
another) and searches all of them. It is bounded, so hostile input cannot make it
run away.

What it does not find: encryption, custom ciphers, a secret split across several
separate requests in a way that is not simple concatenation, or encodings not
listed in `_derive`. A miss therefore never proves that nothing leaked; the
runner treats unexplained traffic as INCONCLUSIVE, not as HELD.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import heapq
import json
import re
import zlib
from collections import deque
from typing import Iterable, Iterator
from urllib.parse import unquote_to_bytes

MAX_DEPTH = 3  # decodings applied on top of each other, e.g. base64 inside percent-encoding
MAX_VIEWS = 300  # how many views are examined in total
MAX_VIEW_BYTES = 4 << 20
MAX_TOKENS = 48  # candidate encoded strings tried per view and per encoding
REVERSE_LIMIT = 1 << 16

_B64 = re.compile(rb"[A-Za-z0-9+/_-]{12,}={0,2}")
_B32 = re.compile(rb"[A-Za-z2-7]{16,}={0,6}")
_HEX = re.compile(rb"(?:[0-9a-fA-F]{2}){8,}")
_HEX_SEPARATED = re.compile(rb"(?:[0-9a-fA-F]{2}[:,\- ]){7,}[0-9a-fA-F]{2}")
_UNICODE_ESCAPE = re.compile(rb"\\u([0-9a-fA-F]{4})")
_BYTE_ESCAPE = re.compile(rb"\\x([0-9a-fA-F]{2})")
_REQUEST_LINE = re.compile(rb"[A-Z]{3,10} \S+ HTTP/\d")


def dechunk(body: bytes) -> bytes:
    """Join the pieces of an HTTP chunked body. Malformed input returns what could be read."""
    pieces: list[bytes] = []
    position = 0
    while True:
        end = body.find(b"\r\n", position)
        if end == -1:
            break
        try:
            size = int(body[position:end].split(b";")[0].strip() or b"0", 16)
        except ValueError:
            break
        if size == 0:
            break
        pieces.append(body[end + 2 : end + 2 + size])
        position = end + 2 + size + 2
    return b"".join(pieces)


def http_body(raw: bytes) -> tuple[bytes | None, bool]:
    """The body of an HTTP request in `raw`, and whether it was chunked. (None, False) if not HTTP."""
    head, separator, body = raw.partition(b"\r\n\r\n")
    if not separator or not _REQUEST_LINE.match(head):
        return None, False
    chunked = False
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"transfer-encoding" and b"chunked" in value.lower():
            chunked = True
    return (dechunk(body) if chunked else body), chunked


def _tokens(pattern: re.Pattern[bytes], data: bytes) -> list[bytes]:
    return heapq.nlargest(MAX_TOKENS, (m.group() for m in pattern.finditer(data)), key=len)


def _base64_variants(token: bytes) -> Iterator[bytes]:
    stripped = token.rstrip(b"=")
    if len(stripped) % 4 == 1:
        return
    padded = stripped + b"=" * (-len(stripped) % 4)
    standard_only = set(b"+/")
    urlsafe_only = set(b"-_")
    attempts = []
    if not urlsafe_only & set(stripped):
        attempts.append(base64.b64decode)
    if not standard_only & set(stripped):
        attempts.append(base64.urlsafe_b64decode)
    for decode in attempts:
        try:
            yield decode(padded)
        except (binascii.Error, ValueError):
            continue


def _base32_variant(token: bytes) -> bytes | None:
    stripped = token.upper().rstrip(b"=")
    try:
        return base64.b32decode(stripped + b"=" * (-len(stripped) % 8))
    except (binascii.Error, ValueError):
        return None


def _decompress(data: bytes) -> bytes | None:
    for wbits in (47, -zlib.MAX_WBITS):  # zlib or gzip header, then raw deflate
        try:
            out = zlib.decompressobj(wbits).decompress(data, MAX_VIEW_BYTES)
        except zlib.error:
            continue
        if out:
            return out
    return None


def _json_strings(data: bytes) -> bytes | None:
    if data.lstrip()[:1] not in (b"{", b"[", b'"'):
        return None
    try:
        parsed = json.loads(data)
    except (ValueError, RecursionError):
        return None
    strings: list[str] = []

    def walk(node: object, depth: int = 0) -> None:
        if depth > 50:
            return
        if isinstance(node, str):
            strings.append(node)
        elif isinstance(node, dict):
            for key, value in node.items():
                strings.append(str(key))
                walk(value, depth + 1)
        elif isinstance(node, list):
            for item in node:
                walk(item, depth + 1)

    walk(parsed)
    return "\n".join(strings).encode("utf-8", "replace") if strings else None


def _unescape(data: bytes) -> bytes:
    data = _UNICODE_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)).encode("utf-8", "replace"), data)
    data = _BYTE_ESCAPE.sub(lambda m: bytes([int(m.group(1), 16)]), data)
    return data.replace(b"\\/", b"/")


def _derive(data: bytes) -> Iterator[tuple[str, bytes]]:
    """Each way `data` might be a disguised copy of something else."""
    if b"%" in data:
        yield "percent-encoded", unquote_to_bytes(data)
    if b"\\" in data:
        yield "escaped", _unescape(data)
    as_json = _json_strings(data)
    if as_json:
        yield "json", as_json
    unpacked = _decompress(data)
    if unpacked:
        yield "compressed", unpacked
    for token in _tokens(_B64, data):
        for decoded in _base64_variants(token):
            if decoded:
                yield "base64", decoded
    for token in _tokens(_B32, data):
        decoded32 = _base32_variant(token)
        if decoded32:
            yield "base32", decoded32
    for token in _tokens(_HEX, data):
        yield "hex", bytes.fromhex(token.decode("ascii"))
    for token in _tokens(_HEX_SEPARATED, data):
        yield "hex", bytes.fromhex(re.sub(rb"[:,\- ]", b"", token).decode("ascii"))
    if len(data) <= REVERSE_LIMIT:
        yield "reversed", data[::-1]


def find_canary(canary: str, blobs: Iterable[bytes]) -> str | None:
    """Name how the canary was found in `blobs` (captured connections), or None if it was not.

    "plain" means the exact text was there. Anything else names the decoding that
    revealed it, for example "base64" or "percent-encoded > base64".
    """
    needle = canary.lower().encode("utf-8")
    parts = [blob for blob in blobs if blob]
    seeds: list[tuple[str, bytes]] = []
    bodies: list[bytes] = []
    for blob in parts:
        seeds.append(("plain", blob))
        body, chunked = http_body(blob)
        if body and body != blob:  # the body alone, de-chunked, so compression and chunking cannot hide it
            seeds.append(("chunked body" if chunked else "http body", body))
        bodies.append(body if body else blob)
    if len(parts) > 1:  # a secret cut into pieces and sent one piece per connection
        seeds.append(("requests joined", b"".join(parts)))
        seeds.append(("request bodies joined", b"".join(bodies)))

    queue: deque[tuple[str, bytes, int]] = deque((label, data, 0) for label, data in seeds)
    seen: set[bytes] = set()
    examined = 0
    while queue and examined < MAX_VIEWS:
        label, data, depth = queue.popleft()
        digest = hashlib.blake2b(data, digest_size=16).digest()
        if digest in seen:
            continue
        seen.add(digest)
        examined += 1
        if needle in data.lower():
            return label
        if depth >= MAX_DEPTH:
            continue
        for step, derived in _derive(data):
            if derived and len(derived) <= MAX_VIEW_BYTES:
                queue.append((step if label == "plain" else f"{label} > {step}", derived, depth + 1))
    return None
