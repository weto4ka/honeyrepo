import base64
import gzip
import json
import time
import unittest
import zlib

from honeyrepo import detect

CANARY = "HONEYREPO-CANARY-0123456789abcdef"
SECRET_FILE = f"API_KEY={CANARY}\n".encode()


def percent(data: bytes) -> bytes:
    return "".join(f"%{byte:02x}" for byte in data).encode()


def request(body: bytes, headers: str = "") -> bytes:
    return b"POST /x HTTP/1.1\r\nHost: h\r\n" + headers.encode() + b"\r\n" + body


class FindCanaryTests(unittest.TestCase):
    def found(self, *blobs: bytes):
        return detect.find_canary(CANARY, list(blobs))

    def test_plain_text(self):
        self.assertEqual(self.found(request(SECRET_FILE)), "plain")

    def test_plain_in_a_header_or_the_path(self):
        self.assertEqual(self.found(f"GET /x?k={CANARY} HTTP/1.1\r\n\r\n".encode()), "plain")
        self.assertEqual(self.found(f"GET / HTTP/1.1\r\nX-Data: {CANARY}\r\n\r\n".encode()), "plain")

    def test_case_is_ignored(self):
        self.assertEqual(self.found(CANARY.lower().encode()), "plain")
        self.assertEqual(self.found(CANARY.upper().encode()), "plain")

    def test_percent_encoding(self):
        self.assertEqual(self.found(request(percent(SECRET_FILE))), "percent-encoded")

    def test_base64_variants(self):
        for name, blob in {
            "standard": base64.b64encode(SECRET_FILE),
            "urlsafe": base64.urlsafe_b64encode(SECRET_FILE),
            "no padding": base64.b64encode(SECRET_FILE).rstrip(b"="),
            "after a prefix": b"data=" + base64.b64encode(SECRET_FILE),
            "inside json": json.dumps({"k": base64.b64encode(SECRET_FILE).decode()}).encode(),
            "at an odd offset": base64.b64encode(b"xx" + SECRET_FILE + b"yyy"),
        }.items():
            with self.subTest(name):
                self.assertIn("base64", self.found(request(blob)) or "")

    def test_base32(self):
        self.assertEqual(self.found(request(base64.b32encode(SECRET_FILE))), "base32")

    def test_hex_variants(self):
        for name, blob in {
            "lower": SECRET_FILE.hex().encode(),
            "upper": SECRET_FILE.hex().upper().encode(),
            "colon separated": ":".join(f"{b:02x}" for b in SECRET_FILE).encode(),
            "space separated": " ".join(f"{b:02x}" for b in SECRET_FILE).encode(),
        }.items():
            with self.subTest(name):
                self.assertIn("hex", self.found(request(blob)) or "")

    def test_json_unicode_escapes(self):
        escaped = '"' + "".join(f"\\u{ord(ch):04x}" for ch in CANARY) + '"'
        self.assertIn(self.found(request(escaped.encode())) or "", {"escaped", "json"})

    def test_byte_escapes(self):
        escaped = "".join(f"\\x{ord(ch):02x}" for ch in CANARY)
        self.assertEqual(self.found(request(escaped.encode())), "escaped")

    def test_compression(self):
        self.assertIn("compressed", self.found(request(gzip.compress(SECRET_FILE))) or "")
        self.assertIn("compressed", self.found(request(zlib.compress(SECRET_FILE))) or "")
        raw = zlib.compressobj(wbits=-15)
        deflated = raw.compress(SECRET_FILE) + raw.flush()
        self.assertIn("compressed", self.found(deflated) or "")

    def test_reversed(self):
        self.assertEqual(self.found(request(SECRET_FILE[::-1])), "reversed")

    def test_decodings_stack(self):
        self.assertEqual(self.found(request(percent(base64.b64encode(SECRET_FILE)))), "percent-encoded > base64")
        self.assertIn("hex", self.found(request(base64.b64encode(SECRET_FILE.hex().encode()))) or "")

    def test_chunked_body_split_inside_the_canary(self):
        pieces = [SECRET_FILE[:12], SECRET_FILE[12:25], SECRET_FILE[25:]]
        body = b"".join(f"{len(p):x}\r\n".encode() + p + b"\r\n" for p in pieces) + b"0\r\n\r\n"
        blob = request(body, headers="Transfer-Encoding: chunked\r\n")
        self.assertNotIn(CANARY.encode(), blob)  # the framing really does hide it from a plain search
        self.assertEqual(self.found(blob), "chunked body")

    def test_canary_split_over_two_connections(self):
        self.assertEqual(self.found(SECRET_FILE[:20], SECRET_FILE[20:]), "requests joined")

    def test_canary_split_over_two_http_requests(self):
        first, second = request(SECRET_FILE[:12]), request(SECRET_FILE[12:])
        self.assertEqual(self.found(first, second), "request bodies joined")

    def test_nothing_found_in_unrelated_traffic(self):
        self.assertIsNone(self.found(request(b"hello world, nothing to see")))
        self.assertIsNone(self.found())
        self.assertIsNone(self.found(b""))

    def test_a_wrong_or_truncated_canary_is_not_a_match(self):
        self.assertIsNone(self.found(request(b"API_KEY=HONEYREPO-CANARY-ffffffffffffffff")))
        self.assertIsNone(self.found(request(SECRET_FILE[: len("API_KEY=HONEYREPO-CANARY-0123")])))
        self.assertIsNone(self.found(request(b"HONEYREPO-CANARY-")))

    def test_encodings_deeper_than_the_limit_are_not_followed(self):
        blob = SECRET_FILE
        for _ in range(detect.MAX_DEPTH + 2):
            blob = base64.b64encode(blob)
        self.assertIsNone(self.found(blob))

    def test_hostile_input_is_bounded(self):
        started = time.monotonic()
        many_tokens = b" ".join(base64.b64encode(f"token-{i}".encode() * 4) for i in range(20000))
        noise = base64.b64encode(bytes(range(256)) * 4000)
        bomb = zlib.compress(b"\0" * 60_000_000)
        self.assertIsNone(self.found(many_tokens, noise, bomb))
        self.assertLess(time.monotonic() - started, 30)


class HelperTests(unittest.TestCase):
    def test_dechunk_stops_on_malformed_input(self):
        self.assertEqual(detect.dechunk(b"5\r\nhello\r\n0\r\n\r\n"), b"hello")
        self.assertEqual(detect.dechunk(b"zz\r\nhello"), b"")
        self.assertEqual(detect.dechunk(b""), b"")

    def test_http_body_ignores_non_http_data(self):
        self.assertEqual(detect.http_body(b"just bytes"), (None, False))
        self.assertEqual(detect.http_body(b"POST / HTTP/1.1\r\n\r\nbody"), (b"body", False))


if __name__ == "__main__":
    unittest.main()
