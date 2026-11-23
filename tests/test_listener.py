import http.client
import socket
import threading
import unittest
from unittest import mock

from honeyrepo import listener as listener_module
from honeyrepo.listener import MAX_BYTES, SENTINEL_PREFIX, Listener, ack_text, http_message_complete


def connect(server: Listener) -> socket.socket:
    return socket.create_connection(("127.0.0.1", server.port), timeout=5)


class ListenerTests(unittest.TestCase):
    def test_binds_to_loopback_only(self):
        with Listener() as server:
            self.assertEqual(server._server.server_address[0], "127.0.0.1")
            self.assertTrue(server.url.startswith("http://127.0.0.1:"))

    def test_records_a_request_and_answers_with_the_nonce(self):
        with Listener("abc123") as server:
            conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=5)
            conn.request("POST", "/exfil", body=b"hello")
            reply = conn.getresponse()
            self.assertEqual(reply.status, 200)
            self.assertEqual(reply.read().decode(), ack_text("abc123"))
            self.assertTrue(server.settle())
            (only,) = server.connections()
            self.assertIn(b"POST /exfil", only.raw)
            self.assertTrue(only.raw.endswith(b"hello"))

    def test_every_http_method_is_recorded(self):
        with Listener() as server:
            for method in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "FOO"):
                conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=5)
                conn.request(method, "/m", body=None if method in ("GET", "OPTIONS") else b"payload-" + method.encode())
                self.assertEqual(conn.getresponse().status, 200, method)
            self.assertTrue(server.settle())
            raw = b"\n".join(c.raw for c in server.connections())
            for method in ("PATCH", "DELETE", "FOO"):
                self.assertIn(b"payload-" + method.encode(), raw)
            self.assertEqual(len(server.connections()), 7)

    def test_headers_are_kept(self):
        with Listener() as server:
            conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=5)
            conn.request("GET", "/", headers={"X-Secret": "in-a-header"})
            conn.getresponse().read()
            server.settle()
            self.assertIn(b"X-Secret: in-a-header", server.connections()[0].raw)

    def test_chunked_request_is_read_to_the_end(self):
        with Listener() as server:
            conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=5)
            conn.request(
                "POST", "/", body=iter([b"first-", b"second-", b"third"]), encode_chunked=True,
                headers={"Transfer-Encoding": "chunked"},
            )
            self.assertEqual(conn.getresponse().status, 200)
            server.settle()
            raw = server.connections()[0].raw
            self.assertTrue(raw.endswith(b"0\r\n\r\n"))

    def test_raw_tcp_bytes_are_recorded(self):
        with Listener() as server:
            with connect(server) as sock:
                sock.sendall(b"\x16\x03\x01 not http at all")
            self.assertTrue(server.settle())
            self.assertIn(b"not http at all", server.connections()[0].raw)

    def test_a_connection_that_sends_nothing_is_still_counted(self):
        with Listener() as server:
            connect(server).close()
            self.assertTrue(server.settle())
            self.assertEqual([c.raw for c in server.connections()], [b""])

    def test_expect_100_continue_is_honoured(self):
        with Listener() as server, connect(server) as sock:
            sock.sendall(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n")
            self.assertIn(b"100 Continue", sock.recv(100))
            sock.sendall(b"body")
            self.assertIn(b"200 OK", sock.recv(1000))
            server.settle()
            self.assertTrue(server.connections()[0].raw.endswith(b"body"))

    def test_an_oversized_request_is_cut_off_and_flagged(self):
        with Listener() as server:
            with connect(server) as sock:
                sock.sendall(b"POST / HTTP/1.1\r\nContent-Length: %d\r\n\r\n" % (MAX_BYTES * 3))
                try:
                    sock.sendall(b"x" * (MAX_BYTES * 2))
                except OSError:
                    pass  # the listener may close first, which is fine
            self.assertTrue(server.settle())
            (only,) = server.connections()
            self.assertTrue(only.truncated)
            self.assertLessEqual(len(only.raw), MAX_BYTES)

    def test_a_stalled_client_is_answered_after_the_idle_timeout(self):
        with mock.patch.object(listener_module, "IDLE_SECONDS", 0.2):
            with Listener() as server, connect(server) as sock:
                sock.sendall(b"POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\npartial")
                self.assertIn(b"200 OK", sock.recv(1000))
                server.settle()
                self.assertTrue(server.connections()[0].raw.endswith(b"partial"))

    def test_settle_waits_for_every_earlier_connection(self):
        with Listener() as server:
            def talk(index: int) -> None:
                with connect(server) as sock:
                    sock.sendall(f"POST /{index} HTTP/1.1\r\nContent-Length: 1\r\n\r\nx".encode())
                    sock.recv(1000)

            threads = [threading.Thread(target=talk, args=(i,)) for i in range(25)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertTrue(server.settle())
            self.assertEqual(len(server.connections()), 25)

    def test_the_settle_probe_is_not_reported_as_a_connection(self):
        with Listener() as server:
            self.assertTrue(server.settle())
            self.assertEqual(server.connections(), [])

    def test_the_attacker_cannot_hide_traffic_by_imitating_the_probe(self):
        with Listener() as server:
            with connect(server) as sock:
                sock.sendall(SENTINEL_PREFIX + b"a-guess")
            self.assertTrue(server.settle())
            self.assertEqual(len(server.connections()), 1)

    def test_a_handler_error_is_recorded_not_swallowed(self):
        with mock.patch.object(Listener, "_serve", side_effect=RuntimeError("boom")):
            with Listener() as server:
                connect(server).close()
                # A broken handler cannot confirm the probe, so settle() must say it is not sure.
                self.assertFalse(server.settle(timeout=1.0))
                self.assertTrue(any("boom" in error for error in server.errors))

    def test_the_port_is_released_after_stopping(self):
        with Listener() as server:
            port = server.port
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", port), timeout=1)

    def test_message_completeness_rules(self):
        self.assertFalse(http_message_complete(b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nabc"))
        self.assertTrue(http_message_complete(b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nabcde"))
        self.assertTrue(http_message_complete(b"GET / HTTP/1.1\r\n\r\n"))
        self.assertFalse(http_message_complete(b"GET / HTTP/1.1\r\nHost"))
        chunked = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
        self.assertFalse(http_message_complete(chunked + b"3\r\nabc\r\n"))
        self.assertTrue(http_message_complete(chunked + b"3\r\nabc\r\n0\r\n\r\n"))
        self.assertTrue(http_message_complete(chunked + b"zz\r\nbad"))  # malformed: stop waiting


if __name__ == "__main__":
    unittest.main()
