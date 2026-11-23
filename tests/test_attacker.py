import errno
import http.client
import unittest

from honeyrepo import attacker


class ClassificationTests(unittest.TestCase):
    def test_connection_failures_that_mean_blocked(self):
        blocked = [
            ConnectionRefusedError(),
            TimeoutError(),
            PermissionError(),
            OSError(errno.ENETUNREACH, "unreachable"),
            OSError(errno.EHOSTUNREACH, "no route"),
            OSError(errno.ENETDOWN, "down"),
            OSError(errno.EACCES, "denied"),
            OSError(errno.EPERM, "not permitted"),
            OSError(errno.ETIMEDOUT, "timed out"),
            OSError(10061, "WSAECONNREFUSED"),
            OSError(10051, "WSAENETUNREACH"),
        ]
        for exc in blocked:
            with self.subTest(repr(exc)):
                self.assertTrue(attacker.is_network_block(exc))

    def test_failures_that_do_not_prove_blocking(self):
        not_blocked = [
            OSError(),  # no errno at all, e.g. a patched socket
            OSError(errno.EMFILE, "too many open files"),
            OSError(errno.ENOMEM, "no memory"),
            MemoryError(),
            ValueError("bad"),
            http.client.RemoteDisconnected("closed without a reply"),
        ]
        for exc in not_blocked:
            with self.subTest(repr(exc)):
                self.assertFalse(attacker.is_network_block(exc))

    def test_read_failure_kinds(self):
        self.assertEqual(attacker.read_failure_kind(PermissionError()), "denied")
        self.assertEqual(attacker.read_failure_kind(FileNotFoundError()), "missing")
        self.assertEqual(attacker.read_failure_kind(NotADirectoryError()), "missing")
        self.assertEqual(attacker.read_failure_kind(IsADirectoryError()), "other")
        self.assertEqual(attacker.read_failure_kind(OSError(errno.EIO, "io")), "other")

    def test_describe_names_the_errno(self):
        info = attacker.describe(OSError(errno.ENETUNREACH, "Network is unreachable"))
        self.assertEqual((info["error"], info["errno_name"]), ("OSError", "ENETUNREACH"))
        self.assertIsNone(attacker.describe(ValueError("x"))["errno"])

    def test_listener_url_parsing(self):
        self.assertEqual(attacker.parse_listener("http://127.0.0.1:5000"), ("127.0.0.1", 5000))
        self.assertEqual(attacker.parse_listener("http://127.0.0.1:5000/"), ("127.0.0.1", 5000))


if __name__ == "__main__":
    unittest.main()
