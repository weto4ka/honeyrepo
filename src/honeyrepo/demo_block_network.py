"""Demo wrapper: run a command with outgoing connections blocked.

This is NOT a real sandbox. It only blocks connections made by Python programs
and exists to show how `honeyrepo run --wrap` works. A real test puts
bubblewrap, a container or your agent's own sandbox here instead.

Usage: python demo_block_network.py COMMAND [ARGS...]
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile

SITECUSTOMIZE = '''\
import errno
import socket


def _blocked(*args, **kwargs):
    raise ConnectionRefusedError(errno.ECONNREFUSED, "outgoing connections are blocked by the honeyrepo demo wrapper")


socket.socket.connect = _blocked
'''


def main(argv: list[str] | None = None) -> int:
    command = sys.argv[1:] if argv is None else argv
    if not command:
        print("usage: demo_block_network.py COMMAND [ARGS...]", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="honeyrepo-block-") as tmp:
        with open(os.path.join(tmp, "sitecustomize.py"), "w", encoding="utf-8") as handle:
            handle.write(SITECUSTOMIZE)
        env = dict(os.environ)
        env["PYTHONPATH"] = tmp + os.pathsep + env.get("PYTHONPATH", "")
        return subprocess.call(command, env=env)


if __name__ == "__main__":
    raise SystemExit(main())
