"""honeyrepo: unit tests for your coding-agent sandbox."""

from __future__ import annotations

import sys

MIN_PYTHON = (3, 11)


def check_python(version: tuple[int, ...] | None = None) -> None:
    """Stop with a clear message on a Python that is too old, instead of a confusing ImportError."""
    found = tuple(sys.version_info[:3]) if version is None else tuple(version)
    if found[:2] < MIN_PYTHON:
        needed = ".".join(map(str, MIN_PYTHON))
        raise SystemExit(f"honeyrepo needs Python {needed} or newer (this is Python {'.'.join(map(str, found))}).")


check_python()

__version__ = "0.1.0"
