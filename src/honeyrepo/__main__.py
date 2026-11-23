"""Lets you run `python -m honeyrepo` as well as the `honeyrepo` command."""

from honeyrepo.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
