"""Command line entry point: `honeyrepo` or `python -m honeyrepo`."""

from __future__ import annotations

import argparse
import json
import shlex
import sys
from typing import Sequence

from honeyrepo import __version__
from honeyrepo.runner import Result, run_scripted
from honeyrepo.scenario import ScenarioError, list_builtin, load

# Exit codes: handy in CI. 0 = the sandbox held, 1 = it leaked, 2 = bad input, 3 = could not tell.
EXIT_CODES = {"HELD": 0, "LEAKED": 1, "INCONCLUSIVE": 3}
EXIT_ERROR = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="honeyrepo",
        description="Test whether your coding agent's sandbox really holds.",
    )
    parser.add_argument("--version", action="version", version=f"honeyrepo {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list the built-in scenarios")

    run = sub.add_parser("run", help="run a scenario in scripted mode (fixed attacker, no model)")
    run.add_argument("scenario", help="name of a built-in scenario, or path to a .toml file")
    run.add_argument(
        "--wrap",
        help=(
            "command prefix that runs the attack inside your sandbox. "
            "{python} is this Python; {repo} and {home} are the temporary bait repo and "
            "home folder, so your sandbox can mount them"
        ),
    )
    run.add_argument("--json", action="store_true", dest="as_json", help="print the result as JSON")
    run.add_argument("--timeout", type=float, default=30.0, help="seconds before the attack is stopped")
    return parser


def split_command(text: str) -> list[str]:
    tokens = shlex.split(text, posix=sys.platform != "win32")
    if sys.platform == "win32":  # non-POSIX splitting keeps the quotes
        tokens = [t[1:-1] if len(t) > 1 and t[0] == t[-1] and t[0] in "\"'" else t for t in tokens]
    return tokens


def format_text(result: Result) -> str:
    return "\n".join(
        [
            f"scenario: {result.scenario_id}",
            "mode:     scripted (fixed attacker, no model)",
            f"result:   {result.verdict} - {result.reason}",
        ]
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "list":
        for name in list_builtin():
            print(name)
        return 0

    try:
        scenario = load(args.scenario)
    except (ScenarioError, OSError) as err:
        print(f"honeyrepo: {err}", file=sys.stderr)
        return EXIT_ERROR

    wrap = split_command(args.wrap) if args.wrap else None
    result = run_scripted(scenario, wrap=wrap, timeout=args.timeout)
    print(json.dumps(result.to_dict(), indent=2) if args.as_json else format_text(result))
    return EXIT_CODES[result.verdict]
