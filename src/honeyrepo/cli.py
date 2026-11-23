"""Command line entry point: `honeyrepo` or `python -m honeyrepo`."""

from __future__ import annotations

import argparse
import json
import math
import shlex
import sys
from typing import Sequence

from honeyrepo import __version__
from honeyrepo.runner import Result, run_scripted
from honeyrepo.scenario import ScenarioError, list_builtin, load

# Exit codes, for CI. 0 = HELD, 1 = LEAKED, 2 = bad input, 3 = INCONCLUSIVE.
# Treat 3 as a failure unless you have read the reason and accept it: HELD is the only "pass".
EXIT_CODES = {"HELD": 0, "LEAKED": 1, "INCONCLUSIVE": 3}
EXIT_ERROR = 2


def positive_seconds(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{text!r} is not a number") from None
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError("must be a positive number of seconds")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="honeyrepo",
        description=(
            "Unit tests for your coding-agent sandbox. honeyrepo tests the sandbox around an agent, "
            "not the model: a fixed attacker tries to read a fake secret and send it to a local listener."
        ),
    )
    parser.add_argument("--version", action="version", version=f"honeyrepo {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="list the built-in scenarios")

    run = sub.add_parser(
        "run",
        help="run a scenario (fixed attacker, no model)",
        description=(
            "Exit codes: 0 HELD (the attack ran and was demonstrably stopped), 1 LEAKED, "
            "2 bad input, 3 INCONCLUSIVE (not enough evidence; read the reason)."
        ),
    )
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
    run.add_argument(
        "--timeout", type=positive_seconds, default=30.0, help="seconds before the attack is stopped (default 30)"
    )
    return parser


def split_command(text: str) -> list[str]:
    tokens = shlex.split(text, posix=sys.platform != "win32")
    if sys.platform == "win32":  # non-POSIX splitting keeps the quotes
        tokens = [t[1:-1] if len(t) > 1 and t[0] == t[-1] and t[0] in "\"'" else t for t in tokens]
    return tokens


def format_text(result: Result) -> str:
    lines = [
        f"scenario: {result.scenario_id}",
        "mode:     scripted (fixed attacker, no model)",
        f"result:   {result.verdict} ({result.reason_code})",
        f"why:      {result.reason}",
    ]
    if result.stages:
        lines.append(f"stages:   {' > '.join(result.stages)}")
    if result.stderr_tail:
        lines.append("stderr:")
        lines.extend(f"          {line}" for line in result.stderr_tail.splitlines())
    lines.extend(f"warning:  {warning}" for warning in result.warnings)
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "list":
        for name in list_builtin():
            print(name)
        return 0

    try:
        scenario = load(args.scenario)
    except (ScenarioError, OSError, UnicodeDecodeError) as err:
        print(f"honeyrepo: {err}", file=sys.stderr)
        return EXIT_ERROR

    wrap = None
    if args.wrap is not None:
        try:
            wrap = split_command(args.wrap)
        except ValueError as err:
            print(f"honeyrepo: cannot read --wrap ({err})", file=sys.stderr)
            return EXIT_ERROR
        if not wrap:
            print("honeyrepo: --wrap is empty, so nothing would be tested. Leave it out to run unprotected.", file=sys.stderr)
            return EXIT_ERROR

    if scenario.attack_command and not scenario.builtin:
        print(
            f"honeyrepo: warning: {args.scenario} runs its own attack command on this machine, "
            "with your privileges and outside any sandbox you did not wrap around it. Read it before you trust it.",
            file=sys.stderr,
        )

    result = run_scripted(scenario, wrap=wrap, timeout=args.timeout)
    print(json.dumps({"honeyrepo": __version__, **result.to_dict()}, indent=2) if args.as_json else format_text(result))
    return EXIT_CODES[result.verdict]
