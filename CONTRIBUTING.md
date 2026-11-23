# Contributing

Thanks for looking. The project is small and the rules are short.

## Set up

```bash
git clone https://github.com/weto4ka/honeyrepo
cd honeyrepo
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
python -m unittest discover -s tests
```

Python 3.11 or newer. There are no runtime dependencies and no test dependencies: the standard library only. Please keep it that way. A dependency is something every user has to trust, and `attacker.py` has to run inside a sandbox where nothing else is importable.

The suite takes about 25 seconds, because several tests start real processes (a hanging attack, a background process, a flood of output). Run a single file with `python -m unittest discover -s tests -p "test_runner.py"`.

`bash scripts/sandbox-check.sh` runs the real-sandbox rows (Linux or WSL2). Rows whose tool is missing are skipped.

## The one rule that matters

**HELD must never be reported without positive evidence.** If your change can turn "we do not know" into HELD, it will not be merged. When you change how a verdict is reached:

1. Write a test that reproduces the wrong result first, and see it fail.
2. Fix it.
3. Add the reason code to `REASON_CODES` in `runner.py` and describe it in [docs/verdicts.md](docs/verdicts.md). A test fails if a code is undocumented.
4. Update the threat model if a limit moved.

## Other conventions

- Tests that start processes use real subprocesses, not mocks, wherever the thing being tested is a verdict. Mocks are for failures that are hard to cause (a listener that cannot start, a failing `rmtree`).
- A test that needs a platform feature skips with a reason. It does not silently pass.
- Never put a real credential in a scenario, a test or an issue. Canaries are fake and generated per run.
- Do not claim in a doc, a commit message or a pull request that something was tested unless it was. Say which Python version and which OS.
- Keep it lightweight. Prefer a few clear lines to a framework.

## Pull requests

Describe what was wrong, how you reproduced it, and which tests cover it. Say what you ran and on which platform. CI runs the suite; it does not run real sandbox tools, so say if you ran `sandbox-check.sh`.

By contributing you agree that your contribution is licensed under the MIT licence of this project.

## Security issues

Do not open a public issue for a false HELD or a data-exposure bug. See [SECURITY.md](SECURITY.md).
