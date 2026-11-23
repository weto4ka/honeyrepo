# Security policy

honeyrepo is a security testing tool, so its worst bug is a wrong answer: reporting **HELD** when a sandbox did not actually stop the attack. That gives false confidence, and it is treated as a security bug.

## What to report

Please report privately if you find any of these:

- **A false HELD.** A setup where the canary can leave (or the attack is not really stopped) and honeyrepo still exits 0. A reproduction is the most useful thing you can send: the `--wrap` command, the scenario, `--json` output and your OS and Python version.
- **A false LEAKED** that is not explained by the limits in the [threat model](docs/threat-model.md).
- Anything that makes honeyrepo expose data: your real environment variables reaching the attack process, the listener binding to a non-loopback address, files written or read outside the temporary folders, a scenario path escaping its folder.
- Temporary folders or processes left behind after a run.
- Code execution through a built-in scenario or through anything other than a wrapper or scenario file you chose to run.

## What is not a vulnerability

- A wrapper or scenario command doing something harmful. Both run with your privileges by design, and the docs say so. Read what you run.
- A weakness in a sandbox tool you test with honeyrepo. Report that to the tool.
- A limit that is already documented: detection of encrypted or custom-encoded data, loopback-only listener, one attack path. These are listed in [docs/threat-model.md](docs/threat-model.md). Suggestions for closing them are welcome as ordinary issues.

## How to report

Use GitHub's private reporting: on the repository page, open the **Security and quality** tab (formerly **Security**) and click **Report a vulnerability**. Please do not open a public issue for a false-HELD or data-exposure bug until it has been looked at.

This is a one-person project. Expect a reply when the maintainer can give one, not on a fixed schedule. Confirmed bugs are fixed in the next release and listed in the [changelog](CHANGELOG.md), with credit if you want it.

## Supported versions

Only the latest release is supported. honeyrepo is alpha software: until 1.0, verdict rules may get stricter between releases, and a stricter rule is not a breaking change when it removes a false HELD.
