# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/). Versions: [Semantic Versioning](https://semver.org/), with the usual caveat that anything before 1.0 may change.

## 0.1.0 - unreleased

A rewrite of how verdicts are reached, after a review of how 0.0.1 could mislead. 0.0.1 was never publicly released, so nothing here keeps backward compatibility with it.

### Changed

- **HELD now needs positive evidence.** In 0.0.1, "the canary did not arrive" was enough. Now the attacker must have started, passed a positive control (read a harmless file in the bait repo) and then been denied the canary file or failed to connect with a "blocked" error, and nothing may have reached the listener. See [docs/verdicts.md](docs/verdicts.md).
- **INCONCLUSIVE (exit code 3) now covers everything that is not proven.** Timeouts used to count as HELD. Crashes, killed processes, missing reports, broken wrappers, listener problems and unexplained traffic now give INCONCLUSIVE with a reason code.
- Results include `reason_code` (the `hits` field is gone), `stages`, `exit_code`, `signal`, `connections`, `found_via`, `stderr_tail`, `wrapper` and `warnings`. `--json` output includes the honeyrepo version. The text output shows the stages and, when the result is not HELD, the last lines of stderr.
- The attack process gets absolute paths to the canary and control files, so changing or unsetting `HOME` cannot send it to a real file.
- The temporary folders are resolved paths, so sandbox rules written with `{repo}` and `{home}` see the real path rather than a symlink.
- Scenario files are validated strictly: unknown fields, absolute or `..` paths (POSIX and Windows flavours), a template without `{canary}` and a missing or doubled `[attack]` are errors.
- `--timeout` must be a positive, finite number. An empty `--wrap` or one with unbalanced quotes exits with code 2 instead of running unprotected.
- Python older than 3.11 gets a clear message instead of a traceback.

### Added

- Detection of the canary in encoded forms: percent-encoding, JSON and `\u`/`\x` escapes, base64 (standard and URL-safe), base32, hex, gzip, zlib, raw deflate, chunked bodies, reversed text, and a secret split over several requests, up to three layers deep.
- A raw TCP listener that records every connection (any HTTP method, chunked bodies, `Expect: 100-continue`, non-HTTP bytes, a 1 MiB cap per connection) and confirms it has read everything before the verdict.
- A stage protocol (`HONEYREPO-STAGE` lines) so attacks report how far they got, and a documented way for custom attack commands to earn HELD ([docs/scenarios.md](docs/scenarios.md)).
- A warning on stderr when a scenario that is not built in runs its own command.
- A warning in every result on platforms other than Linux, because 0.1.0 has only been verified on Linux and WSL2.
- `docs/verdicts.md`, `docs/scenarios.md`, `SECURITY.md`, `CONTRIBUTING.md` and this file.
- `scripts/sandbox-check.sh` reports a reason code per row, and has three "not a sandbox" rows that must not give HELD.
- A test suite of more than 140 tests. The ones that decide a verdict run real subprocesses, including every false-verdict case found in the review.

### Fixed

Each of these gave a wrong verdict, or a wrong run, in 0.0.1 and now has a regression test.

- HELD when the wrapper changed or unset `HOME`, because the attacker read `~/.env`, found nothing and stopped.
- HELD when the attack crashed or was killed after printing its start marker. The marker only proved that Python started.
- HELD on timeout.
- HELD when the canary was sent in a way the old listener did not record or search: methods other than GET, POST and PUT, chunked bodies, headers and cookies, binary or compressed bodies (they were decoded as text), and any encoding of the secret.
- A request still being handled when the attack exited could be missed. The listener now confirms it has read every connection before the verdict.
- Processes started by the attack could outlive the run, and a background process that kept the output open held the run until the timeout. The attack now runs in its own process group (POSIX), which is stopped when the run ends.
- All of the attack's output was held in memory, so a flood of output could exhaust it. Output is now read with a bound.

### Known limits

See [docs/threat-model.md](docs/threat-model.md). The main ones: the listener is loopback only, detection is not exhaustive, and only one attack path is tested.
