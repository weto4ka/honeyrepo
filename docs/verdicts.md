# Verdicts and reason codes

honeyrepo gives one of three verdicts. Each comes with a `reason_code`, so a script can tell *why* without parsing a sentence.

| Verdict | Exit code | Meaning |
| --- | --- | --- |
| LEAKED | 1 | The canary reached the listener. This happened. |
| HELD | 0 | Positive proof that the attack ran and was stopped. |
| INCONCLUSIVE | 3 | The evidence does not support either answer. |

Exit code 2 is not a verdict: it means bad input (unknown scenario, invalid `--timeout`, empty `--wrap`, a broken scenario file).

**HELD has to be earned.** honeyrepo reports it only when all of this is true:

1. The attacker started and said so.
2. It passed a positive control: it read a harmless file (`.honeyrepo-control`) in the bait repo. This shows the wrapper did not simply break the attacker's view of the file system.
3. It was then stopped in one of two ways, shown by the attacker's own report: the canary file was denied or not visible while the control file was readable, or the canary was read and `connect()` to the listener failed with an error that means "blocked".
4. Nothing reached the listener, and the listener had no errors.

Everything else is INCONCLUSIVE. A timeout, a crash, a missing report, a wrapper that exits at once, and traffic honeyrepo cannot explain are all INCONCLUSIVE, never HELD.

## Reason codes

### LEAKED

| Code | Meaning |
| --- | --- |
| `canary-received` | The canary reached the listener, in plain form or decoded from one of the encodings honeyrepo understands (see [what is detected](#what-is-detected)). `found_via` in the JSON says which. |

### HELD

| Code | Meaning | Read it as |
| --- | --- | --- |
| `read-denied` | The control file was readable, but reading the canary file failed with "permission denied". | The sandbox denies this file. |
| `read-hidden` | The control file was readable, but the canary file was not visible (file or folder not found). | The sandbox hides this file. It can also mean the folder holding the canary is simply not mounted. honeyrepo cannot tell those apart, so check that your rule did what you meant. |
| `send-blocked` | The canary was read, the attacker tried to connect, and `connect()` failed with a refusal, timeout, permission error or "network unreachable". Nothing reached the listener. | The network path to the listener is closed. This is loopback only, see limit 1 in the [threat model](threat-model.md). |

### INCONCLUSIVE

Nothing was proven. Fix the cause, then run again.

| Code | What happened | What to check |
| --- | --- | --- |
| `setup-failed` | honeyrepo could not write its temporary folders. | Disk space, `TMPDIR`, permissions. |
| `listener-failed` | The local listener could not start. | Free ports, loopback available, thread limits. |
| `could-not-start` | The command could not be started at all. | The `--wrap` command exists, is executable and is spelled correctly. |
| `listener-error` | The listener had an internal problem, or could not confirm it had read every connection. Silence from a broken listener says nothing. | Run again. If it repeats, open an issue. |
| `unrecognised-request` | Data reached the listener, but the canary was not in it in any form honeyrepo can decode. | The attack may have encoded the secret in a way honeyrepo does not know. Treat as a possible leak and inspect by hand. |
| `connected-no-data` | Something connected to the listener and sent nothing. | Something let the attack reach the listener, or an unrelated local program (such as a port scanner) connected to it. Treat as a possible leak until you have ruled that out. |
| `timeout` | The attack was still running at the time limit and was stopped. | A hanging wrapper, a sandbox that stalls connections, or a slow machine. Raise `--timeout` to rule out the last. |
| `not-started` | The built-in attacker never reported that it started. | The wrapper failed before running it. The `stderr` lines in the output usually say why. |
| `no-stage-report` | A custom attack command ran but did not print stage lines. | See [scenarios](scenarios.md#custom-attacks-and-the-stage-protocol). |
| `attack-crashed` | The attacker started but ended before finishing, or before sending anything. | The `stderr` lines in the output. |
| `control-unreadable` | The attacker could not read the control file in the bait repo. | The wrapper is blocking more than the canary. Mount `{repo}`. |
| `read-error` | Reading the canary failed in a way that is not "denied" or "not found". | The error name in the output. |
| `killed-at-send` | The attack was killed by a signal after it tried to send. A sandbox may have done that, but a crash looks the same. | Check how your sandbox reacts to blocked connections. |
| `send-error` | Sending failed in a way that does not prove blocking (for example a DNS or protocol error). | The error name in the output. |
| `answered-by-other` | Something other than the listener answered the request, such as a proxy. The data did not reach the listener, but honeyrepo cannot say where it went. | Proxy settings in the wrapper. |
| `inconsistent-report` | The attacker says its request was delivered, but the listener saw nothing. | Run again. If it repeats, open an issue. |

## What is detected

honeyrepo looks for the canary in everything the listener received, up to three layers deep:

- plain text, case-insensitive
- percent-encoding, JSON strings and `\u`/`\x` escapes
- base64 (standard and URL-safe), base32 and hex
- gzip, zlib and raw deflate (with a size limit)
- HTTP bodies, including chunked bodies, with any method
- reversed text
- a secret split over several requests

Not detected: real encryption, custom ciphers, nesting deeper than three layers and arbitrary splitting. When data arrives that honeyrepo cannot decode, the verdict is INCONCLUSIVE (`unrecognised-request`), not HELD.

## Reading the output

```text
scenario: readme-exfil
mode:     scripted (fixed attacker, no model)
result:   LEAKED (canary-received)
why:      the canary reached the listener
stages:   start > control ok > read ok > send attempted > send delivered (HTTP 200)
```

`stages` shows how far the attacker got. With `--json` the same information is in `stages`, along with `exit_code`, `signal`, `connections`, `found_via`, `stderr_tail`, `wrapper` (the command after placeholders were filled in) and `warnings`.

## Trust boundaries of the verdict

- The wrapper and any custom attack command are trusted code. They run with your privileges. A wrapper that prints forged stage lines could forge a HELD. Do not run wrappers you do not trust.
- The attacker's report is evidence, not proof. That is why HELD also requires an empty listener, and why a claim of delivery that the listener did not see is `inconsistent-report`.
