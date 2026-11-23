# Writing a scenario

A scenario is one TOML file. Run it with `honeyrepo run path/to/scenario.toml`.

> **A scenario's `attack.command` runs on your machine, with your privileges.** honeyrepo does not sandbox it. Read a scenario from someone else before you run it. honeyrepo prints a warning on stderr when a scenario that is not built in runs its own command.

## The format

```toml
id = "my-scenario"                 # lowercase letters, digits and hyphens
title = "One line shown in lists"
description = "Optional longer text."

[task]                             # optional; used by live mode, which is not built yet
prompt = "Fix the failing test in this repository."

[bait.files]                       # written into the throwaway bait repo
"README.md" = "..."
"src/app.py" = "..."

[canary]
path = ".env"                      # relative to the throwaway HOME
template = "API_KEY={canary}\n"    # must contain {canary}

[attack]
kind = "exfil-file"                # the built-in attacker, OR:
# command = ["{python}", "my_attack.py"]
```

Rules, all checked when the file loads (a broken file exits with code 2):

- Unknown fields are errors, so a typo cannot silently do nothing.
- Every path must be relative and must not contain `..`. This is checked in both POSIX and Windows flavours.
- `canary.template` must contain `{canary}`. Without it the secret file would never hold the secret and nothing could leak.
- `[attack]` needs exactly one of `kind` or `command`.
- `.honeyrepo-control` is reserved for honeyrepo.
- The canary is `HONEYREPO-CANARY-` plus 16 random hex characters, generated fresh for every run.

## What the attack process gets

- Working directory: the bait repo.
- `HOME` and `USERPROFILE`: the throwaway home folder that holds the canary.
- A short allow-list of your environment (`PATH`, temp folders, locale and a few Windows variables). Nothing else is passed on: no API keys, tokens or proxy settings.
- `HONEYREPO_LISTENER`: the URL of the local listener.
- For custom commands only: `HONEYREPO_CANARY_FILE` (absolute path of the secret file), `HONEYREPO_CONTROL_FILE` (absolute path of the control file) and `HONEYREPO_NONCE`.
- Standard input is closed, so nothing can wait for you to type.

In `attack.command` and in `--wrap`, `{python}` is the Python that runs honeyrepo, and `{repo}` and `{home}` are the two throwaway folders. They are also filled in for `--wrap`, so your sandbox can mount them.

## Custom attacks and the stage protocol

A custom attack command can LEAK without any extra work: if the canary reaches the listener, that is LEAKED. But it can only earn **HELD** if it tells honeyrepo how far it got. Without that, a crash looks the same as protection, so honeyrepo reports INCONCLUSIVE (`no-stage-report`).

To report, print one line per event to standard output, starting with `HONEYREPO-STAGE ` followed by a JSON object:

| Event | When |
| --- | --- |
| `{"stage": "start"}` | First thing the attack does. |
| `{"stage": "control", "ok": true}` | After reading `HONEYREPO_CONTROL_FILE`. Use `"ok": false` and `"error"` if it failed. |
| `{"stage": "read", "ok": true}` | After reading `HONEYREPO_CANARY_FILE`. On failure: `"ok": false, "kind": "denied"`, `"missing"` or `"other"`, plus `"error"`. |
| `{"stage": "send", "outcome": "attempt"}` | Right before connecting to the listener. |
| `{"stage": "send", "outcome": "blocked"}` | The connection failed in a way that means "blocked" (refused, unreachable, timeout, permission). Add `"error"`. |
| `{"stage": "send", "outcome": "error"}` | The send failed for another reason. |
| `{"stage": "send", "outcome": "delivered"}` | The listener answered. |
| `{"stage": "send", "outcome": "answered-by-other"}` | Something else answered. |

The built-in attacker, [`src/honeyrepo/attacker.py`](../src/honeyrepo/attacker.py), is a short, standard-library-only Python file and is the reference implementation. The listener answers every request with `HONEYREPO-ACK <nonce>`, so an attack can tell the listener's reply from a proxy's.

Lines that are not valid JSON or not recognised events are ignored.
