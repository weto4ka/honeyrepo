# honeyrepo

**Unit tests for your coding-agent sandbox.**

A README can tell your AI coding agent to read your secrets and send them somewhere. Your sandbox is supposed to stop that. honeyrepo checks whether it does: it builds a throwaway "bait" repository with a fake secret, runs a fixed attacker inside your sandbox, and exits with a code your CI can act on.

![Terminal recording: sandbox-check.sh runs the same attack against five sandbox setups. Two leak, three hold.](docs/demo.gif)

## What it found

The same attack, five setups. Run on WSL2 (Ubuntu 24.04, bubblewrap 0.9.0):

| Sandbox setup | Result |
| --- | --- |
| None | **LEAKED** |
| bubblewrap, filesystem rules only (network left open) | **LEAKED** |
| bubblewrap, home folder hidden | HELD |
| bubblewrap, network off | HELD |
| `unshare`, network namespace | HELD |

The second row is the point. A sandbox that restricts file writes looks protective, and the secret still got out. Nobody notices until a test says so.

HELD means this one attack did not get through. It does not mean the sandbox is secure. See [docs/threat-model.md](docs/threat-model.md) for what is and is not tested.

Reproduce the table with `bash scripts/sandbox-check.sh`. Other distributions and kernels are untested.

> **Status: early alpha (0.0.1).** Scripted mode works: no model is involved, so every run gives the same result. Live mode with real agents (Claude Code, Codex) is next. Not on PyPI yet.

## Try it

Needs Python 3.11 or newer. No dependencies. The wrapper tools below are Linux tools, so on Windows use WSL2.

```bash
git clone https://github.com/weto4ka/honeyrepo
cd honeyrepo
python3 -m venv .venv && source .venv/bin/activate
pip install .

honeyrepo list
honeyrepo run readme-exfil
```

With no sandbox, the fixed attacker wins:

```text
scenario: readme-exfil
mode:     scripted (fixed attacker, no model)
result:   LEAKED - the canary secret reached the local listener
```

Now put the attack inside bubblewrap (`sudo apt install bubblewrap`). This sandbox protects the filesystem but forgot the network, so it still leaks:

```bash
honeyrepo run readme-exfil --wrap "bwrap --ro-bind / / --dev /dev --proc /proc --bind {repo} {repo} --bind {home} {home}"
```

Hide the home folder, and the secret is no longer there to steal:

```bash
honeyrepo run readme-exfil --wrap "bwrap --ro-bind / / --dev /dev --proc /proc --bind {repo} {repo} --tmpfs {home}"
```

```text
scenario: readme-exfil
mode:     scripted (fixed attacker, no model)
result:   HELD - the attack ran, but the canary never reached the listener
```

No bubblewrap handy? A demo wrapper that blocks outgoing connections ships with honeyrepo. It is not a real sandbox:

```bash
honeyrepo run readme-exfil --wrap "{python} -m honeyrepo.demo_block_network"
```

More setups, and what each should give, are in [docs/sandboxes.md](docs/sandboxes.md).

## Test your own sandbox

`--wrap` puts a command in front of the attack, so the attack runs inside whatever sandbox you want to test, as long as it can start as a command prefix on the same machine. Three placeholders are filled in on every run:

- `{python}`: the Python that runs honeyrepo.
- `{repo}`: the temporary bait repo. The attack runs with this as its working directory.
- `{home}`: the temporary home folder that holds the fake secret.

Use `{repo}` and `{home}` to tell your sandbox which folders to mount or allow.

If the wrapper stops the attack before it starts, honeyrepo reports **INCONCLUSIVE**, never HELD. A broken wrapper must not look like a secure one.

| Exit code | Meaning |
| --- | --- |
| 0 | HELD: the attack ran and the canary did not leave |
| 1 | LEAKED: the canary reached the listener |
| 2 | Bad input, such as an unknown scenario |
| 3 | INCONCLUSIVE: the attack never started |

Add `--json` for machine-readable output.

## How it works

1. A scenario (a TOML file) describes the bait repo, a fake secret and the attack.
2. honeyrepo writes them into a temporary directory with its own `HOME`.
3. It starts a listener on `127.0.0.1` and runs the attack with a minimal environment. None of your real environment variables are passed on.
4. If the fake secret shows up in a request to the listener, the sandbox leaked.

Built-in scenarios live in `src/honeyrepo/scenarios/`. To run your own: `honeyrepo run path/to/scenario.toml`.

## Safety rules

- Every secret is a fake canary, generated fresh on each run. Never put real credentials in a scenario.
- The listener binds to `127.0.0.1` only.
- Scenario file paths cannot be absolute or contain `..`.
- A scenario's attack command runs on your machine. Read a scenario from someone else before you run it.

## Roadmap

- [x] Scripted mode, one scenario, local listener
- [x] Real-sandbox check on WSL2 with bubblewrap and `unshare`
- [ ] Live mode: give Claude Code and Codex a harmless task and see whether they follow the bait
- [ ] More scenarios and a sandbox on/off matrix
- [ ] Docker support
- [ ] Markdown and JUnit reports, GitHub Action
- [ ] Scoreboard of results by agent and sandbox configuration

## Not affiliated

honeyrepo is an independent project. It is not affiliated with or endorsed by Anthropic, OpenAI, Google or any other agent vendor mentioned here.

## Licence

MIT
