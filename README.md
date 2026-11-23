# honeyrepo

**Does your coding agent leak your keys when a README tells it to?**

honeyrepo builds a throwaway "bait" repository with a fake secret, lets an attacker try to steal it, and tells you whether your sandbox held or leaked. All secrets are fake canaries, and the only server involved listens on `127.0.0.1`.

> **Status: early alpha (0.0.1).** Scripted mode works. Live mode with real agents (Claude Code, Codex) is next. Not on PyPI yet.

## Try it

Needs Python 3.11 or newer. No dependencies.

```bash
git clone https://github.com/weto4ka/honeyrepo
cd honeyrepo
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

Now run the same attack through a wrapper that blocks outgoing connections. It is a demo, not a real sandbox:

```bash
honeyrepo run readme-exfil --wrap "{python} -m honeyrepo.demo_block_network"
```

```text
scenario: readme-exfil
mode:     scripted (fixed attacker, no model)
result:   HELD - the attack ran, but the canary never reached the listener
```

## Test your own sandbox

`--wrap` puts a command in front of the attack, so the attack runs inside whatever sandbox you want to test: bubblewrap, sandbox-exec, Docker, or your agent's built-in sandbox. `{python}` stands for the Python that runs honeyrepo.

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
- [ ] Live mode: give Claude Code and Codex a harmless task and see whether they follow the bait
- [ ] More scenarios and a sandbox on/off matrix
- [ ] Markdown and JUnit reports, GitHub Action
- [ ] Scoreboard of results by agent and sandbox configuration

See [docs/threat-model.md](docs/threat-model.md) for what this project does and does not test.

## Not affiliated

honeyrepo is an independent project. It is not affiliated with or endorsed by Anthropic, OpenAI, Google or any other agent vendor mentioned here.

## Licence

MIT
