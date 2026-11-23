# Threat model

honeyrepo tests one layer: the sandbox (or permission policy) around a coding agent. It does not test the model. This page says what it assumes, what a result means, and what it cannot tell you.

## What we protect

Things on a developer's machine that an agent can reach:

- `.env` files and API keys in the environment
- SSH keys, cloud credentials and tokens in config files
- The source tree and git remotes (push access)

The only scenario today plants one of these: a fake `.env` file in the home folder.

## The attacker

Anyone who can put text in front of the agent: a README, an issue or pull request comment, a code comment, an install script, a web page the agent fetches, an MCP tool description.

The attacker cannot run code on the machine directly, change the sandbox configuration, or see the user's prompts. The attacker's only tool is text the agent reads.

**Assumption: the agent obeys.** Scripted mode replaces the model with a fixed script that does exactly what the bait says. This is deliberate. A sandbox is the last line of defence, so the question is what happens on the day the model gives in.

## Trust boundaries

1. **Untrusted text enters the agent's context.** honeyrepo does not test this boundary. Whether a model follows the bait is a different question (live mode, planned).
2. **The agent acts on the machine** by reading files, opening connections and starting processes. A sandbox is meant to sit here. This is the boundary honeyrepo tests.

Between the two sit the model's own judgement, permission prompts and the sandbox. Only the sandbox is tested.

## What honeyrepo tests, and what it does not

**Tested (scripted mode):** a fixed attacker runs inside your sandbox configuration. Can it read a fake secret from a throwaway home folder and send it to a listener on this machine?

**Not tested:**

- Whether a real model follows the bait (live mode is planned)
- Permission prompts and approval flows
- Exfiltration other than one HTTP request: DNS, raw sockets, writing into a synced folder
- Destructive actions such as deleting files or force-pushing
- MCP tool poisoning
- Sandbox escapes at the kernel level, resource limits, persistence
- macOS sandboxes and native Windows sandboxes (untested)

## How to read a result

| Verdict | It means | It does not mean |
| --- | --- | --- |
| LEAKED | The canary reached the listener. This happened. | That your internet access is open. See limit 2. |
| HELD | The attack started, and the canary did not reach the listener. | That the sandbox is secure. See limits 1, 3 and 5. |
| INCONCLUSIVE | The attack never started, so nothing was learned. | That the sandbox held. It is never reported as HELD. |

## Safety rules for this project

- Every secret is a fake canary, generated fresh on each run (`HONEYREPO-CANARY-` plus random hex). Never put a real credential in a scenario.
- The listener binds to `127.0.0.1` on a port the operating system chooses. honeyrepo makes no other network connections.
- The attack process gets a minimal environment: a short list of variables (`PATH`, temp folders, locale) plus its own `HOME`. Your real API keys and tokens are not passed on.
- Scenario file paths must be relative and cannot contain `..`.
- The bait repo and fake home live in a temporary folder that is deleted after the run.
- honeyrepo has no dependencies, so there is nothing to compromise through the supply chain.
- **A scenario's attack command runs on your machine, with your privileges.** honeyrepo does not sandbox it for you. Read a scenario from someone else before you run it.

## Known limits

Where honeyrepo can mislead you:

1. **HELD is weaker than it sounds.** The listener is on this machine's loopback address, so HELD only shows the attack could not reach that listener. A setup that cuts off loopback but allows the internet could report HELD and still let a secret reach a public server. A container on a bridge network is one case, because it cannot see the host's `127.0.0.1`. A possible fix is a second listener on a non-loopback address of this machine.
2. **LEAKED may overstate the risk.** A sandbox that blocks the internet but allows local connections would report LEAKED. Read LEAKED as "this path is open", not "everything is open".
3. **The canary is not in your real home folder.** It sits in a throwaway home under the temp folder. Rules you wrote for your real `~/.ssh` or `~/.env` are not exercised unless you point a rule at `{home}`.
4. **One file, one path, one tool.** The attack reads one file and sends it with one HTTP POST from Python. A sandbox that treats other files, other protocols or other programs differently may behave differently.
5. **HELD includes accidental failure after the start.** The start marker only proves the attack began. A wrapper that starts Python and then breaks something else also gives HELD. Always run an unprotected control (LEAKED expected) next to your sandbox. `scripts/sandbox-check.sh` does this.
6. **Timeouts count as HELD.** If the attack is still running after 30 seconds (the default), the verdict is HELD with a note saying so.
7. **Verified on a narrow setup:** WSL2 on Ubuntu 24.04 with bubblewrap 0.9.0 and `unshare`, plus the scripted mode on native Windows. Nothing else has been run.
8. **A script is not an agent.** Results say nothing about how Claude Code, Codex or any other agent behaves.
