# Threat model

honeyrepo tests one layer: the sandbox (or permission policy) around a coding agent. It does not test the model. This page says what it assumes, what a result means, and what it cannot tell you.

## What we protect

Things on a developer's machine that an agent can reach:

- `.env` files and API keys in the environment
- SSH keys, cloud credentials and tokens in config files
- The source tree and git remotes (push access)

The only scenario today plants one of these: a fake `.env` file in a throwaway home folder.

## The attacker

Anyone who can put text or files in front of the agent: a README, an issue or pull request comment, a code comment, an install script, a web page the agent fetches, an MCP tool description.

The attacker cannot run code on the machine by themselves, change the sandbox configuration, or see the user's prompts. What they control is content the agent reads. That content can include a script, but the script only runs if the agent (or the user) runs it, and then it runs inside whatever the sandbox allows.

**Assumption: the agent obeys.** Scripted mode replaces the model with a fixed script that does exactly what the bait says. This is deliberate. A sandbox is often the last line of defence, so the question is what happens on the day the model gives in.

## Trust boundaries

1. **Untrusted text enters the agent's context.** honeyrepo does not test this boundary. Whether a model follows the bait is a different question (live mode, planned).
2. **The agent acts on the machine** by reading files, opening connections and starting processes. A sandbox is meant to sit here. This is the boundary honeyrepo tests.
3. **The person running honeyrepo trusts the wrapper and the scenario.** Both are code that runs with their privileges. honeyrepo does not defend against a malicious wrapper or scenario. See "Safety rules" below.

Between the first two sit the model's own judgement, permission prompts and the sandbox. Only the sandbox is tested.

## What honeyrepo tests, and what it does not

**Tested (scripted mode):** a fixed attacker runs inside your sandbox configuration. Can it read a fake secret from a throwaway home folder and send it to a listener on this machine? honeyrepo watches each stage (start, positive control, read, send) and looks for the canary in whatever reaches the listener, including common encodings.

**Not tested:**

- Whether a real model follows the bait (live mode is planned)
- Permission prompts and approval flows
- Exfiltration channels other than one HTTP request to a loopback listener: DNS, raw sockets to other hosts, writing into a synced folder (a custom attack can try them; the built-in one does not)
- Destructive actions such as deleting files or force-pushing
- MCP tool poisoning
- Sandbox escapes at the kernel level, resource limits, persistence
- macOS sandboxes and native Windows sandboxes

## How to read a result

| Verdict | It means | It does not mean |
| --- | --- | --- |
| LEAKED | The canary reached the listener. This happened. | That your internet access is open. See limit 2. |
| HELD | The attacker ran, could read the bait repo, and was then denied the canary file or blocked from connecting. Nothing reached the listener. | That the sandbox is secure. See limits 1, 3, 4 and 5. |
| INCONCLUSIVE | The evidence does not support either answer. | That the sandbox held. It is never reported as HELD. |

HELD requires positive evidence. A wrapper that breaks the attacker, a crash, a timeout, a missing report or traffic honeyrepo cannot explain gives INCONCLUSIVE. [verdicts.md](verdicts.md) lists every reason code.

## Safety rules for this project

- Every secret is a fake canary, generated fresh on each run (`HONEYREPO-CANARY-` plus random hex). Never put a real credential in a scenario.
- The listener binds to `127.0.0.1` on a port the operating system chooses, and honeyrepo checks that it did. honeyrepo makes no other network connections.
- The attack process gets a minimal environment: a short list of variables (`PATH`, temp folders, locale) plus its own `HOME`. Your real API keys and tokens are not passed on. The built-in attacker is given absolute paths, so changing or unsetting `HOME` cannot send it to a real file.
- Scenario file paths must be relative and cannot contain `..`.
- The bait repo and fake home live in a temporary folder created with owner-only permissions and deleted after the run, including after failures and interrupts. If deletion fails, honeyrepo says so.
- honeyrepo has no runtime dependencies, which keeps what you have to trust small. Installing it still involves your Python packaging tools, and its CI uses GitHub Actions.
- On POSIX the attack runs in its own process group, and the whole group is stopped when the run ends, so background processes do not outlive the run.
- **A wrapper or scenario command runs on your machine, with your privileges.** honeyrepo does not sandbox it for you. Read a scenario from someone else before you run it.

## Known limits

Where honeyrepo can mislead you:

1. **HELD proves less than it sounds for the network.** The listener is on this machine's loopback address, so `send-blocked` only shows the attack could not reach that listener. A setup that cuts off loopback but allows the internet could report HELD and still let a secret reach a public server. A container on a bridge network is one case, because it cannot see the host's `127.0.0.1`. A possible fix is a second listener on a non-loopback address of this machine. That is not built.
2. **LEAKED may overstate the risk.** A sandbox that blocks the internet but allows local connections would report LEAKED. Read LEAKED as "this path is open", not "everything is open".
3. **The canary is not in your real home folder.** It sits in a throwaway home under the temp folder. Rules you wrote for your real `~/.ssh` or `~/.env` are not exercised unless you point a rule at `{home}`.
4. **One file, one path, one tool.** The built-in attack reads one file and sends it with one HTTP POST from Python. A sandbox that treats other files, other protocols or other programs differently may behave differently.
5. **`read-hidden` cannot tell a hiding rule from a missing mount.** If the folder with the canary is not visible but the bait repo is, honeyrepo reports HELD. It cannot know whether you meant that.
6. **Detection is not exhaustive.** honeyrepo decodes plain text, percent-encoding, JSON and `\u`/`\x` escapes, base64, base32, hex, gzip/zlib/deflate, chunked bodies, reversed text and a secret split over requests, up to three layers. Encryption and custom ciphers are not detected. Undecodable data gives INCONCLUSIVE, not HELD, but you then have to look at it yourself.
7. **Processes that leave the process group can survive.** An attack that starts a process in a new session is not stopped by honeyrepo. If such a process keeps the output open, honeyrepo reports a warning. Windows process cleanup uses `taskkill` and has not been tested. On POSIX the group is stopped by its ID after the attack exits; in theory that ID could be reused by an unrelated process in the instant between the two, though the group is normally still alive then.
8. **A script is not an agent.** Results say nothing about how Claude Code, Codex or any other agent behaves.
9. **A forged report can forge a HELD.** The attacker's stage lines are evidence, and HELD also needs an empty listener, but a wrapper or custom attack that prints false stage lines is trusted code. See the trust boundary above.

## What has been verified

This table says what was actually run. "Not run" means no result exists, not that it fails. On any platform other than Linux, honeyrepo prints a warning saying so with every result.

| Environment | Status |
| --- | --- |
| Linux, Python 3.11, 3.12, 3.13, as root and as an unprivileged user: full test suite, `sandbox-check.sh` rows for no sandbox, `unshare --net` and the three "not a sandbox" rows | Run against 0.1.0 |
| Linux: wheel built, installed into a clean virtual environment, CLI run from there | Run against 0.1.0 |
| WSL2 (Ubuntu 24.04.2 LTS, bubblewrap 0.9.0; checkout under `/mnt/d`): all eight rows of `sandbox-check.sh`, including the three `bwrap` rows | Run against 0.1.0: all eight matched |
| GitHub Actions, Ubuntu, Python 3.11 to 3.13 | Run with 0.0.1. Not run with 0.1.0 until pushed |
| Native Windows | Test suite run with 0.0.1. Not run with 0.1.0 |
| macOS | Not run |
| Docker | Not run, not supported yet |
