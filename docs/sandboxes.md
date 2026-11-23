# Testing a real sandbox

`honeyrepo run SCENARIO --wrap "..."` puts a command in front of the attack, so the attack runs inside your sandbox. The verdict tells you whether the canary secret reached the listener, and if not, whether there is proof that the sandbox stopped it. See [verdicts.md](verdicts.md).

Placeholders you can use inside `--wrap`:

| Placeholder | Becomes |
|---|---|
| `{python}` | the Python that runs honeyrepo |
| `{repo}` | the throwaway bait repo folder (the attack's working directory) |
| `{home}` | the throwaway HOME that holds the canary |

Your wrapper must let the attack read `{repo}`. The attack first reads a harmless control file there. If it cannot, the result is INCONCLUSIVE (`control-unreadable`).

## Status of the commands below

| Wrapper | Expected | Status |
|---|---|---|
| none | LEAKED | Run on Linux with 0.1.0 (Python 3.11, 3.12, 3.13): LEAKED |
| `unshare --map-root-user --net` | HELD (`send-blocked`) | Run on Linux and on WSL2 with 0.1.0: HELD (`send-blocked`) |
| `bwrap`, filesystem only | LEAKED | Run on WSL2 with 0.1.0: LEAKED (`canary-received`) |
| `bwrap`, home hidden | HELD (`read-hidden`) | Run on WSL2 with 0.1.0: HELD (`read-hidden`) |
| `bwrap`, network off | HELD (`send-blocked`) | Run on WSL2 with 0.1.0: HELD (`send-blocked`) |
| `env HOME=/nonexistent`, `env -i` (not sandboxes) | LEAKED | Run on Linux and on WSL2 with 0.1.0: LEAKED. The 0.0.1 rules reported HELD here, which was wrong |
| `false` (a wrapper that fails at once) | INCONCLUSIVE (`not-started`) | Run on Linux and on WSL2 with 0.1.0 |

The WSL2 rows were run on Ubuntu 24.04.2 LTS with bubblewrap 0.9.0. `bash scripts/sandbox-check.sh` runs every row and prints the expected and the actual verdict. Other distributions, kernels, macOS and native Windows are untested.

## Windows: use WSL2

Run honeyrepo inside WSL2 (Ubuntu), not from PowerShell. The wrapper tools are Linux tools, and the temp folders honeyrepo creates must be paths that the sandbox can see.

1. Open Ubuntu and check `python3 --version`. honeyrepo needs 3.11 or newer (Ubuntu 24.04 ships 3.12).
2. Clone into the Linux home, not into `/mnt/d` (slow, and file permissions behave differently):

   ```bash
   cd ~
   git clone https://github.com/weto4ka/honeyrepo
   cd honeyrepo
   sudo apt install -y python3-venv bubblewrap
   python3 -m venv .venv
   .venv/bin/python -m pip install -e .
   ```

   To run every check below in one go (no install needed, wrappers that are missing are skipped), use `bash scripts/sandbox-check.sh`.

3. No sandbox. Expect `LEAKED`, exit code 1:

   ```bash
   .venv/bin/honeyrepo run readme-exfil
   ```

4. Network namespace (needs no extra install). Expect `HELD` (`send-blocked`), exit code 0:

   ```bash
   .venv/bin/honeyrepo run readme-exfil --wrap "unshare --map-root-user --net"
   ```

5. bubblewrap, three configurations of the same tool:

   ```bash
   # a) filesystem sandbox that forgot the network. Expect LEAKED
   .venv/bin/honeyrepo run readme-exfil --wrap "bwrap --ro-bind / / --dev /dev --proc /proc --bind {repo} {repo} --bind {home} {home}"

   # b) same, but the home folder is hidden. Expect HELD (read-hidden)
   .venv/bin/honeyrepo run readme-exfil --wrap "bwrap --ro-bind / / --dev /dev --proc /proc --bind {repo} {repo} --tmpfs {home}"

   # c) same as (a), plus no network. Expect HELD (send-blocked)
   .venv/bin/honeyrepo run readme-exfil --wrap "bwrap --unshare-net --ro-bind / / --dev /dev --proc /proc --bind {repo} {repo} --bind {home} {home}"
   ```

   Result (a) is the interesting one. A sandbox that restricts writes looks safe and still lets the secret out.

   Result (b) is HELD because the attacker could read `{repo}` but not the canary. honeyrepo cannot tell "your rule hides the file" from "that folder was never mounted". Check that your rule does what you meant.

## If you get INCONCLUSIVE (exit code 3)

honeyrepo is telling you it has no proof either way, so it does not call it HELD. Read the `why:` line and the `stderr:` lines first. The usual causes:

- `not-started`: the wrapper failed before running the attack (wrong flag, missing tool, a command that needs `sudo`).
- `control-unreadable`: the wrapper hides `{repo}`. Mount it.
- `timeout`: the sandbox stalls the attack. Raise `--timeout` to rule out a slow machine.
- `unrecognised-request`, `connected-no-data`: something reached the listener but honeyrepo cannot show it was the canary. Look at it as a possible leak.

Every code is explained in [verdicts.md](verdicts.md).

## Why not Docker yet

`{python}` expands to the interpreter on the machine that runs honeyrepo. That path does not exist inside a container, and the temp folders would need to be mounted in. A container on a bridge network also cannot see the host's `127.0.0.1`, so the loopback listener could not be reached at all, and `send-blocked` would say nothing about the internet. Docker needs a few additions to honeyrepo, so it is on the roadmap rather than documented here.
